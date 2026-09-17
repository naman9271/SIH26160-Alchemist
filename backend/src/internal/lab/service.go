package lab

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io"
	_ "modernc.org/sqlite"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Settings struct {
	Name               string   `json:"name"`
	Profiles           []int    `json:"profiles"`
	Labels             []string `json:"labels"`
	Repetitions        int      `json:"repetitions"`
	EvaluationLabels   []string `json:"evaluation_labels"`
	IncludeProtocol    bool     `json:"include_protocol"`
	EvaluationDuration int      `json:"evaluation_duration"`
}
type Status struct {
	State   string   `json:"state"`
	Ready   bool     `json:"ready"`
	Message string   `json:"message"`
	Logs    []string `json:"logs"`
}
type Run struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	State     string   `json:"state"`
	CreatedAt string   `json:"created_at"`
	Settings  Settings `json:"settings"`
	Logs      []string `json:"logs"`
}
type Dataset struct {
	ID        string `json:"id"`
	RunID     string `json:"run_id"`
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	Records   int    `json:"records"`
	CreatedAt string `json:"created_at"`
}
type Runner func(context.Context, []string, func(string)) error
type Service struct {
	db         *sql.DB
	mu         sync.Mutex
	datasetDir string
	runner     Runner
	ctx        context.Context
	cancel     context.CancelFunc
	workers    sync.WaitGroup
}

func encode(value any) string { b, _ := json.Marshal(value); return string(b) }
func decodeStrings(raw string) []string {
	var v []string
	_ = json.Unmarshal([]byte(raw), &v)
	if v == nil {
		return []string{}
	}
	return v
}
func New(path string, runner Runner) (*Service, error) {
	if path == "" {
		path = "app.db"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
 CREATE TABLE IF NOT EXISTS lab_runtime(id INTEGER PRIMARY KEY,state TEXT NOT NULL,activated_at TEXT);
 INSERT OR IGNORE INTO lab_runtime(id,state) VALUES(1,'INACTIVE');
 CREATE TABLE IF NOT EXISTS lab_runtime_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,line TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS lab_runs(id TEXT PRIMARY KEY,name TEXT NOT NULL,state TEXT NOT NULL,created_at TEXT NOT NULL,settings_json TEXT NOT NULL,logs_json TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS lab_datasets(id TEXT PRIMARY KEY,run_id TEXT NOT NULL,path TEXT NOT NULL,kind TEXT NOT NULL,records INTEGER NOT NULL,created_at TEXT NOT NULL);
 CREATE UNIQUE INDEX IF NOT EXISTS lab_artifact_path ON lab_datasets(run_id,path);
 UPDATE lab_runtime SET state='INACTIVE' WHERE id=1;
 UPDATE lab_runs SET state='FAILED' WHERE state='RUNNING';`)
	if err != nil {
		db.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{db: db, datasetDir: filepath.Join(filepath.Dir(path), "datasets"), runner: runner, ctx: ctx, cancel: cancel}, nil
}
func (s *Service) Close() error { s.cancel(); s.workers.Wait(); return s.db.Close() }
func (s *Service) Status(ctx context.Context) (Status, error) {
	var state string
	if err := s.db.QueryRowContext(ctx, "SELECT state FROM lab_runtime WHERE id=1").Scan(&state); err != nil {
		return Status{}, err
	}
	logs := []string{}
	rows, err := s.db.QueryContext(ctx, "SELECT line FROM lab_runtime_logs ORDER BY id")
	if err != nil {
		return Status{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return Status{}, err
		}
		logs = append(logs, line)
	}
	message := map[string]string{"INACTIVE": "Activate the lab to prepare gateways and traffic fixtures.", "STARTING": "Building gateways and preparing traffic fixtures. Follow the process logs.", "READY": "Gateways and fixtures are ready for real PCAP capture.", "FAILED": "Activation failed. Open runtime logs for the command error."}[state]
	return Status{State: state, Ready: state == "READY", Message: message, Logs: logs}, rows.Err()
}
func (s *Service) Activate(ctx context.Context) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	status, err := s.Status(ctx)
	if err != nil {
		return Status{}, err
	}
	if status.State == "STARTING" || status.Ready {
		return status, nil
	}
	if s.runner == nil {
		return Status{}, fmt.Errorf("managed lab runner is not configured")
	}
	if _, err = s.db.ExecContext(ctx, "DELETE FROM lab_runtime_logs; UPDATE lab_runtime SET state='STARTING' WHERE id=1"); err != nil {
		return Status{}, err
	}
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		jobCtx, cancel := context.WithTimeout(s.ctx, 15*time.Minute)
		defer cancel()
		log := func(line string) {
			_, _ = s.db.Exec("INSERT INTO lab_runtime_logs(line) VALUES(?)", time.Now().UTC().Format("15:04:05")+" "+line)
		}
		log("Starting managed.sh activate")
		state := "READY"
		if err := s.runner(jobCtx, []string{"activate"}, log); err != nil {
			state = "FAILED"
			log("ERROR: " + err.Error())
		}
		_, _ = s.db.Exec("UPDATE lab_runtime SET state=? WHERE id=1", state)
	}()
	return Status{State: "STARTING", Message: "Starting the managed capture lab", Logs: []string{}}, nil
}
func validate(v Settings) error {
	if strings.TrimSpace(v.Name) == "" || len(v.Name) > 120 {
		return fmt.Errorf("experiment name must contain 1–120 characters")
	}
	if len(v.Profiles) == 0 || len(v.Profiles) > 5 {
		return fmt.Errorf("choose one or more profiles")
	}
	seen := map[int]bool{}
	for _, p := range v.Profiles {
		if p < 1 || p > 5 || seen[p] {
			return fmt.Errorf("profiles must be unique values from 1 to 5")
		}
		seen[p] = true
	}
	valid := map[string]bool{"web": true, "video": true, "voip": true, "email": true, "file_transfer": true, "messaging": true, "icmp": true}
	if len(v.Labels) == 0 || len(v.Labels) > 7 {
		return fmt.Errorf("choose one or more traffic labels")
	}
	labels := map[string]bool{}
	for _, l := range v.Labels {
		if !valid[l] || labels[l] {
			return fmt.Errorf("unsupported or repeated traffic label")
		}
		labels[l] = true
	}
	if v.Repetitions < 1 || v.Repetitions > 5 {
		return fmt.Errorf("repetitions must be between 1 and 5")
	}
	allowedEvaluations := map[string]bool{"dns": true, "ssh": true, "gaming_udp": true, "database": true, "remote_desktop": true, "icmp_flood": true, "udp_flood": true, "beacon_burst": true}
	seenEvaluations := map[string]bool{}
	for _, label := range v.EvaluationLabels {
		if !allowedEvaluations[label] || seenEvaluations[label] {
			return fmt.Errorf("unsupported or repeated evaluation label")
		}
		seenEvaluations[label] = true
	}
	if len(v.EvaluationLabels) > 0 && (v.EvaluationDuration < 5 || v.EvaluationDuration > 120) {
		return fmt.Errorf("evaluation duration must be 5–120 seconds")
	}
	return nil
}
func (s *Service) Start(ctx context.Context, v Settings) (Run, error) {
	if err := validate(v); err != nil {
		return Run{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	status, err := s.Status(ctx)
	if err != nil {
		return Run{}, err
	}
	if !status.Ready {
		return Run{}, fmt.Errorf("activate the lab before starting capture")
	}
	var active int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM lab_runs WHERE state='RUNNING'").Scan(&active); err != nil {
		return Run{}, err
	}
	if active > 0 {
		return Run{}, fmt.Errorf("a capture is already running; shared gateways can run one experiment at a time")
	}
	r := Run{ID: uuid.NewString(), Name: v.Name, State: "RUNNING", CreatedAt: time.Now().UTC().Format(time.RFC3339), Settings: v, Logs: []string{"Preparing real PCAP dataset"}}
	_, err = s.db.ExecContext(ctx, "INSERT INTO lab_runs VALUES(?,?,?,?,?,?)", r.ID, r.Name, r.State, r.CreatedAt, encode(v), encode(r.Logs))
	if err != nil {
		return Run{}, err
	}
	s.workers.Add(1)
	go func() { defer s.workers.Done(); s.complete(r) }()
	return r, nil
}
func (s *Service) appendLog(id, line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var raw string
	if s.db.QueryRow("SELECT logs_json FROM lab_runs WHERE id=?", id).Scan(&raw) != nil {
		return
	}
	logs := decodeStrings(raw)
	logs = append(logs, time.Now().UTC().Format("15:04:05")+" "+line)
	if len(logs) > 10000 {
		logs = logs[len(logs)-10000:]
	}
	_, _ = s.db.Exec("UPDATE lab_runs SET logs_json=? WHERE id=?", encode(logs), id)
}
func (s *Service) complete(r Run) {
	dir := filepath.Join(s.datasetDir, r.ID)
	log := func(line string) {
		s.appendLog(r.ID, line)
		if strings.HasPrefix(line, "Captured ") {
			if err := s.index(s.ctx, r.ID, dir); err != nil {
				s.appendLog(r.ID, "Artifact indexing: "+err.Error())
			}
		}
	}
	var profiles []string
	for _, p := range r.Settings.Profiles {
		profiles = append(profiles, strconv.Itoa(p))
	}
	ctx, cancel := context.WithTimeout(s.ctx, 6*time.Hour)
	defer cancel()
	err := s.runner(ctx, []string{"generate", dir, strings.Join(profiles, ","), strings.Join(r.Settings.Labels, ","), strconv.Itoa(r.Settings.Repetitions), strings.Join(r.Settings.EvaluationLabels, ","), strconv.FormatBool(r.Settings.IncludeProtocol), strconv.Itoa(r.Settings.EvaluationDuration)}, log)
	if err == nil {
		err = s.index(ctx, r.ID, dir)
	}
	state := "COMPLETED"
	if err != nil {
		state = "FAILED"
		log("ERROR: " + err.Error())
	} else {
		log("Capture, metadata and artifact indexing completed")
	}
	_, _ = s.db.Exec("UPDATE lab_runs SET state=? WHERE id=?", state, r.ID)
}
func (s *Service) index(ctx context.Context, id, dir string) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "lab" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		kind := "artifact"
		count := 0
		if strings.HasSuffix(rel, ".pcap") {
			kind = "encrypted outer PCAP"
		}
		if rel == "metadata.csv" {
			kind = "capture metadata"
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			rows, err := csv.NewReader(file).ReadAll()
			file.Close()
			if err != nil {
				return err
			}
			count = len(rows) - 1
			if count < 1 {
				return fmt.Errorf("metadata contains no captures")
			}
		}
		_, err = s.db.ExecContext(ctx, "INSERT INTO lab_datasets VALUES(?,?,?,?,?,?) ON CONFLICT(run_id,path) DO UPDATE SET records=excluded.records", uuid.NewString(), id, filepath.ToSlash(rel), kind, count, time.Now().UTC().Format(time.RFC3339))
		return err
	})
}
func (s *Service) Runs(ctx context.Context) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,name,state,created_at,settings_json,logs_json FROM lab_runs ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Run{}
	for rows.Next() {
		var r Run
		var settings, logs string
		if err := rows.Scan(&r.ID, &r.Name, &r.State, &r.CreatedAt, &settings, &logs); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(settings), &r.Settings)
		r.Logs = decodeStrings(logs)
		result = append(result, r)
	}
	return result, rows.Err()
}
func (s *Service) Datasets(ctx context.Context) ([]Dataset, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,run_id,path,kind,records,created_at FROM lab_datasets ORDER BY run_id,path")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Dataset{}
	for rows.Next() {
		var d Dataset
		if err := rows.Scan(&d.ID, &d.RunID, &d.Path, &d.Kind, &d.Records, &d.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, d)
	}
	return result, rows.Err()
}
func (s *Service) Artifact(ctx context.Context, id, path string) ([]byte, error) {
	var stored string
	if err := s.db.QueryRowContext(ctx, "SELECT path FROM lab_datasets WHERE run_id=? AND path=?", id, path).Scan(&stored); err != nil {
		return nil, err
	}
	if filepath.IsAbs(stored) || strings.Contains(stored, "..") {
		return nil, fmt.Errorf("invalid path")
	}
	return os.ReadFile(filepath.Join(s.datasetDir, id, filepath.FromSlash(strings.TrimPrefix(stored, "labs/"+id+"/"))))
}
func (s *Service) Archive(ctx context.Context, id string) ([]byte, string, error) {
	var buffer bytes.Buffer
	if err := s.WriteArchive(ctx, id, &buffer); err != nil {
		return nil, "", err
	}
	return buffer.Bytes(), "ipsec-dataset-" + id + ".zip", nil
}
func (s *Service) ArchiveReady(ctx context.Context, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return err
	}
	var state string
	if err := s.db.QueryRowContext(ctx, "SELECT state FROM lab_runs WHERE id=?", id).Scan(&state); err != nil {
		return err
	}
	if state != "COMPLETED" {
		return fmt.Errorf("dataset not complete")
	}
	return nil
}
func (s *Service) WriteArchive(ctx context.Context, id string, output io.Writer) error {
	if err := s.ArchiveReady(ctx, id); err != nil {
		return err
	}
	archive := zip.NewWriter(output)
	datasets, err := s.Datasets(ctx)
	if err != nil {
		return err
	}
	for _, d := range datasets {
		if d.RunID != id {
			continue
		}
		if filepath.IsAbs(d.Path) || strings.Contains(d.Path, "..") {
			return fmt.Errorf("invalid artifact path")
		}
		source, err := os.Open(filepath.Join(s.datasetDir, id, filepath.FromSlash(strings.TrimPrefix(d.Path, "labs/"+id+"/"))))
		if err != nil {
			return err
		}
		file, err := archive.Create(d.Path)
		if err != nil {
			source.Close()
			return err
		}
		_, err = io.Copy(file, source)
		source.Close()
		if err != nil {
			return err
		}
	}
	if err := archive.Close(); err != nil {
		return err
	}
	return nil
}

type logWriter struct {
	mu      sync.Mutex
	pending string
	log     func(string)
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending += string(p)
	for {
		pos := strings.IndexByte(w.pending, '\n')
		if pos < 0 {
			break
		}
		line := strings.TrimSpace(w.pending[:pos])
		w.pending = w.pending[pos+1:]
		if line != "" {
			w.log(line)
		}
	}
	return len(p), nil
}
func ScriptRunner(path string) Runner {
	return func(ctx context.Context, args []string, log func(string)) error {
		if path == "" {
			return fmt.Errorf("LAB_RUNNER_SCRIPT is not configured")
		}
		cmd := exec.CommandContext(ctx, "bash", append([]string{path}, args...)...)
		writer := &logWriter{log: log}
		cmd.Stdout = writer
		cmd.Stderr = writer
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
		cmd.WaitDelay = 10 * time.Second
		err := cmd.Run()
		if writer.pending != "" {
			log(writer.pending)
		}
		if err != nil {
			return fmt.Errorf("runner failed: %w", err)
		}
		return nil
	}
}

var _ io.Writer = (*logWriter)(nil)

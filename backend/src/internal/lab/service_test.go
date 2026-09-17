package lab

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunPersistsDatasetsAndHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labs", "app.db")
	runner := func(ctx context.Context, args []string, log func(string)) error {
		if args[0] == "activate" {
			log("gateways ready")
			return nil
		}
		dir := args[1]
		if err := os.MkdirAll(filepath.Join(dir, "pcaps", "known", "icmp"), 0750); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "pcaps", "known", "icmp", "icmp_p01_R01.pcap"), []byte("test-fixture"), 0640); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "metadata.csv"), []byte("sample_id,packet_count\nicmp_p01_R01,5\n"), 0640); err != nil {
			return err
		}
		log("capture finished")
		return os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{}"), 0640)
	}
	service, err := New(path, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if _, err := service.db.Exec("UPDATE lab_runtime SET state='READY' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	run, err := service.Start(context.Background(), Settings{Name: "test data", Profiles: []int{1}, Labels: []string{"icmp"}, Repetitions: 1})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		runs, err := service.Runs(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(runs) == 1 && runs[0].State == "COMPLETED" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	datasets, err := service.Datasets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(datasets) != 3 {
		t.Fatalf("datasets = %d, want 3", len(datasets))
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), "datasets", run.ID, "metadata.csv")); err != nil {
		t.Fatalf("dataset file not written: %v", err)
	}
	contents, filename, err := service.Archive(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Ext(filename) != ".zip" {
		t.Fatalf("archive filename = %q", filename)
	}
	archive, err := zip.NewReader(bytes.NewReader(contents), int64(len(contents)))
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.File) != 3 {
		t.Fatalf("archive files = %d, want 3", len(archive.File))
	}
}

func TestActivationReportsActualRunnerFailure(t *testing.T) {
	service, err := New(filepath.Join(t.TempDir(), "app.db"), func(ctx context.Context, args []string, log func(string)) error {
		log("Docker socket permission denied")
		return fmt.Errorf("exit status 1")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if _, err := service.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status, err := service.Status(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if status.State == "FAILED" {
			if !strings.Contains(strings.Join(status.Logs, "\n"), "permission denied") {
				t.Fatal("runner output not retained")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("activation did not report failure")
}
func TestScriptRunnerStreamsStdoutAndStderr(t *testing.T) {
	script := filepath.Join(t.TempDir(), "runner.sh")
	if err := os.WriteFile(script, []byte("printf 'capture stdout\\n'; printf 'capture stderr\\n' >&2; exit 7\n"), 0640); err != nil {
		t.Fatal(err)
	}
	var lines []string
	if err := ScriptRunner(script)(context.Background(), nil, func(line string) { lines = append(lines, line) }); err == nil {
		t.Fatal("expected process error")
	}
	if len(lines) != 2 || lines[0] != "capture stdout" || lines[1] != "capture stderr" {
		t.Fatalf("logs = %#v", lines)
	}
}

package fusion

import (
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/confidence"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/conflict"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/correlation"
	fusionengine "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/engine"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/event"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/ingest"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/provenance"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/query"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/session"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/store"
	fusionsystem "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/system"
)

// Runtime wires the internal Fusion services to one authoritative in-memory
// store. It is embedded in Go Core; it is intentionally not a gRPC server.
type Runtime struct {
	System       *fusionsystem.Service
	Sessions     *session.Service
	Ingest       *ingest.Service
	Query        *query.Service
	Correlations *correlation.Service
	Conflicts    *conflict.Service
	Confidence   *confidence.Service
	Fusion       *fusionengine.Service
	Provenance   *provenance.Service
	Policy       *policy.Service
	Events       *event.Service
	Store        *store.Memory
	Policies     *policy.Memory
}

type RuntimeOptions struct {
	Version            fusionsystem.Version
	Correlator         fusionsystem.Probe
	RecomputeScheduler ingest.RecomputeScheduler
	FusionEvents       fusionengine.EventSink
	PolicyDirectory    string
}

func NewRuntime(options RuntimeOptions) *Runtime {
	evidenceStore := store.NewMemory()
	policies := policy.NewDefault()
	eventService := event.New(0)
	correlationService := correlation.New(evidenceStore, eventService)
	confidenceService := confidence.New(evidenceStore, policies)
	conflictService := conflict.New(evidenceStore, policies, eventService)
	fusionService := fusionengine.New(evidenceStore, correlationService, conflictService, confidenceService, policies, options.FusionEvents, eventService)
	provenanceService := provenance.New(evidenceStore, policies, eventService)
	var loader policy.Loader
	if options.PolicyDirectory != "" {
		loader = policy.DirectoryLoader{Directory: options.PolicyDirectory}
	}
	policyService := policy.NewService(policies, loader)
	sessionService := session.New(evidenceStore, policies, eventService)
	correlatorProbe := options.Correlator
	if correlatorProbe == nil {
		correlatorProbe = correlationService
	}
	systemService := fusionsystem.New(fusionsystem.Options{
		Policy: policies, EvidenceStore: evidenceStore, Correlator: correlatorProbe,
		ConflictEngine: conflictService, ConfidenceEngine: confidenceService,
		Version: options.Version,
		Capabilities: fusionsystem.Capabilities{
			PassiveEvidence: true, VICIEvidence: true, XFRMEvidence: true,
			MLEvidence: true, SHAPEvidence: true, SecurityFindingRefs: true,
			ConflictDetection: true, ConfidenceCalculation: true, Provenance: true,
			IncrementalRecomputation: true,
		},
	})
	scheduler := options.RecomputeScheduler
	if scheduler == nil {
		scheduler = fusionService
	}
	return &Runtime{
		System: systemService, Sessions: sessionService,
		Ingest: ingest.New(evidenceStore, scheduler, eventService), Query: query.New(evidenceStore), Correlations: correlationService,
		Conflicts: conflictService, Confidence: confidenceService, Fusion: fusionService,
		Provenance: provenanceService, Policy: policyService, Events: eventService,
		Store: evidenceStore, Policies: policies,
	}
}

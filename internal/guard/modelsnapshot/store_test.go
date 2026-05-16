package modelsnapshot

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/markov"
	"github.com/kontext-security/kontext-cli/internal/guard/trace"
)

func TestActivateFromFilePersistsActiveSnapshot(t *testing.T) {
	source := writeModel(t, t.TempDir(), "model.json", "v1")
	store := New(t.TempDir())

	snapshot, err := store.ActivateFromFile(source)
	if err != nil {
		t.Fatalf("ActivateFromFile() error = %v", err)
	}
	if snapshot.ID == "" || snapshot.Path == "" || snapshot.SHA256 == "" {
		t.Fatalf("snapshot missing metadata: %+v", snapshot)
	}
	if snapshot.SourcePath != source {
		t.Fatalf("SourcePath = %q, want %q", snapshot.SourcePath, source)
	}
	if _, err := os.Stat(snapshot.Path); err != nil {
		t.Fatalf("snapshot model file: %v", err)
	}
	active, err := store.Active()
	if err != nil {
		t.Fatalf("Active() error = %v", err)
	}
	if active.ID != snapshot.ID || active.Path != snapshot.Path {
		t.Fatalf("active = %+v, want snapshot %+v", active, snapshot)
	}
}

func TestActivateBytesPersistsPrivateSnapshot(t *testing.T) {
	source := writeModel(t, t.TempDir(), "model.json", "v1")
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store := New(root)

	snapshot, err := store.ActivateBytes("embedded:test-model", data)
	if err != nil {
		t.Fatalf("ActivateBytes() error = %v", err)
	}
	if snapshot.SourcePath != "embedded:test-model" {
		t.Fatalf("SourcePath = %q, want embedded source", snapshot.SourcePath)
	}
	for _, path := range []string{snapshot.Path, store.activePath(), store.snapshotMetadataPath(snapshot.ID)} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat(%s) error = %v", path, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode = %o, want 600", path, got)
		}
	}
	if info, err := os.Stat(filepath.Join(root, "snapshots")); err != nil {
		t.Fatalf("snapshot dir stat error = %v", err)
	} else if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("snapshot dir mode = %o, want 700", got)
	}
}

func TestActivateFromFileReusesActiveSnapshotForSameModel(t *testing.T) {
	source := writeModel(t, t.TempDir(), "model.json", "v1")
	store := New(t.TempDir())

	first, err := store.ActivateFromFile(source)
	if err != nil {
		t.Fatalf("first ActivateFromFile() error = %v", err)
	}
	second, err := store.ActivateFromFile(source)
	if err != nil {
		t.Fatalf("second ActivateFromFile() error = %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("second ID = %q, want reused active ID %q", second.ID, first.ID)
	}
}

func TestRollbackActivatesPreviousSnapshot(t *testing.T) {
	dir := t.TempDir()
	store := New(t.TempDir())
	firstSource := writeModel(t, dir, "model-v1.json", "v1")
	secondSource := writeModel(t, dir, "model-v2.json", "v2")

	first, err := store.ActivateFromFile(firstSource)
	if err != nil {
		t.Fatalf("first ActivateFromFile() error = %v", err)
	}
	second, err := store.ActivateFromFile(secondSource)
	if err != nil {
		t.Fatalf("second ActivateFromFile() error = %v", err)
	}
	if second.PreviousID != first.ID {
		t.Fatalf("PreviousID = %q, want %q", second.PreviousID, first.ID)
	}
	rolledBack, err := store.Rollback()
	if err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	if rolledBack.ID != first.ID {
		t.Fatalf("rolledBack ID = %q, want %q", rolledBack.ID, first.ID)
	}
	active, err := store.Active()
	if err != nil {
		t.Fatalf("Active() error = %v", err)
	}
	if active.ID != first.ID || active.PreviousID != second.ID {
		t.Fatalf("active after rollback = %+v, want first with previous second", active)
	}
	persisted, err := store.readSnapshot(first.ID)
	if err != nil {
		t.Fatalf("readSnapshot() error = %v", err)
	}
	if persisted.ID != first.ID || persisted.PreviousID != second.ID {
		t.Fatalf("persisted snapshot after rollback = %+v, want first with previous second", persisted)
	}
	if !persisted.ActivatedAt.Equal(rolledBack.ActivatedAt) {
		t.Fatalf("persisted ActivatedAt = %s, want returned rollback activation time %s", persisted.ActivatedAt, rolledBack.ActivatedAt)
	}
}

func TestActiveReturnsNoActiveSnapshot(t *testing.T) {
	_, err := New(t.TempDir()).Active()
	if !errors.Is(err, ErrNoActiveSnapshot) {
		t.Fatalf("Active() error = %v, want ErrNoActiveSnapshot", err)
	}
}

func TestActivateFromFileRejectsInvalidModel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(path, []byte(`{"states":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(t.TempDir()).ActivateFromFile(path); err == nil {
		t.Fatal("ActivateFromFile() error = nil, want invalid model error")
	}
}

func TestActivateFromFileRejectsValidatorError(t *testing.T) {
	source := writeModel(t, t.TempDir(), "model.json", "v1")
	store := NewWithValidator(t.TempDir(), func(*markov.Model) error {
		return errors.New("unsupported abstraction")
	})

	if _, err := store.ActivateFromFile(source); err == nil {
		t.Fatal("ActivateFromFile() error = nil, want validator error")
	}
	if _, err := store.Active(); !errors.Is(err, ErrNoActiveSnapshot) {
		t.Fatalf("Active() error = %v, want ErrNoActiveSnapshot", err)
	}
}

func writeModel(t *testing.T, dir, name, version string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	metadata, err := json.Marshal(map[string]string{"abstraction_version": trace.RiskAbstractionVersion, "version": version})
	if err != nil {
		t.Fatal(err)
	}
	model := markov.Model{
		States: []string{"safe"},
		StateIndex: map[string]int{
			"safe": 0,
		},
		TransitionProbs: map[int]map[int]float64{
			0: {0: 1},
		},
		Metadata: map[string]json.RawMessage{
			"abstraction_version": metadata,
		},
	}
	data, err := json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

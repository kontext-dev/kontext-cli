package modelsnapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/markov"
)

var ErrNoActiveSnapshot = errors.New("no active model snapshot")

type Snapshot struct {
	ID          string    `json:"id"`
	SourcePath  string    `json:"source_path"`
	Path        string    `json:"path"`
	SHA256      string    `json:"sha256"`
	CreatedAt   time.Time `json:"created_at"`
	ActivatedAt time.Time `json:"activated_at"`
	PreviousID  string    `json:"previous_id,omitempty"`
}

type Store struct {
	root     string
	validate func(*markov.Model) error
}

func New(root string) *Store {
	return &Store{root: root}
}

func NewWithValidator(root string, validate func(*markov.Model) error) *Store {
	return &Store{root: root, validate: validate}
}

func (s *Store) ActivateFromFile(path string) (Snapshot, error) {
	if strings.TrimSpace(path) == "" {
		return Snapshot{}, fmt.Errorf("model path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	model, err := markov.ReadModelJSON(bytes.NewReader(data))
	if err != nil {
		return Snapshot{}, fmt.Errorf("validate model snapshot: %w", err)
	}
	if s.validate != nil {
		if err := s.validate(model); err != nil {
			return Snapshot{}, fmt.Errorf("validate model snapshot: %w", err)
		}
	}

	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	active, activeErr := s.Active()
	if activeErr == nil && active.SHA256 == hash {
		return active, nil
	} else if activeErr != nil && !errors.Is(activeErr, ErrNoActiveSnapshot) {
		return Snapshot{}, activeErr
	}

	now := time.Now().UTC()
	previousID := ""
	if activeErr == nil {
		previousID = active.ID
	}

	id := now.Format("20060102T150405.000000000Z") + "-" + hash[:12]
	snapshotDir := filepath.Join(s.root, "snapshots")
	if err := os.MkdirAll(snapshotDir, 0o755); err != nil {
		return Snapshot{}, err
	}
	modelPath := filepath.Join(snapshotDir, id+".json")
	if err := writeFileAtomic(modelPath, data, 0o644); err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{
		ID:          id,
		SourcePath:  path,
		Path:        modelPath,
		SHA256:      hash,
		CreatedAt:   now,
		ActivatedAt: now,
		PreviousID:  previousID,
	}
	if err := s.writeSnapshot(snapshot); err != nil {
		return Snapshot{}, err
	}
	if err := s.writeActive(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func (s *Store) Active() (Snapshot, error) {
	data, err := os.ReadFile(s.activePath())
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, ErrNoActiveSnapshot
	}
	if err != nil {
		return Snapshot{}, err
	}
	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return Snapshot{}, err
	}
	if snapshot.ID == "" || snapshot.Path == "" {
		return Snapshot{}, fmt.Errorf("active model snapshot is invalid")
	}
	return snapshot, nil
}

func (s *Store) Rollback() (Snapshot, error) {
	active, err := s.Active()
	if err != nil {
		return Snapshot{}, err
	}
	if active.PreviousID == "" {
		return Snapshot{}, fmt.Errorf("active model snapshot has no rollback target")
	}
	previous, err := s.readSnapshot(active.PreviousID)
	if err != nil {
		return Snapshot{}, err
	}
	previous.PreviousID = active.ID
	previous.ActivatedAt = time.Now().UTC()
	if err := s.writeSnapshot(previous); err != nil {
		return Snapshot{}, err
	}
	if err := s.writeActive(previous); err != nil {
		return Snapshot{}, err
	}
	return previous, nil
}

func (s *Store) writeSnapshot(snapshot Snapshot) error {
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileAtomic(s.snapshotMetadataPath(snapshot.ID), data, 0o644)
}

func (s *Store) readSnapshot(id string) (Snapshot, error) {
	data, err := os.ReadFile(s.snapshotMetadataPath(id))
	if err != nil {
		return Snapshot{}, err
	}
	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return Snapshot{}, err
	}
	if snapshot.ID == "" || snapshot.Path == "" {
		return Snapshot{}, fmt.Errorf("model snapshot %q is invalid", id)
	}
	return snapshot, nil
}

func (s *Store) writeActive(snapshot Snapshot) error {
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileAtomic(s.activePath(), data, 0o644)
}

func (s *Store) activePath() string {
	return filepath.Join(s.root, "active.json")
}

func (s *Store) snapshotMetadataPath(id string) string {
	return filepath.Join(s.root, "snapshots", id+".metadata.json")
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

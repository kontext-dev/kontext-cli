package counttable

import "testing"

func TestObserveSequenceKeepsBoundaries(t *testing.T) {
	table, err := New[uint32](2)
	if err != nil {
		t.Fatal(err)
	}
	if err := table.ObserveSequence([]uint32{1, 2}); err != nil {
		t.Fatal(err)
	}
	if err := table.ObserveSequence([]uint32{3, 4}); err != nil {
		t.Fatal(err)
	}

	if got := table.Row([]uint32{2}).Next[3]; got != 0 {
		t.Fatalf("cross-boundary count [2] -> 3 = %d, want 0", got)
	}
	if got := table.Row([]uint32{3}).Next[4]; got != 1 {
		t.Fatalf("count [3] -> 4 = %d, want 1", got)
	}
}

func TestCloneKeepsRowsAndAlphabet(t *testing.T) {
	table, err := New[uint32](2)
	if err != nil {
		t.Fatal(err)
	}
	if err := table.ObserveSequence([]uint32{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	table.AddAlphabet([]uint32{9})

	restored := table.Clone()
	if got := restored.Row([]uint32{1, 2}).Next[3]; got != 1 {
		t.Fatalf("restored count [1 2] -> 3 = %d, want 1", got)
	}
	if got := restored.Alphabet(); len(got) != 4 || got[0] != 1 || got[1] != 2 || got[2] != 3 || got[3] != 9 {
		t.Fatalf("alphabet = %v, want [1 2 3 9]", got)
	}
}

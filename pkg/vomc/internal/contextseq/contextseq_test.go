package contextseq

import (
	"reflect"
	"testing"
)

func TestKey(t *testing.T) {
	seq := []uint32{3, 1, 4}
	if got := Key(seq); got != "3,1,4" {
		t.Fatalf("key = %q, want 3,1,4", got)
	}
	if got := Key([]uint32{}); got != "" {
		t.Fatalf("empty key = %q, want empty string", got)
	}
}

func TestSuffix(t *testing.T) {
	seq := []uint32{1, 2, 3, 4}
	if got := Suffix(seq, 2); !reflect.DeepEqual(got, []uint32{3, 4}) {
		t.Fatalf("suffix = %#v, want [3 4]", got)
	}
	if got := Suffix(seq, 0); got != nil {
		t.Fatalf("zero suffix = %#v, want nil", got)
	}
}

func TestSortContexts(t *testing.T) {
	contexts := [][]uint32{{2, 1}, {}, {1}, {1, 2}, {2}}
	SortContexts[uint32, []uint32](contexts)
	want := [][]uint32{{}, {1}, {2}, {1, 2}, {2, 1}}
	if !reflect.DeepEqual(contexts, want) {
		t.Fatalf("contexts = %#v, want %#v", contexts, want)
	}
}

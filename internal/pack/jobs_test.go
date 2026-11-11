package pack

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeJobs(t *testing.T) {
	def := normalizeJobs(0)
	if def < 1 || def > 16 {
		t.Fatalf("default jobs = %d, want 1..16", def)
	}
	if got := normalizeJobs(-2); got != def {
		t.Fatalf("negative jobs = %d, want default %d", got, def)
	}
	if got := normalizeJobs(1); got != 1 {
		t.Fatalf("jobs 1 = %d", got)
	}
	if got := normalizeJobs(4096); got != 4096 {
		t.Fatalf("large jobs = %d, want 4096", got)
	}
}

// TestScanTreeJobsDeterministic hashes small trees (below and at the parallel
// threshold) with jobs 1 and 16 and requires identical entries.
func TestScanTreeJobsDeterministic(t *testing.T) {
	for _, n := range []int{parallelThreshold - 1, parallelThreshold} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			dir := t.TempDir()
			for i := 0; i < n; i++ {
				name := filepath.Join(dir, fmt.Sprintf("f%03d", i))
				if err := os.WriteFile(name, []byte(strings.Repeat("y", i%97)), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			one, err := scanTree(dir, Limits{}, false, 1)
			if err != nil {
				t.Fatal(err)
			}
			many, err := scanTree(dir, Limits{}, false, 16)
			if err != nil {
				t.Fatal(err)
			}
			if len(one) != len(many) {
				t.Fatalf("entry count %d != %d", len(one), len(many))
			}
			for i := range one {
				if one[i].Path != many[i].Path || strPtr(one[i].SHA256) != strPtr(many[i].SHA256) ||
					intPtr(one[i].Size) != intPtr(many[i].Size) {
					t.Fatalf("entry %d differs: %+v vs %+v", i, one[i], many[i])
				}
			}
		})
	}
}

func strPtr(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func intPtr(p *int64) int64 {
	if p == nil {
		return -1
	}
	return *p
}

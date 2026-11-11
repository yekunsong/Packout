package scan

import (
	"fmt"
	"strings"
	"testing"
)

func TestNormalizeJobs(t *testing.T) {
	def := normalizeJobs(0)
	if def < 1 || def > 16 {
		t.Fatalf("default jobs = %d, want 1..16", def)
	}
	if got := normalizeJobs(-5); got != def {
		t.Fatalf("negative jobs = %d, want default %d", got, def)
	}
	if got := normalizeJobs(1); got != 1 {
		t.Fatalf("jobs 1 = %d", got)
	}
	if got := normalizeJobs(4096); got != 4096 {
		t.Fatalf("large jobs = %d, want 4096", got)
	}
}

// TestJobsDeterministic scans the same tree with jobs 1 and a job count above
// the parallel threshold and requires byte-identical unit lines. It also
// covers the "fewer than 32 pending items" rule, which the run with a large
// job count exercises for small trees.
func TestJobsDeterministic(t *testing.T) {
	e := setup(t, `{
      "id":"work","selftest_exempt":"integration","kind":"glob-group","root":"home","paths":["work/**/*.txt"],
      "layer":"L3","secret":"none","extractor":"digest",
      "signals":[{"src":"observed_behavior","note":"work"}]},
      `+catchHome)
	const n = 40
	for i := 0; i < n; i++ {
		e.write(fmt.Sprintf("home/work/f%02d.txt", i), strings.Repeat("x", i*7))
	}
	base := e.out
	var got [2][]string
	for i, jobs := range []int{1, 1000} {
		cfg := e.cfg()
		cfg.Jobs = jobs
		cfg.OutDir = fmt.Sprintf("%s-j%d", base, jobs)
		if _, err := Run(t.Context(), cfg); err != nil {
			t.Fatalf("jobs %d: %v", jobs, err)
		}
		for _, rec := range readRaw(t, cfg.OutDir) {
			if rec["type"] != "unit" || rec["entry"] != "work" {
				continue
			}
			rec["scan_id"] = "X"
			got[i] = append(got[i], fmt.Sprint(rec["id"], "|", rec["path_key"], "|", rec["fingerprint"], "|", rec["risk_flags"]))
		}
		if len(got[i]) != n {
			t.Fatalf("jobs %d emitted %d units, want %d", jobs, len(got[i]), n)
		}
	}
	for i := range got[0] {
		if got[0][i] != got[1][i] {
			t.Fatalf("unit %d differs:\n jobs1=%s\n jobs1000=%s", i, got[0][i], got[1][i])
		}
	}
}

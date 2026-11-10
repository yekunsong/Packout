package pack

import (
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"testing"
)

func TestSIGCanonicalSample(t *testing.T) {
	dirMode := "0755"
	fileMode := "0644"
	size := int64(3)
	sha := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	link := "a.txt"
	entries := []SIGEntry{
		{Type: TypeDir, Path: "d", Mode: &dirMode},
		{Type: TypeFile, Path: "d/a.txt", Mode: &fileMode, Size: &size, SHA256: &sha},
		{Type: TypeSymlink, Path: "d/l", LinkTarget: &link},
	}
	sig, err := NewSIG(entries)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Signed || sig.Method != MethodSHA256Tree || sig.FormatVersion != FormatVersion {
		t.Fatalf("bad header: %+v", sig)
	}
	if len(sig.TreeSHA256) != 64 {
		t.Fatalf("bad tree hash %q", sig.TreeSHA256)
	}
	enc, err := sig.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeSIG(enc)
	if err != nil {
		t.Fatal(err)
	}
	if back.TreeSHA256 != sig.TreeSHA256 || len(back.Entries) != 3 {
		t.Fatal("round trip changed the SIG")
	}
	if p := CompareSIG(sig, back); len(p) != 0 {
		t.Fatalf("compare: %v", p)
	}
	// The canonical hash must not depend on input order.
	rev, _ := NewSIG([]SIGEntry{entries[2], entries[1], entries[0]})
	if rev.TreeSHA256 != sig.TreeSHA256 {
		t.Fatal("tree hash depends on entry order")
	}
}

func TestDecodeSIGRejectsBadHeader(t *testing.T) {
	good := SIG{Format: PackageFormat, FormatVersion: FormatVersion, Method: MethodSHA256Tree,
		TreeSHA256: fmt.Sprintf("%064d", 0), EntryCount: 0, Entries: []SIGEntry{}}
	enc := func(s SIG) []byte { b, _ := json.Marshal(s); return b }

	s := good
	s.Signed = true
	if _, err := DecodeSIG(enc(s)); err == nil {
		t.Fatal("signed accepted")
	}
	s = good
	s.Method = "rsync"
	if _, err := DecodeSIG(enc(s)); err == nil {
		t.Fatal("unknown method accepted")
	}
	s = good
	s.FormatVersion = 2
	if _, err := DecodeSIG(enc(s)); err == nil {
		t.Fatal("unknown version accepted")
	}
	s = good
	s.EntryCount = 3
	if _, err := DecodeSIG(enc(s)); err == nil {
		t.Fatal("mismatched entry count accepted")
	}
	if _, err := DecodeSIG([]byte(`{"format":"packout-package","format_version":1,"method":"sha256-tree","signed":false,"tree_sha256":"` + good.TreeSHA256 + `","entry_count":0,"total_bytes":0,"entries":[],"extra":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestMillionEntrySIG(t *testing.T) {
	if testing.Short() {
		t.Skip("1M entries in -short")
	}
	oldGC := debug.SetGCPercent(20)
	defer debug.SetGCPercent(oldGC)
	mode := "0755"
	entries := make([]SIGEntry, 1_000_000)
	for i := range entries {
		entries[i] = SIGEntry{Type: TypeDir, Path: fmt.Sprintf("d%07d", i), Mode: &mode}
	}
	sig, err := NewSIG(entries)
	if err != nil {
		t.Fatal(err)
	}
	if sig.EntryCount != 1_000_000 {
		t.Fatalf("count %d", sig.EntryCount)
	}
	if len(sig.TreeSHA256) != 64 {
		t.Fatalf("bad tree hash %q", sig.TreeSHA256)
	}
	// The default limit must make a million-entry package stop at scan time.
	// Encoding/decoding is exercised below at a size that keeps the shared
	// 1.6 GB CI box out of swap.
	if DefaultMaxEntries >= 1_000_000 {
		t.Fatalf("default MaxEntries %d would accept a million entries unexamined", DefaultMaxEntries)
	}
	entries = nil
	runtime.GC()
	small := make([]SIGEntry, 200_000)
	for i := range small {
		small[i] = SIGEntry{Type: TypeDir, Path: fmt.Sprintf("s%06d", i), Mode: &mode}
	}
	ssig, err := NewSIG(small)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := ssig.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeSIG(enc)
	if err != nil {
		t.Fatal(err)
	}
	if back.TreeSHA256 != ssig.TreeSHA256 {
		t.Fatal("hash changed")
	}
}

func TestSIGFormatSample(t *testing.T) {
	// Documents the on-disk shape; logged with -v and used in the review notes.
	dirMode, fileMode := "0755", "0644"
	size := int64(25)
	sha := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	linkTarget := "settings.json"
	entries := []SIGEntry{
		{Type: TypeDir, Path: "config", Mode: &dirMode},
		{Type: TypeDir, Path: "config/home", Mode: &dirMode},
		{Type: TypeFile, Path: "config/home/settings.json", Mode: &fileMode, Size: &size, SHA256: &sha},
		{Type: TypeSymlink, Path: "config/home/link.json", LinkTarget: &linkTarget},
		{Type: TypeDir, Path: "manifest", Mode: &dirMode},
		{Type: TypeDir, Path: "reinstall", Mode: &dirMode},
	}
	sig, err := NewSIG(entries)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := sig.Encode()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SIG.json sample:\n%s", enc)
}

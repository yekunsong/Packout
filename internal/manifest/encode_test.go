package manifest

import (
	"encoding/json"
	"strings"
	"testing"
)

// Windows paths, quotes, control characters and non-ASCII all have to survive
// the hand-written encoder byte for byte (D-034).
func TestAppendJSONStringRoundTrip(t *testing.T) {
	cases := []string{
		`C:\a\b`,
		`\\srv\share\dir`,
		`quote " and backslash \`,
		"line\nbreak\r\ttab",
		"\x00\x01\x1f",
		"中文路径/文件.txt",
		"",
		`trailing\`,
	}
	for _, want := range cases {
		line := appendJSONString(nil, want)
		if !json.Valid(line) {
			t.Fatalf("appendJSONString(%q) = %s is not valid JSON", want, line)
		}
		var got string
		if err := json.Unmarshal(line, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", line, err)
		}
		if got != want {
			t.Fatalf("round trip = %q, want %q", got, want)
		}
	}
}

func TestEncodeUnitEscapesEveryString(t *testing.T) {
	u := fixtureUnit("e1", `C:\Users\a\proj`)
	u.PathKey = `c:/users/a/proj`
	origin := `D:\Study\Chatrix`
	originKey := `d:/study/chatrix`
	u.Origin = &origin
	u.OriginPathKey = &originKey
	u.Notes = "quote \" backslash \\ newline \n ctrl \x01 中文"
	u.Signals[0].Note = `src C:\a\b "quoted"`
	u.Extra = map[string][]byte{`extra\key"x`: []byte("1")}

	line := EncodeUnit(&u)
	if !json.Valid(line) {
		t.Fatalf("EncodeUnit produced invalid JSON:\n%s", line)
	}

	var back struct {
		Path          string `json:"path"`
		PathKey       string `json:"path_key"`
		Origin        string `json:"origin"`
		OriginPathKey string `json:"origin_path_key"`
		Notes         string `json:"notes"`
	}
	if err := json.Unmarshal(line, &back); err != nil {
		t.Fatalf("unmarshal own output: %v", err)
	}
	if back.Path != u.Path || back.PathKey != u.PathKey {
		t.Fatalf("path round trip = %q / %q, want %q / %q", back.Path, back.PathKey, u.Path, u.PathKey)
	}
	if back.Origin != origin || back.OriginPathKey != originKey {
		t.Fatalf("origin round trip = %q / %q", back.Origin, back.OriginPathKey)
	}
	if back.Notes != u.Notes {
		t.Fatalf("notes round trip = %q, want %q", back.Notes, u.Notes)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		t.Fatalf("unmarshal map: %v", err)
	}
	if _, ok := raw[`extra\key"x`]; !ok {
		t.Fatalf("escaped extra key missing; keys: %v", keysOf(raw))
	}
	var sigs []struct {
		Note string `json:"note"`
	}
	if err := json.Unmarshal(raw["signals"], &sigs); err != nil {
		t.Fatalf("unmarshal signals: %v", err)
	}
	if len(sigs) != 1 || sigs[0].Note != u.Signals[0].Note {
		t.Fatalf("signal note round trip = %q, want %q", sigs, u.Signals[0].Note)
	}
}

func keysOf(m map[string]json.RawMessage) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}

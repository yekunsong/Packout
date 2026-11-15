package main

import (
	"context"
	"io"
	"runtime"

	"github.com/yekunsong/Packout/internal/profile"
)

// Build-injected values: -ldflags "-X main.commit=<sha> -X main.version=<v>".
var (
	version = "0.1.0"
	commit  = ""
)

type versionInfo struct {
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	Go            string `json:"go"`
	ProfileSchema string `json:"profile_schema"`
	GOOS          string `json:"goos"`
	GOARCH        string `json:"goarch"`
}

func runVersion(_ context.Context, cfg versionConfig, stdout, stderr io.Writer) int {
	r := &reporter{stdout: stdout, stderr: stderr, json: cfg.json, quiet: cfg.quiet}
	c := commit
	if c == "" {
		c = "(未注入)"
	}
	r.value(versionInfo{
		Version:       version,
		Commit:        c,
		Go:            runtime.Version(),
		ProfileSchema: profile.Schema,
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
	})
	r.info("packout %s", version)
	r.info("commit: %s", c)
	r.info("go: %s", runtime.Version())
	r.info("profile_schema: %s", profile.Schema)
	return exitOK
}

type versionConfig struct {
	json  bool
	quiet bool
}

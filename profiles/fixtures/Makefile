# Materialize packout selftest fixtures.
#
# Works in WSL/Linux/macOS when `make` and `pwsh` are present, and on Windows
# via `make` in Git Bash or by running the PowerShell script directly:
#
#   pwsh -NoProfile -File tools/make-fixtures.ps1 -Clean
#
# Objects the OS cannot represent (symlinks, junctions, sparse files, the NTFS
# offline attribute) are created best-effort and reported as SKIP. A skip never
# fails the build; the script always exits 0.

FIXTURES_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
OUT_DIR ?= $(FIXTURES_DIR)/build
PWSH := $(shell command -v pwsh 2>/dev/null)
POWERSHELL := $(shell command -v powershell.exe 2>/dev/null)

.PHONY: all fixtures materialize clean verify

all: materialize

fixtures: materialize

materialize:
	@if [ -n "$(PWSH)" ]; then \
		"$(PWSH)" -NoProfile -File "$(FIXTURES_DIR)/tools/make-fixtures.ps1" -OutDir "$(OUT_DIR)"; \
	elif [ -n "$(POWERSHELL)" ]; then \
		"$(POWERSHELL)" -NoProfile -ExecutionPolicy Bypass -File "$$(wslpath -w "$(FIXTURES_DIR)/tools/make-fixtures.ps1" 2>/dev/null || echo "$(FIXTURES_DIR)/tools/make-fixtures.ps1")" -OutDir "$(OUT_DIR)"; \
	else \
		echo "SKIP  neither pwsh nor powershell.exe found; run tools/make-fixtures.ps1 on Windows"; \
	fi

clean:
	@rm -rf "$(OUT_DIR)"
	@echo "cleaned $(OUT_DIR)"

# Read-only sanity check: the sources must stay text-only and free of
# committed binaries/special files.
verify:
	@if find "$(FIXTURES_DIR)/claude-code" "$(FIXTURES_DIR)/codex" -type l | grep -q .; then \
		echo "FAIL  committed symlink found"; exit 1; \
	fi
	@if find "$(FIXTURES_DIR)/claude-code" "$(FIXTURES_DIR)/codex" -type f -size +64k | grep -q .; then \
		echo "FAIL  committed fixture exceeds 64 KiB"; exit 1; \
	fi
	@echo "OK    fixture sources are text-only and small"

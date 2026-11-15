# packout

**An AI session migration tool that gives different workspaces the same AI session baseline.**

[English](README.md) | [简体中文](README.zh-CN.md)

[![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](#build)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](#platform)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

packout scans the state left behind by AI coding assistants (Claude Code, Codex, Cursor), separates what
can travel, and turns it into a **session baseline** — configuration, memory, skills, rules and, optionally,
session content. The result is a verifiable, encryptable, restorable package that can be replayed on another
machine or in another workspace. Moving machines, reinstalling, or working across several machines no longer
means rebuilding assistant habits from scratch.

Machine-bound items and credentials that require a fresh login are not part of the baseline: they appear in the
report only, never pretending to be migratable.

> Unlike single-machine "session handoff" tools such as `claude-handoff`, packout targets **cross-workspace,
> cross-machine** baseline consistency.

## Features

- **Read-only scanning**: `scan` / `report` never delete, modify or move scanned files.
- **Layered inventory**: every entry carries a layer (L0–L5), confidence, signals and provenance, so each
  conclusion can be checked.
- **Selectable and prunable**: presets (`minimal` / `standard` / `full`), category include/exclude, and session
  filters by time, project and count.
- **Verifiable**: content-tree SHA-256 plus minisign signatures; `verify` returns `ok` / `tampered` /
  `bad-signature` / `unsigned`.
- **Encryptable**: RESTORE credentials can go into an age-encrypted `secrets.age` (passphrase or recipient).
- **Rehearsable**: `drill` is a dry run by default; `restore --dry-run` writes nothing.
- **Controlled landing**: `--map ROLE=PATH` decides where each role lands on the new machine, with a diff before
  anything is overwritten.
- **Read-only MCP surface**: `packout mcp` exposes six read-only tools to AI assistants.
- **Offline first**: report pages make no external requests; CSP is `default-src 'none'`.

## How it works

1. **Build the baseline**: scan `home` / `repo` / `appdata` / `localappdata` roots with the built-in profile,
   classifying config, memory, sessions, skills, agents, commands, rules, history and plugins. Regenerable
   L0/L1 items stay in the report.
2. **Carry and verify**: export a directory package (`SIG.json` + `manifest/` + `config/` + `reinstall/`), with
   optional signing and encryption.
3. **Restore**: a fixed order — verify signature, target gate, decrypt, plan, write, read back and re-hash.
   The target must be empty by default; `--in-place` prints a diff and `--force` confirms overwrites (no backup).

## Build

Requires Go 1.26+ and git.

```bash
git clone https://github.com/yekunsong/Packout.git
cd Packout
go build -o packout ./cmd/packout
```

Windows, macOS and Linux are supported; Windows junction, placeholder and short-name semantics have dedicated
implementations and tests.

## Quick start

```bash
# 1. Initialise: config, age identity and minisign keys (the local public key goes into trusted_keys)
packout init

# 2. Read-only self-check and scan
packout doctor --out ./out
packout scan --out ./out                        # default standard: config + memory, no sessions
packout scan --out ./out --preset full          # include session transcripts
packout scan --out ./out --include agent --exclude history   # fine-grained selection

# 3. Inspect the report (binds 127.0.0.1 only)
packout report --manifest ./out --out ./REPORT.html

# 4. Pack, sign and verify
packout pack ./pack --seal
packout verify ./pack                           # should print ok

# 5. Rehearse, then restore
packout drill ./pack                            # dry run, plan only
packout restore ./pack --into ./restore-test    # restore into an empty directory
```

### Landing on a new machine

By default `restore --into` mirrors roles to `<into>/home`, `<into>/repo`. To land the baseline directly at
real locations, use `--map` (paths are relative to `--into`; `.` means `--into` itself):

```bash
packout restore ./pack --into $HOME --in-place --dry-run --map home=. --map repo=work/proj2
packout restore ./pack --into $HOME --in-place --force  --map home=. --map repo=work/proj2
```

If the package carries `secrets.age`, settle decryption first: passphrase packages use the same passphrase file;
`--recipient` packages require the **source** machine's `~/.config/packout/identity.age` (a private key — keep it
out of the package and out of git), carried over a secure channel and passed via `--identity`, or placed at the new
machine's `<configDir>/identity.age` (0600) for the default path. MCP `restore_plan` accepts identity only;
use the CLI for passphrase packages.

## Commands

| Command | Purpose | Writes |
| --- | --- | --- |
| `init` | Create config, age identity, minisign keys and register the local public key | config dir |
| `doctor` | Read-only self-check; exits 2 on failure | `--out` |
| `scan` | Scan and write a manifest | `--out` |
| `report` | Render a self-contained HTML report; can serve locally | `--out` |
| `export` | Export a package from a manifest | `--out` |
| `sign` | Sign a package | package dir |
| `verify` | Verify a package (read-only) | none |
| `drill` | Rehearse a restore in the system temp dir; dry run by default | temp dir (kept with `--keep`) |
| `restore` | Restore in a fixed order | `--into` |
| `mcp` | Read-only MCP server over stdio | none |
| `status` | Show config, roots and recent operations | none |
| `completion` | Print a shell completion script | none |
| `profile` | List, probe and test built-in profiles | none |
| `version` | Version and build information | none |
| `help` | Layered help; `help --all` lists everything | none |

Exit codes: `0` success / `2` execution or verification failure / `3` usage or config / `4` target not empty /
`5` interrupted.

## Security model

- **Only two write paths**: `export` writes `--out`; `restore` writes `--into` (and whatever `--map` points at).
- **Unsigned is not ok**: `unsigned` / `bad-signature` exit 2 and `restore` refuses unless `--allow-unverified`;
  `tampered` and empty packages are always refused.
- **Credentials show prefixes and fingerprints only**; full values stay local or go into encrypted `secrets.age`.
- **TOFU plus fingerprint checks**: a first-seen public key prints its SHA-256 fingerprint; check it via
  `--pubkey` from another channel.
- **Overwrites keep no backup**: `--in-place --force` replaces existing files and the report states the count;
  copy anything you want to keep first.

See [`SECURITY.md`](SECURITY.md) and [`docs/threat-model.md`](docs/threat-model.md).

## Configuration and files

Config lives at `~/.config/packout/config.json` (Windows: `%APPDATA%\packout\config.json`, Unix 0600).
`init` also maintains `identity.age`, `minisign.key`, `trusted_keys` and `state.json`. CLI flags always win over
config; a broken config exits 3 and prints its path.

## Known limitations

- The manifest is sorted in memory: about 140 MiB peak and 11 seconds for 100k files.
- Hard links, ADS, ACLs/ownership and Windows reserved names are not special-cased.
- `--preset full` stores transcripts as plaintext raw bytes; only entries up to 8 MiB get credential placeholder
  substitution. Per-file cap is 1 GiB; larger files are skipped with a warning.
- `--passphrase-file` reads the first line only.
- Machine-bound items and keychain/registry entries stay in the report (`probe_unavailable`).
- No source deletion, no GUI, no telemetry; MCP is read-only and never executes on your behalf.

## Development

```bash
go vet ./... && go test ./...
python scripts/check-jsonc.py   # validate built-in profiles
```

`scripts/rtest.sh` syncs tests to a remote Linux host and cross-compiles for Windows.
Design documents live in [`docs/`](docs/); trade-off records live in [`DECISIONS.md`](DECISIONS.md).

## License

[MIT](LICENSE)

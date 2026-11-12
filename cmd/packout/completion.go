package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
)

// completionConfig carries the requested shell.
type completionConfig struct {
	shell string
}

var completionShells = []string{"bash", "zsh", "fish", "powershell"}

func parseCompletion(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("completion", flag.ContinueOnError)
	var cfg completionConfig
	pos, code := parse(fs, args, 1, completionHelp, stdout, stderr)
	if code >= 0 {
		return code
	}
	if len(pos) != 1 {
		const msg = "completion 需要一个 shell：bash | zsh | fish | powershell"
		if wantsJSON(args) {
			_ = jsonEncode(stdout, errObject{Error: msg, Exit: exitUsage})
		}
		fmt.Fprintf(stderr, "packout: %s\n\n%s", msg, completionHelp)
		return exitUsage
	}
	cfg.shell = pos[0]
	return runCompletion(ctx, cfg, stdout, stderr)
}

// runCompletion writes a static script to stdout. It never touches the disk:
// the user decides where the script lands.
func runCompletion(ctx context.Context, cfg completionConfig, stdout, stderr io.Writer) int {
	r := &reporter{stdout: stdout, stderr: stderr}
	if ctx.Err() != nil {
		return exitFromCtx(r, ctx)
	}
	switch cfg.shell {
	case "bash":
		fmt.Fprint(stdout, bashCompletion())
	case "zsh":
		fmt.Fprint(stdout, zshCompletion())
	case "fish":
		fmt.Fprint(stdout, fishCompletion())
	case "powershell":
		fmt.Fprint(stdout, powershellCompletion())
	default:
		return r.usage("不认识的 shell %q（可用：%s）", cfg.shell, strings.Join(completionShells, " | "))
	}
	return exitOK
}

// completionVerbNames derives the offered subcommands from allVerbs, the same
// data `help --all` renders, so a new command can never be missing here.
func completionVerbNames() []string {
	names := make([]string, 0, len(allVerbs)+1)
	for _, v := range allVerbs {
		names = append(names, v.name)
	}
	return append(names, "help")
}

// completionVerbList is the space separated form used by bash.
func completionVerbList() string { return strings.Join(completionVerbNames(), " ") }

// completionFlagList is the space separated form used by bash and friends.
func completionFlagList() string { return strings.Join(completionFlags, " ") }

// completionFlags lists the long flags worth completing. It is deliberately a
// superset: completing a flag a command does not take is rejected by that
// command's own parser, never silently accepted.
var completionFlags = []string{
	"--out", "--src", "--into", "--map", "--manifest", "--profile", "--root", "--preset",
	"--with-sessions", "--include", "--exclude", "--sessions-since", "--sessions-project",
	"--sessions-max-per-project", "--force", "--with-secrets", "--recipient",
	"--passphrase", "--passphrase-file", "--identity", "--key", "--sign", "--seal",
	"--pubkey", "--in-place", "--dry-run", "--allow-unverified", "--write",
	"--keep", "--jobs", "--follow-symlinks", "--stable-salt", "--json", "--quiet",
	"--help", "--all",
}

func bashCompletion() string {
	return `# packout bash completion: source <(packout completion bash)
_packout_completions() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    local verbs="` + completionVerbList() + `"
    local flags="` + completionFlagList() + `"
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$verbs" -- "$cur") )
        return 0
    fi
    case "$prev" in
        completion) COMPREPLY=( $(compgen -W "` + strings.Join(completionShells, " ") + `" -- "$cur") ); return 0 ;;
        --preset)   COMPREPLY=( $(compgen -W "minimal standard full" -- "$cur") ); return 0 ;;
        --sessions-since) COMPREPLY=( $(compgen -W "7d 30d all" -- "$cur") ); return 0 ;;
    esac
    case "$cur" in
        -*) COMPREPLY=( $(compgen -W "$flags" -- "$cur") ) ;;
        *)  COMPREPLY=( $(compgen -f -- "$cur") ) ;;
    esac
    return 0
}
complete -o bashdefault -o default -F _packout_completions packout
`
}

func zshCompletion() string {
	var b strings.Builder
	b.WriteString(`#compdef packout
# packout zsh completion: source <(packout completion zsh)
_packout() {
    local -a verbs flags
    verbs=(
`)
	for _, v := range allVerbs {
		fmt.Fprintf(&b, "        '%s:%s'\n", v.name, v.desc)
	}
	b.WriteString(`        'help:帮助'
    )
    flags=(
`)
	for _, f := range completionFlags {
		fmt.Fprintf(&b, "        %s\n", f)
	}
	b.WriteString(`    )
    if (( CURRENT == 2 )); then
        _describe 'command' verbs
        return
    fi
    if [[ "$words[2]" == "completion" ]]; then
        _values 'shell' ` + strings.Join(completionShells, " ") + `
        return
    fi
    _values 'flag' $flags
}
compdef _packout packout
`)
	return b.String()
}

func fishCompletion() string {
	var b strings.Builder
	b.WriteString("# packout fish completion: packout completion fish | source\n")
	for _, v := range allVerbs {
		fmt.Fprintf(&b, "complete -c packout -f -n '__fish_use_subcommand' -a '%s' -d '%s'\n", v.name, v.desc)
	}
	b.WriteString("complete -c packout -f -n '__fish_use_subcommand' -a 'help' -d '帮助'\n")
	fmt.Fprintf(&b, "complete -c packout -f -n '__fish_seen_subcommand_from completion' -a '%s'\n", strings.Join(completionShells, " "))
	fmt.Fprintf(&b, "complete -c packout -f -n '__fish_seen_subcommand_from help' -a '%s'\n", completionVerbList())
	for _, f := range completionFlags {
		name := strings.TrimPrefix(f, "--")
		if name != f {
			fmt.Fprintf(&b, "complete -c packout -l %s\n", name)
		}
	}
	return b.String()
}

func powershellCompletion() string {
	var b strings.Builder
	b.WriteString(`# packout PowerShell completion: packout completion powershell | Out-String | Invoke-Expression
Register-ArgumentCompleter -Native -CommandName packout -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $verbs = @('`)
	b.WriteString(strings.Join(completionVerbNames(), "','"))
	b.WriteString(`')
    $flags = @('`)
	b.WriteString(strings.Join(completionFlags, "','"))
	b.WriteString(`')
    $elements = $commandAst.CommandElements
    $candidates = if ($elements.Count -le 2) { $verbs } else { $flags }
    $candidates | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
`)
	return b.String()
}

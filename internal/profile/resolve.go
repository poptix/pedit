// Package profile resolves a profile's command template against a staged
// temp file path.
package profile

import (
	"fmt"
	"regexp"
	"strings"
)

var envVarPattern = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)

// Resolve substitutes {file} into cmdTemplate (shell-quoted) and prepends a
// guard clause for every $VARNAME the template references. Without this, an
// unset variable in whatever environment ends up running the command (e.g.
// $EDITOR, if the approving shell has no EDITOR exported) doesn't fail --
// POSIX sh treats the empty expansion as "no command word" and shifts the
// next token into the command-name position, so `$EDITOR '/path/to/file'`
// silently becomes an attempt to *execute* '/path/to/file' directly. For
// content that arrived from a possibly-compromised remote host, that's
// exactly the kind of accidental code execution pedit's whole approval
// model exists to prevent -- caught live when a profile referencing
// $EDITOR ran on a host with no EDITOR set and tried to execute the staged
// file, failing only because it happened not to be executable.
func Resolve(cmdTemplate, filePath string) string {
	return guardEnvVars(cmdTemplate) + strings.ReplaceAll(cmdTemplate, "{file}", shellQuote(filePath))
}

func guardEnvVars(cmdTemplate string) string {
	seen := map[string]bool{}
	var guards []string
	for _, m := range envVarPattern.FindAllStringSubmatch(cmdTemplate, -1) {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		guards = append(guards, fmt.Sprintf(`: "${%s:?pedit: profile references %s, which is not set}"`, name, name))
	}
	if len(guards) == 0 {
		return ""
	}
	return strings.Join(guards, "; ") + "; "
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

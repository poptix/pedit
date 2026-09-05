// Package config loads peditagentd's config file. It deliberately implements
// only the small subset of TOML the file actually needs (top-level
// key = value, [section] / [section.name] headers, quoted string / bare
// number values, '#' comments) rather than pulling in a general TOML
// library -- keeping pedit buildable with zero external dependencies.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Profile struct {
	Command string // shell command template; {file} is replaced with the temp file path

	// OneWay profiles hand the file to a detached handler (xdg-open and
	// friends) and never return content. peditagentd does not wait for the
	// command, does not read the file back, and answers StatusOpened.
	OneWay bool

	// RetainSeconds is how long a OneWay profile's temp file survives.
	// Normal profiles delete theirs as soon as the command exits, but a
	// detached viewer is still loading the file at that point -- deleting it
	// immediately yanks it out from under the app. 0 uses DefaultRetain.
	RetainSeconds int
}

// DefaultRetain is the fallback lifetime for a OneWay profile's temp file.
const DefaultRetain = 900

type Config struct {
	Listen           string // unix socket path peditagentd listens on, when not replacing $SSH_AUTH_SOCK in place
	BackingAgent     string // real agent socket to proxy normal requests to; "" = capture $SSH_AUTH_SOCK at startup
	ReplaceAuthSock  bool   // move the original $SSH_AUTH_SOCK aside and bind our own socket at that same path
	MaxSizeBytes     int64
	Approver         string // "exec", "socket", or "serial"
	AuditLog         string
	Debug            bool
	ExecCommand      string
	ExecTimeoutSec   int
	ControlSocket    string
	SocketTimeoutSec int
	SerialDevice     string // e.g. /dev/serial/by-id/... -- an ESP32 running firmware/pedit-approver
	SerialBaud       int
	SerialTimeoutSec int
	BootstrapScript  string // path to pedit.sh to serve over the bootstrap extension; "" disables
	Foreground       bool   // stay attached to the terminal instead of backgrounding
	LogFile          string // where a backgrounded daemon writes its output
	PidFile          string

	// TransferDir is the one directory the built-in pup/pdown profiles use,
	// in both directions: pup deposits into it, pdown serves out of it. It
	// is the confinement boundary for every remote-supplied name.
	TransferDir string

	// ConfirmUp/ConfirmDown gate the built-ins on human approval. Separate
	// keys because the two directions are not the same decision: an upload
	// only ever adds a file to a sandbox directory, while a download hands
	// a file from this machine to whoever asked.
	ConfirmUp   bool
	ConfirmDown bool

	Profiles map[string]Profile

	// Warnings collects keys that parsed but were not recognised where they
	// appeared. Silently ignoring these is dangerous: a top-level key such
	// as max_size_bytes written below a [section] header lands in that
	// section, matches nothing, and silently leaves the limit at its
	// default -- caught by e2e tests doing exactly that by accident.
	Warnings []string
}

func Default() Config {
	return Config{
		Listen:           "~/.cache/pedit/agent.sock",
		ReplaceAuthSock:  true,
		MaxSizeBytes:     10 * 1024 * 1024,
		Approver:         "exec",
		AuditLog:         "~/.cache/pedit/audit.log",
		ExecTimeoutSec:   120,
		ControlSocket:    "~/.cache/pedit/control.sock",
		LogFile:          "~/.cache/pedit/agentd.log",
		PidFile:          "~/.cache/pedit/agentd.pid",
		TransferDir:      "~/pedit-transfers",
		ConfirmUp:        true,
		ConfirmDown:      true,
		SerialBaud:       115200,
		SerialTimeoutSec: 120,
		SocketTimeoutSec: 300,
		Profiles:         map[string]Profile{},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()

	section := ""
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			return cfg, fmt.Errorf("%s:%d: expected key = value", path, lineNo)
		}
		key := strings.TrimSpace(line[:eq])
		val := unquote(strings.TrimSpace(line[eq+1:]))
		if !applyKV(&cfg, section, key, val) {
			where := "top level"
			if section != "" {
				where = "[" + section + "]"
			}
			hint := ""
			if isTopLevelKey(key) && section != "" {
				hint = fmt.Sprintf(" -- %q is a top-level key; move it ABOVE the first [section] header or it has no effect", key)
			}
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("%s:%d: ignored key %q in %s%s", path, lineNo, key, where, hint))
		}
	}
	if err := sc.Err(); err != nil {
		return cfg, err
	}
	cfg.expandPaths()
	return cfg, nil
}

// expandPaths resolves a leading ~/ in every path-valued field, once, so no
// consumer has to remember to call ExpandHome -- forgetting it for
// backing_agent is exactly how a "~/.ssh/agent.sock" turned into a literal
// dial of "~/.ssh/agent.sock" and every ssh op got "agent refused
// operation". Every path lives in this list; add new ones here.
func (c *Config) expandPaths() {
	for _, p := range []*string{
		&c.Listen, &c.BackingAgent, &c.AuditLog, &c.LogFile, &c.PidFile,
		&c.ControlSocket, &c.BootstrapScript, &c.TransferDir, &c.SerialDevice,
	} {
		*p = ExpandHome(*p)
	}
}

func parseBool(v string, fallback bool) bool {
	switch strings.ToLower(v) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return fallback
	}
}

// unquote strips one layer of surrounding double quotes and nothing else.
// Escape sequences are NOT interpreted: a value written "a \"b\" c" keeps
// its backslash-quotes literally. That surprised a test author (the quotes
// showed up in the executed command), so it is stated rather than implied.
// Use single quotes inside a double-quoted value to avoid the issue:
//
//	command = "sh -c 'printf hi >> {file}'"
func unquote(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	return v
}

// topLevelKeys is used only to produce a better warning when one of them is
// found inside a section.
var topLevelKeys = map[string]bool{
	"listen": true, "backing_agent": true, "replace_auth_sock": true,
	"max_size_bytes": true, "approver": true, "audit_log": true,
	"debug": true, "bootstrap_script": true, "foreground": true,
	"log_file": true, "pid_file": true, "transfer_dir": true,
	"confirm_up": true, "confirm_down": true,
}

func isTopLevelKey(k string) bool { return topLevelKeys[k] }

// applyKV reports whether the key was recognised in the section it appeared in.
func applyKV(cfg *Config, section, key, val string) bool {
	switch section {
	case "":
		switch key {
		case "listen":
			cfg.Listen = val
		case "backing_agent":
			cfg.BackingAgent = val
		case "replace_auth_sock":
			cfg.ReplaceAuthSock = parseBool(val, cfg.ReplaceAuthSock)
		case "max_size_bytes":
			if n, err := strconv.ParseInt(val, 10, 64); err == nil {
				cfg.MaxSizeBytes = n
			}
		case "approver":
			cfg.Approver = val
		case "audit_log":
			cfg.AuditLog = val
		case "debug":
			cfg.Debug = parseBool(val, cfg.Debug)
		case "bootstrap_script":
			cfg.BootstrapScript = val
		case "foreground":
			cfg.Foreground = parseBool(val, cfg.Foreground)
		case "log_file":
			cfg.LogFile = val
		case "pid_file":
			cfg.PidFile = val
		case "transfer_dir":
			cfg.TransferDir = val
		case "confirm_up":
			cfg.ConfirmUp = parseBool(val, cfg.ConfirmUp)
		case "confirm_down":
			cfg.ConfirmDown = parseBool(val, cfg.ConfirmDown)
		default:
			return false
		}
	case "exec":
		switch key {
		case "command":
			cfg.ExecCommand = val
		case "timeout_seconds":
			if n, err := strconv.Atoi(val); err == nil {
				cfg.ExecTimeoutSec = n
			}
		default:
			return false
		}
	case "socket":
		switch key {
		case "control_socket":
			cfg.ControlSocket = val
		case "timeout_seconds":
			if n, err := strconv.Atoi(val); err == nil {
				cfg.SocketTimeoutSec = n
			}
		default:
			return false
		}
	case "serial":
		switch key {
		case "device":
			cfg.SerialDevice = val
		case "baud":
			if n, err := strconv.Atoi(val); err == nil {
				cfg.SerialBaud = n
			}
		case "timeout_seconds":
			if n, err := strconv.Atoi(val); err == nil {
				cfg.SerialTimeoutSec = n
			}
		default:
			return false
		}
	default:
		// Deliberately not strings.CutPrefix (Go 1.20+) -- keep this
		// buildable on older/alternate toolchains (e.g. gccgo builds have
		// been seen shipping a pre-1.20 stdlib despite a go.mod floor of
		// 1.24), matching pedit's general goal of minimal toolchain
		// requirements.
		if name, ok := profileName(section); ok {
			p := cfg.Profiles[name]
			switch key {
			case "command":
				p.Command = val
			case "oneway":
				p.OneWay = parseBool(val, p.OneWay)
			case "retain_seconds":
				if n, err := strconv.Atoi(val); err == nil {
					p.RetainSeconds = n
				}
			default:
				return false
			}
			cfg.Profiles[name] = p
			return true
		}
		return false
	}
	return true
}

func profileName(section string) (string, bool) {
	if strings.HasPrefix(section, "profiles.") {
		return section[len("profiles."):], true
	}
	return "", false
}

// ExpandHome replaces a leading "~/" with the current user's home directory.
func ExpandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + p[1:]
		}
	}
	return p
}

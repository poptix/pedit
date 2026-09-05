package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, body string) Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestParsesTopLevelAndSections(t *testing.T) {
	cfg := load(t, `
listen = "/tmp/a.sock"
max_size_bytes = 123
debug = true
replace_auth_sock = false
approver = "socket"
[socket]
control_socket = "/tmp/c.sock"
timeout_seconds = 42
[profiles.view]
command = "cat {file}"
[profiles.edit]
command = "vi {file}"
`)
	if cfg.Listen != "/tmp/a.sock" || cfg.MaxSizeBytes != 123 || !cfg.Debug || cfg.ReplaceAuthSock {
		t.Errorf("top-level keys mis-parsed: %+v", cfg)
	}
	if cfg.ControlSocket != "/tmp/c.sock" || cfg.SocketTimeoutSec != 42 {
		t.Errorf("[socket] mis-parsed: %+v", cfg)
	}
	if cfg.Profiles["view"].Command != "cat {file}" || cfg.Profiles["edit"].Command != "vi {file}" {
		t.Errorf("profiles mis-parsed: %+v", cfg.Profiles)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", cfg.Warnings)
	}
}

// The bug this guards: a top-level key written BELOW a [section] header
// parses cleanly, lands in that section, matches nothing, and silently
// keeps the default. For max_size_bytes that quietly removes a size limit.
// Found when an e2e test did it by accident and the limit never applied.
func TestTopLevelKeyInsideSectionIsWarnedNotSilent(t *testing.T) {
	cfg := load(t, `
listen = "/tmp/a.sock"
[exec]
command = "true"
max_size_bytes = 16
`)
	if cfg.MaxSizeBytes == 16 {
		t.Fatal("misplaced key was applied; this test no longer tests anything")
	}
	if len(cfg.Warnings) == 0 {
		t.Fatal("misplaced top-level key produced NO warning -- it would be silently ignored")
	}
	joined := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{"max_size_bytes", "top-level key", "[exec]"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warning should mention %q; got: %s", want, joined)
		}
	}
}

func TestUnknownKeysWarn(t *testing.T) {
	cfg := load(t, `
totally_made_up = "x"
[exec]
nonsense = 1
`)
	if len(cfg.Warnings) != 2 {
		t.Errorf("expected 2 warnings, got %d: %v", len(cfg.Warnings), cfg.Warnings)
	}
}

func TestBoolFormsAndDefaults(t *testing.T) {
	d := Default()
	if !d.ReplaceAuthSock {
		t.Error("replace_auth_sock should default true")
	}
	if d.MaxSizeBytes <= 0 {
		t.Error("max_size_bytes should have a nonzero default")
	}
	if d.BootstrapScript != "" {
		t.Error("bootstrap must be disabled by default")
	}
	for _, tc := range []struct {
		in   string
		want bool
	}{{"true", true}, {"yes", true}, {"1", true}, {"on", true},
		{"false", false}, {"no", false}, {"0", false}, {"off", false}} {
		if got := parseBool(tc.in, !tc.want); got != tc.want {
			t.Errorf("parseBool(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	// An unparseable value must keep the fallback rather than flipping it.
	if got := parseBool("maybe", true); !got {
		t.Error("unparseable bool should keep the fallback")
	}
}

func TestCommentsAndBlankLinesIgnored(t *testing.T) {
	cfg := load(t, `
# a comment
   # indented comment

listen = "/tmp/x.sock"
`)
	if cfg.Listen != "/tmp/x.sock" {
		t.Errorf("listen = %q", cfg.Listen)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("comments should not warn: %v", cfg.Warnings)
	}
}

func TestQuotedValuesWithSpacesAndBraces(t *testing.T) {
	cfg := load(t, `
[profiles.edit]
command = "vim -u NONE --cmd 'set nomodeline' {file}"
`)
	want := "vim -u NONE --cmd 'set nomodeline' {file}"
	if got := cfg.Profiles["edit"].Command; got != want {
		t.Errorf("command = %q, want %q", got, want)
	}
}

func TestTransferKeysParse(t *testing.T) {
	cfg := load(t, `
transfer_dir = "/srv/staging"
confirm_up = false
confirm_down = true
`)
	if cfg.TransferDir != "/srv/staging" {
		t.Errorf("TransferDir = %q", cfg.TransferDir)
	}
	if cfg.ConfirmUp {
		t.Error("confirm_up = false was not applied")
	}
	if !cfg.ConfirmDown {
		t.Error("confirm_down = true was not applied")
	}
}

// Confirmation must be on unless it is explicitly turned off. A default of
// false here would mean a fresh install silently accepted transfers.
func TestConfirmDefaultsAreOn(t *testing.T) {
	cfg := load(t, "listen = \"/tmp/x.sock\"\n")
	if !cfg.ConfirmUp || !cfg.ConfirmDown {
		t.Errorf("confirmation defaults must be on, got up=%v down=%v",
			cfg.ConfirmUp, cfg.ConfirmDown)
	}
	if cfg.TransferDir == "" {
		t.Error("transfer_dir should have a default rather than silently disabling pup/pdown")
	}
}

// The keys that switch confirmation off are exactly the ones that must not
// be silently ignored when written in the wrong place.
func TestMisplacedTransferKeysWarn(t *testing.T) {
	for _, key := range []string{"transfer_dir", "confirm_up", "confirm_down"} {
		cfg := load(t, "[exec]\ncommand = \"true\"\n"+key+" = \"x\"\n")
		var found bool
		for _, w := range cfg.Warnings {
			if strings.Contains(w, key) && strings.Contains(w, "top-level key") {
				found = true
			}
		}
		if !found {
			t.Errorf("%q inside [exec] produced no top-level-key warning: %v", key, cfg.Warnings)
		}
	}
}

// Every path field must have ~/ expanded at load time. backing_agent being
// the one field that was NOT expanded is exactly how "~/.ssh/agent.sock"
// got dialed literally and every ssh op returned "agent refused operation".
func TestAllPathFieldsExpandTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	cfg := load(t, `
listen = "~/l.sock"
backing_agent = "~/a.sock"
audit_log = "~/audit.log"
log_file = "~/log"
pid_file = "~/pid"
transfer_dir = "~/xfer"
bootstrap_script = "~/pedit.sh"
[socket]
control_socket = "~/ctl.sock"
[serial]
device = "~/serialdev"
`)
	checks := map[string]string{
		"listen":           cfg.Listen,
		"backing_agent":    cfg.BackingAgent,
		"audit_log":        cfg.AuditLog,
		"log_file":         cfg.LogFile,
		"pid_file":         cfg.PidFile,
		"transfer_dir":     cfg.TransferDir,
		"bootstrap_script": cfg.BootstrapScript,
		"control_socket":   cfg.ControlSocket,
		"device":           cfg.SerialDevice,
	}
	for name, got := range checks {
		if strings.HasPrefix(got, "~") {
			t.Errorf("%s was not expanded: %q", name, got)
		}
		if !strings.HasPrefix(got, home) {
			t.Errorf("%s = %q, expected it under %q", name, got, home)
		}
	}
}

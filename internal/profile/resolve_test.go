package profile

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestResolveGuardsUnsetVar(t *testing.T) {
	os.Unsetenv("PEDIT_TEST_EDITOR_VAR")
	cmd := Resolve("$PEDIT_TEST_EDITOR_VAR {file}", "/tmp/pedit-should-never-run")
	out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	if err == nil {
		t.Fatalf("expected the guard to fail when the var is unset, got success: %s", out)
	}
	if !strings.Contains(string(out), "PEDIT_TEST_EDITOR_VAR") {
		t.Fatalf("expected a clear error naming the unset var (not e.g. a bare "+
			"'file not found', which is what the old bug looked like), got: %s", out)
	}
}

func TestResolveRunsNormallyWhenVarSet(t *testing.T) {
	os.Setenv("PEDIT_TEST_EDITOR_VAR", "echo")
	defer os.Unsetenv("PEDIT_TEST_EDITOR_VAR")
	cmd := Resolve("$PEDIT_TEST_EDITOR_VAR {file}", "hello-world-marker")
	out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("expected success, got err=%v output=%s", err, out)
	}
	if !strings.Contains(string(out), "hello-world-marker") {
		t.Fatalf("expected the file path echoed in output, got: %s", out)
	}
}

func TestResolveNoGuardForPlainCommand(t *testing.T) {
	cmd := Resolve("cat {file}", "/tmp/x")
	if strings.Contains(cmd, ":?") {
		t.Fatalf("did not expect a guard clause for a template with no env vars: %s", cmd)
	}
}

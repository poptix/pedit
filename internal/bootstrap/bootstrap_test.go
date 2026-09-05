package bootstrap

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pedit/internal/proto"
	"pedit/internal/wire"
)

// The bootstrap one-liner de-frames the reply with `tail -c +N` instead of
// parsing it, so proto.BootstrapPrefixLen must equal the real number of
// bytes in front of the script on the wire. If anyone changes the response
// framing (or the extension-type string) without updating that constant,
// every documented one-liner silently returns a corrupt script -- which
// would then be *sourced*. This test is the guard.
func TestBootstrapPrefixLenMatchesWireFraming(t *testing.T) {
	script := []byte("#!/bin/bash\necho hello\n")

	var wireBytes bytes.Buffer
	if err := wire.WriteFrame(&wireBytes, proto.BuildBootstrapResponseFrame(script)); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	got := wireBytes.Bytes()
	if len(got) < proto.BootstrapPrefixLen {
		t.Fatalf("response shorter (%d) than the declared prefix (%d)", len(got), proto.BootstrapPrefixLen)
	}
	if stripped := got[proto.BootstrapPrefixLen:]; !bytes.Equal(stripped, script) {
		t.Errorf("stripping %d bytes did not yield the script.\n got: %q\nwant: %q",
			proto.BootstrapPrefixLen, stripped, script)
	}
}

// The request must round-trip through the same parsing the proxy does, so
// the printf byte string in the one-liner stays valid.
func TestBootstrapRequestRoundTrip(t *testing.T) {
	body := proto.BuildBootstrapRequestFrame("amd64")
	if body[0] != wire.MsgAgentcExtension {
		t.Fatalf("wrong message type: %d", body[0])
	}
	rd := wire.NewReader(body[1:])
	extType, err := rd.String()
	if err != nil || extType != proto.BootstrapExtensionType {
		t.Fatalf("ext type = %q, %v", extType, err)
	}
	arch, err := wire.NewReader(rd.Rest()).String()
	if err != nil || arch != "amd64" {
		t.Fatalf("arch = %q, %v", arch, err)
	}
}

func fakeScript() []byte {
	var sb strings.Builder
	sb.WriteString("# header\n")
	for _, a := range KnownArches {
		sb.WriteString("_pedit_blob_" + a + "=\"BLOB" + a + "\"\n")
		sb.WriteString("_pedit_sha256_" + a + "=\"SHA" + a + "\"\n")
	}
	sb.WriteString("pedit() { :; }\n")
	return []byte(sb.String())
}

func TestTrimKeepsOnlyRequestedArch(t *testing.T) {
	out := string(Trim(fakeScript(), "arm64"))
	if !strings.Contains(out, "_pedit_blob_arm64=") || !strings.Contains(out, "_pedit_sha256_arm64=") {
		t.Errorf("kept arch was dropped:\n%s", out)
	}
	for _, a := range []string{"amd64", "386", "arm"} {
		if strings.Contains(out, "_pedit_blob_"+a+"=") {
			t.Errorf("arch %q should have been trimmed:\n%s", a, out)
		}
	}
	// Non-blob lines must survive, or the script won't define pedit at all.
	if !strings.Contains(out, "pedit() { :; }") || !strings.Contains(out, "# header") {
		t.Errorf("trim removed non-blob content:\n%s", out)
	}
}

// "arm" is a prefix of "arm64" -- make sure trimming one doesn't eat the
// other, which a naive substring match would do.
func TestTrimArmDoesNotEatArm64(t *testing.T) {
	out := string(Trim(fakeScript(), "arm"))
	if !strings.Contains(out, "_pedit_blob_arm=") {
		t.Errorf("arm blob missing:\n%s", out)
	}
	if strings.Contains(out, "_pedit_blob_arm64=") {
		t.Errorf("arm64 blob should have been trimmed:\n%s", out)
	}
}

// The pasted string must have no whitespace at all: anything that wraps or
// re-flows at spaces then has nothing to break at.
func TestOneLinerHasNoWhitespaceAndIsOneLine(t *testing.T) {
	got := OneLiner()
	if got == "" {
		t.Fatal("empty one-liner")
	}
	if i := strings.IndexAny(got, " \t\n\r"); i >= 0 {
		t.Errorf("one-liner has whitespace at offset %d:\n%s", i, got)
	}
}

// The command inside the envelope is the thing that has to be correct; the
// envelope only has to survive a clipboard.
func TestReadableFormIsCorrectlyFramed(t *testing.T) {
	got := OneLinerReadable()
	if !strings.Contains(got, "tail -c+37") { // 4+1+4+27 prefix, +1 for tail's 1-indexing
		t.Errorf("wrong tail offset: %s", got)
	}
	if !strings.Contains(got, "SSH_AUTH_SOCK") {
		t.Errorf("does not reference SSH_AUTH_SOCK: %s", got)
	}
	// It must ask for an EMPTY arch: stage 1 cannot know what the remote
	// host is, which is the reason the loader exists.
	if !strings.Contains(got, "\\000\\000\\000\\000'") {
		t.Errorf("does not request an empty arch: %s", got)
	}
	// One string, every client. If a client is dropped from stage 1 its
	// distro family loses coverage, so all four must be present.
	for _, cli := range []string{"perl", "python3", "socat", "nc -U"} {
		if !strings.Contains(got, cli) {
			t.Errorf("stage 1 is missing the %q client:\n%s", cli, got)
		}
	}
	// Stage 1 has to run in a plain POSIX shell.
	for _, forbidden := range []string{"<<<", "/dev/stdin"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("uses the bashism %q", forbidden)
		}
	}
	for _, f := range strings.Fields(got) {
		if f == "source" {
			t.Errorf("calls bash's source; use POSIX eval or .")
		}
	}
}

// Decoding the envelope must give back exactly the command.
func TestEnvelopeCarriesTheCommandIntact(t *testing.T) {
	enc := OneLiner()
	const pre = `eval${IFS}"$(echo${IFS}"`
	const post = `"|tr${IFS}-dc${IFS}A-Za-z0-9+/=|base64${IFS}-d)"`
	if !strings.HasPrefix(enc, pre) || !strings.HasSuffix(enc, post) {
		t.Fatalf("envelope is not the expected shape:\n%s", enc)
	}
	blob := strings.TrimSuffix(strings.TrimPrefix(enc, pre), post)
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		t.Fatalf("payload is not valid base64: %v", err)
	}
	if string(raw) != OneLinerReadable() {
		t.Error("decoded payload does not match the readable command")
	}
}

// An empty arch means "send me the loader", not "send me the whole
// untrimmed script".
func TestLoadWithEmptyArchServesTheLoader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pedit.sh")
	if err := os.WriteFile(path, []byte("# pedit -- huge\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, Loader()) {
		t.Errorf("Load(path, \"\") returned the script, not the loader")
	}
	if !strings.HasPrefix(string(got), "# pedit") {
		t.Errorf("loader does not start with the marker stage 1 checks for:\n%.60s", got)
	}
}

// Stage 1 has to run in a plain POSIX shell. The bash-only source/<<< form
// died in dash with "Syntax error: redirection unexpected".

// An empty arch means "send me the loader", not "send me the whole
// untrimmed script".

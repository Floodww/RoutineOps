//go:build !windows && !linux && (!darwin || !cgo)

package lockui

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestRun_UnsupportedPlatform — заглушка Run на Linux (и на CGO=0-сборках macOS)
// должна лишь предупредить в лог и вернуться, не паниковать и не блокировать.
func TestRun_UnsupportedPlatform(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))

	Run("/tmp/does-not-matter.json", log)

	if !strings.Contains(buf.String(), "не реализован") {
		t.Errorf("ожидали предупреждение о неподдерживаемой ОС в логе, получили: %q", buf.String())
	}
}

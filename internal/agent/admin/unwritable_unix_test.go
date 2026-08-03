//go:build !windows

package admin

import (
	"os"
	"testing"
)

// makeUnwritable снимает право записи с каталога состояния.
func makeUnwritable(t *testing.T, dir string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("под root права каталога не ограничивают запись")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("не удалось снять право записи с каталога: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}

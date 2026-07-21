package service

import (
	"path/filepath"
	"runtime"
	"testing"
)

// TestInstallLayout: на macOS/Linux раскладка включена и все пути абсолютные
// (служба не должна жить в /tmp); на прочих платформах (Windows — установка через
// MSI) раскладка выключена, чтобы не ломать рабочий поток установщика.
func TestInstallLayout(t *testing.T) {
	lay := InstallLayout()
	switch runtime.GOOS {
	case "darwin", "linux":
		if !lay.Relocate {
			t.Fatalf("на %s раскладка должна быть включена", runtime.GOOS)
		}
		for name, p := range map[string]string{
			"BinPath": lay.BinPath, "DataDir": lay.DataDir,
			"CertDir": lay.CertDir, "LogDir": lay.LogDir,
		} {
			if p == "" {
				t.Errorf("%s пустой", name)
			} else if !filepath.IsAbs(p) {
				t.Errorf("%s не абсолютный: %q", name, p)
			}
		}
		// Серты лежат внутри DataDir — единый каталог состояния.
		if filepath.Dir(lay.CertDir) != lay.DataDir {
			t.Errorf("CertDir %q не внутри DataDir %q", lay.CertDir, lay.DataDir)
		}
	default:
		if lay.Relocate {
			t.Fatalf("на %s раскладка должна быть выключена (установка через MSI)", runtime.GOOS)
		}
		// Windows: перекладка бинаря/сертов — забота MSI, но каталог изменяемого
		// состояния обязан быть задан и абсолютен (ProgramData\RoutineOps\state),
		// иначе state снова уедет в CWD службы (C:\Windows\System32).
		if runtime.GOOS == "windows" {
			if lay.DataDir == "" || !filepath.IsAbs(lay.DataDir) {
				t.Errorf("на windows DataDir должен быть абсолютным, got %q", lay.DataDir)
			}
		}
	}
}

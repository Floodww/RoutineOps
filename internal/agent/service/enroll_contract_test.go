package service

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestEnrollArtifactsContract ловит дрейф констант enroll_contract.go относительно
// упаковочных скриптов. Если перенести enroll.env/ca.crt или сменить identifier
// пакета только в скрипте, план decommission продолжил бы удалять СТАРЫЕ пути —
// токен энролла/receipt переживали бы снос без единого сигнала (симптом
// неотличим от исходного бага). Тест без build-тега — сверка на любом `go test`.
func TestEnrollArtifactsContract(t *testing.T) {
	root := filepath.Join("..", "..", "..")

	checks := []struct {
		script string
		what   string
		expect string
	}{
		{"build/nfpm/scripts/postinstall.sh", "linuxEnrollEnvPath", `ENROLL_ENV="` + linuxEnrollEnvPath + `"`},
		{"build/nfpm/scripts/postinstall.sh", "linuxBootstrapCAPath", `CA_PATH="` + linuxBootstrapCAPath + `"`},
		{"build/pkg/build-pkg.sh", "darwinEnrollEnvPath", `ENROLL_ENV="` + darwinEnrollEnvPath + `"`},
		{"build/pkg/build-pkg.sh", "darwinBootstrapCAPath", `CA_PATH="` + darwinBootstrapCAPath + `"`},
		{"build/pkg/build-pkg.sh", "pkgReceiptIdentifier", "--identifier " + pkgReceiptIdentifier},
	}
	for _, c := range checks {
		path := filepath.Join(root, filepath.FromSlash(c.script))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("не прочитать %s: %v", c.script, err)
		}
		if !strings.Contains(string(raw), c.expect) {
			t.Errorf("дрейф %s: в %s нет %q — константа разошлась со скриптом, "+
				"decommission перестанет удалять энролл-материал/receipt", c.what, c.script, c.expect)
		}
	}
}

// Layout текущей платформы обязан ссылаться ровно на контрактные пути — иначе
// контрактный тест выше зеленел бы, а план сноса всё равно целился бы мимо.
func TestInstallLayoutMatchesEnrollContract(t *testing.T) {
	lay := InstallLayout()
	switch runtime.GOOS {
	case "linux":
		if lay.EnrollEnvPath != linuxEnrollEnvPath || lay.BootstrapCAPath != linuxBootstrapCAPath {
			t.Errorf("Layout linux: enroll=%q ca=%q, ожидались контрактные %q/%q",
				lay.EnrollEnvPath, lay.BootstrapCAPath, linuxEnrollEnvPath, linuxBootstrapCAPath)
		}
	case "darwin":
		if lay.EnrollEnvPath != darwinEnrollEnvPath || lay.BootstrapCAPath != darwinBootstrapCAPath {
			t.Errorf("Layout darwin: enroll=%q ca=%q, ожидались контрактные %q/%q",
				lay.EnrollEnvPath, lay.BootstrapCAPath, darwinEnrollEnvPath, darwinBootstrapCAPath)
		}
	}
}

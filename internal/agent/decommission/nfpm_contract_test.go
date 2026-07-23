package decommission

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNfpmContract ловит дрейф linuxPackageName относительно build/nfpm/nfpm.yaml.
// Разъезд имени тихо выключил бы дерегистрацию пакета при decommission (dpkg-query
// не нашёл бы пакет) — снос выглядел бы полным, а `apt install --reinstall`
// по-прежнему возвращал бы машину в парк. Тест без build-тега: сверка на любом
// `go test`, не только на Linux.
func TestNfpmContract(t *testing.T) {
	path := filepath.Join("..", "..", "..", "build", "nfpm", "nfpm.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("не прочитать nfpm.yaml %s: %v", path, err)
	}
	expect := "name: " + linuxPackageName
	if !strings.Contains(string(raw), expect) {
		t.Errorf("дрейф linuxPackageName: в %s нет %q — deregisterPackage перестанет "+
			"находить пакет, регистрация переживёт снос", path, expect)
	}
}

package decommission

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWxsContract ловит дрейф констант decommission относительно MSI-манифеста
// build/msi/mdm-agent.wxs. Если правка wxs (смена UpgradeCode, ренейм exe/каталога,
// смена Run-ключа) разойдётся с этими константами, resolveProductCode вернёт ok=false
// (msiexec /x тихо пропустится → ARP-хвост вернётся) или снос каталога перестанет
// узнавать наш путь — симптом неотличим от исходного бага и ничем не сигналит.
// Тест без build-тега: сверка идёт на любом `go test`, не только на Windows.
func TestWxsContract(t *testing.T) {
	wxsPath := filepath.Join("..", "..", "..", "build", "msi", "mdm-agent.wxs")
	raw, err := os.ReadFile(wxsPath)
	if err != nil {
		t.Fatalf("не прочитать wxs %s: %v", wxsPath, err)
	}
	wxs := string(raw)

	checks := []struct {
		what   string
		expect string // подстрока, обязанная присутствовать в wxs
	}{
		// UpgradeCode в wxs — без фигурных скобок; в константе они есть (нужны MsiEnumRelatedProducts).
		{"upgradeCode", `UpgradeCode="` + strings.Trim(upgradeCode, "{}") + `"`},
		{"agentImageName (File Name)", `Name="` + agentImageName + `"`},
		{"installDirName (Directory INSTALLFOLDER Name)", `Name="` + installDirName + `"`},
		{"runKeyPath (RegistryValue Key)", `Key="` + runKeyPath + `"`},
		{"trayRunValue (RegistryValue Name)", `Name="` + trayRunValue + `"`},
	}
	for _, c := range checks {
		if !strings.Contains(wxs, c.expect) {
			t.Errorf("дрейф %s: в %s нет %q — константа разошлась с MSI-манифестом; "+
				"decommission перестанет узнавать установку (msiexec /x пропустится → ARP-хвост)",
				c.what, wxsPath, c.expect)
		}
	}
}

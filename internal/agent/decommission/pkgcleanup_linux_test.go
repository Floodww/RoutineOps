//go:build linux

package decommission

import (
	"strings"
	"testing"
)

// Гард состава команд дерегистрации: query обязан целиться ровно в наш пакет и
// гейтить remove (иначе rpm-утилита на Debian дёрнула бы не тот менеджер), remove —
// форсить снятие при зависимостях и не задевать другие пакеты. Сами dpkg/rpm здесь
// НЕ запускаются (реальное снятие — полевой e2e); тест держит контракт аргументов.
func TestLinuxPackageManagers_Commands(t *testing.T) {
	want := map[string]string{
		"dpkg-query -W " + linuxPackageName: "dpkg -r --force-depends " + linuxPackageName,
		"rpm -q " + linuxPackageName:        "rpm -e --nodeps " + linuxPackageName,
	}
	if len(linuxPackageManagers) != len(want) {
		t.Fatalf("менеджеров %d, ожидалось %d", len(linuxPackageManagers), len(want))
	}
	for _, m := range linuxPackageManagers {
		q := strings.Join(m.query, " ")
		r, ok := want[q]
		if !ok {
			t.Errorf("неожиданная query-команда %q", q)
			continue
		}
		if got := strings.Join(m.remove, " "); got != r {
			t.Errorf("remove для %q = %q, ожидалось %q", q, got, r)
		}
		if m.query[len(m.query)-1] != linuxPackageName || m.remove[len(m.remove)-1] != linuxPackageName {
			t.Errorf("команды обязаны целиться ровно в %q: query=%v remove=%v",
				linuxPackageName, m.query, m.remove)
		}
	}
}

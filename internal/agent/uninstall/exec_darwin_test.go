//go:build darwin

package uninstall

import (
	"context"
	"strings"
	"testing"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
)

// removableAppBundle — последняя проверка перед os.RemoveAll, поэтому её
// отрицательные случаи важнее положительных: каждый пропуск здесь означает
// рекурсивное удаление не того каталога от имени root.
func TestRemovableAppBundle_Rejects(t *testing.T) {
	bad := []string{
		"",
		".app",
		"/Applications",                  // сам каталог приложений
		"/Applications/Safari",           // не бандл
		"/System/Applications/Music.app", // под SIP
		"/System/Library/CoreServices/Finder.app",                 // под SIP
		"/Library/Apple/System/Library/CoreServices/XProtect.app", // под SIP
		"/Applications/Пакет/Вложенный.app",                       // часть чужой установки
		"/Applications/Xcode.app/Contents/Applications/Instruments.app",
		"/Users/ivan/Downloads/Скачанное.app",   // не установка
		"/Users/ivan/Applications/Sub/Deep.app", // не прямое вложение
		"/Users/Applications/X.app",             // нет имени пользователя
		"/Applications/../etc",
		"/Applications/../../tmp/Evil.app",
		"relative/Path.app",
		"/",
		"/Applications/Chrome.app/", // хвостовой слэш снимает вызывающий, здесь путь уже не канонический
	}
	for _, p := range bad {
		t.Run(p, func(t *testing.T) {
			if removableAppBundle(p) {
				t.Fatalf("путь признан пригодным к рекурсивному удалению: %q", p)
			}
		})
	}
}

func TestRemovableAppBundle_Accepts(t *testing.T) {
	good := []string{
		"/Applications/Google Chrome.app",
		"/Applications/Telegram.app",
		"/Users/ivan/Applications/Личное.app",
	}
	for _, p := range good {
		t.Run(p, func(t *testing.T) {
			if !removableAppBundle(p) {
				t.Fatalf("штатное приложение признано неудаляемым: %q", p)
			}
		})
	}
}

// execute обязан отказать до любых файловых операций, если путь не проходит
// проверку формы, — даже когда метод в записи выставлен верно.
func TestExecute_RefusesBadPathBeforeTouchingDisk(t *testing.T) {
	target := collector.Software{
		Name:            "Finder",
		InstallLocation: "/System/Library/CoreServices/Finder.app",
		UninstallMethod: collector.UninstallMacAppBundle,
	}
	_, err := execute(context.Background(), target, quietLog())
	if err == nil {
		t.Fatal("ожидали отказ на SIP-защищённом пути")
	}
	if !strings.Contains(err.Error(), "не является приложением") {
		t.Errorf("причина отказа невнятная: %v", err)
	}
}

func TestExecute_RefusesForeignMethod(t *testing.T) {
	target := collector.Software{
		Name:            "Пакет",
		UninstallMethod: collector.UninstallDpkg,
		InstallLocation: "/Applications/Пакет.app",
	}
	if _, err := execute(context.Background(), target, quietLog()); err == nil {
		t.Fatal("на macOS метод dpkg должен отклоняться")
	}
}

// Несуществующий бандл — отказ с внятной причиной, а не паника и не молчаливый
// «успех» (иначе снятое-но-не-снятое ПО уехало бы оператору как удалённое).
func TestExecute_MissingBundle(t *testing.T) {
	target := collector.Software{
		Name:            "Отсутствует",
		InstallLocation: "/Applications/Заведомо Отсутствует.app",
		UninstallMethod: collector.UninstallMacAppBundle,
	}
	if _, err := execute(context.Background(), target, quietLog()); err == nil {
		t.Fatal("ожидали ошибку на отсутствующем бандле")
	}
}

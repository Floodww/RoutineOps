//go:build linux

package uninstall

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
)

// noninteractiveEnv глушит интерактивные приглашения пакетных менеджеров.
// Без него apt-get на настроенном debconf останавливается на диалоге в session 0:
// невидимо, без вывода и до самого таймаута.
var noninteractiveEnv = []string{"DEBIAN_FRONTEND=noninteractive"}

// execute снимает пакет штатным менеджером дистрибутива. Имя пакета берётся из
// свежего снимка (Software.UninstallID), а не от сервера.
func execute(ctx context.Context, target collector.Software, log *slog.Logger) (string, error) {
	pkg := strings.TrimSpace(target.UninstallID)
	if pkg == "" {
		return "", fmt.Errorf("пустое имя пакета — снимать нечего")
	}
	// Имя пакета уезжает в argv. Пакетные менеджеры принимают спецификаторы
	// вида "имя>=версия" и опции, начинающиеся с дефиса, поэтому пропускаем
	// только знаки, из которых состоят реальные имена пакетов.
	if !validPackageName(pkg) {
		return "", fmt.Errorf("недопустимое имя пакета %q", pkg)
	}

	var argv []string
	switch target.UninstallMethod {
	case collector.UninstallDpkg:
		argv = []string{"apt-get", "remove", "-y", pkg}
	case collector.UninstallRPM:
		// dnf на современных RHEL-подобных, yum на старых. Выбираем по наличию
		// бинаря, а не по версии дистрибутива.
		mgr := "dnf"
		if _, err := exec.LookPath(mgr); err != nil {
			mgr = "yum"
		}
		argv = []string{mgr, "remove", "-y", pkg}
	case collector.UninstallPacman:
		argv = []string{"pacman", "-R", "--noconfirm", pkg}
	case collector.UninstallAPK:
		argv = []string{"apk", "del", pkg}
	default:
		return "", fmt.Errorf("способ снятия %q не поддержан на Linux", target.UninstallMethod)
	}

	log.Info("uninstall: пакетный менеджер", slog.String("cmd", argv[0]), slog.String("package", pkg))
	return runCommand(ctx, argv[0], argv[1:], noninteractiveEnv)
}

// validPackageName живёт в validate.go без build-тега — чтобы проверка,
// стоящая последней перед запуском пакетного менеджера, гонялась на каждом
// прогоне тестов, а не только на Linux.

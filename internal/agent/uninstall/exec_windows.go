//go:build windows

package uninstall

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
)

// Ветки ARP, из которых коллектор читает установленное ПО. Ищем строку снятия
// РОВНО там же и по тому же ключу (Software.UninstallID — имя подключа).
const (
	uninstallKeyPath     = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	uninstallKeyPathWow  = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
	msiexecName          = "msiexec.exe"
	quietUninstallString = "QuietUninstallString"
)

// execute снимает ПО штатным для записи способом.
//
// Ключевое: строка деинсталлятора читается ИЗ РЕЕСТРА ЭТОЙ МАШИНЫ, а не приходит
// от сервера. Сервер называет только цель; что именно запускать — решает агент
// по локальным данным. Иначе поле в задаче стало бы прямым исполнением
// произвольной командной строки от имени LocalSystem.
func execute(ctx context.Context, target collector.Software, log *slog.Logger) (string, error) {
	// Per-user установка: деинсталлятор лежит в профиле и пишет в HKCU того
	// пользователя, а служба работает от LocalSystem — её HKCU другой. Запуск
	// «сработал бы» и оставил продукт на месте. Коллектор такие записи и не
	// помечает методом, но проверяем повторно: запись могла приехать из снимка
	// агента другой версии.
	if target.Scope == collector.ScopeUser {
		return "", fmt.Errorf("установка в профиль пользователя не снимается из-под службы (LocalSystem)")
	}

	switch target.UninstallMethod {
	case collector.UninstallMSI:
		// ProductCode — это имя подключа; коллектор кладёт его в UninstallID и
		// уже проверил, что это валидный GUID.
		if !looksLikeProductCode(target.UninstallID) {
			return "", fmt.Errorf("ключ продукта %q не похож на ProductCode", target.UninstallID)
		}
		args := []string{"/x", target.UninstallID, "/qn", "/norestart"}
		log.Info("uninstall: msiexec", slog.String("product_code", target.UninstallID))
		return runCommand(ctx, msiexecName, args, nil)

	case collector.UninstallWindowsQuiet:
		line, err := readQuietUninstallString(target.UninstallID)
		if err != nil {
			return "", err
		}
		argv, err := windows.DecomposeCommandLine(line)
		if err != nil || len(argv) == 0 {
			return "", fmt.Errorf("строка тихого снятия из реестра неразбираема: %v", err)
		}
		log.Info("uninstall: QuietUninstallString", slog.String("exe", argv[0]))
		return runCommand(ctx, argv[0], argv[1:], nil)

	default:
		return "", fmt.Errorf("способ снятия %q не поддержан на Windows", target.UninstallMethod)
	}
}

// readQuietUninstallString достаёт строку тихого снятия из той же ветки ARP, из
// которой коллектор увидел запись. Обе ветки (нативная и WOW6432Node) —
// 32-битный продукт на 64-битной ОС живёт во второй.
func readQuietUninstallString(keyName string) (string, error) {
	if !validRegistryKeyName(keyName) {
		return "", fmt.Errorf("недопустимый ключ записи %q", keyName)
	}
	for _, root := range []string{uninstallKeyPath, uninstallKeyPathWow} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, root+`\`+keyName, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := k.GetStringValue(quietUninstallString)
		k.Close()
		if err == nil && strings.TrimSpace(v) != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("в реестре больше нет тихого деинсталлятора для %q (запись изменилась после снимка)", keyName)
}

// looksLikeProductCode и validRegistryKeyName живут в validate.go без build-тега:
// это чистые строковые проверки, и гоняться они обязаны на каждом прогоне
// тестов, а не только на Windows.

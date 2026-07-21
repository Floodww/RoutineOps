//go:build darwin

package admin

import (
	"fmt"
	"os/exec"
	"strings"
)

type osPriv struct{}

func newOSPrivilegeManager() PrivilegeManager { return osPriv{} }

// Grant добавляет пользователя в группу admin (нужны права root у сервиса).
func (osPriv) Grant(user string) error {
	return exec.Command("dseditgroup", "-o", "edit", "-a", user, "-t", "user", "admin").Run()
}

// Revoke убирает пользователя из группы admin.
func (osPriv) Revoke(user string) error {
	return exec.Command("dseditgroup", "-o", "edit", "-d", user, "-t", "user", "admin").Run()
}

// IsAdmin сообщает, состоит ли пользователь в группе admin прямо сейчас.
// `dseditgroup -o checkmember` печатает "yes <user> is a member of admin" либо
// "no <user> is NOT a member of admin"; парсим вывод (код возврата у разных версий
// macOS непоследователен).
func (osPriv) IsAdmin(user string) (bool, error) {
	out, err := exec.Command("dseditgroup", "-o", "checkmember", "-m", user, "admin").CombinedOutput()
	s := strings.ToLower(strings.TrimSpace(string(out)))
	switch {
	case strings.HasPrefix(s, "yes"):
		return true, nil
	case strings.HasPrefix(s, "no"):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("dseditgroup checkmember: %w (%s)", err, s)
	default:
		return false, fmt.Errorf("dseditgroup checkmember: неожиданный вывод %q", s)
	}
}

// osConsoleUserFull — на macOS полной формы с доменом нет; отличается от
// osConsoleUser только явным флагом успешности пробы (для инвентаря).
func osConsoleUserFull() (string, bool) { return consoleUserProbe() }

// osConsoleUser — вошедший в графическую сессию пользователь. "" если никого
// (loginwindow → владелец /dev/console = root).
func osConsoleUser() string {
	u, _ := consoleUserProbe()
	return u
}

// consoleUserProbe возвращает пользователя и флаг успешности пробы. При отказе
// stat "" значит «не знаю», а не «никого», и в инвентарь не отдаётся (см.
// ConsoleUser).
func consoleUserProbe() (string, bool) {
	out, err := exec.Command("stat", "-f", "%Su", "/dev/console").Output()
	if err != nil {
		return "", false
	}
	u := strings.TrimSpace(string(out))
	if u == "root" {
		return "", true // loginwindow: никого за консолью, но проба успешна
	}
	return u, true
}

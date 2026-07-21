//go:build windows

package admin

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"
)

type osPriv struct{}

func newOSPrivilegeManager() PrivilegeManager { return osPriv{} }

// adminGroupName возвращает локализованное имя встроенной группы администраторов
// по well-known SID S-1-5-32-544 (RU «Администраторы», DE «Administratoren», ...).
// Хардкод "Administrators" ломал `net localgroup` на локализованной Windows:
// группы с таким именем нет → System error 1376 → exit status 2.
func adminGroupName() (string, error) {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return "", fmt.Errorf("well-known SID администраторов: %w", err)
	}
	name, _, _, err := sid.LookupAccount("")
	if err != nil {
		return "", fmt.Errorf("имя группы по SID %s: %w", sid, err)
	}
	return name, nil
}

// runNet запускает `net` и при ошибке возвращает её вместе с выводом утилиты —
// иначе наверх уходил бы голый "exit status 2" без причины (см. silent failure
// в manager.grant).
func runNet(args ...string) error {
	out, err := exec.Command("net", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("net %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Grant добавляет пользователя в локальную группу администраторов (нужны права админа).
func (osPriv) Grant(user string) error {
	group, err := adminGroupName()
	if err != nil {
		return err
	}
	return runNet("localgroup", group, user, "/add")
}

// Revoke убирает пользователя из группы администраторов.
func (osPriv) Revoke(user string) error {
	group, err := adminGroupName()
	if err != nil {
		return err
	}
	return runNet("localgroup", group, user, "/delete")
}

// IsAdmin сообщает, состоит ли пользователь в группе администраторов прямо сейчас.
// `net localgroup <group>` печатает список членов между строкой из дефисов и
// "The command completed successfully"; сравниваем без учёта регистра.
func (osPriv) IsAdmin(user string) (bool, error) {
	group, err := adminGroupName()
	if err != nil {
		return false, err
	}
	out, err := exec.Command("net", "localgroup", group).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("net localgroup %s: %w (%s)", group, err, strings.TrimSpace(string(out)))
	}
	target := strings.ToLower(strings.TrimSpace(user))
	for _, line := range strings.Split(string(out), "\n") {
		if strings.ToLower(strings.TrimSpace(line)) == target {
			return true, nil
		}
	}
	return false, nil
}

// queryConsoleUserName возвращает Win32_ComputerSystem.UserName как есть
// (DOMAIN\user) либо ошибку опроса. Общий источник для инвентаря и admin-выдачи,
// которые по-разному трактуют ОТКАЗ (см. ниже).
func queryConsoleUserName() (string, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-CimInstance Win32_ComputerSystem).UserName").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// osConsoleUserFull — интерактивный пользователь для ИНВЕНТАРЯ в исходной форме
// DOMAIN\user (домен не отбрасываем — по нему учётка матчится с каталогом).
// Второй результат — успешность пробы. При отказе опроса — ("", false), НЕ
// %USERNAME%: служба работает под LocalSystem, где env дал бы "SYSTEM" —
// выдуманное значение уехало бы на сервер в PII-поле как «текущий пользователь».
// false отличает отказ WMI от честного «за консолью никого» ("", true) — иначе
// транзиентный сбой выглядел бы для сервера как логаут (см. ConsoleUser).
func osConsoleUserFull() (string, bool) {
	u, err := queryConsoleUserName()
	if err != nil {
		return "", false
	}
	return u, true
}

// osConsoleUser — интерактивный пользователь БЕЗ домена для ВЫДАЧИ временной
// админки (`net localgroup` ждёт голое имя локальной учётки). При отказе опроса
// сохраняется прежний env-фолбэк: тут неверное имя лишь безвредно уронит
// net localgroup, наружу (в инвентарь/каталог) оно не уходит.
func osConsoleUser() string {
	u, err := queryConsoleUserName()
	if err != nil {
		return os.Getenv("USERNAME")
	}
	if i := strings.LastIndex(u, `\`); i >= 0 {
		u = u[i+1:] // DOMAIN\user -> user
	}
	return u
}

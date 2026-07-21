//go:build linux

package admin

import (
	"fmt"
	"os"
	"os/exec"
	osuser "os/user"
	"regexp"
	"strconv"
	"strings"
)

type osPriv struct{}

func newOSPrivilegeManager() PrivilegeManager { return osPriv{} }

// adminGroups — группы sudo-доступа в порядке предпочтения: Debian/Ubuntu держат
// его в `sudo`, RHEL/Fedora/Arch/SUSE — в `wheel`. Берём ту, что реально заведена
// в системе: добавление в несуществующую группу молча не даёт никаких прав.
var adminGroups = []string{"sudo", "wheel"}

// userNameRe повторяет NAME_REGEX из useradd(8). Первым символом дефис запрещён
// намеренно: имя уходит в argv gpasswd/usermod, и "-r" там стал бы флагом.
var userNameRe = regexp.MustCompile(`^[a-zA-Z0-9._][a-zA-Z0-9._-]*$`)

// validUsername — гейт перед любым сабпроцессом. Имя приходит из osConsoleUser,
// то есть из вывода чужой утилиты; доверять ему нельзя.
func validUsername(u string) bool {
	return len(u) > 0 && len(u) <= 32 && userNameRe.MatchString(u)
}

// hasGroupLine ищет группу в формате /etc/group ("имя:x:gid:члены").
func hasGroupLine(etcGroup, name string) bool {
	for _, line := range strings.Split(etcGroup, "\n") {
		if n, _, ok := strings.Cut(line, ":"); ok && n == name {
			return true
		}
	}
	return false
}

// groupExists спрашивает getent (он видит и NSS/LDAP-группы, не только локальные)
// и лишь при его отсутствии читает /etc/group напрямую.
func groupExists(name string) bool {
	if _, err := exec.LookPath("getent"); err == nil {
		return exec.Command("getent", "group", name).Run() == nil
	}
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return false
	}
	return hasGroupLine(string(data), name)
}

func adminGroup() (string, error) {
	for _, g := range adminGroups {
		if groupExists(g) {
			return g, nil
		}
	}
	return "", fmt.Errorf("группы администраторов (%s) нет в системе — права выдавать некуда",
		strings.Join(adminGroups, "/"))
}

// runPriv запускает утилиту управления группами и возвращает ошибку вместе с её
// выводом: голый "exit status 1" от gpasswd не говорит, чего не хватило — прав
// root, пользователя или группы (см. silent failure в manager.grant).
func runPriv(bin string, args ...string) error {
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Grant добавляет пользователя в админ-группу (нужны права root у сервиса).
func (osPriv) Grant(user string) error {
	if !validUsername(user) {
		return fmt.Errorf("недопустимое имя пользователя %q", user)
	}
	group, err := adminGroup()
	if err != nil {
		return err
	}
	if _, err := exec.LookPath("gpasswd"); err == nil {
		return runPriv("gpasswd", "-a", user, group)
	}
	// Фолбэк для образов без shadow-utils. Именно -aG (append): голый -G задаёт
	// список групп целиком и вычистил бы все остальные членства пользователя.
	if _, err := exec.LookPath("usermod"); err == nil {
		return runPriv("usermod", "-aG", group, user)
	}
	return fmt.Errorf("нет ни gpasswd, ни usermod — некому добавить %s в группу %s", user, group)
}

// Revoke убирает пользователя из админ-группы.
func (osPriv) Revoke(user string) error {
	if !validUsername(user) {
		return fmt.Errorf("недопустимое имя пользователя %q", user)
	}
	group, err := adminGroup()
	if err != nil {
		return err
	}
	if _, err := exec.LookPath("gpasswd"); err == nil {
		return runPriv("gpasswd", "-d", user, group)
	}
	// deluser <user> <group> (Debian/busybox) удаляет ровно одно членство.
	// usermod -G здесь не годится: он требует пересчитать полный список групп
	// пользователя, и гонка с любым другим изменением стоила бы ему членств.
	if _, err := exec.LookPath("deluser"); err == nil {
		return runPriv("deluser", user, group)
	}
	return fmt.Errorf("нет ни gpasswd, ни deluser — не могу снять %s с группы %s", user, group)
}

// hasGroup ищет группу в выводе `id -nG` (имена через пробел).
func hasGroup(idOutput, group string) bool {
	for _, g := range strings.Fields(idOutput) {
		if g == group {
			return true
		}
	}
	return false
}

// IsAdmin сообщает, состоит ли пользователь в админ-группе ПРЯМО СЕЙЧАС.
//
// Спрашиваем `id -nG <user>`, а НЕ geteuid агента: агент всегда работает под root,
// и geteuid()==0 вернул бы true для любого пользователя. Тогда grant() записал бы
// wasAdmin=true, а revoke() счёл бы права собственными и никогда бы их не снял —
// временный грант стал бы вечным.
func (osPriv) IsAdmin(user string) (bool, error) {
	if !validUsername(user) {
		return false, fmt.Errorf("недопустимое имя пользователя %q", user)
	}
	group, err := adminGroup()
	if err != nil {
		return false, err
	}
	out, err := exec.Command("id", "-nG", user).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("id -nG %s: %w (%s)", user, err, strings.TrimSpace(string(out)))
	}
	return hasGroup(string(out), group), nil
}

// minRegularUID — граница «человеческих» учёток (SYS_UID_MAX у дистрибутивов ≤999).
//
// Это единственное, чем greeter дисплей-менеджера отличается от вошедшего человека:
// gdm/sddm/lightdm держат НАСТОЯЩИЙ сеанс на seat0, а колонки Class в выводе
// `list-sessions` нет. Без фильтра по UID машина, стоящая на экране входа, получала
// бы `gpasswd -a gdm sudo` — sudo сервисной учётке и запись «выдано gdm» в аудите.
const minRegularUID = 1000

// parseLoginctl выбирает пользователя локального сеанса из вывода
// `loginctl list-sessions --no-legend`; колонки: SESSION UID USER SEAT [TTY].
// Консольным считаем только сеанс с РЕАЛЬНЫМ местом — имя seat по systemd
// обязано начинаться с "seat" (seat0, seat1, ...). Сеанс без места (ssh/cron)
// печатает колонку SEAT ПУСТОЙ (пробелы, не литерал "-"); strings.Fields такую
// колонку схлопывает, и в f[3] попадает TTY (pts/0, tty2). Прежняя проверка
// `seat != "-"` принимала этот TTY за место и выдавала удалённому ssh-юзеру
// права/инвентарь консольного пользователя — теперь prefix "seat" их отсекает
// (pts/0/tty2 префиксу не соответствуют).
func parseLoginctl(out string) string {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		uid, err := strconv.Atoi(f[1])
		if err != nil {
			continue // UID обязан быть числом: иначе это заголовок или мусор
		}
		if uid < minRegularUID {
			continue // root и системные учётки, включая greeter'ы
		}
		if seat := f[3]; strings.HasPrefix(seat, "seat") {
			return f[2]
		}
	}
	return ""
}

// regularUser отсекает системные учётки в фолбэке на `who`: UID он не печатает,
// поэтому спрашиваем /etc/passwd (импорт под алиасом: параметр `user` в Grant/Revoke
// затеняет одноимённый пакет). Пользователь не резолвится — считаем обычным:
// `who` перечисляет только реально вошедших (greeter'ы в utmp не попадают), а
// поломка резолвинга не повод навсегда сломать выдачу прав.
func regularUser(name string) bool {
	u, err := osuser.Lookup(name)
	if err != nil {
		return true
	}
	uid, err := strconv.Atoi(u.Uid)
	return err != nil || uid >= minRegularUID
}

// parseWho — фолбэк, когда systemd-logind недоступен (SysV/musl-дистрибутивы).
// Графический вход (":0") приоритетнее текстовой консоли ("tty1"): за машиной
// может быть открыто и то и другое, но интерактивный пользователь — тот, кто в графике.
func parseWho(out string) string {
	var tty string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] == "root" {
			continue
		}
		switch {
		case strings.HasPrefix(f[1], ":"):
			return f[0]
		case strings.HasPrefix(f[1], "tty") && tty == "":
			tty = f[0]
		}
	}
	return tty
}

// osConsoleUserFull — на Linux полной формы с доменом нет; отличается от
// osConsoleUser только явным флагом успешности пробы (для инвентаря).
func osConsoleUserFull() (string, bool) { return consoleUserProbe() }

// osConsoleUser — пользователь активного графического/консольного сеанса.
// "" если никого (или только root — его права временными не бывают).
func osConsoleUser() string {
	u, _ := consoleUserProbe()
	return u
}

// consoleUserProbe возвращает пользователя и флаг успешности пробы. false —
// только когда НИ loginctl, НИ who не отработали: тогда "" значит «не знаю»,
// а не «никого», и в инвентарь его отдавать нельзя (см. ConsoleUser).
func consoleUserProbe() (string, bool) {
	probed := false
	if out, err := exec.Command("loginctl", "list-sessions", "--no-legend").Output(); err == nil {
		probed = true
		if u := parseLoginctl(string(out)); u != "" {
			return u, true
		}
	}
	if out, err := exec.Command("who").Output(); err == nil {
		probed = true
		if u := parseWho(string(out)); u != "" && regularUser(u) {
			return u, true
		}
	}
	return "", probed
}

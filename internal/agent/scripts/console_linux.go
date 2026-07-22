//go:build linux

package scripts

import (
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

// minRegularUID — граница «человеческих» учёток (SYS_UID_MAX у дистрибутивов ≤999).
//
// Это единственное, чем greeter дисплей-менеджера отличается от вошедшего человека:
// gdm/sddm/lightdm держат НАСТОЯЩИЙ сеанс на seat0, а колонки Class в выводе
// `list-sessions` нет — по имени и месту они неотличимы. Без фильтра по UID агент
// считал бы «gdm» залогиненным пользователем, пока машина стоит на экране входа.
const minRegularUID = 1000

// parseLoginctl выбирает пользователя локального сеанса из вывода
// `loginctl list-sessions --no-legend`; колонки: SESSION UID USER SEAT [TTY].
// Физический вход — только сеанс с реальным местом (SEAT = seat0/seat1…); ssh/cron
// несут в этой колонке tty/pts или "-", за машиной физически никого нет, и
// LOGIN/LOGOUT-триггеры на них срабатывать не должны.
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
		// prefix "seat" (seat0/seat1…), а НЕ просто "!= -": ssh/cron-сессии несут в
		// колонке SEAT место tty/pts (или "-"), и seat != "-" ошибочно принимал их
		// за физический вход → ложная пара LOGIN/LOGOUT-триггеров на каждый ssh-
		// коннект (немодемпотентная политика отрабатывала лишний раз от root).
		// Вторая копия той же функции — admin/priv_linux.go: держать в синхроне.
		if seat := f[3]; strings.HasPrefix(seat, "seat") {
			return f[2]
		}
	}
	return ""
}

// regularUser отсекает системные учётки в фолбэке на `who`: UID он не печатает,
// поэтому спрашиваем /etc/passwd. Пользователь не резолвится — считаем обычным:
// `who` перечисляет только реально вошедших (greeter'ы в utmp не попадают), а
// поломка резолвинга не повод молча выключить триггеры.
func regularUser(name string) bool {
	u, err := user.Lookup(name)
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

// osConsoleUser — текущий интерактивный пользователь Linux. "" если только root
// (никто не вошёл в графическую или консольную сессию).
func osConsoleUser() string {
	if out, err := exec.Command("loginctl", "list-sessions", "--no-legend").Output(); err == nil {
		if u := parseLoginctl(string(out)); u != "" {
			return u
		}
	}
	if out, err := exec.Command("who").Output(); err == nil {
		if u := parseWho(string(out)); u != "" && regularUser(u) {
			return u
		}
	}
	return ""
}

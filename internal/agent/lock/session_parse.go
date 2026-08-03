package lock

import (
	"bytes"
	"strconv"
	"strings"
)

// Разбор вывода systemd-logind и окружения процессов — чистые функции без exec и без
// build-тегов: только они решают, В КАКОЙ сессии и с каким окружением поднимать замок,
// а ошибка здесь означает «замок молча не показался», что снаружи неотличимо от
// работающей блокировки. Поэтому разбор обязан проверяться тестами на любой машине,
// а не только на живом Linux.

// SessionInfo — то, что нужно знать о сессии, чтобы решить, показывать ли в ней замок.
type SessionInfo struct {
	ID      string
	UID     int
	User    string
	Type    string // x11 | wayland | tty
	State   string // active | online | closing
	Active  bool
	Remote  bool
	Leader  int    // pid лидера сессии — из его /proc/<pid>/environ берём DISPLAY/XAUTHORITY
	Display string // ":0" из logind, если процесс окружения не дал
}

// ParseSessionIDs достаёт идентификаторы сессий из `loginctl list-sessions --no-legend`.
// Формат колонок между версиями systemd менялся (добавлялись TTY и STATE), поэтому
// берём только первую колонку — она была первой всегда.
func ParseSessionIDs(out []byte) []string {
	var ids []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		// Строка сессии — это минимум SESSION UID USER, где UID числовой. Проверка
		// именно по UID, а не по первому полю: идентификатор сессии тоже бывает
		// числом, и хвост «2 sessions listed.» без этой проверки приезжал как сессия
		// с id «2» — то есть дублировал реальную и уводил замок не туда.
		if len(f) < 3 {
			continue
		}
		if _, err := strconv.Atoi(f[1]); err != nil {
			continue
		}
		ids = append(ids, f[0])
	}
	return ids
}

// ParseSessionProperties разбирает `loginctl show-session -p ...` (строки KEY=VALUE).
func ParseSessionProperties(out []byte) map[string]string {
	props := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || k == "" {
			continue
		}
		props[k] = v
	}
	return props
}

// SessionFromProperties собирает SessionInfo из свойств logind.
func SessionFromProperties(id string, props map[string]string) SessionInfo {
	uid, _ := strconv.Atoi(props["User"])
	leader, _ := strconv.Atoi(props["Leader"])
	return SessionInfo{
		ID:      id,
		UID:     uid,
		User:    props["Name"],
		Type:    strings.ToLower(props["Type"]),
		State:   strings.ToLower(props["State"]),
		Active:  props["Active"] == "yes",
		Remote:  props["Remote"] == "yes",
		Leader:  leader,
		Display: props["Display"],
	}
}

// PickGraphicalSession выбирает сессию, в которой имеет смысл показывать замок.
//
// Требования и почему они такие:
//   - Active=yes и State=active: неактивная сессия сидит на другом VT, окно там никто
//     не увидит, а захват клавиатуры чужого VT не удастся;
//   - Remote=no: в ssh-сессии графики нет, а замок «для галочки» создаёт ложное
//     ощущение заблокированного устройства;
//   - Type ∈ {x11, wayland}: tty-сессии замку не по адресу. wayland ОТБИРАЕТСЯ
//     намеренно, хотя оверлей там невозможен — вызывающий обязан увидеть тип и
//     сказать об этом в лог, иначе Wayland-парк молча числился бы заблокированным.
//
// Из нескольких подходящих берётся первая: одновременно активной графической сессии
// на seat0 в норме ровно одна.
func PickGraphicalSession(sessions []SessionInfo) (SessionInfo, bool) {
	for _, s := range sessions {
		if !s.Active || s.State != "active" || s.Remote {
			continue
		}
		if s.Type != "x11" && s.Type != "wayland" {
			continue
		}
		return s, true
	}
	return SessionInfo{}, false
}

// ParseProcEnviron разбирает /proc/<pid>/environ (пары KEY=VALUE через NUL).
func ParseProcEnviron(b []byte) map[string]string {
	env := map[string]string{}
	for _, part := range bytes.Split(b, []byte{0}) {
		if len(part) == 0 {
			continue
		}
		k, v, ok := strings.Cut(string(part), "=")
		if !ok || k == "" {
			continue
		}
		env[k] = v
	}
	return env
}

// OverlayEnv собирает окружение для процесса замка. Служба живёт вне графической
// сессии, поэтому X-клиенту нужно передать и адрес дисплея, и путь к куке доступа:
// без XAUTHORITY соединение с X-сервером отвергается, и замок «не показывается» без
// внятной причины.
//
// sessionEnv — окружение лидера сессии (/proc/<pid>/environ). Оно авторитетнее
// свойств logind: там реальные значения того сеанса, включая нестандартные пути
// XAUTHORITY дисплей-менеджеров (gdm кладёт куку в /run/user/<uid>/gdm/Xauthority).
func OverlayEnv(s SessionInfo, sessionEnv map[string]string) []string {
	get := func(key, fallback string) string {
		if v := sessionEnv[key]; v != "" {
			return v
		}
		return fallback
	}
	runtimeDir := get("XDG_RUNTIME_DIR", "/run/user/"+strconv.Itoa(s.UID))
	home := get("HOME", "/home/"+s.User)
	env := []string{
		"DISPLAY=" + get("DISPLAY", s.Display),
		"XDG_RUNTIME_DIR=" + runtimeDir,
		"HOME=" + home,
		"USER=" + s.User,
		"LOGNAME=" + s.User,
	}
	// XAUTHORITY добавляем, только если знаем путь: пустое значение переменной хуже
	// её отсутствия — библиотека X перестанет искать куку в ~/.Xauthority.
	if xauth := get("XAUTHORITY", ""); xauth != "" {
		env = append(env, "XAUTHORITY="+xauth)
	}
	return env
}

// Backend — на чём сессия рисует графику.
type Backend string

const (
	BackendX11     Backend = "x11"     // полноценный оверлей возможен
	BackendWayland Backend = "wayland" // оверлей НЕ реализуем клиентом, см. docs/lock-linux.md
	BackendNone    Backend = "none"    // графики нет вообще (сервер, tty)
)

// DetectBackend решает по окружению сессии, чем мы располагаем. lookup — доступ к
// переменным окружения СЕССИИ ПОЛЬЗОВАТЕЛЯ (не процесса службы: служба живёт вне
// графической сессии, у неё этих переменных нет).
//
// Порядок проверок неслучаен: под XWayland в сессии есть ОБЕ переменные, и решение
// «раз есть DISPLAY, значит X11» дало бы окно, которое компоновщик Wayland не держит
// поверх и не отдаёт нам клавиатуру, — то есть замок, который выглядит рабочим и не
// запирает. Поэтому WAYLAND_DISPLAY проверяется первым.
func DetectBackend(lookup func(string) string) Backend {
	if lookup("WAYLAND_DISPLAY") != "" {
		return BackendWayland
	}
	if lookup("DISPLAY") != "" {
		return BackendX11
	}
	return BackendNone
}

// SessionBackend — чем сессия рисует графику: сперва по её окружению, а если лидер
// сессии окружения не отдал (например, /proc недоступен) — по типу из logind.
//
// Двойной источник не перестраховка: под XWayland тип сессии logind сообщает как
// "wayland", а DISPLAY в окружении есть, и наоборот — на голом X-сервере без
// дисплей-менеджера тип бывает "tty" при живом DISPLAY. Ошибка в любую сторону даёт
// либо молчащий замок, либо окно, которое не запирает.
func SessionBackend(s SessionInfo, sessionEnv map[string]string) Backend {
	if len(sessionEnv) > 0 {
		return DetectBackend(func(k string) string { return sessionEnv[k] })
	}
	switch s.Type {
	case "x11":
		return BackendX11
	case "wayland":
		return BackendWayland
	default:
		return BackendNone
	}
}

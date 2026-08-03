package lock

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseSessionIDs(t *testing.T) {
	// Формат `loginctl list-sessions --no-legend` менялся между версиями systemd:
	// в старых 5 колонок, в новых добавились TTY и STATE. Опираемся только на первую.
	out := []byte("" +
		"   2 1000 artem seat0 tty2\n" +
		"   c1 1000 artem seat0 tty1 active\n" +
		"\n" +
		"2 sessions listed.\n")
	got := ParseSessionIDs(out)
	if want := []string{"2", "c1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("id сессий = %v, want %v", got, want)
	}
}

func TestParseSessionProperties(t *testing.T) {
	out := []byte("Active=yes\nState=active\nType=x11\nRemote=no\nUser=1000\nName=artem\nLeader=1234\nDisplay=:0\n")
	props := ParseSessionProperties(out)
	s := SessionFromProperties("2", props)
	want := SessionInfo{
		ID: "2", UID: 1000, User: "artem", Type: "x11", State: "active",
		Active: true, Remote: false, Leader: 1234, Display: ":0",
	}
	if s != want {
		t.Fatalf("сессия = %+v, want %+v", s, want)
	}
}

func TestPickGraphicalSession(t *testing.T) {
	x11 := SessionInfo{ID: "2", Type: "x11", State: "active", Active: true}
	cases := []struct {
		name     string
		in       []SessionInfo
		wantID   string
		wantNone bool
	}{
		{"обычная графическая", []SessionInfo{x11}, "2", false},
		{
			// Замок в неактивной сессии никто не увидит: она на другом VT.
			name: "неактивная пропускается",
			in: []SessionInfo{
				{ID: "1", Type: "x11", State: "online", Active: false},
				x11,
			},
			wantID: "2",
		},
		{
			// ssh-сессия графики не имеет; показать в ней «замок» — соврать оператору.
			name:     "удалённая не годится",
			in:       []SessionInfo{{ID: "5", Type: "x11", State: "active", Active: true, Remote: true}},
			wantNone: true,
		},
		{
			name:     "tty не годится",
			in:       []SessionInfo{{ID: "3", Type: "tty", State: "active", Active: true}},
			wantNone: true,
		},
		{
			// Wayland ОБЯЗАН выбираться, хотя оверлей там невозможен: вызывающий
			// увидит тип и скажет об этом в лог. Пропусти мы её здесь — парк на
			// Wayland молча числился бы заблокированным.
			name:   "wayland выбирается для честного отчёта",
			in:     []SessionInfo{{ID: "7", Type: "wayland", State: "active", Active: true}},
			wantID: "7",
		},
		{"пусто", nil, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := PickGraphicalSession(c.in)
			if c.wantNone {
				if ok {
					t.Fatalf("выбрана сессия %+v, ожидали отказ", got)
				}
				return
			}
			if !ok || got.ID != c.wantID {
				t.Fatalf("выбрана %q (ok=%v), want %q", got.ID, ok, c.wantID)
			}
		})
	}
}

func TestParseProcEnviron(t *testing.T) {
	raw := []byte("DISPLAY=:0\x00XAUTHORITY=/run/user/1000/gdm/Xauthority\x00HOME=/home/artem\x00")
	env := ParseProcEnviron(raw)
	if env["DISPLAY"] != ":0" || env["XAUTHORITY"] != "/run/user/1000/gdm/Xauthority" {
		t.Fatalf("окружение разобрано неверно: %+v", env)
	}
	if len(ParseProcEnviron(nil)) != 0 {
		t.Fatal("пустой environ должен давать пустую карту")
	}
}

func TestOverlayEnv(t *testing.T) {
	s := SessionInfo{UID: 1000, User: "artem", Display: ":0"}

	t.Run("берёт значения из окружения сессии", func(t *testing.T) {
		env := OverlayEnv(s, map[string]string{
			"DISPLAY":         ":1",
			"XAUTHORITY":      "/run/user/1000/gdm/Xauthority",
			"XDG_RUNTIME_DIR": "/run/user/1000",
			"HOME":            "/home/artem",
		})
		assertEnv(t, env, "DISPLAY", ":1") // окружение сессии авторитетнее logind
		assertEnv(t, env, "XAUTHORITY", "/run/user/1000/gdm/Xauthority")
	})

	t.Run("падает на logind и умолчания, когда лидер молчит", func(t *testing.T) {
		env := OverlayEnv(s, nil)
		assertEnv(t, env, "DISPLAY", ":0")
		assertEnv(t, env, "XDG_RUNTIME_DIR", "/run/user/1000")
		assertEnv(t, env, "HOME", "/home/artem")
		assertEnv(t, env, "USER", "artem")
	})

	// Пустой XAUTHORITY ХУЖЕ отсутствующего: с ним библиотека X не пойдёт искать
	// куку в ~/.Xauthority и соединение отвалится там, где оно бы состоялось.
	t.Run("пустой XAUTHORITY не выставляется", func(t *testing.T) {
		for _, kv := range OverlayEnv(s, map[string]string{"XAUTHORITY": ""}) {
			if strings.HasPrefix(kv, "XAUTHORITY=") {
				t.Fatalf("XAUTHORITY выставлен пустым: %q", kv)
			}
		}
	})
}

func assertEnv(t *testing.T, env []string, key, want string) {
	t.Helper()
	for _, kv := range env {
		if k, v, _ := strings.Cut(kv, "="); k == key {
			if v != want {
				t.Fatalf("%s=%q, want %q", key, v, want)
			}
			return
		}
	}
	t.Fatalf("%s отсутствует в окружении %v", key, env)
}

func TestDetectBackend(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	cases := []struct {
		name string
		vars map[string]string
		want Backend
	}{
		{"чистый X11", map[string]string{"DISPLAY": ":0"}, BackendX11},
		{"чистый Wayland", map[string]string{"WAYLAND_DISPLAY": "wayland-0"}, BackendWayland},
		// XWayland: есть обе переменные. Ответ обязан быть wayland — иначе замок
		// нарисует X-окно, которое компоновщик не держит поверх и не отдаёт нам
		// клавиатуру: снаружи «замок висит», по факту не запирает.
		{"XWayland", map[string]string{"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0"}, BackendWayland},
		{"без графики", map[string]string{}, BackendNone},
		{"пустые значения", map[string]string{"DISPLAY": "", "WAYLAND_DISPLAY": ""}, BackendNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DetectBackend(env(c.vars)); got != c.want {
				t.Fatalf("бэкенд = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSessionBackend(t *testing.T) {
	cases := []struct {
		name string
		sess SessionInfo
		env  map[string]string
		want Backend
	}{
		{"окружение важнее типа", SessionInfo{Type: "tty"}, map[string]string{"DISPLAY": ":0"}, BackendX11},
		// XWayland: logind говорит wayland, DISPLAY в сессии есть. Ответ обязан
		// остаться wayland — X-окно там не запирает.
		{"XWayland", SessionInfo{Type: "wayland"}, map[string]string{"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0"}, BackendWayland},
		{"нет окружения — по типу x11", SessionInfo{Type: "x11"}, nil, BackendX11},
		{"нет окружения — по типу wayland", SessionInfo{Type: "wayland"}, nil, BackendWayland},
		{"нет окружения — tty", SessionInfo{Type: "tty"}, nil, BackendNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SessionBackend(c.sess, c.env); got != c.want {
				t.Fatalf("бэкенд = %q, want %q", got, c.want)
			}
		})
	}
}

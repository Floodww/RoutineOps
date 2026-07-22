//go:build linux

package scripts

import "testing"

// Сеанс без места (seat="-") — ssh/cron: LOGIN/LOGOUT-триггеры на нём не срабатывают.
func TestParseLoginctl(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want string
	}{
		{"графический сеанс за seat0", "   3 1000 alice seat0 tty2\n", "alice"},
		{"старый systemd без колонки TTY", "   3 1000 alice seat0\n", "alice"},
		{"ssh-сеанс (seat='-') пропускается", "  15 1001 deploy - -\n", ""},
		// Пустой SEAT схлопывается strings.Fields → в f[3] попадает pts/tty. Прежнее
		// `seat != "-"` принимало это за физический вход → ложные LOGIN/LOGOUT на
		// каждый ssh-коннект (#1.4). Prefix "seat" отсекает.
		{"ssh с pts в колонке места (пустой seat схлопнут) пропускается", "  20 1001 deploy pts/0\n", ""},
		{"текстовый сеанс tty без места пропускается", "  21 1000 alice tty3\n", ""},
		{"ssh пропущен, локальный найден", "  15 1001 deploy - -\n   3 1000 alice seat0 tty2\n", "alice"},
		{"root не возвращается никогда", "   1    0 root seat0 tty1\n", ""},
		{"строка-заголовок (UID не число) пропускается", "SESSION UID USER SEAT TTY\n   3 1000 alice seat0 tty2\n", "alice"},
		// Greeter на экране входа держит сеанс на seat0 и отличается от человека
		// только UID: иначе LOGIN-триггеры срабатывали бы на «вход gdm».
		{"greeter дисплей-менеджера не возвращается", "  c1  120 gdm seat0 tty1\n", ""},
		{"greeter пропущен, вошедший человек найден", "  c1  120 gdm seat0 tty1\n   3 1000 alice seat0 tty2\n", "alice"},
		{"никто не вошёл", "", ""},
		{"короткая строка не паникует", "3 1000\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseLoginctl(tt.out); got != tt.want {
				t.Errorf("parseLoginctl(%q)=%q, want %q", tt.out, got, tt.want)
			}
		})
	}
}

// who — фолбэк без logind. Графический вход (":0") приоритетнее консоли ("tty1").
func TestParseWho(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want string
	}{
		{"графический вход", "alice   :0           2026-07-10 09:12 (:0)\n", "alice"},
		{"только текстовая консоль", "alice   tty1         2026-07-10 09:12\n", "alice"},
		{"графика приоритетнее консоли", "console  tty1         2026-07-10 08:00\nalice   :0           2026-07-10 09:12 (:0)\n", "alice"},
		{"root на tty1 пропущен", "root     tty1         2026-07-10 08:00\nalice   :0           2026-07-10 09:12 (:0)\n", "alice"},
		{"только root → пусто", "root     tty1         2026-07-10 08:00\n", ""},
		{"ssh (pts) не считается входом за машину", "deploy   pts/1        2026-07-10 09:15 (203.0.113.5)\n", ""},
		{"пустой вывод", "", ""},
		{"короткая строка не паникует", "alice\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseWho(tt.out); got != tt.want {
				t.Errorf("parseWho(%q)=%q, want %q", tt.out, got, tt.want)
			}
		})
	}
}

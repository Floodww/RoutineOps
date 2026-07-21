//go:build linux

package admin

import (
	"strings"
	"testing"
)

// Имя пользователя уходит в argv gpasswd/usermod — гейт обязан отсекать флаги,
// пробелы и метасимволы до запуска сабпроцесса.
func TestValidUsername(t *testing.T) {
	tests := []struct {
		name string
		user string
		want bool
	}{
		{"обычное имя", "alice", true},
		{"цифры и точки", "user.name42", true},
		{"подчёркивание", "_svc", true},
		{"дефис внутри", "some-user", true},
		{"начинается с цифры", "1user", true},
		{"ровно 32 символа", strings.Repeat("a", 32), true},
		{"пустое", "", false},
		{"33 символа", strings.Repeat("a", 33), false},
		{"начинается с дефиса (флаг!)", "-rf", false},
		{"пробел", "user name", false},
		{"перевод строки", "user\nroot", false},
		{"точка с запятой", "user;id", false},
		{"подстановка команды", "$(id)", false},
		{"слэш (путь)", "../etc/passwd", false},
		{"обратный слэш (домен)", `DOMAIN\user`, false},
		{"кириллица", "пользователь", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validUsername(tt.user); got != tt.want {
				t.Errorf("validUsername(%q)=%v, want %v", tt.user, got, tt.want)
			}
		})
	}
}

// Сеанс без места (seat="-") — ssh/cron: за машиной физически никого нет.
func TestParseLoginctl(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want string
	}{
		{
			name: "графический сеанс за seat0",
			out:  "   3 1000 alice seat0 tty2\n",
			want: "alice",
		},
		{
			name: "старый systemd без колонки TTY",
			out:  "   3 1000 alice seat0\n",
			want: "alice",
		},
		{
			name: "ssh-сеанс (seat='-') пропускается",
			out:  "  15 1001 deploy - -\n",
			want: "",
		},
		{
			// Реальный формат seatless-сеанса: колонка SEAT ПУСТА (пробелы, не
			// "-"), strings.Fields её схлопывает и в f[3] попадает TTY (pts/0).
			// Прежняя проверка `seat != "-"` принимала pts/0 за место и выдавала
			// удалённому ssh-юзеру права консольного — теперь prefix "seat" режет.
			name: "ssh с пустым SEAT (pts в f[3]) пропускается",
			out:  "  12 1000 alice        pts/0\n",
			want: "",
		},
		{
			name: "ssh с пустым SEAT пропущен, локальный за seat0 найден",
			out:  "  12 1000 bob          pts/1\n   3 1000 alice seat0 tty2\n",
			want: "alice",
		},
		{
			name: "ssh пропущен, локальный найден",
			out:  "  15 1001 deploy - -\n   3 1000 alice seat0 tty2\n",
			want: "alice",
		},
		{
			name: "root не возвращается никогда",
			out:  "   1    0 root seat0 tty1\n",
			want: "",
		},
		{
			name: "root пропущен, обычный пользователь найден",
			out:  "   1    0 root seat0 tty1\n   3 1000 alice seat0 tty2\n",
			want: "alice",
		},
		{
			name: "строка-заголовок (UID не число) пропускается",
			out:  "SESSION UID USER SEAT TTY\n   3 1000 alice seat0 tty2\n",
			want: "alice",
		},
		// Экран входа: greeter дисплей-менеджера держит НАСТОЯЩИЙ сеанс на seat0 и
		// от пользовательского в выводе list-sessions отличается только UID. Без
		// фильтра агент выдавал бы sudo учётке gdm/sddm/lightdm.
		{
			name: "greeter дисплей-менеджера не возвращается",
			out:  "  c1  120 gdm seat0 tty1\n",
			want: "",
		},
		{
			name: "greeter пропущен, вошедший человек найден",
			out:  "  c1  120 gdm seat0 tty1\n   3 1000 alice seat0 tty2\n",
			want: "alice",
		},
		{
			name: "системная учётка на месте не возвращается",
			out:  "  c2  999 sddm seat0 tty7\n",
			want: "",
		},
		{
			name: "пустой вывод (никто не вошёл)",
			out:  "",
			want: "",
		},
		{
			name: "короткая строка не паникует",
			out:  "3 1000\n",
			want: "",
		},
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
		{
			name: "графический вход",
			out:  "alice   :0           2026-07-10 09:12 (:0)\n",
			want: "alice",
		},
		{
			name: "только текстовая консоль",
			out:  "alice   tty1         2026-07-10 09:12\n",
			want: "alice",
		},
		{
			name: "графика приоритетнее консоли, даже если ниже в выводе",
			out:  "console  tty1         2026-07-10 08:00\nalice   :0           2026-07-10 09:12 (:0)\n",
			want: "alice",
		},
		{
			name: "root на tty1 пропущен, графический пользователь найден",
			out:  "root     tty1         2026-07-10 08:00\nalice   :0           2026-07-10 09:12 (:0)\n",
			want: "alice",
		},
		{
			name: "только root → пусто",
			out:  "root     tty1         2026-07-10 08:00\n",
			want: "",
		},
		{
			name: "ssh (pts) не считается входом за машину",
			out:  "deploy   pts/1        2026-07-10 09:15 (203.0.113.5)\n",
			want: "",
		},
		{
			name: "пустой вывод",
			out:  "",
			want: "",
		},
		{
			name: "короткая строка не паникует",
			out:  "alice\n",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseWho(tt.out); got != tt.want {
				t.Errorf("parseWho(%q)=%q, want %q", tt.out, got, tt.want)
			}
		})
	}
}

// hasGroup разбирает `id -nG`: имена групп через пробел, без частичных совпадений.
func TestHasGroup(t *testing.T) {
	tests := []struct {
		name  string
		out   string
		group string
		want  bool
	}{
		{"состоит в sudo", "alice adm sudo docker\n", "sudo", true},
		{"состоит в wheel", "alice wheel\n", "wheel", true},
		{"не состоит", "alice adm docker\n", "sudo", false},
		{"частичное совпадение не считается", "alice sudoers\n", "sudo", false},
		{"единственная группа", "sudo\n", "sudo", true},
		{"пустой вывод", "", "sudo", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasGroup(tt.out, tt.group); got != tt.want {
				t.Errorf("hasGroup(%q, %q)=%v, want %v", tt.out, tt.group, got, tt.want)
			}
		})
	}
}

// hasGroupLine разбирает /etc/group ("имя:x:gid:члены") — фолбэк, когда нет getent.
func TestHasGroupLine(t *testing.T) {
	const etcGroup = "root:x:0:\nsudo:x:27:alice\nwheel:x:998:\n"
	tests := []struct {
		name  string
		group string
		want  bool
	}{
		{"sudo есть", "sudo", true},
		{"wheel есть", "wheel", true},
		{"docker нет", "docker", false},
		{"имя члена группы не считается именем группы", "alice", false},
		{"пустое имя", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasGroupLine(etcGroup, tt.group); got != tt.want {
				t.Errorf("hasGroupLine(_, %q)=%v, want %v", tt.group, got, tt.want)
			}
		})
	}
}

// Grant/Revoke/IsAdmin обязаны отбить кривое имя ДО запуска сабпроцесса —
// проверяем на имени, которое иначе стало бы флагом gpasswd.
func TestPrivRejectsInvalidUsername(t *testing.T) {
	p := osPriv{}
	const bad = "-rf"

	if err := p.Grant(bad); err == nil {
		t.Error("Grant принял недопустимое имя")
	}
	if err := p.Revoke(bad); err == nil {
		t.Error("Revoke принял недопустимое имя")
	}
	if _, err := p.IsAdmin(bad); err == nil {
		t.Error("IsAdmin принял недопустимое имя")
	}
}

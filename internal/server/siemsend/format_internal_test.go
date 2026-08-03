package siemsend

import (
	"strings"
	"testing"
)

// В CEF значение поля не должно уметь закрыть запись и начать новую: перевод строки
// для syslog — граница сообщения, а `|` и `=` — разделители формата. Поля берутся из
// пользовательского ввода (имя скрипта, причина, e-mail), поэтому без экранирования
// тот, кто может назвать скрипт, пишет в SIEM произвольные события от имени сервера.
func TestCEFEscape(t *testing.T) {
	cases := []struct{ in, want string }{
		{`обычный текст`, `обычный текст`},
		{`a|b`, `a\|b`},
		{`k=v`, `k\=v`},
		{`c:\temp`, `c:\\temp`},
		{"строка\nвторая", "строка вторая"},
		{"строка\rвторая", "строка вторая"},
	}
	for _, c := range cases {
		if got := cefEscape(c.in); got != c.want {
			t.Errorf("cefEscape(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	// Инъекция целиком: попытка дописать «чужое» событие после своего.
	evil := "login\nCEF:0|RoutineOps|MDM|1.0|admin_granted|admin_granted|10|suser=attacker"
	got := cefEscape(evil)
	if strings.Contains(got, "\n") {
		t.Fatalf("перевод строки уцелел: %q", got)
	}
}

// Тот же класс инъекции для обычного syslog. Разделителей CEF там нет, но граница
// сообщения — по-прежнему перевод строки, и без него оператор с правом назвать
// скрипт дописывал бы в журнал ИБ собственные строки.
func TestSyslogFormatIsSingleLine(t *testing.T) {
	ev := &Event{
		TenantID:  "00000000-0000-4000-8000-000000000001",
		Action:    "run_script",
		UserEmail: "admin@example.com",
		Details:   map[string]any{"name": "плохой\nскрипт\r<13>1 подделка"},
	}
	line := formatSyslog(ev)
	if n := strings.Count(line, "\n"); n != 1 || !strings.HasSuffix(line, "\n") {
		t.Fatalf("сообщение syslog не однострочное: %q", line)
	}
	if strings.Contains(line, "\r") {
		t.Fatalf("возврат каретки уцелел: %q", line)
	}
}

// Разбор адреса приёмника: порт по умолчанию, схема по умолчанию, адрес без схемы.
func TestParseSyslogAddr(t *testing.T) {
	cases := []struct{ in, wantNet, wantAddr string }{
		{"udp://192.0.2.10:514", "udp", "192.0.2.10:514"},
		{"tcp://192.0.2.10:1514", "tcp", "192.0.2.10:1514"},
		{"udp://collector.test.local", "udp", "collector.test.local:514"},
	}
	for _, c := range cases {
		gotNet, gotAddr, err := parseSyslogAddr(c.in)
		if err != nil {
			t.Errorf("parseSyslogAddr(%q): %v", c.in, err)
			continue
		}
		if gotNet != c.wantNet || gotAddr != c.wantAddr {
			t.Errorf("parseSyslogAddr(%q) = %q/%q; ожидалось %q/%q", c.in, gotNet, gotAddr, c.wantNet, c.wantAddr)
		}
	}
	if _, _, err := parseSyslogAddr("udp://"); err == nil {
		t.Error("адрес без хоста принят — доставка ушла бы в никуда")
	}
}

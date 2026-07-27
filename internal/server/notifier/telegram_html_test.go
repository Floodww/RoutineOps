package notifier

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Разметка живёт в формат-строке и должна доезжать живой, а всё подставляемое —
// экранированным. Неэкранированный '<' в hostname/details ломает разбор на стороне
// Bot API, и алерт не доставляется ВООБЩЕ: тот, про кого событие, глушил бы его
// одним символом в подконтрольном ему поле.
func TestHTMLfEscapesArgsNotMarkup(t *testing.T) {
	got := HTMLf("🚨 <b>Алерт</b>\nУстройство: <code>%s</code>\nДетали: %s",
		"<b>evil</b>", "5 & 6 < 7")

	if !strings.Contains(got, "<b>Алерт</b>") || !strings.Contains(got, "<code>") {
		t.Fatalf("разметка формат-строки не должна экранироваться: %q", got)
	}
	if strings.Contains(got, "<b>evil</b>") {
		t.Fatalf("разметка из аргумента прошла неэкранированной: %q", got)
	}
	if !strings.Contains(got, "&lt;b&gt;evil&lt;/b&gt;") || !strings.Contains(got, "5 &amp; 6 &lt; 7") {
		t.Fatalf("аргумент экранирован не полностью: %q", got)
	}
}

// Числа/bool проходят как есть: экранирование через fmt.Sprint сломало бы %d.
func TestHTMLfPassesNonStringsThrough(t *testing.T) {
	if got := HTMLf("устройств: %d", 42); got != "устройств: 42" {
		t.Fatalf("got %q, want %q", got, "устройств: 42")
	}
}

// Отказ Bot API — это НЕ отправленное сообщение. До проверки статуса send()
// возвращал nil на любой ответ телеги: 400 на битой разметке, 403 от
// заблокировавшего бота админа, 429 rate limit — алерт терялся молча.
func TestSendReportsNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: can't parse entities"}`))
	}))
	defer srv.Close()

	b := New("test-token", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.baseURL = srv.URL

	err := b.send(1, "текст")
	if err == nil {
		t.Fatal("отказ Bot API принят за успешную отправку")
	}
	if !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "can't parse entities") {
		t.Fatalf("ошибка не несёт причину отказа: %v", err)
	}
}

// Успешный ответ остаётся успехом — проверка статуса не должна ломать рабочий путь.
func TestSendAcceptsOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	b := New("test-token", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.baseURL = srv.URL

	if err := b.send(1, "текст"); err != nil {
		t.Fatalf("send: %v", err)
	}
}

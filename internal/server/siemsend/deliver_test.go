package siemsend

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Подпись вебхука. Адрес приёмника не секрет — он лежит в конфиге и в журнале
// доставки, — поэтому без подписи приёмник ИБ не может отличить наши события от
// чужого POST'а на тот же URL, то есть кто угодно наполняет журнал безопасности
// произвольными записями «от сервера».
func TestWebhookSignature(t *testing.T) {
	const secret = "shared-secret-приёмника"

	var (
		gotSig  string
		gotTS   string
		gotBody []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-RoutineOps-Signature")
		gotTS = r.Header.Get("X-RoutineOps-Timestamp")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ev := &Event{TenantID: "t", Action: "login", UserEmail: "admin@example.com"}
	if err := Deliver(context.Background(), typeWebhook, srv.URL, secret, ev); err != nil {
		t.Fatalf("доставка: %v", err)
	}

	if !strings.HasPrefix(gotSig, "sha256=") {
		t.Fatalf("подписи нет либо она в неизвестном формате: %q", gotSig)
	}
	// 🔴 Метка времени входит в подпись. Без неё перехваченный запрос переигрывается
	// бесконечно и подпись остаётся валидной — то есть подпись доказывает только
	// «это когда-то отправляли мы», а не «отправили сейчас».
	if gotTS == "" {
		t.Fatal("метки времени нет — подпись не защищает от переигрывания")
	}
	if ts, err := strconv.ParseInt(gotTS, 10, 64); err != nil || time.Since(time.Unix(ts, 0)) > time.Minute {
		t.Fatalf("метка времени неправдоподобна: %q", gotTS)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(gotTS))
	mac.Write([]byte("."))
	mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("подпись не сходится:\n  получена %s\n  ожидалась %s", gotSig, want)
	}
}

// Без секрета подпись не ставится вовсе — заголовка нет, а не пустой.
func TestWebhookWithoutSecretHasNoSignature(t *testing.T) {
	var hasSig bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hasSig = r.Header["X-Routineops-Signature"]
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := Deliver(context.Background(), typeWebhook, srv.URL, "", &Event{Action: "login"}); err != nil {
		t.Fatalf("доставка: %v", err)
	}
	if hasSig {
		t.Fatal("подпись поставлена без секрета — приёмник будет проверять её неизвестно чем")
	}
}

// Ошибка приёмника обязана быть ОШИБКОЙ, а не тихим успехом: на этом и держится
// ретрай очереди и счётчик в панели.
func TestWebhookErrorStatusIsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if err := Deliver(context.Background(), typeWebhook, srv.URL, "", &Event{Action: "login"}); err == nil {
		t.Fatal("приёмник ответил 500, а доставка объявлена успешной")
	}
}

// Неизвестный тип приёмника — отказ, а не молчаливый пропуск. Молчаливый пропуск
// означал бы, что события никуда не едут, а панель показывает «доставлено».
func TestUnknownTypeIsError(t *testing.T) {
	if err := Deliver(context.Background(), "carrier-pigeon", "udp://192.0.2.1:514", "", &Event{}); err == nil {
		t.Fatal("неизвестный тип принят")
	}
}

package notifier

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/alerting"
	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/testutil"
)

var sharedDSN string

func TestMain(m *testing.M) {
	dsn, cleanup := testutil.NewDSNWithCleanup()
	sharedDSN = dsn
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func newDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Connect(context.Background(), sharedDSN)
	if err != nil {
		t.Fatalf("storage.Connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// captureServer — фейковый Telegram Bot API. Записывает тела всех sendMessage;
// для getUpdates один раз отдаёт заранее заданный апдейт, затем пустой список.
type captureServer struct {
	*httptest.Server
	mu          sync.Mutex
	sent        []string
	updatesOnce string // тело result для первого getUpdates
	served      bool
}

func newCaptureServer(t *testing.T) *captureServer {
	t.Helper()
	cs := &captureServer{}
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/getUpdates") {
			cs.mu.Lock()
			body := `{"ok":true,"result":[]}`
			if cs.updatesOnce != "" && !cs.served {
				body = fmt.Sprintf(`{"ok":true,"result":[%s]}`, cs.updatesOnce)
				cs.served = true
			}
			cs.mu.Unlock()
			_, _ = w.Write([]byte(body))
			return
		}
		body, _ := io.ReadAll(r.Body)
		cs.mu.Lock()
		cs.sent = append(cs.sent, string(body))
		cs.mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(cs.Close)
	return cs
}

func (cs *captureServer) messages() []string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return append([]string(nil), cs.sent...)
}

func newBot(db *storage.DB, baseURL string) *Bot {
	b := New("test-token", db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.baseURL = baseURL
	return b
}

func uniqEmail(prefix string) string {
	return fmt.Sprintf("%s-%d@test.local", prefix, time.Now().UnixNano())
}

// Валидный токен привязки: chat_id сохраняется, токен инвалидируется, юзер получает подтверждение.
func TestHandleStart_ValidToken_LinksAccount(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	cs := newCaptureServer(t)
	bot := newBot(db, cs.URL)

	user, err := db.CreateUser(ctx, "Admin", uniqEmail("link"), "hash", "it_admin")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	token := "tok-" + fmt.Sprintf("%d", time.Now().UnixNano())
	if err := db.SetUserLinkToken(ctx, user.ID, token); err != nil {
		t.Fatalf("SetUserLinkToken: %v", err)
	}

	const chatID = int64(424242)
	bot.handleStart(ctx, chatID, token)

	// chat_id должен сохраниться (юзер it_admin → попадает в список рассылки).
	ids, err := db.GetITAdminsWithTelegramChatID(ctx)
	if err != nil {
		t.Fatalf("GetITAdminsWithTelegramChatID: %v", err)
	}
	if !contains(ids, "424242") {
		t.Errorf("chat_id 424242 не сохранён, список = %v", ids)
	}

	// Токен должен быть инвалидирован — повторный lookup не находит юзера.
	again, err := db.GetUserByLinkToken(ctx, token)
	if err != nil {
		t.Fatalf("GetUserByLinkToken: %v", err)
	}
	if again != nil {
		t.Error("токен не инвалидирован после успешной привязки")
	}

	// Юзеру отправлено подтверждение.
	msgs := cs.messages()
	if len(msgs) == 0 {
		t.Fatal("ни одного сообщения не отправлено")
	}
	if !containsSub(msgs, "успешно подключён") {
		t.Errorf("нет подтверждающего сообщения, отправлено: %v", msgs)
	}
}

// Неизвестный токен: chat_id не сохраняется, юзеру уходит сообщение об ошибке.
func TestHandleStart_UnknownToken_NoLink(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	cs := newCaptureServer(t)
	bot := newBot(db, cs.URL)

	before, err := db.GetITAdminsWithTelegramChatID(ctx)
	if err != nil {
		t.Fatalf("GetITAdminsWithTelegramChatID: %v", err)
	}

	bot.handleStart(ctx, 999001, "does-not-exist-"+fmt.Sprintf("%d", time.Now().UnixNano()))

	after, err := db.GetITAdminsWithTelegramChatID(ctx)
	if err != nil {
		t.Fatalf("GetITAdminsWithTelegramChatID: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("количество привязанных админов изменилось: было %d, стало %d", len(before), len(after))
	}
	if contains(after, "999001") {
		t.Error("chat_id 999001 сохранён для несуществующего токена")
	}

	msgs := cs.messages()
	if !containsSub(msgs, "Токен не найден") {
		t.Errorf("нет сообщения об ошибке токена, отправлено: %v", msgs)
	}
}

// NotifyITAdmins рассылает сообщение всем привязанным IT-админам.
func TestNotifyITAdmins_SendsToLinkedAdmins(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	cs := newCaptureServer(t)
	bot := newBot(db, cs.URL)

	user, err := db.CreateUser(ctx, "Admin", uniqEmail("notify"), "hash", "it_admin")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := db.SetUserTelegramChatID(ctx, user.ID, "777111"); err != nil {
		t.Fatalf("SetUserTelegramChatID: %v", err)
	}

	bot.NotifyITAdmins(ctx, "тревога: сработал монитор ПО")

	msgs := cs.messages()
	if !containsSub(msgs, "тревога: сработал монитор ПО") {
		t.Errorf("текст уведомления не отправлен, сообщения: %v", msgs)
	}
	if !containsSub(msgs, "777111") {
		t.Errorf("сообщение не адресовано chat_id 777111, сообщения: %v", msgs)
	}
}

// NotifyAlert уважает порог доставки каждого получателя (миграция 041): админ с
// порогом critical не получает high, админ с порогом low получает всё.
//
// Проверяются оба направления одним прогоном намеренно: тест «отфильтрованный не
// получил» в одиночку зелёный и при полностью сломанной рассылке.
func TestNotifyAlert_RespectsPerRecipientThreshold(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	cs := newCaptureServer(t)
	bot := newBot(db, cs.URL)

	quiet, err := db.CreateUser(ctx, "Quiet Admin", uniqEmail("quiet"), "hash", "it_admin")
	if err != nil {
		t.Fatalf("CreateUser quiet: %v", err)
	}
	loud, err := db.CreateUser(ctx, "Loud Admin", uniqEmail("loud"), "hash", "it_admin")
	if err != nil {
		t.Fatalf("CreateUser loud: %v", err)
	}
	if err := db.SetUserTelegramChatID(ctx, quiet.ID, "777222"); err != nil {
		t.Fatalf("chat id quiet: %v", err)
	}
	if err := db.SetUserTelegramChatID(ctx, loud.ID, "777333"); err != nil {
		t.Fatalf("chat id loud: %v", err)
	}
	if err := db.SetUserNotifyMinSeverity(ctx, quiet.ID, string(alerting.SeverityCritical)); err != nil {
		t.Fatalf("порог quiet: %v", err)
	}
	if err := db.SetUserNotifyMinSeverity(ctx, loud.ID, string(alerting.SeverityLow)); err != nil {
		t.Fatalf("порог loud: %v", err)
	}

	bot.NotifyAlert(ctx, alerting.SeverityHigh, "запрещённое ПО на ноутбуке")

	msgs := cs.messages()
	if !containsSub(msgs, "777333") {
		t.Errorf("админ с порогом low не получил high-алерт, сообщения: %v", msgs)
	}
	if containsSub(msgs, "777222") {
		t.Errorf("админ с порогом critical получил high-алерт, сообщения: %v", msgs)
	}

	// Тот же получатель обязан получить critical — иначе предыдущая проверка
	// доказывала бы лишь то, что рассылка не работает вовсе.
	bot.NotifyAlert(ctx, alerting.SeverityCritical, "попытка обхода блокировки")
	if !containsSub(cs.messages(), "777222") {
		t.Errorf("админ с порогом critical не получил critical-алерт, сообщения: %v", cs.messages())
	}
}

// StartPolling должен забрать апдейт "/start TOKEN", выполнить привязку и завершиться
// по отмене контекста.
func TestStartPolling_DispatchesStartCommand(t *testing.T) {
	db := newDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cs := newCaptureServer(t)
	bot := newBot(db, cs.URL)

	user, err := db.CreateUser(ctx, "Admin", uniqEmail("poll"), "hash", "it_admin")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	token := "polltok-" + fmt.Sprintf("%d", time.Now().UnixNano())
	if err := db.SetUserLinkToken(ctx, user.ID, token); err != nil {
		t.Fatalf("SetUserLinkToken: %v", err)
	}
	// chat_id уникален на прогон: общая БД переживает -count, и устаревший chat_id
	// от прошлого прогона не должен ложно сигналить «привязано».
	chatID := time.Now().UnixNano() % 1_000_000_000
	cs.updatesOnce = fmt.Sprintf(`{"update_id":1,"message":{"chat":{"id":%d},"text":"/start %s"}}`, chatID, token)

	done := make(chan struct{})
	go func() { bot.StartPolling(ctx); close(done) }()

	// Финальный сигнал успешной привязки — подтверждающее сообщение (отправляется
	// последним шагом handleStart, уже после записей в БД).
	linked := false
	for i := 0; i < 200; i++ {
		if containsSub(cs.messages(), "успешно подключён") {
			linked = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	if !linked {
		t.Fatalf("StartPolling не выполнил привязку, отправлено: %v", cs.messages())
	}
	// chat_id сохранён (читаем фоновым ctx — основной уже отменён).
	ids, err := db.GetITAdminsWithTelegramChatID(context.Background())
	if err != nil {
		t.Fatalf("GetITAdminsWithTelegramChatID: %v", err)
	}
	if !contains(ids, fmt.Sprintf("%d", chatID)) {
		t.Errorf("chat_id %d не сохранён, список = %v", chatID, ids)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func containsSub(xs []string, sub string) bool {
	for _, x := range xs {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}

// Username не должен ходить в сеть: он зовётся из HTTP-хендлера, и поход в Telegram
// на каждый запрос сделал бы страницу заложником его доступности.
func TestUsernameDoesNotHitNetwork(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"ok":true,"result":{"username":"AcmeRoutineOps_bot"}}`))
	}))
	defer srv.Close()

	b := New("tok", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.baseURL = srv.URL

	if got := b.Username(context.Background()); got != "" {
		t.Errorf("до резолва Username = %q, ожидали пусто", got)
	}
	if calls != 0 {
		t.Errorf("Username сходил в сеть %d раз", calls)
	}

	if err := b.resolveUsername(context.Background()); err != nil {
		t.Fatalf("resolveUsername: %v", err)
	}
	if got := b.Username(context.Background()); got != "AcmeRoutineOps_bot" {
		t.Errorf("после резолва Username = %q", got)
	}
	if calls != 1 {
		t.Errorf("getMe вызван %d раз, ожидали 1", calls)
	}
}

// Пустой bot_username лучше, чем ссылка на чужого бота: getMe с ok=false не должен
// записывать мусор в кэш.
func TestResolveUsernameRejectsBadResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false}`))
	}))
	defer srv.Close()

	b := New("tok", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.baseURL = srv.URL

	if err := b.resolveUsername(context.Background()); err == nil {
		t.Fatal("ожидали ошибку на ok=false")
	}
	if got := b.Username(context.Background()); got != "" {
		t.Errorf("кэш загрязнён: %q", got)
	}
}

// M3-регресс: redact вырезает bot-токен из строки ошибки — иначе *url.Error с токеном
// в URL-path утекал бы в JSON-stdout при любой сетевой ошибке к Bot API.
func TestBotRedactStripsToken(t *testing.T) {
	b := &Bot{token: "123456:AAH-live-secret-token"}
	err := fmt.Errorf(`Get "https://api.telegram.org/bot123456:AAH-live-secret-token/getMe": dial tcp: i/o timeout`)
	got := b.redact(err)
	if strings.Contains(got, "AAH-live-secret-token") {
		t.Fatalf("токен не вырезан: %s", got)
	}
	if !strings.Contains(got, "***") {
		t.Fatalf("нет маркера редакции ***: %s", got)
	}
	if b.redact(nil) != "" {
		t.Fatal("redact(nil) должен быть пустым")
	}
}

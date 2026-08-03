package recipient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func signed(t *testing.T, priv ed25519.PrivateKey, epoch int64, rec, fpr string) Signed {
	t.Helper()
	s := Signed{Epoch: epoch, Recipient: rec, FPR: fpr}
	s.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Canon(s)))
	return s
}

func TestVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	good := signed(t, priv, 1, "age1abc", "fpr-1")

	if err := Verify(good, pub); err != nil {
		t.Fatalf("валидная запись отклонена: %v", err)
	}
	if err := Verify(good, other); err == nil {
		t.Error("запись принята чужим релизным ключом")
	}

	// Подстановка другого получателя под ту же подпись — главная атака, ради
	// которой канон покрывает все три поля.
	swapped := good
	swapped.Recipient = "age1attacker"
	if err := Verify(swapped, pub); err == nil {
		t.Error("подменённый получатель принят под старой подписью")
	}
	// Перестановка epoch тем же порядком: обход anti-rollback, если бы подпись
	// покрывала только получателя.
	relabeled := good
	relabeled.Epoch = 99
	if err := Verify(relabeled, pub); err == nil {
		t.Error("переставленный epoch принят под старой подписью")
	}

	unsigned := good
	unsigned.Signature = ""
	if err := Verify(unsigned, pub); err == nil {
		t.Error("запись без подписи принята — схема обязана быть fail-closed")
	}
	if err := Verify(good, nil); err == nil {
		t.Error("проверка без релизного ключа не должна проходить")
	}
	zeroEpoch := signed(t, priv, 0, "age1abc", "fpr-1")
	if err := Verify(zeroEpoch, pub); err == nil {
		t.Error("epoch=0 принят — тогда любой откат к нулю был бы валиден")
	}
}

func TestChoose(t *testing.T) {
	cached := &Signed{Epoch: 5, Recipient: "age1old"}
	newer := &Signed{Epoch: 6, Recipient: "age1new"}
	older := &Signed{Epoch: 4, Recipient: "age1older"}

	if got, save, err := Choose(newer, cached); err != nil || got != newer || !save {
		t.Errorf("новее: got=%v save=%v err=%v", got, save, err)
	}
	// Откат обязан быть ошибкой, а не молчаливым «оставим кеш»: оператору нужно
	// увидеть, что сервер отдаёт не то.
	got, save, err := Choose(older, cached)
	if err == nil {
		t.Error("откат epoch принят без ошибки")
	}
	if got != cached || save {
		t.Errorf("при откате действующей осталась не кешированная запись: got=%v save=%v", got, save)
	}
	// Тот же epoch — кеш не переписываем.
	if got, save, err := Choose(&Signed{Epoch: 5, Recipient: "age1other"}, cached); err != nil || got != cached || save {
		t.Errorf("равный epoch: got=%v save=%v err=%v", got, save, err)
	}
	// Сервер недоступен, кеш есть — работаем по кешу.
	if got, save, err := Choose(nil, cached); err != nil || got != cached || save {
		t.Errorf("без сети: got=%v save=%v err=%v", got, save, err)
	}
	// Ничего нет — не ошибка: парк до первой публикации живёт на вшитом пине.
	if got, _, err := Choose(nil, nil); err != nil || got != nil {
		t.Errorf("пусто: got=%v err=%v", got, err)
	}
}

func TestFetch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	want := signed(t, priv, 3, "age1srv", "fpr-3")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != Path {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	got, err := Fetch(context.Background(), srv.Client(), srv.URL+Path)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got == nil || got.Epoch != 3 || got.Recipient != "age1srv" {
		t.Fatalf("получено %+v", got)
	}
	if err := Verify(*got, pub); err != nil {
		t.Fatalf("запись с сервера не проходит проверку: %v", err)
	}

	// 404 — «ещё не публиковали», это не ошибка: иначе включение схемы ломало бы
	// уже раскатанный парк.
	none, err := Fetch(context.Background(), srv.Client(), srv.URL+"/nope")
	if err != nil || none != nil {
		t.Fatalf("404 должен давать (nil, nil), получено (%v, %v)", none, err)
	}
}

func TestEndpointFrom(t *testing.T) {
	got, err := EndpointFrom("https://host:8443/api/v1/agent/version?os=darwin&arch=arm64")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://host:8443"+Path {
		t.Errorf("endpoint = %q", got)
	}
	if _, err := EndpointFrom(""); err == nil {
		t.Error("пустой update-url должен давать ошибку, а не молча несуществующий адрес")
	}
}

func TestLoadStore(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "state", "recipient.json")

	if got, err := Load(path, pub); err != nil || got != nil {
		t.Fatalf("отсутствующий кеш: got=%v err=%v", got, err)
	}

	rec := signed(t, priv, 7, "age1cached", "fpr-7")
	if err := Store(path, rec); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := Load(path, pub)
	if err != nil || got == nil || got.Epoch != 7 {
		t.Fatalf("Load: got=%+v err=%v", got, err)
	}

	// Правка кеша на диске обязана ловиться подписью: иначе локальная подмена
	// получателя была бы тише серверной.
	tampered := rec
	tampered.Recipient = "age1attacker"
	data, _ := json.Marshal(tampered)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, pub); err == nil {
		t.Error("подменённый кеш принят")
	}
}

func TestResolve(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cache := filepath.Join(t.TempDir(), "recipient.json")
	rec := signed(t, priv, 2, "age1live", "fpr-2")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(rec)
	}))
	defer srv.Close()

	active, err := Resolve(context.Background(), srv.Client(), srv.URL+Path, cache, pub)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if active == nil || active.Recipient != "age1live" {
		t.Fatalf("действующая запись = %+v", active)
	}
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("кеш не сохранён: %v", err)
	}

	// Сервер лёг — действующей остаётся кешированная запись, но проблема
	// возвращается вместе с ней (деградация обязана быть видна в журнале).
	srv.Close()
	active, err = Resolve(context.Background(), srv.Client(), srv.URL+Path, cache, pub)
	if active == nil || active.Recipient != "age1live" {
		t.Fatalf("без сети действующая запись = %+v", active)
	}
	if err == nil {
		t.Error("недоступный сервер не отражён в возвращённой проблеме")
	}
}

// Сервер отдаёт валидную, но СТАРУЮ запись поверх более свежего кеша: Resolve
// обязан оставить кеш и сообщить об откате.
func TestResolve_RollbackRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cache := filepath.Join(t.TempDir(), "recipient.json")
	if err := Store(cache, signed(t, priv, 9, "age1current", "fpr-9")); err != nil {
		t.Fatal(err)
	}
	old := signed(t, priv, 3, "age1ancient", "fpr-3")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(old)
	}))
	defer srv.Close()

	active, err := Resolve(context.Background(), srv.Client(), srv.URL+Path, cache, pub)
	if active == nil || active.Recipient != "age1current" {
		t.Fatalf("после отката действующая запись = %+v", active)
	}
	if err == nil || !strings.Contains(err.Error(), "откат") {
		t.Errorf("откат не назван в проблеме: %v", err)
	}
}

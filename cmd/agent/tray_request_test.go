//go:build windows || (darwin && cgo)

package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Кнопка «Запросить админ-права» обязана сообщать сотруднику то, что ПРОВЕРЕНО.
// До 04.08 она показывала галочку сразу после записи файла — то есть подтверждала
// собственное действие, а не доставку. При отказе на сервере (RLS отбивала вставку,
// служба ретраила вечно) сотрудник видел успех и ждал прав, которых никто не запросил.

func TestWaitRequestPickedUpDetectsServicePickup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin-request.json")
	if err := os.WriteFile(path, []byte(`{"reason":"тест"}`), 0o644); err != nil {
		t.Fatalf("подготовка заявки: %v", err)
	}

	// Служба забирает файл через мгновение — ровно так это и выглядит в поле.
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = os.Remove(path)
	}()

	start := time.Now()
	if !waitRequestPickedUp(path, 5*time.Second) {
		t.Fatal("исчезновение файла не распознано как «служба забрала заявку»")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("ожидание затянулось на %v — трей не должен висеть до таймаута после успеха", time.Since(start))
	}
}

// Служба остановлена (или не видит каталог): файл лежит, и трей обязан сказать об
// этом, а не молчать. Молчание здесь — это сотрудник, ждущий прав впустую.
func TestWaitRequestPickedUpTimesOutWhenServiceIsDown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin-request.json")
	if err := os.WriteFile(path, []byte(`{"reason":"тест"}`), 0o644); err != nil {
		t.Fatalf("подготовка заявки: %v", err)
	}

	if waitRequestPickedUp(path, 300*time.Millisecond) {
		t.Fatal("лежащий на месте файл принят за забранную заявку")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("ожидание не должно трогать файл: %v", err)
	}
}

// recordingMenuItem запоминает последовательность подписей кнопки.
type recordingMenuItem struct {
	mu     sync.Mutex
	titles []string
}

func (m *recordingMenuItem) SetTitle(s string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.titles = append(m.titles, s)
}

func (m *recordingMenuItem) snapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.titles...)
}

// Неписучий каталог: заявку положить некуда, и кнопка обязана сказать это СРАЗУ, а не
// делать вид, что отправила. На Windows именно так выглядит сломанный ACL общего
// каталога состояния — трей работает от пользователя, каталог держит SYSTEM.
func TestSubmitAdminRequestReportsWriteFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatalf("подготовка каталога: %v", err)
	}
	if f, err := os.CreateTemp(dir, "probe"); err == nil {
		f.Close()
		t.Skip("каталог всё-таки доступен на запись (запуск от root?) — проверять нечего")
	}

	mi := &recordingMenuItem{}
	submitAdminRequest(mi, filepath.Join(dir, "admin-request.json"), time.Second)

	got := mi.snapshot()
	if len(got) != 1 || got[0] != "Не удалось отправить — повторить" {
		t.Fatalf("подписи кнопки: %v — сотруднику должно быть сказано об отказе, и только он", got)
	}
}

// Счастливый путь: служба забрала файл — кнопка подтверждает то, что действительно
// произошло, и не раньше.
func TestSubmitAdminRequestConfirmsOnlyAfterPickup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin-request.json")
	mi := &recordingMenuItem{}

	submitAdminRequest(mi, path, 3*time.Second)

	// Сразу после нажатия — только «Отправляю…»: подтверждения ещё нет и быть не может.
	if got := mi.snapshot(); len(got) != 1 || got[0] != "Отправляю…" {
		t.Fatalf("сразу после нажатия подписи %v — подтверждение выдано до доставки", got)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("заявка не положена: %v", err)
	}

	// Служба забирает заявку.
	if err := os.Remove(path); err != nil {
		t.Fatalf("снятие заявки: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		got := mi.snapshot()
		if len(got) >= 2 {
			if got[1] != "Заявка принята агентом ✓" {
				t.Fatalf("после того как служба забрала заявку, кнопка сказала %q", got[1])
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("подтверждение не появилось: %v", got)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Служба стоит: файл лежит, и кнопка обязана сказать об этом, а не показать галочку.
func TestSubmitAdminRequestReportsServiceDown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin-request.json")
	mi := &recordingMenuItem{}

	submitAdminRequest(mi, path, 300*time.Millisecond)

	deadline := time.Now().Add(3 * time.Second)
	for {
		got := mi.snapshot()
		if len(got) >= 2 {
			if got[1] != "Агент не забрал заявку — повторить" {
				t.Fatalf("служба не забрала заявку, а кнопка сказала %q", got[1])
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("трей промолчал о том, что заявку никто не забрал: %v", got)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

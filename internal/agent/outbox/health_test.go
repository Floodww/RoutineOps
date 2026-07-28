package outbox

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// Смерть очереди обязана быть ВИДНА. Без этого признака отказ ввода-вывода
// уходил только в локальный лог, а сервер видел живое устройство, у которого
// просто ничего не происходит: outbox и есть канал доставки отчётов, статусов
// лока и security-событий (полевой баг 2.5.1 на Windows — пустой DACL на
// каталоге очереди).
func TestUnavailable_SetOnWriteFailureClearedOnSuccess(t *testing.T) {
	dir := t.TempDir()
	q, err := New(dir, 10, time.Hour, quietLogger(), func(context.Context, string, []byte) error { return nil })
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if down, _ := q.Unavailable(); down {
		t.Fatal("исправная очередь не должна репортить деградацию")
	}

	// Отбираем у процесса возможность писать в каталог очереди: на unix — права,
	// и это ближайший аналог того, что случилось в поле на Windows (SYSTEM
	// потерял доступ к собственному каталогу).
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("не удалось снять право записи с каталога: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	if err := q.Enqueue(KindTask, []byte("payload")); err == nil {
		t.Skip("запись прошла несмотря на снятые права (root?) — проверять нечего")
	}
	down, detail := q.Unavailable()
	if !down {
		t.Fatal("после отказа записи очередь обязана репортить недоступность")
	}
	if detail == "" {
		t.Error("причина пустая — оператору нечего показать")
	}
	if !strings.Contains(detail, "outbox") {
		t.Errorf("причина не опознаётся как отказ очереди: %q", detail)
	}

	// Возврат прав: признак должен сняться сам, без вмешательства.
	os.Chmod(dir, 0o700)
	if err := q.Enqueue(KindTask, []byte("payload")); err != nil {
		t.Fatalf("после возврата прав запись должна проходить: %v", err)
	}
	if down, _ := q.Unavailable(); down {
		t.Error("признак деградации не снялся после успешной записи — панель залипнет в аварии")
	}
}

// Признак снимается и фоновым сливом, а не только следующей записью: очередь
// может простаивать часами, а панель обязана вернуться в норму сама.
func TestUnavailable_ClearedByFlush(t *testing.T) {
	dir := t.TempDir()
	q, err := New(dir, 10, time.Hour, quietLogger(), func(context.Context, string, []byte) error { return nil })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	msg := "outbox запись: искусственный отказ"
	q.ioErr.Store(&msg)
	if down, _ := q.Unavailable(); !down {
		t.Fatal("подготовка: признак должен стоять")
	}

	q.FlushOnce(context.Background())

	if down, detail := q.Unavailable(); down {
		t.Errorf("успешный слив обязан снять признак, осталось: %q", detail)
	}
}

// Отказ ЧТЕНИЯ каталога тоже деградация: именно эта строка и была в полевом
// логе каждые 30 секунд.
func TestUnavailable_SetOnListFailure(t *testing.T) {
	dir := t.TempDir()
	q, err := New(dir, 10, time.Hour, quietLogger(), func(context.Context, string, []byte) error { return nil })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Каталог очереди исчез — list() отказывает.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("подготовка: %v", err)
	}

	q.FlushOnce(context.Background())

	down, detail := q.Unavailable()
	if !down {
		t.Fatal("отказ чтения очереди обязан репортиться как недоступность")
	}
	if !strings.Contains(detail, "чтение очереди") {
		t.Errorf("причина не указывает на чтение: %q", detail)
	}
	_ = filepath.Join(dir, "x")
}

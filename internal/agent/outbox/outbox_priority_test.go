package outbox

import (
	"sync"
	"testing"
	"time"
)

// #1: под флудом самовосстанавливающихся script-результатов единственный
// ИБ-алерт (loss-sensitive, серверной компенсации нет) НЕ должен вытесняться —
// evictable-виды (script/task) жертвуются первыми.
func TestEnforceLimit_ProtectsLossSensitiveKinds(t *testing.T) {
	dir := t.TempDir()
	q, err := New(dir, 2, time.Hour, discardLog(), nil) // max=2; Run не запускаем
	if err != nil {
		t.Fatal(err)
	}
	// Самый старый в очереди — security-алерт, затем флуд script-результатов.
	if err := q.Enqueue(KindSecurity, []byte("forbidden-software")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if err := q.Enqueue(KindScript, []byte("cron output")); err != nil {
			t.Fatal(err)
		}
	}

	files, err := q.list()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("после enforceLimit ожидалось 2 записи (max), got %d", len(files))
	}
	hasSecurity := false
	for _, f := range files {
		if fileKind(f) == KindSecurity {
			hasSecurity = true
		}
	}
	if !hasSecurity {
		t.Fatal("security-алерт вытеснен флудом script — приоритет вытеснения не сработал (#1)")
	}
}

// Когда вытеснять нечего кроме protected — вытесняем их (иначе очередь не
// соблюдала бы max), но самые новые остаются.
func TestEnforceLimit_AllProtected_DropsOldest(t *testing.T) {
	dir := t.TempDir()
	q, err := New(dir, 2, time.Hour, discardLog(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := q.Enqueue(KindLock, []byte("lock report")); err != nil {
			t.Fatal(err)
		}
	}
	if got := q.Len(); got != 2 {
		t.Fatalf("ожидалось соблюдение max=2 даже для protected-видов, got %d", got)
	}
}

// Очередь забита protected-видами: свежая evictable-запись НЕ вытесняет их и не
// остаётся сама — Enqueue обязан вернуть ошибку (вызывающий уходит в фолбэк), а
// не молча удалить только что записанный файл и отрапортовать durable-успех.
func TestEnqueue_EvictableIntoProtectedFullQueue_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	q, err := New(dir, 2, time.Hour, discardLog(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := q.Enqueue(KindSecurity, []byte("alert")); err != nil {
			t.Fatal(err)
		}
	}

	if err := q.Enqueue(KindTask, []byte("task result")); err == nil {
		t.Fatal("Enqueue вернул nil, хотя запись вытеснена — вызывающий не уйдёт в фолбэк, результат не существует нигде")
	}
	files, err := q.list()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("ожидалось 2 записи (protected целы, свежая удалена), got %d", len(files))
	}
	for _, f := range files {
		if fileKind(f) != KindSecurity {
			t.Fatalf("protected-запись вытеснена свежей evictable: %v", files)
		}
	}
}

func TestFileKind(t *testing.T) {
	cases := map[string]string{
		"0000000000000000001-000000000001-security.json": KindSecurity,
		"0000000000000000002-000000000002-script.json":   KindScript,
		"0000000000000000003-000000000003-lock.json":     KindLock,
		"garbage.json": "",
	}
	for name, want := range cases {
		if got := fileKind(name); got != want {
			t.Errorf("fileKind(%q)=%q, want %q", name, got, want)
		}
	}
}

// №4.3: enforceLimit вне q.mu защищал только запись СВОЕГО вызова (исключение
// f == newName) — свежий файл ПАРАЛЛЕЛЬНОГО Enqueue лежал в списке обычным
// кандидатом и вытеснялся чужим проходом, а его собственный проход видел
// очередь уже в пределах max и возвращал nil: ложный durable-успех, вызывающий
// не уходил в фолбэк. С Enqueue под q.mu каждый параллельный evictable-Enqueue
// в очередь, забитую protected, обязан вернуть ошибку.
func TestEnqueue_ParallelEvictableIntoProtectedFullQueue_AllError(t *testing.T) {
	dir := t.TempDir()
	q, err := New(dir, 2, time.Hour, discardLog(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := q.Enqueue(KindSecurity, []byte("alert")); err != nil {
			t.Fatal(err)
		}
	}

	const par = 8
	begin := make(chan struct{})
	errs := make(chan error, par)
	var wg sync.WaitGroup
	for i := 0; i < par; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-begin
			errs <- q.Enqueue(KindTask, []byte("task result"))
		}()
	}
	close(begin)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err == nil {
			t.Fatal("параллельный Enqueue вернул durable-успех, а его запись вытеснена чужим enforceLimit (№4.3)")
		}
	}
	files, err := q.list()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("ожидалось 2 записи (protected целы), got %d", len(files))
	}
	for _, f := range files {
		if fileKind(f) != KindSecurity {
			t.Fatalf("protected-запись вытеснена параллельным evictable-Enqueue: %v", files)
		}
	}
}

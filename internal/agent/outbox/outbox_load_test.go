package outbox

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Нагрузочные и краш-тесты outbox. Цель — доказать контракт durable at-least-once
// FIFO под объёмом и при жёстком падении процесса посреди слива очереди.
//
// Краш-тест переисполняет тестовый бинарь как «ребёнка» (через TestMain), который
// наполняет очередь, начинает слив и делает hard `os.Exit(1)` ровно внутри
// dispatch'а граничной записи — ДО того как flush успевает удалить её файл. Родитель
// затем поднимает новый Queue поверх того же каталога и досливает остаток. Так
// воспроизводится ровно тот сбой, ради которого outbox и написан (см. шапку
// outbox.go: события терялись при редеплоях сервера).

const (
	crashEnvFlag = "ROUTINEOPS_OUTBOX_CRASH_CHILD" // "1" → процесс выступает крашащимся ребёнком
	crashEnvDir  = "ROUTINEOPS_OUTBOX_CRASH_DIR"   // каталог очереди
	crashEnvN    = "ROUTINEOPS_OUTBOX_CRASH_N"     // сколько событий поставить
	crashEnvK    = "ROUTINEOPS_OUTBOX_CRASH_K"     // индекс, на доставке которого падаем
	crashEnvJrnl = "ROUTINEOPS_OUTBOX_CRASH_JRNL"  // путь журнала доставок
)

// TestMain перехватывает запуск: если выставлен crashEnvFlag — это краш-ребёнок,
// он не гоняет тесты, а исполняет сценарий и жёстко падает. Иначе обычный прогон.
func TestMain(m *testing.M) {
	if os.Getenv(crashEnvFlag) == "1" {
		runCrashChild()
		return // недостижимо: runCrashChild всегда вызывает os.Exit
	}
	os.Exit(m.Run())
}

// runCrashChild наполняет очередь N записями (payload = десятичный индекс), затем
// синхронно сливает её. dispatch дописывает доставленный индекс в журнал и при
// индексе == K делает os.Exit(1) — файл этой записи к этому моменту ещё НЕ удалён
// flush'ем, значит после рестарта она будет передоставлена (at-least-once).
func runCrashChild() {
	dir := os.Getenv(crashEnvDir)
	n, _ := strconv.Atoi(os.Getenv(crashEnvN))
	k, _ := strconv.Atoi(os.Getenv(crashEnvK))
	jf, err := os.OpenFile(os.Getenv(crashEnvJrnl), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		os.Exit(2)
	}

	dispatch := func(_ context.Context, _ string, data []byte) error {
		idx, _ := strconv.Atoi(string(data))
		fmt.Fprintln(jf, idx)
		_ = jf.Sync() // гарантируем, что строка на диске до возможного краша
		if idx == k {
			os.Exit(1) // жёсткий краш ДО os.Remove граничной записи в flush
		}
		return nil
	}

	q, err := New(dir, 0, time.Hour, discardLog(), dispatch)
	if err != nil {
		os.Exit(2)
	}
	for i := 0; i < n; i++ {
		if err := q.Enqueue(KindSecurity, []byte(strconv.Itoa(i))); err != nil {
			os.Exit(2)
		}
	}
	q.FlushOnce(context.Background())
	os.Exit(0) // если K вне диапазона — выходим чисто
}

// TestLoadFIFO10k: 10k событий должны слиться строго в порядке постановки, без
// потерь и дублей в одном процессе.
func TestLoadFIFO10k(t *testing.T) {
	n := 10000
	if testing.Short() {
		n = 500
	}
	rec := &recorder{}
	q := newQ(t, rec, 0)
	for i := 0; i < n; i++ {
		if err := q.Enqueue(KindSecurity, []byte(strconv.Itoa(i))); err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
	}
	if q.Len() != n {
		t.Fatalf("в очереди %d записей, ждали %d", q.Len(), n)
	}
	q.flush(context.Background())
	if q.Len() != 0 {
		t.Fatalf("очередь не пуста после слива: %d", q.Len())
	}
	got := rec.delivered()
	if len(got) != n {
		t.Fatalf("доставлено %d, ждали %d", len(got), n)
	}
	for i := 0; i < n; i++ {
		if got[i] != strconv.Itoa(i) {
			t.Fatalf("FIFO нарушен на позиции %d: got %q want %q", i, got[i], strconv.Itoa(i))
		}
	}
}

// TestCrashMidFlushPreservesFIFO: краш ребёнка посреди слива не теряет ни одной
// записи, сохраняет FIFO-порядок, а граничная запись передоставляется ровно один
// раз (доказательство at-least-once durability).
func TestCrashMidFlushPreservesFIFO(t *testing.T) {
	dir := t.TempDir()
	journal := filepath.Join(t.TempDir(), "journal.log")
	n := 2000
	k := 777
	if testing.Short() {
		n, k = 200, 77
	}

	// Фаза 1 — краш-ребёнок: наполняет очередь и падает на доставке записи k.
	child := exec.Command(os.Args[0], "-test.run=TestMain")
	child.Env = append(os.Environ(),
		crashEnvFlag+"=1",
		crashEnvDir+"="+dir,
		crashEnvN+"="+strconv.Itoa(n),
		crashEnvK+"="+strconv.Itoa(k),
		crashEnvJrnl+"="+journal,
	)
	err := child.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("ждали краш ребёнка с кодом 1, получили: %v", err)
	}

	// На диске должна остаться неслитой запись k и всё, что после неё.
	q, err := New(dir, 0, time.Hour, discardLog(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if remaining := q.Len(); remaining != n-k {
		t.Fatalf("после краша осталось %d записей, ждали %d (k..n-1)", remaining, n-k)
	}

	// Фаза 2 — родитель досливает остаток в тот же журнал.
	jf, err := os.OpenFile(journal, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer jf.Close()
	resume, err := New(dir, 0, time.Hour, discardLog(), func(_ context.Context, _ string, data []byte) error {
		idx, _ := strconv.Atoi(string(data))
		fmt.Fprintln(jf, idx)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	resume.flush(context.Background())
	if resume.Len() != 0 {
		t.Fatalf("очередь не дослита после восстановления: %d", resume.Len())
	}

	// Разбор журнала: порядок доставок за обе фазы.
	delivered := readJournal(t, journal)

	// 1) Нет потерь: каждый индекс 0..n-1 встречается хотя бы раз.
	seen := make([]int, n)
	for _, v := range delivered {
		if v < 0 || v >= n {
			t.Fatalf("в журнале посторонний индекс %d", v)
		}
		seen[v]++
	}
	for i := 0; i < n; i++ {
		if seen[i] == 0 {
			t.Fatalf("потеряна запись %d (краш съел событие)", i)
		}
	}

	// 2) FIFO: последовательность доставок неубывающая (порядок никогда не ломается).
	for i := 1; i < len(delivered); i++ {
		if delivered[i] < delivered[i-1] {
			t.Fatalf("FIFO нарушен: на позиции %d индекс %d < предыдущего %d", i, delivered[i], delivered[i-1])
		}
	}

	// 3) At-least-once: дубль ровно один и ровно на границе краша (запись k).
	dups := 0
	for i := 0; i < n; i++ {
		if seen[i] > 1 {
			dups += seen[i] - 1
			if i != k {
				t.Fatalf("дубль не на границе краша: индекс %d доставлен %d раз", i, seen[i])
			}
		}
	}
	if dups != 1 {
		t.Fatalf("ждали ровно 1 передоставку на границе (at-least-once), получили %d", dups)
	}
}

func readJournal(t *testing.T, path string) []int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		v, err := strconv.Atoi(line)
		if err != nil {
			t.Fatalf("битая строка журнала %q: %v", line, err)
		}
		out = append(out, v)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

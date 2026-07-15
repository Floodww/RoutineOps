package outbox

import (
	"context"
	"os"
	"runtime"
	"runtime/pprof"
	"sync/atomic"
	"testing"
	"time"
)

// TestNoLeakUnderSustainedLoad — нагрузочно-долгоживущий soak: фоновый Run
// непрерывно сливает очередь, пока тест с большой частотой ставит новые события.
// Меряем HeapInuse и число горутин до и после прогона; рост сверх порога ловит
// утечку памяти/горутин в durable-конвейере (пункт «memory leak 24ч (pprof)»
// тест-плана).
//
// Длительность задаётся ROUTINEOPS_SOAK_DURATION (напр. "24h" для боевого прогона), по
// умолчанию короткая — чтобы шла в CI. ROUTINEOPS_SOAK_HEAP_OUT=<путь> сбрасывает heap-
// профиль для ручного анализа `go tool pprof`.
func TestNoLeakUnderSustainedLoad(t *testing.T) {
	dur := 2 * time.Second
	if v := os.Getenv("ROUTINEOPS_SOAK_DURATION"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			dur = d
		}
	}
	if testing.Short() {
		dur = 300 * time.Millisecond
	}

	var delivered int64
	dispatch := func(_ context.Context, _ string, _ []byte) error {
		atomic.AddInt64(&delivered, 1)
		return nil // всегда успешно: очередь держится у нуля, как в норме
	}
	q, err := New(t.TempDir(), 1000, 5*time.Millisecond, discardLog(), dispatch)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { q.Run(ctx); close(done) }()

	// Прогрев, затем базовый замер: дать аллокаторам/пулам выйти на режим.
	payload := make([]byte, 256)
	warmup := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(warmup) {
		_ = q.Enqueue(KindSecurity, payload)
	}
	baseHeap, baseGor := sample()

	deadline := time.Now().Add(dur)
	var enqueued int64
	for time.Now().Before(deadline) {
		for i := 0; i < 500; i++ {
			_ = q.Enqueue(KindSecurity, payload)
			enqueued++
		}
		time.Sleep(time.Millisecond) // дать Run сливать, иначе упрёмся в лимит
	}

	cancel()
	<-done

	endHeap, endGor := sample()

	if out := os.Getenv("ROUTINEOPS_SOAK_HEAP_OUT"); out != "" {
		if f, err := os.Create(out); err == nil {
			_ = pprof.WriteHeapProfile(f)
			_ = f.Close()
			t.Logf("heap-профиль записан в %s", out)
		}
	}

	t.Logf("soak: длительность=%s поставлено=%d доставлено=%d heap %d→%d КБ горутины %d→%d",
		dur, enqueued, atomic.LoadInt64(&delivered), baseHeap/1024, endHeap/1024, baseGor, endGor)

	// Горутины: после отмены ctx фоновый Run завершился — лишних быть не должно.
	if endGor > baseGor+2 {
		t.Errorf("утечка горутин: было %d, стало %d", baseGor, endGor)
	}

	// Куча: очередь дренируется, поэтому установившийся heap должен быть плоским.
	// Порог щедрый (буферы аллокатора, профайлер), но ловит линейный рост.
	const maxGrowth = 16 << 20 // 16 МБ
	if endHeap > baseHeap+maxGrowth {
		t.Errorf("подозрение на утечку памяти: HeapInuse вырос на %d КБ (порог %d КБ)",
			(endHeap-baseHeap)/1024, maxGrowth/1024)
	}
}

// sample форсирует GC и возвращает (HeapInuse, число горутин).
func sample() (heap uint64, goroutines int) {
	runtime.GC()
	runtime.GC() // второй проход добивает финализаторы/отложенное
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapInuse, runtime.NumGoroutine()
}

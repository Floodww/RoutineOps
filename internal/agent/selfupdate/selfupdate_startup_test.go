package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync/atomic"
	"testing"
	"time"
)

// Первая проверка идёт вскоре после старта, НЕ через полный интервал. Интервал здесь
// заведомо больше времени жизни теста: если бы проверка ждала тика, тест бы упал —
// именно так выглядел полевой симптом (перезапуск службы отодвигал уже
// опубликованный релиз на 6 часов).
func TestRunChecksOnStartup(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("новый-бинарь")
	m := signedManifest("v2.0.0", bin, priv)

	applied := make(chan []byte, 1)
	u := &Updater{
		current:    "v1.0.0",
		pubKey:     pub,
		interval:   time.Hour,
		log:        discardLog(),
		firstDelay: func() time.Duration { return 0 },
		check:      func(context.Context) (*Manifest, error) { return m, nil },
		download:   func(context.Context, string) ([]byte, error) { return bin, nil },
		replace: func(data []byte) error {
			select {
			case applied <- data:
			default:
			}
			return nil
		},
		restart: func() {},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go u.Run(ctx)

	select {
	case got := <-applied:
		if string(got) != string(bin) {
			t.Fatalf("применён не тот бинарь: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run не проверил обновления на старте — ждёт первого тика интервала")
	}
}

// Ошибка первой проверки не мешает дальнейшим тикам: сервер может быть недоступен
// именно в момент старта машины (сеть ещё не поднялась) — это норма, не выход.
func TestRunContinuesAfterStartupCheckError(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var checks int32
	u := &Updater{
		current:    "v1.0.0",
		pubKey:     pub,
		interval:   5 * time.Millisecond,
		log:        discardLog(),
		firstDelay: func() time.Duration { return 0 },
		check: func(context.Context) (*Manifest, error) {
			atomic.AddInt32(&checks, 1)
			return nil, context.DeadlineExceeded
		},
		download: func(context.Context, string) ([]byte, error) { return nil, nil },
		replace:  func([]byte) error { return nil },
		restart:  func() {},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go u.Run(ctx)

	deadline := time.After(2 * time.Second)
	for atomic.LoadInt32(&checks) < 3 {
		select {
		case <-deadline:
			t.Fatalf("Run встал после ошибки первой проверки (checks=%d)", atomic.LoadInt32(&checks))
		case <-time.After(2 * time.Millisecond):
		}
	}
}

// Пока идёт задержка первой проверки, отмена ctx должна выводить Run немедленно и
// без обращения к серверу: остановка службы не повод дёргать манифест.
func TestRunSkipsCheckWhenCanceledDuringStartupDelay(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var checks int32
	done := make(chan struct{})
	u := &Updater{
		current:    "v1.0.0",
		pubKey:     pub,
		interval:   time.Hour,
		log:        discardLog(),
		firstDelay: func() time.Duration { return 10 * time.Second },
		check: func(context.Context) (*Manifest, error) {
			atomic.AddInt32(&checks, 1)
			return nil, nil
		},
		download: func(context.Context, string) ([]byte, error) { return nil, nil },
		replace:  func([]byte) error { return nil },
		restart:  func() {},
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { u.Run(ctx); close(done) }()
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run не вышел по отмене ctx — досиживает задержку первой проверки")
	}
	if n := atomic.LoadInt32(&checks); n != 0 {
		t.Fatalf("после отмены сделано %d проверок, ожидалось 0", n)
	}
}

func TestStartupJitter(t *testing.T) {
	cases := []struct {
		name     string
		interval time.Duration
		max      time.Duration
	}{
		// Дефолт службы: потолок упирается в startupJitterCap.
		{"default-6h", 6 * time.Hour, startupJitterCap},
		// Полевая приёмка гоняет минутный интервал — ждать 5 минут первой проверки
		// там бессмысленно, потолок должен съезжать вместе с интервалом.
		{"acceptance-60s", time.Minute, 6 * time.Second},
		// Вырожденный интервал не должен давать отрицательную или паникующую задержку.
		{"degenerate", time.Nanosecond, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			seen := make(map[time.Duration]struct{})
			for range 200 {
				d := startupJitter(c.interval)
				if d < 0 || d > c.max {
					t.Fatalf("задержка %s вне [0, %s]", d, c.max)
				}
				seen[d] = struct{}{}
			}
			// Постоянная задержка — не jitter: парк после массового ребута придёт
			// за манифестом одновременно, ровно чего приём и должен избегать.
			if c.max > 0 && len(seen) < 2 {
				t.Fatalf("задержка не размазана: 200 попыток дали %d различных значений", len(seen))
			}
		})
	}
}

package admin

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	pb "github.com/Floodww/RoutineOps/proto"
)

// TestRunNoGoroutineLeakAtScale симулирует множество агентов: N admin-менеджеров
// крутят свой Run (тикер поллинга), затем все отменяются. После отмены число
// горутин должно вернуться к базовому — регрессионная страховка против утечки в
// цикле поллинга (часть проверки «горутин-лики» Phase 7).
func TestRunNoGoroutineLeakAtScale(t *testing.T) {
	const agents = 30

	settle := func(want int) int {
		deadline := time.Now().Add(2 * time.Second)
		for {
			runtime.GC()
			n := runtime.NumGoroutine()
			if n <= want || time.Now().After(deadline) {
				return n
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	runtime.GC()
	runtime.GC()
	base := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for i := 0; i < agents; i++ {
		m := &Manager{
			interval:    5 * time.Millisecond,
			log:         quietLog(),
			priv:        &fakePriv{},
			consoleUser: func() (string, bool) { return "alice", true },
			fetch: func(context.Context) (*pb.FetchAdminStatusResponse, error) {
				return &pb.FetchAdminStatusResponse{}, nil // активной заявки нет
			},
			report: func(context.Context, *pb.ReportAdminAccessRequest) error { return nil },
		}
		wg.Add(1)
		go func() { defer wg.Done(); m.Run(ctx) }()
	}

	time.Sleep(50 * time.Millisecond)
	if running := runtime.NumGoroutine(); running <= base {
		t.Fatalf("ожидали рост горутин под нагрузкой (база %d, сейчас %d)", base, running)
	}

	cancel()
	wg.Wait()

	if end := settle(base + 2); end > base+2 {
		t.Errorf("утечка горутин: база %d, после отмены %d агентов осталось %d", base, agents, end)
	}
}

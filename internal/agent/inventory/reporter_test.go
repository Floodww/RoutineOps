package inventory

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	pb "github.com/Floodww/RoutineOps/proto"
)

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// build собирает отчёт из реального коллектора: DeviceInfo должен быть заполнен,
// а повторный build — давать тот же хэш (детерминизм для дедупа).
func TestBuild_PopulatesDeviceInfo(t *testing.T) {
	rep := build("1.2.3")
	if rep.GetDeviceInfo() == nil {
		t.Fatal("build вернул отчёт без DeviceInfo")
	}
	if got := rep.GetDeviceInfo().GetAgentVersion(); got != "1.2.3" {
		t.Errorf("agent_version = %q, want 1.2.3", got)
	}
	if mustHash(t, rep) != mustHash(t, build("1.2.3")) {
		t.Error("два последовательных build дали разный хэш — дедуп сломается")
	}
}

// reportOnce: успешная отправка запоминает хэш; повторный вызов с тем же
// снимком пропускается (отправки нет).
func TestReportOnce_SendsThenSkipsUnchanged(t *testing.T) {
	var mu sync.Mutex
	var calls int
	r := &Reporter{
		Interval: time.Hour,
		Log:      quietLog(),
		sendReport: func(context.Context, *pb.InventoryReport) (bool, error) {
			mu.Lock()
			calls++
			mu.Unlock()
			return true, nil
		},
	}

	r.reportOnce(context.Background())
	if r.lastHash == "" {
		t.Fatal("lastHash не сохранён после успешной отправки")
	}
	r.reportOnce(context.Background()) // снимок не изменился → пропуск

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("ожидалась 1 отправка (вторая — пропуск дедупом), получено %d", calls)
	}
}

// Ошибка отправки не должна сохранять хэш — следующий тик повторит попытку.
func TestReportOnce_ErrorDoesNotStoreHash(t *testing.T) {
	var calls int
	r := &Reporter{
		Interval: time.Hour,
		Log:      quietLog(),
		sendReport: func(context.Context, *pb.InventoryReport) (bool, error) {
			calls++
			return false, errors.New("network down")
		},
	}

	r.reportOnce(context.Background())
	if r.lastHash != "" {
		t.Error("lastHash сохранён несмотря на ошибку отправки")
	}
	r.reportOnce(context.Background()) // должен повторить, а не пропустить
	if calls != 2 {
		t.Errorf("после ошибки ожидался повтор отправки, всего вызовов %d", calls)
	}
}

// Run выполняет первый отчёт после initialDelay и завершается по отмене контекста.
func TestRun_ReportsThenStops(t *testing.T) {
	old := initialDelay
	initialDelay = time.Millisecond
	defer func() { initialDelay = old }()

	sent := make(chan struct{}, 1)
	r := &Reporter{
		Interval: time.Hour,
		Log:      quietLog(),
		sendReport: func(context.Context, *pb.InventoryReport) (bool, error) {
			select {
			case sent <- struct{}{}:
			default:
			}
			return true, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("Run не отправил первый отчёт")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run не завершился после отмены контекста")
	}
}

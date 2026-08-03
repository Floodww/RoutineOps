package inventory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/Floodww/RoutineOps/proto"
)

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeBuild — «сбор» для тестов РАСПИСАНИЯ, не для тестов дедупа.
//
// Настоящий build обходит реестр установленного ПО и список служб: на живой
// Windows это секунды, и тесты первого отчёта, внеочередного сигнала и отмены
// контекста укладывались в свои две секунды только на macOS. Падали они с
// диагнозом «Run не отправил первый отчёт», хотя расписание работало — просто
// сбор не успевал.
//
// Каждый вызов отдаёт РАЗНЫЙ снимок: одинаковый проглотил бы дедуп reportOnce, и
// тест внеочередного сигнала ждал бы вторую отправку, которой по построению не
// случилось бы. Тесты дедупа, наоборот, сознательно продолжают ходить в
// настоящий build — там проверяется именно его стабильность.
func fakeBuild() func(string) *pb.InventoryReport {
	var n atomic.Int64
	return func(version string) *pb.InventoryReport {
		return &pb.InventoryReport{
			DeviceInfo: &pb.DeviceInfo{AgentVersion: fmt.Sprintf("%s-%d", version, n.Add(1))},
		}
	}
}

// build собирает отчёт из реального коллектора: DeviceInfo должен быть заполнен,
// а повторный build — давать тот же хэш (детерминизм для дедупа).
func TestBuild_PopulatesDeviceInfo(t *testing.T) {
	rep := build("1.2.3", nil)
	if rep.GetDeviceInfo() == nil {
		t.Fatal("build вернул отчёт без DeviceInfo")
	}
	if got := rep.GetDeviceInfo().GetAgentVersion(); got != "1.2.3" {
		t.Errorf("agent_version = %q, want 1.2.3", got)
	}
	if mustHash(t, rep) != mustHash(t, build("1.2.3", nil)) {
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
		Interval:    time.Hour,
		Log:         quietLog(),
		buildReport: fakeBuild(),
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

// Внеочередной снимок: агент сам изменил состав ПО (снял программу), и карточка
// устройства обязана обновиться сразу, а не через Interval — иначе успешная
// задача читается оператором как несработавшая.
//
// Проверяется именно ОТПРАВКА, а не факт получения сигнала: снимок между двумя
// отправками разный (дедуп по хэшу), и молчаливый пропуск из-за него был бы
// ровно тем поведением, ради устранения которого сигнал и заводился.
func TestRun_NudgeSendsOutOfBand(t *testing.T) {
	old := initialDelay
	initialDelay = time.Hour // штатный цикл в этом тесте не должен сработать вовсе
	defer func() { initialDelay = old }()

	sent := make(chan struct{}, 4)
	nudge := make(chan struct{}, 1)
	var mu sync.Mutex
	var snapshot int
	r := &Reporter{
		Interval:    time.Hour,
		Log:         quietLog(),
		Nudge:       nudge,
		buildReport: fakeBuild(),
		sendReport: func(context.Context, *pb.InventoryReport) (bool, error) {
			mu.Lock()
			snapshot++
			mu.Unlock()
			sent <- struct{}{}
			return true, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	nudge <- struct{}{}
	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatal("сигнал не вызвал внеочередную отправку")
	}

	mu.Lock()
	got := snapshot
	mu.Unlock()
	if got != 1 {
		t.Fatalf("отправок = %d, ожидали ровно одну (штатный таймер стоит на час)", got)
	}
}

// Репортер без подключённого сигнала обязан работать как раньше: чтение из
// nil-канала в select просто никогда не срабатывает, а не блокирует цикл.
func TestRun_NilNudgeDoesNotBlockCycle(t *testing.T) {
	old := initialDelay
	initialDelay = time.Millisecond
	defer func() { initialDelay = old }()

	sent := make(chan struct{}, 1)
	r := &Reporter{
		Interval:    time.Hour,
		Log:         quietLog(),
		buildReport: fakeBuild(),
		sendReport: func(context.Context, *pb.InventoryReport) (bool, error) {
			select {
			case sent <- struct{}{}:
			default:
			}
			return true, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatal("без подключённого сигнала штатный цикл перестал отправлять")
	}
}

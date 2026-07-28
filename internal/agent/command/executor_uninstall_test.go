package command

import (
	"context"
	"sync"
	"testing"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
	"github.com/Floodww/RoutineOps/internal/agent/uninstall"
	pb "github.com/Floodww/RoutineOps/proto"
)

// fakeUninstaller подменяет исполнитель снятия ПО: реальный msiexec/pacman в
// тесте не запустить, поэтому проверяемой границей становится контракт
// executor↔исполнитель.
type fakeUninstaller struct {
	mu  sync.Mutex
	got []uninstall.Request
	ret uninstall.Result
}

func (f *fakeUninstaller) Run(_ context.Context, req uninstall.Request) uninstall.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, req)
	return f.ret
}

func (f *fakeUninstaller) requests() []uninstall.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uninstall.Request(nil), f.got...)
}

func TestHandleUninstall_PassesSelectorAndReportsOutcome(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	fu := &fakeUninstaller{ret: uninstall.Result{
		Outcome: pb.UninstallOutcome_UNINSTALL_OUTCOME_REMOVED,
		Detail:  "снято: Google Chrome 120.0.1",
	}}
	e.SetUninstaller(fu)
	nudged := make(chan struct{}, 1)
	e.SetInventoryNudge(func() { nudged <- struct{}{} })

	e.Submit(&pb.Task{TaskId: "t-uninst", Uninstall: &pb.UninstallCommand{
		RequestId:       "req-1",
		SoftwareName:    "Google Chrome",
		Version:         "120.0.1",
		UninstallId:     "{42488912-25F8-4C42-AE88-DF4D50E17832}",
		InstallLocation: `C:\Program Files\Google\Chrome`,
		UninstallMethod: pb.UninstallMethod_UNINSTALL_METHOD_MSI,
		Scope:           "machine",
		Reason:          "запрещённое ПО",
	}})
	waitFor(t, "результат удаления", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	reqs := fu.requests()
	if len(reqs) != 1 {
		t.Fatalf("исполнитель вызван %d раз, ожидали 1", len(reqs))
	}
	got := reqs[0]
	if got.Name != "Google Chrome" || got.Version != "120.0.1" || got.Scope != "machine" {
		t.Errorf("селектор потерян по дороге: %+v", got)
	}
	if got.UninstallID != "{42488912-25F8-4C42-AE88-DF4D50E17832}" {
		t.Errorf("машинный ключ не доехал: %q", got.UninstallID)
	}
	if got.Method != collector.UninstallMSI {
		t.Errorf("метод = %q, ожидали msi", got.Method)
	}
	if got.Reason != "запрещённое ПО" {
		t.Errorf("причина для аудита не доехала: %q", got.Reason)
	}

	res := fc.resultsCopy()[0]
	if res.GetStatus() != pb.TaskStatus_TASK_STATUS_SUCCESS {
		t.Errorf("статус = %v, ожидали SUCCESS", res.GetStatus())
	}
	if res.GetUninstallOutcome() != pb.UninstallOutcome_UNINSTALL_OUTCOME_REMOVED {
		t.Errorf("исход = %v, ожидали REMOVED", res.GetUninstallOutcome())
	}
	if res.GetOutput() == "" {
		t.Error("подробности не доехали до оператора")
	}
	select {
	case <-nudged:
	default:
		t.Error("после снятия ПО не запрошен внеочередной инвентарь — карточка устройства осталась бы врать до пяти минут")
	}
}

// Исход обязан ехать машиночитаемым кодом, а не только текстом: панели нужно
// различать «снято» и «нечего удалять», а по строке этого не сделать.
func TestHandleUninstall_OutcomeToStatusMapping(t *testing.T) {
	cases := []struct {
		outcome    pb.UninstallOutcome
		wantStatus pb.TaskStatus
		wantNudge  bool
	}{
		{pb.UninstallOutcome_UNINSTALL_OUTCOME_REMOVED, pb.TaskStatus_TASK_STATUS_SUCCESS, true},
		// Намерение оператора выполнено — ПО на машине нет. Но состав ПО при этом
		// не менялся, пересобирать инвентарь незачем.
		{pb.UninstallOutcome_UNINSTALL_OUTCOME_ALREADY_ABSENT, pb.TaskStatus_TASK_STATUS_SUCCESS, false},
		{pb.UninstallOutcome_UNINSTALL_OUTCOME_TARGET_CHANGED, pb.TaskStatus_TASK_STATUS_ERROR, false},
		{pb.UninstallOutcome_UNINSTALL_OUTCOME_AMBIGUOUS, pb.TaskStatus_TASK_STATUS_ERROR, false},
		{pb.UninstallOutcome_UNINSTALL_OUTCOME_NOT_REMOVABLE, pb.TaskStatus_TASK_STATUS_ERROR, false},
		{pb.UninstallOutcome_UNINSTALL_OUTCOME_SELF_PROTECTED, pb.TaskStatus_TASK_STATUS_ERROR, false},
		{pb.UninstallOutcome_UNINSTALL_OUTCOME_FAILED, pb.TaskStatus_TASK_STATUS_ERROR, false},
		{pb.UninstallOutcome_UNINSTALL_OUTCOME_STILL_PRESENT, pb.TaskStatus_TASK_STATUS_ERROR, false},
	}
	for _, c := range cases {
		t.Run(c.outcome.String(), func(t *testing.T) {
			fc := &fakeClient{}
			e, _ := newTestExecutor(t, fc)
			e.SetUninstaller(&fakeUninstaller{ret: uninstall.Result{Outcome: c.outcome, Detail: "причина"}})
			nudged := make(chan struct{}, 1)
			e.SetInventoryNudge(func() { nudged <- struct{}{} })

			e.Submit(&pb.Task{TaskId: "t-" + c.outcome.String(), Uninstall: &pb.UninstallCommand{SoftwareName: "X"}})
			waitFor(t, "результат", func() bool { return len(fc.resultsCopy()) == 1 })
			e.Shutdown()

			res := fc.resultsCopy()[0]
			if res.GetStatus() != c.wantStatus {
				t.Errorf("статус = %v, ожидали %v", res.GetStatus(), c.wantStatus)
			}
			if res.GetUninstallOutcome() != c.outcome {
				t.Errorf("исход = %v, ожидали %v", res.GetUninstallOutcome(), c.outcome)
			}
			// Причина обязана быть видна оператору в любом исходе.
			if res.GetOutput() == "" && res.GetErrorLog() == "" {
				t.Error("отчёт без причины")
			}
			gotNudge := len(nudged) > 0
			if gotNudge != c.wantNudge {
				t.Errorf("внеочередной инвентарь = %v, ожидали %v", gotNudge, c.wantNudge)
			}
		})
	}
}

// Исполнитель не подключён (сборка/ОС без поддержки) — отчитываемся ОШИБКОЙ, а
// не молчим: молчание оставило бы задачу висеть в 'acked' до серверного sweep,
// и оператор не узнал бы причину вообще.
func TestHandleUninstall_NoUninstallerReportsError(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)

	e.Submit(&pb.Task{TaskId: "t-none", Uninstall: &pb.UninstallCommand{SoftwareName: "X"}})
	waitFor(t, "результат", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	res := fc.resultsCopy()[0]
	if res.GetStatus() != pb.TaskStatus_TASK_STATUS_ERROR {
		t.Errorf("статус = %v, ожидали ERROR", res.GetStatus())
	}
	if res.GetErrorLog() == "" {
		t.Error("причина отказа пустая")
	}
	if ids := fc.ackedIDs(); len(ids) != 1 || ids[0] != "t-none" {
		t.Errorf("задача не подтверждена: %v", ids)
	}
}

// Отсутствующий nudge не должен ронять обработку: он опционален.
func TestHandleUninstall_NilNudgeIsSafe(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	e.SetUninstaller(&fakeUninstaller{ret: uninstall.Result{Outcome: pb.UninstallOutcome_UNINSTALL_OUTCOME_REMOVED, Detail: "ok"}})

	e.Submit(&pb.Task{TaskId: "t-nonudge", Uninstall: &pb.UninstallCommand{SoftwareName: "X"}})
	waitFor(t, "результат", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()
}

// request_id пустой — падаем на task_id, иначе идемпотентность и аудит
// разъехались бы с задачей.
func TestHandleUninstall_RequestIDFallsBackToTaskID(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	fu := &fakeUninstaller{ret: uninstall.Result{Outcome: pb.UninstallOutcome_UNINSTALL_OUTCOME_ALREADY_ABSENT}}
	e.SetUninstaller(fu)

	e.Submit(&pb.Task{TaskId: "t-fallback", Uninstall: &pb.UninstallCommand{SoftwareName: "X"}})
	waitFor(t, "результат", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	if got := fu.requests()[0].RequestID; got != "t-fallback" {
		t.Errorf("request_id = %q, ожидали подстановку task_id", got)
	}
}

// Метод из контракта — это СВЕРКА, а не приказ, и незнакомое значение (новый
// сервер против старого агента) обязано означать «сервер метода не назвал», а
// не случайный метод из соседней позиции enum.
func TestUninstallMethodName_MapsEveryKnownValue(t *testing.T) {
	want := map[pb.UninstallMethod]collector.UninstallMethod{
		pb.UninstallMethod_UNINSTALL_METHOD_UNSPECIFIED:      collector.UninstallNone,
		pb.UninstallMethod_UNINSTALL_METHOD_MSI:              collector.UninstallMSI,
		pb.UninstallMethod_UNINSTALL_METHOD_WINDOWS_QUIET:    collector.UninstallWindowsQuiet,
		pb.UninstallMethod_UNINSTALL_METHOD_MACOS_APP_BUNDLE: collector.UninstallMacAppBundle,
		pb.UninstallMethod_UNINSTALL_METHOD_DPKG:             collector.UninstallDpkg,
		pb.UninstallMethod_UNINSTALL_METHOD_RPM:              collector.UninstallRPM,
		pb.UninstallMethod_UNINSTALL_METHOD_PACMAN:           collector.UninstallPacman,
		pb.UninstallMethod_UNINSTALL_METHOD_APK:              collector.UninstallAPK,
	}
	// Полнота: в enum не должно остаться значения, которое здесь не разобрано, —
	// иначе новый метод молча отобразился бы в «метод не назван».
	for v := range pb.UninstallMethod_name {
		m := pb.UninstallMethod(v)
		exp, ok := want[m]
		if !ok {
			t.Fatalf("значение %v есть в контракте, но не покрыто отображением — допишите обе стороны", m)
		}
		if got := uninstallMethodName(m); got != exp {
			t.Errorf("%v → %q, ожидали %q", m, got, exp)
		}
	}
	if got := uninstallMethodName(pb.UninstallMethod(99)); got != collector.UninstallNone {
		t.Errorf("незнакомое значение → %q, ожидали пустой метод", got)
	}
}

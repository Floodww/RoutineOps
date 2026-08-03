package command

import (
	"strings"
	"testing"

	pb "github.com/Floodww/RoutineOps/proto"
)

// Задача незнакомого типа (сервер новее агента: ни одна известная команда не
// заполнена, тела скрипта нет) обязана отчитаться ОШИБКОЙ. Полевой симптом, ради
// которого тест и написан: сервер поставил task_type='filevault_provision',
// обработчика в агенте не было, а оператор в панели увидел «выполнено» с пустым
// error_log — работа не сделана, но выглядит сделанной.
func TestHandle_UnknownTaskType_ReportsError(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	e.SetAgentVersion("v2.5.7")

	e.Submit(&pb.Task{TaskId: "t-unknown", Platform: testPlatform()})
	waitFor(t, "результат задачи", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	res := fc.resultsCopy()
	if res[0].GetStatus() != pb.TaskStatus_TASK_STATUS_ERROR {
		t.Fatalf("статус = %v, ожидался ERROR (иначе оператор видит успех несделанной работы)", res[0].GetStatus())
	}
	log := res[0].GetErrorLog()
	if log == "" {
		t.Fatal("error_log пуст — оператору неоткуда узнать, почему ничего не произошло")
	}
	// Версия в тексте нужна на парке из разных версий: без неё «не поддерживается»
	// не подсказывает, какое устройство отстало.
	if !strings.Contains(log, "v2.5.7") {
		t.Errorf("в error_log нет версии агента: %q", log)
	}
	if !strings.Contains(log, "НЕ выполнялась") {
		t.Errorf("в error_log не сказано, что работа не выполнялась: %q", log)
	}
}

// Пустая версия не должна давать «поддерживается ()» — текст обязан остаться
// осмысленным даже в dev-сборке без ldflags.
func TestUnsupportedTaskError_NoVersion(t *testing.T) {
	got := unsupportedTaskError("")
	if strings.Contains(got, "()") || !strings.Contains(got, "версия неизвестна") {
		t.Errorf("текст без версии: %q", got)
	}
}

// Скрипт-задача с пустым телом идёт тем же путём: интерпретатор отработал бы
// вхолостую и вернул 0, то есть панель показала бы успех пустой работы.
func TestHandle_EmptyScript_ReportsError(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)

	e.Submit(&pb.Task{TaskId: "t-empty", Platform: testPlatform(), ScriptContent: ""})
	waitFor(t, "результат задачи", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	if st := fc.resultsCopy()[0].GetStatus(); st != pb.TaskStatus_TASK_STATUS_ERROR {
		t.Fatalf("статус = %v, ожидался ERROR", st)
	}
}

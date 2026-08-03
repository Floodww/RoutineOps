//go:build windows

package service

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

// drainStatus сливает статусы службы, чтобы Execute не блокировался на отправке
// в неблокирующий канал статуса.
func drainStatus(s <-chan svc.Status) {
	go func() {
		for range s {
		}
	}()
}

// childWorkErrEnv переводит тест ниже в режим «я — дочерний процесс».
const childWorkErrEnv = "ROUTINEOPS_TEST_EXECUTE_WORK_ERR"

// TestExecuteWorkExitCodeCrashes проверяет ключевой инвариант self-update: когда
// work() завершается сам с ошибкой (запрос на перезапуск для применения нового
// exe), процесс службы ОБРЫВАЕТСЯ с ненулевым кодом — иначе FailureActions не
// сработают и агент останется лежать (полевой баг 2.2.2).
//
// Сценарий гоняется в ДОЧЕРНЕМ процессе, потому что Execute на этой ветке зовёт
// os.Exit(1) (run_windows.go: обрыв процесса триггерит recovery-actions в SCM
// надёжнее штатного возврата). Прежняя редакция теста ждала ВОЗВРАТА из Execute
// и потому не просто не проходила — она убивала весь прогон пакета на первом же
// подтесте, унося с собой все тесты после него. Заметить это было негде: файл
// под windows-тегом, на маке не компилируется, Go на билд-боксе не стоит, CI лежит.
//
// Проверять надо именно ту границу, на которой ломалось в поле: код выхода
// процесса, а не значение, возвращённое функцией.
func TestExecuteWorkExitCodeCrashes(t *testing.T) {
	if os.Getenv(childWorkErrEnv) == "1" {
		h := &handler{work: func(context.Context) error {
			return errors.New("перезапуск для применения самообновления")
		}}
		s := make(chan svc.Status, 8)
		drainStatus(s)
		h.Execute(nil, make(chan svc.ChangeRequest), s)
		// Сюда попадать нельзя: Execute обязан был оборвать процесс.
		os.Exit(0)
	}

	// Путь берём из os.Executable, а не из os.Args[0]: там лежит строка запуска, и
	// при запуске из текущего каталога («t.exe») Go отказывается её исполнять —
	// «cannot run executable found relative to current directory». `go test` в
	// репозитории даёт абсолютный путь и это прячет, а тест-бинарь, перенесённый
	// на живую Windows, падал бы с диагнозом «Execute вернулся штатно», хотя
	// дочерний процесс просто не запустился.
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(self, "-test.run=TestExecuteWorkExitCodeCrashes")
	cmd.Env = append(os.Environ(), childWorkErrEnv+"=1")
	err = cmd.Run()

	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("дочерний процесс завершился без ошибки (err=%v) — значит Execute вернулся штатно, "+
			"SCM увидит STOPPED с кодом 0 и FailureActions не сработают", err)
	}
	if ee.ExitCode() != 1 {
		t.Fatalf("код выхода дочернего процесса=%d, ожидался 1", ee.ExitCode())
	}
}

// TestExecuteWorkNoErrorReturnsZero — вторая ветка: work вышел без ошибки,
// процесс НЕ обрывается, Execute штатно возвращает код 0. Здесь дочерний
// процесс не нужен — os.Exit на этой ветке как раз не зовётся.
func TestExecuteWorkNoErrorReturnsZero(t *testing.T) {
	h := &handler{work: func(context.Context) error { return nil }}
	s := make(chan svc.Status, 8)
	drainStatus(s)

	type result struct {
		svcSpecific bool
		code        uint32
	}
	res := make(chan result, 1)
	go func() {
		ss, code := h.Execute(nil, make(chan svc.ChangeRequest), s)
		res <- result{ss, code}
	}()

	select {
	case got := <-res:
		if got.svcSpecific {
			t.Fatalf("svcSpecificEC=true, ожидался win32-код выхода")
		}
		if got.code != 0 {
			t.Fatalf("код выхода=%d, ожидался 0", got.code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Execute не завершился после выхода work()")
	}
}

// TestExecuteStopReturnsZero проверяет, что штатный стоп по команде SCM остаётся
// успешным (код 0): фикс self-update не должен ломать ветку Stop/Shutdown.
func TestExecuteStopReturnsZero(t *testing.T) {
	// work блокируется до отмены контекста — имитация живого агента.
	h := &handler{work: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}

	r := make(chan svc.ChangeRequest)
	s := make(chan svc.Status, 8)
	drainStatus(s)

	type result struct {
		svcSpecific bool
		code        uint32
	}
	res := make(chan result, 1)
	go func() {
		ss, code := h.Execute(nil, r, s)
		res <- result{ss, code}
	}()

	// Даём службе выйти в Running и шлём Stop.
	r <- svc.ChangeRequest{Cmd: svc.Stop}

	select {
	case got := <-res:
		if got.svcSpecific || got.code != 0 {
			t.Fatalf("Stop вернул svcSpecific=%v code=%d, ожидался false/0", got.svcSpecific, got.code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Execute не завершился после Stop")
	}
}

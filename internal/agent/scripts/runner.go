// Package scripts реализует агентскую сторону скрипт-политик (Этап 5): поллинг
// эффективного набора политик (FetchScriptPolicies), их исполнение по триггерам
// (cron-расписание, событие ОС, on_connect) и отчёт о результате
// (ReportScriptResult) через устойчивую очередь outbox.
package scripts

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"os/exec"
	"runtime"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/outbox"
	"github.com/Floodww/RoutineOps/internal/agent/scriptenc"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/protobuf/proto"
)

const defaultTimeout = 5 * time.Minute

// EnqueueFunc ставит отчёт в устойчивую очередь доставки (outbox).
type EnqueueFunc func(kind string, data []byte) error

// execResult — результат одного запуска интерпретатора.
type execResult struct {
	exitCode int32
	stdout   string
	stderr   string
}

// execFunc исполняет содержимое скрипта заданным интерпретатором с таймаутом.
// Выделено в поле, чтобы подменять в тестах без запуска реальных процессов.
type execFunc func(ctx context.Context, interpreter, content string) execResult

// Runner исполняет скрипт-политику и шлёт результат через outbox.
type Runner struct {
	log     *slog.Logger
	enqueue EnqueueFunc
	exec    execFunc
}

func NewRunner(enqueue EnqueueFunc, log *slog.Logger) *Runner {
	return &Runner{log: log, enqueue: enqueue, exec: defaultExec}
}

// Run исполняет политику p (инициирован триггером trigger) и ставит ScriptResult
// в очередь доставки. Блокирует на время исполнения (вызывать в отдельной горутине).
func (r *Runner) Run(ctx context.Context, p *pb.ScriptPolicy, trigger pb.ScriptTrigger) {
	timeout := defaultTimeout
	if p.GetTimeoutSeconds() > 0 {
		timeout = time.Duration(p.GetTimeoutSeconds()) * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	started := time.Now()
	r.log.Info("scripts: запуск политики",
		slog.String("policy_id", p.GetPolicyId()), slog.String("name", p.GetName()),
		slog.String("trigger", trigger.String()))
	res := r.exec(runCtx, p.GetInterpreter(), p.GetScriptContent())
	finished := time.Now()

	// Обрезка до отправки: гигантский вывод даёт кадр >4 МБ, сервер отвергает его
	// ResourceExhausted'ом, и запись насмерть встаёт в голове FIFO-очереди outbox.
	result := &pb.ScriptResult{
		PolicyId:   p.GetPolicyId(),
		RunId:      randID(),
		ExitCode:   res.exitCode,
		Stdout:     scriptenc.TruncateOutput(res.stdout),
		Stderr:     scriptenc.TruncateOutput(res.stderr),
		StartedAt:  started.Unix(),
		FinishedAt: finished.Unix(),
		Trigger:    trigger,
	}
	data, err := proto.Marshal(result)
	if err != nil {
		r.log.Error("scripts: сериализация результата", slog.Any("error", err))
		return
	}
	if err := r.enqueue(outbox.KindScript, data); err != nil {
		r.log.Error("scripts: постановка результата в очередь", slog.Any("error", err))
		return
	}
	r.log.Info("scripts: результат поставлен в очередь",
		slog.String("policy_id", p.GetPolicyId()), slog.Int("exit_code", int(res.exitCode)),
		slog.Int("stdout_len", len(res.stdout)), slog.Int("stderr_len", len(res.stderr)),
		slog.Duration("took", finished.Sub(started)))
}

// defaultExec запускает интерпретатор, передавая скрипт через флаг -c/-Command.
func defaultExec(ctx context.Context, interpreter, content string) execResult {
	name, args := interpreterCommand(interpreter, content)
	if name == "" {
		return execResult{exitCode: -1, stderr: "неизвестный интерпретатор: " + interpreter}
	}
	cmd := exec.CommandContext(ctx, name, args...)
	// Capped-буферы (scriptenc): потолок памяти ВО ВРЕМЯ выполнения — скрипт-
	// политика с гигабайтным выводом не роняет агента под root в OOM.
	var stdout, stderr scriptenc.CaptureBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Без WaitDelay политика, поднявшая фоновую службу (`daemon &` с унаследованным
	// stdout), подвешивала Run() до смерти потомка (см. scriptenc.PipeWaitDelay).
	cmd.WaitDelay = scriptenc.PipeWaitDelay
	err := cmd.Run()

	res := execResult{stdout: stdout.String(), stderr: stderr.String()}
	switch {
	case err == nil:
		res.exitCode = 0
	case errors.Is(err, exec.ErrWaitDelay):
		// Подменяет ТОЛЬКО nil: сам скрипт вышел с кодом 0, но фоновый потомок
		// держал stdout — пайпы закрыты принудительно. Это успех, не ошибка.
		res.exitCode = 0
		res.stderr += "\n[фоновые потомки скрипта продолжают работать — их дальнейший вывод не захвачен]"
	case ctx.Err() == context.DeadlineExceeded:
		res.exitCode = -1
		res.stderr += "\n[прервано по таймауту]"
	default:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.exitCode = int32(ee.ExitCode())
		} else {
			res.exitCode = -1
			res.stderr += "\n[ошибка запуска: " + err.Error() + "]"
		}
	}
	// Backstop: гарантируем валидный UTF-8, иначе proto.Marshal(ScriptResult)
	// упадёт и результат политики молча потеряется (в script_results ничего,
	// даже acked-следа нет). Санитайз ПОСЛЕ switch — накрывает и дописанные
	// выше пометки. См. internal/agent/scriptenc.
	res.stdout = scriptenc.SanitizeUTF8(res.stdout)
	res.stderr = scriptenc.SanitizeUTF8(res.stderr)
	return res
}

// interpreterCommand сопоставляет имя интерпретатора с командой и аргументами.
// Содержимое скрипта передаётся инлайном (-c / -Command), без временных файлов.
func interpreterCommand(interpreter, content string) (string, []string) {
	switch interpreter {
	case "", "shell", "sh":
		return "sh", []string{"-c", content}
	case "bash":
		return "bash", []string{"-c", content}
	case "python", "python3":
		return "python3", []string{"-c", content}
	case "powershell", "pwsh":
		// UTF-8-префикс: stdout командлетов на RU-Windows иначе в OEM/ANSI
		// → невалидный UTF-8 → Marshal(ScriptResult) падает. См. scriptenc.
		psContent := scriptenc.PSUTF8Prefix + content
		if runtime.GOOS == "windows" {
			return "powershell", []string{"-NonInteractive", "-NoProfile", "-Command", psContent}
		}
		return "pwsh", []string{"-NonInteractive", "-NoProfile", "-Command", psContent}
	default:
		return "", nil
	}
}

// randID — случайный 128-битный идентификатор запуска (hex), для идемпотентности.
func randID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

package command

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"github.com/Floodww/RoutineOps/internal/agent/scriptenc"
)

// interpreterCmd выбирает интерпретатор по полю platform задачи:
// windows → powershell -Command, иначе (macOS/Linux) → bash -c.
//
// Сравнение РЕГИСТРОНЕЗАВИСИМОЕ намеренно: значение platform едет из разных мест с
// разным регистром — UI шлёт строчное "windows" (web agentPlatform()), а справочник
// скриптов и серверная валидация оперируют "Windows". Строгое `case "Windows"`
// молча отправляло UI-задачи на Windows в bash-ветку → «exec: bash not found in
// %PATH%», все скрипты на Windows через интерфейс падали. Нормализуем в одном месте,
// где значение реально используется, а не чиним каждый источник по отдельности.
func interpreterCmd(ctx context.Context, platform, script string) *exec.Cmd {
	switch strings.ToLower(platform) {
	case "windows":
		return exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", scriptenc.PSUTF8Prefix+script)
	default: // macOS, Linux
		return exec.CommandContext(ctx, "bash", "-c", script)
	}
}

// runScript выполняет script_content интерпретатором по полю platform задачи.
// stdout → output задачи, stderr → error_log при ошибке.
//
// Оба буфера прогоняются через scriptenc.SanitizeUTF8: proto3 string обязан быть
// валидным UTF-8, иначе ReportTaskResult падает на маршалинге и результат задачи
// теряется навсегда (задача виснет в статусе acked на сервере). Backstop
// гарантирует, что отчёт уйдёт при любой кодировке вывода.
func runScript(ctx context.Context, platform, script string) (stdout, stderr string, err error) {
	cmd := interpreterCmd(ctx, platform, script)
	// Capped-буферы: скрипт с гигабайтным выводом не раздувает RAM агента (под
	// root) — потолок держится ВО ВРЕМЯ выполнения, а не пост-фактум (scriptenc).
	var out, errBuf scriptenc.CaptureBuffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	// Без WaitDelay скрипт с фоновым потомком (`daemon &`), унаследовавшим stdout,
	// подвешивал Run() навсегда — и слот семафора executor'а вместе с ним
	// (см. scriptenc.PipeWaitDelay). ErrWaitDelay подменяет ТОЛЬКО nil, то есть
	// сам скрипт вышел успешно — это успех, но пайпы закрыты принудительно и
	// пишущие потомки будут прерваны (EPIPE). Пометка об этом идёт в STDOUT, а
	// не в stderr: на успехе executor кладёт в TaskResult только Output, stderr
	// выбрасывает — пометка в stderr до оператора не дошла бы. AppendNote
	// гарантирует, что пометку не съест обрезка (она режет именно хвост).
	cmd.WaitDelay = scriptenc.PipeWaitDelay
	err = cmd.Run()

	// Порядок Sanitize → TruncateTotal → AppendNote: кадр >4 МБ сервер отвергает
	// ResourceExhausted'ом, и отчёт навсегда застревает в голове outbox-очереди
	// (scriptenc.MaxOutputBytes). TruncateTotal берёт реальный объём из
	// CaptureBuffer.Total — честное «из M», а не константа из уже-урезанной строки
	// (#1.6). WaitDelay-пометка дописывается ПОСЛЕ обрезки, по её ≤ Max выходу.
	stdout = scriptenc.TruncateTotal(scriptenc.SanitizeUTF8(out.String()), out.Total())
	stderr = scriptenc.TruncateTotal(scriptenc.SanitizeUTF8(errBuf.String()), errBuf.Total())
	if errors.Is(err, exec.ErrWaitDelay) {
		err = nil
		stdout = scriptenc.AppendNote(stdout, scriptenc.WaitDelayNote)
	}
	return stdout, stderr, err
}

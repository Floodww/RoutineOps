package scripts

import (
	"context"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/outbox"
	"github.com/Floodww/RoutineOps/internal/agent/scriptenc"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/protobuf/proto"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestRunnerEnqueuesResult(t *testing.T) {
	var got []byte
	r := &Runner{
		log:     discardLog(),
		enqueue: func(kind string, data []byte) error { got = data; return nil },
		exec: func(_ context.Context, interp, content string) execResult {
			if interp != "shell" || content != "echo hi" {
				t.Fatalf("в exec пришло interp=%q content=%q", interp, content)
			}
			return execResult{exitCode: 0, stdout: "hi\n"}
		},
	}
	p := &pb.ScriptPolicy{
		PolicyId: "p1", Name: "greet", Interpreter: "shell", ScriptContent: "echo hi",
		Trigger: pb.ScriptTrigger_SCRIPT_TRIGGER_ON_CONNECT,
	}
	r.Run(context.Background(), p, pb.ScriptTrigger_SCRIPT_TRIGGER_ON_CONNECT)

	if got == nil {
		t.Fatal("результат не поставлен в очередь")
	}
	var res pb.ScriptResult
	if err := proto.Unmarshal(got, &res); err != nil {
		t.Fatal(err)
	}
	if res.GetPolicyId() != "p1" || res.GetExitCode() != 0 || res.GetStdout() != "hi\n" {
		t.Fatalf("неверный ScriptResult: %+v", &res)
	}
	if res.GetRunId() == "" {
		t.Fatal("run_id пустой")
	}
	if res.GetTrigger() != pb.ScriptTrigger_SCRIPT_TRIGGER_ON_CONNECT {
		t.Fatalf("trigger=%v", res.GetTrigger())
	}
	if res.GetStartedAt() == 0 || res.GetFinishedAt() == 0 {
		t.Fatalf("метки времени не проставлены: %+v", &res)
	}
}

// TestDefaultExecRealShell — реальный запуск shell (быстрый, кроссплатформенно
// на unix). Проверяет exit-код и stdout.
func TestDefaultExecRealShell(t *testing.T) {
	res := defaultExec(context.Background(), "shell", "printf out; exit 3")
	if res.exitCode != 3 {
		t.Fatalf("exit_code=%d want 3", res.exitCode)
	}
	if res.stdout != "out" {
		t.Fatalf("stdout=%q want %q", res.stdout, "out")
	}
}

// Политика, поднявшая фоновый процесс с унаследованным stdout, НЕ подвешивает
// defaultExec до его смерти: WaitDelay закрывает пайпы, exit-код самого скрипта
// (0) сохраняется, в stderr — человекочитаемая пометка.
func TestDefaultExecBackgroundChildDoesNotHang(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh-скрипт: unix-платформы")
	}
	start := time.Now()
	res := defaultExec(context.Background(), "shell", "sleep 30 & echo hi")
	elapsed := time.Since(start)
	if res.exitCode != 0 {
		t.Fatalf("exit_code=%d want 0 (ErrWaitDelay — успех): stderr=%q", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stdout, "hi") {
		t.Errorf("stdout=%q, ожидали вывод до фонового потомка", res.stdout)
	}
	if !strings.Contains(res.stderr, "будут прерваны") {
		t.Errorf("stderr=%q, ожидали ЧЕСТНУЮ пометку WaitDelayNote (пайпы закрыты — пишущие потомки будут прерваны)", res.stderr)
	}
	if elapsed >= 20*time.Second {
		t.Fatalf("defaultExec висел %v — WaitDelay не сработал", elapsed)
	}
}

func TestDefaultExecUnknownInterpreter(t *testing.T) {
	res := defaultExec(context.Background(), "brainfuck", "++")
	if res.exitCode != -1 {
		t.Fatalf("ожидали exit -1 для неизвестного интерпретатора, got %d", res.exitCode)
	}
}

// №4.5 (регресс порядка sanitize/append): пометка обязана пережить UTF-8-
// санитайз, даже когда он РАСШИРЯЕТ хвост за MaxOutputBytes. defaultExec
// заливает stderr одиночными 0xC0 (каждый → 3-байтовый U+FFFD при санитайзе,
// ~3x рост) до потолка CaptureBuffer и валится по таймауту (ветка с пометкой
// «прервано по таймауту»). Прежний порядок (AppendNote на СЫРОЙ хвост →
// SanitizeUTF8 → TruncateOutput в Run) уводил пометку за 256 КиБ и срезал её;
// правильный (Sanitize → AppendNote) держит её. Пишем через Runner.Run, чтобы
// пройти и финальный TruncateOutput. Дедлайн 500мс против мгновенной заливки —
// детерминизм не на тайминге, а на факте DeadlineExceeded.
func TestDefaultExecNoteSurvivesExpandingSanitize(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh + /dev/zero + tr: unix-платформы")
	}
	var got []byte
	r := &Runner{log: discardLog(), exec: defaultExec,
		enqueue: func(_ string, data []byte) error { got = data; return nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	// ЧЕРЕДУЮЩИЙСЯ паттерн "A\300": каждый одиночный 0xC0 между валидными 'A' —
	// отдельный невалидный ПРОГОН, поэтому SanitizeUTF8 (strings.ToValidUTF8
	// заменяет каждый прогон одним U+FFFD) расширяет его в 3 байта, а не
	// схлопывает. Сплошной прогон 0xC0 (tr) дал бы ОДИН U+FFFD на весь хвост и
	// расширения бы не было — баг не воспроизвёлся бы. 300 КиБ пар → CaptureBuffer
	// срежет до ~260 КиБ сырых, после санитайза ~530 КиБ; затем блок до дедлайна.
	r.Run(ctx, &pb.ScriptPolicy{
		PolicyId:      "p-expand",
		Interpreter:   "shell",
		ScriptContent: `awk 'BEGIN{for(i=0;i<300000;i++)printf "A\300"}' >&2; sleep 10`,
	}, pb.ScriptTrigger_SCRIPT_TRIGGER_UNSPECIFIED)

	var result pb.ScriptResult
	if err := proto.Unmarshal(got, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !strings.Contains(result.GetStderr(), "прервано по таймауту") {
		t.Errorf("пометка о таймауте не пережила расширяющий санитайз (регресс порядка): хвост=%q",
			tail(result.GetStderr(), 80))
	}
	if n := len(result.GetStderr()); n > scriptenc.MaxOutputBytes+512 {
		t.Errorf("stderr=%d байт, ожидали ≤ MaxOutputBytes(+пометка)", n)
	}
}

// tail возвращает последние n байт строки (для диагностики без гигантских дампов).
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// Гарантия, что Runner удовлетворяет интерфейсу policyRunner.
var _ policyRunner = (*Runner)(nil)

// Гарантия, что строковый вид kind совпадает с outbox.
func TestScriptKindConst(t *testing.T) {
	if outbox.KindScript != "script" {
		t.Fatalf("KindScript=%q", outbox.KindScript)
	}
}

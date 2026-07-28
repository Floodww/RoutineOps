package uninstall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"

	"github.com/Floodww/RoutineOps/internal/agent/scriptenc"
)

// captureCap — потолок захвата вывода деинсталлятора. Чуть больше потолка
// отчёта, чтобы итоговая обрезка увидела превышение и честно пометила его, а не
// молча отдала ровно обрезанный хвост. Без потолка вообще болтливый
// деинсталлятор (msiexec с /l*v в аргументах вендора) съел бы память агента.
const captureCap = scriptenc.MaxOutputBytes + 4*1024

// runCommand запускает деинсталлятор и возвращает объединённый вывод.
//
// Контекст с дедлайном ставит вызывающий (executor): истечение ctx УБИВАЕТ
// процесс. Для деинсталляции это осознанный компромисс — убитый на середине
// msiexec оставит продукт в полуснятом виде, но альтернатива (ждать без
// ограничения) вешает слот исполнения задач навсегда. Поэтому потолок один и
// тот же со скриптами, и его истечение отчитывается как FAILED с явной
// формулировкой, а не как «снято».
func runCommand(ctx context.Context, name string, args []string, extraEnv []string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(extraEnv) > 0 {
		cmd.Env = append(cmd.Environ(), extraEnv...)
	}
	var buf bytes.Buffer
	w := &capWriter{buf: &buf, limit: captureCap}
	cmd.Stdout = w
	cmd.Stderr = w
	// Stdin из /dev/null: деинсталлятор, спросивший подтверждение, обязан
	// упасть на EOF, а не ждать ввода, которого в session 0 не будет никогда.
	cmd.Stdin = nil

	err := cmd.Run()
	out := buf.String()
	if err == nil {
		return out, nil
	}
	if ctxErr := ctx.Err(); errors.Is(ctxErr, context.DeadlineExceeded) {
		return out, fmt.Errorf("деинсталлятор не уложился в отведённое время и был прерван (продукт мог остаться снятым частично): %s", name)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out, fmt.Errorf("%s завершился с кодом %d", name, ee.ExitCode())
	}
	return out, fmt.Errorf("%s не запустился: %w", name, err)
}

// capWriter пишет в буфер не больше limit байт, дальнейшее молча отбрасывает
// (пометку об обрезке добавляет уже scriptenc.TruncateOutput на выходе).
type capWriter struct {
	buf   *bytes.Buffer
	limit int
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.limit - w.buf.Len(); room > 0 {
		if len(p) <= room {
			w.buf.Write(p)
		} else {
			w.buf.Write(p[:room])
		}
	}
	// Всегда сообщаем полную длину: короткий ответ означал бы для exec.Cmd
	// ошибку записи и прервал бы сам деинсталлятор на середине.
	return len(p), nil
}

//go:build darwin || linux

package reboot

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// defaultMessage — текст по умолчанию, когда оператор причину не указал.
const defaultMessage = "Устройство будет перезагружено администратором"

// delayMinutes переводит отсрочку в целые минуты для `shutdown -r +N`: и на
// macOS (BSD shutdown), и на Linux (systemd) секундной гранулярности у отсрочки
// нет. Округляем ВВЕРХ и не ниже одной минуты — в сторону БОЛЬШЕГО
// предупреждения. Округление вниз (или +0, что значит «сейчас») отняло бы у
// сотрудника уже обещанное ему время, а это ровно тот случай, когда ошибка
// должна быть в безопасную сторону.
func delayMinutes(d time.Duration) int {
	m := int((d + time.Minute - 1) / time.Minute)
	if m < 1 {
		m = 1
	}
	return m
}

// scheduleArgs собирает аргументы `shutdown`: -r (перезагрузка), +N (отсрочка в
// минутах) и текст, который shutdown рассылает как wall-сообщение.
//
// Известный потолок: wall доходит до терминальных сессий, но НЕ до графического
// сеанса — сотрудник за десктопом macOS/Linux системного предупреждения с
// причиной не увидит, только сам факт перезагрузки. Паритет с Windows-диалогом
// потребовал бы уведомления из трея (юзер-сессия) и сюда не относится.
func scheduleArgs(delay time.Duration, msg string) []string {
	if msg == "" {
		msg = defaultMessage
	}
	return []string{"-r", "+" + strconv.Itoa(delayMinutes(delay)), msg}
}

func schedule(ctx context.Context, delay time.Duration, msg string) (time.Duration, error) {
	args := scheduleArgs(delay, msg)
	out, err := exec.CommandContext(ctx, "shutdown", args...).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("shutdown %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	// Возвращаем ФАКТИЧЕСКУЮ отсрочку (после округления до минут), а не
	// запрошенную: сервер покажет оператору и запишет в аудит то время, которое
	// реально задано планировщику.
	return time.Duration(delayMinutes(delay)) * time.Minute, nil
}

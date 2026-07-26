//go:build windows

package reboot

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// defaultMessage — что показать сотруднику, если оператор причину не указал.
// Пустой текст в `shutdown /c` был бы хуже отсутствия флага: диалог без
// объяснения выглядит как сбой.
const defaultMessage = "Устройство будет перезагружено администратором"

// scheduleArgs собирает аргументы для `shutdown`. Чистая функция — на Windows
// нельзя прогнать реальную перезагрузку в тесте, поэтому проверяемой границей
// становится именно набор аргументов.
//
//	/r — перезагрузка (а не выключение);
//	/t — отсрочка в СЕКУНДАХ (Windows принимает секунды нативно, округлять не надо);
//	/f — по истечении отсрочки приложения закрываются принудительно. Без этого
//	     несохранённый документ блокирует перезагрузку, и команда оператора молча
//	     не срабатывает: задача отчитана успехом, а машина осталась как была.
//	     Форс применяется именно В КОНЦЕ отсрочки, поэтому предупреждение
//	     сотрудник всё равно получает;
//	/c — текст в системном предупреждении.
func scheduleArgs(delay time.Duration, msg string) []string {
	if msg == "" {
		msg = defaultMessage
	}
	secs := int(delay.Round(time.Second) / time.Second)
	if secs < 0 {
		secs = 0
	}
	return []string{"/r", "/t", strconv.Itoa(secs), "/f", "/c", msg}
}

func schedule(ctx context.Context, delay time.Duration, msg string) (time.Duration, error) {
	args := scheduleArgs(delay, msg)
	out, err := exec.CommandContext(ctx, "shutdown", args...).CombinedOutput()
	if err != nil {
		// Вывод shutdown кладём в ошибку целиком: он объясняет отказ по существу
		// (нет прав SeShutdownPrivilege, уже запланирована другая перезагрузка —
		// код 1190), и без него разбор полевого случая упирается в «exit status 1».
		return 0, fmt.Errorf("shutdown %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return delay, nil
}

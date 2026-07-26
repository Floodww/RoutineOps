//go:build windows

package reboot

import (
	"testing"
	"time"
)

// Windows принимает отсрочку в секундах нативно — округлять до минут не нужно, и
// именно поэтому набор аргументов отличается от unix-варианта.
func TestScheduleArgs_SecondsAndForce(t *testing.T) {
	args := scheduleArgs(90*time.Second, "Установка обновлений")
	want := []string{"/r", "/t", "90", "/f", "/c", "Установка обновлений"}
	if len(args) != len(want) {
		t.Fatalf("args = %q, want %q", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args = %q, want %q", args, want)
		}
	}
}

// /f обязателен: без него несохранённый документ блокирует перезагрузку, задача
// отчитывается успехом, а машина остаётся как была — молчаливый отказ команды
// оператора. Форс применяется в КОНЦЕ отсрочки, предупреждение сотрудник получает.
func TestScheduleArgs_AlwaysForces(t *testing.T) {
	for _, d := range []time.Duration{MinDelay, DefaultDelay, MaxDelay} {
		args := scheduleArgs(d, "причина")
		found := false
		for _, a := range args {
			if a == "/f" {
				found = true
			}
		}
		if !found {
			t.Fatalf("отсрочка %v: аргумент /f потерян — перезагрузка станет отменяемой молча (args=%q)", d, args)
		}
	}
}

func TestScheduleArgs_EmptyReasonGetsDefault(t *testing.T) {
	args := scheduleArgs(time.Minute, "")
	if args[len(args)-1] != defaultMessage {
		t.Fatalf("args = %q, ожидали текст по умолчанию последним аргументом", args)
	}
}

// Отсрочка не должна уезжать в отрицательные секунды ни при каком входе: `/t -1`
// shutdown отвергнет, и команда оператора превратится в ошибку вместо действия.
func TestScheduleArgs_NeverNegativeSeconds(t *testing.T) {
	args := scheduleArgs(-time.Hour, "причина")
	if args[2] != "0" {
		t.Fatalf("аргумент /t = %q, ожидали 0", args[2])
	}
}

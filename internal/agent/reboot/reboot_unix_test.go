//go:build darwin || linux

package reboot

import (
	"strings"
	"testing"
	"time"
)

// Округление отсрочки до минут обязано идти ВВЕРХ: и BSD (macOS), и systemd
// принимают только целые минуты, а округление вниз отняло бы у сотрудника уже
// обещанное время. Отдельно проверяем, что не получается «+0» — это значило бы
// «перезагрузить сейчас», то есть без предупреждения вовсе.
func TestDelayMinutes_RoundsUpNeverToZero(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want int
	}{
		{MinDelay, 1},         // 10с → 1 минута, а не 0
		{time.Second, 1},      // защита от «сейчас» даже на секунде
		{time.Minute, 1},      // ровная минута не раздувается
		{time.Minute + 1, 2},  // на секунду больше — уже вверх
		{90 * time.Second, 2}, // 1.5 минуты
		{5 * time.Minute, 5},  // обычный случай
		{MaxDelay, 24 * 60},   // потолок
		{0, 1},                // clampDelay сюда 0 не пропустит, но и здесь не «сейчас»
		{-time.Minute, 1},     // то же для отрицательной
	}
	for _, c := range cases {
		if got := delayMinutes(c.in); got != c.want {
			t.Fatalf("delayMinutes(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestScheduleArgs(t *testing.T) {
	args := scheduleArgs(5*time.Minute, "Установка обновлений")
	want := []string{"-r", "+5", "Установка обновлений"}
	if len(args) != len(want) {
		t.Fatalf("args = %q, want %q", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args = %q, want %q", args, want)
		}
	}
}

// Пустая причина не должна превращаться в пустой аргумент: перезагрузка без
// объяснения читается сотрудником как сбой устройства.
func TestScheduleArgs_EmptyReasonGetsDefault(t *testing.T) {
	args := scheduleArgs(time.Minute, "")
	if len(args) != 3 || args[2] != defaultMessage {
		t.Fatalf("args = %q, ожидали текст по умолчанию третьим аргументом", args)
	}
}

// Текст едет ОДНИМ аргументом (exec без оболочки), поэтому пробелы в нём
// безопасны и не превращаются в отдельные аргументы shutdown.
func TestScheduleArgs_MessageStaysSingleArgument(t *testing.T) {
	msg := "плановое обслуживание -r сегодня"
	args := scheduleArgs(time.Minute, msg)
	if len(args) != 3 {
		t.Fatalf("args = %q, ожидали ровно 3 аргумента", args)
	}
	if args[2] != msg {
		t.Fatalf("текст исказился: %q", args[2])
	}
	if strings.Contains(args[1], " ") {
		t.Fatalf("аргумент отсрочки содержит пробел: %q", args[1])
	}
}

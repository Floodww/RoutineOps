package reboot

import (
	"strings"
	"testing"
	"time"
)

// Границы отсрочки. Главный случай — 0: сервер не задал поле, и это ОБЯЗАНО
// означать дефолтную отсрочку, а не мгновенную перезагрузку без предупреждения
// (нулевое значение не должно быть самым деструктивным вариантом).
func TestClampDelay(t *testing.T) {
	cases := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"поле не задано → дефолт, не «сейчас»", 0, DefaultDelay},
		{"отрицательная → дефолт", -5 * time.Minute, DefaultDelay},
		{"меньше минимума → минимум", time.Second, MinDelay},
		{"ровно минимум", MinDelay, MinDelay},
		{"обычное значение проходит как есть", 5 * time.Minute, 5 * time.Minute},
		{"больше потолка → потолок", 72 * time.Hour, MaxDelay},
		{"ровно потолок", MaxDelay, MaxDelay},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := clampDelay(c.in); got != c.want {
				t.Fatalf("clampDelay(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestSanitizeMessage(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"обычный текст", "Установка обновлений", "Установка обновлений"},
		{"переводы строк сворачиваются в пробел", "первая\nвторая\r\nтретья", "первая вторая третья"},
		{"табы и кратные пробелы сжимаются", "много\t\t  пробелов", "много пробелов"},
		{"края обрезаются", "  \n текст \t ", "текст"},
		{"управляющие символы выкидываются", "текст\x00\x07ещё", "текстещё"},
		{"пустая строка остаётся пустой", "   \n\t ", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeMessage(c.in); got != c.want {
				t.Fatalf("sanitizeMessage(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// Обрезка длинного текста идёт по границе РУН: на байтах кириллица порвалась бы
// пополам, и в предупреждении сотруднику вместо причины оказался бы мусор ровно
// в месте разреза.
func TestSanitizeMessage_TruncatesOnRuneBoundary(t *testing.T) {
	long := strings.Repeat("я", maxMessageRunes+50)
	got := sanitizeMessage(long)
	if n := len([]rune(got)); n != maxMessageRunes {
		t.Fatalf("длина в рунах = %d, want %d", n, maxMessageRunes)
	}
	if !strings.HasPrefix(long, got) {
		t.Fatal("обрезанный текст не является префиксом исходного — рунная граница нарушена")
	}
	for _, r := range got {
		if r == '�' {
			t.Fatal("в обрезанном тексте появился U+FFFD — рез прошёл посреди руны")
		}
	}
}

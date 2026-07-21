package scriptenc

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// #7: CaptureBuffer держит потолок памяти ВО ВРЕМЯ выполнения — гигабайтный
// вывод скрипта не раздувает RAM агента; Write всегда сообщает полный len(p)
// (иначе exec посчитал бы это ошибкой пайпа), но буферизует не больше captureCap.
func TestCaptureBuffer_CapsMemory(t *testing.T) {
	var c CaptureBuffer
	chunk := make([]byte, 1<<20) // 1 МиБ за запись
	total := 0
	for i := 0; i < 64; i++ { // 64 МиБ суммарно
		n, err := c.Write(chunk)
		if err != nil || n != len(chunk) {
			t.Fatalf("Write вернул (%d,%v), ожидалось (%d,nil)", n, err, len(chunk))
		}
		total += n
	}
	if got := len(c.String()); got > captureCap {
		t.Fatalf("буфер %d байт превысил потолок captureCap=%d", got, captureCap)
	}
	if total != 64<<20 {
		t.Fatalf("Write недосчитал записанное: %d, want %d", total, 64<<20)
	}
	// Превышение captureCap → итоговый TruncateOutput дописывает пометку об обрезке.
	if out := TruncateOutput(c.String()); !strings.Contains(out, "вывод обрезан") {
		t.Fatal("TruncateOutput не пометил обрезку при переполнении CaptureBuffer")
	}
}

// TestSanitizeUTF8 проверяет, что невалидные UTF-8 байты (норма на RU-Windows,
// где stdout приезжает в cp866/cp1251) заменяются заглушкой и строка становится
// валидной для proto3-маршалинга — иначе результат задачи/политики теряется.
func TestSanitizeUTF8(t *testing.T) {
	// Валидная кириллица и ASCII должны пройти без изменений.
	if got := SanitizeUTF8("Привет, world 123"); got != "Привет, world 123" {
		t.Errorf("валидный UTF-8 не должен меняться: %q", got)
	}
	// Невалидная последовательность (0xFF/0xFE — недопустимые стартовые байты).
	bad := "ok\xff\xfetail"
	got := SanitizeUTF8(bad)
	if !utf8.ValidString(got) {
		t.Errorf("после санитайза строка обязана быть валидным UTF-8: %q", got)
	}
	if !strings.Contains(got, "ok") || !strings.Contains(got, "tail") {
		t.Errorf("полезные ASCII-части должны сохраниться: %q", got)
	}
}

// Вывод длиннее MaxOutputBytes обязан обрезаться: иначе gRPC-кадр перерастает
// серверный лимит 4 МБ, сервер отвечает ResourceExhausted, и отчёт намертво встаёт
// в голове outbox-очереди, блокируя доставку всего остального.
func TestTruncateOutput(t *testing.T) {
	short := "маленький вывод"
	if got := TruncateOutput(short); got != short {
		t.Errorf("короткий вывод не должен меняться: %q", got)
	}

	// Кириллица: граница обрезки попадает в середину двухбайтовой руны.
	long := strings.Repeat("я", MaxOutputBytes)
	got := TruncateOutput(long)
	if len(got) <= MaxOutputBytes-4 {
		t.Errorf("обрезали слишком агрессивно: %d байт", len(got))
	}
	if !utf8.ValidString(got) {
		t.Error("после обрезки строка обязана оставаться валидным UTF-8")
	}
	if !strings.Contains(got, "вывод обрезан") {
		t.Error("обрезание должно быть видно человеку")
	}
	body := strings.TrimSuffix(got, got[strings.Index(got, "\n\n[вывод обрезан"):])
	if len(body) > MaxOutputBytes {
		t.Errorf("тело после обрезки = %d байт, максимум %d", len(body), MaxOutputBytes)
	}
}

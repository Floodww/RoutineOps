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

// №4.5 (хвост): пометка (WaitDelayNote и др.) дописывается в хвост, а обрезка
// режет именно хвост — прямая конкатенация теряла пометку на выводе ≥ 256 КиБ.
// AppendNote обязан гарантировать выживание пометки и итог ≤ MaxOutputBytes,
// чтобы повторный TruncateOutput поверх был no-op.
func TestAppendNote(t *testing.T) {
	// Короткий вывод: пометка дописывается как есть.
	if got := AppendNote("out", "[note]"); got != "out\n[note]" {
		t.Errorf("короткий вывод: %q", got)
	}

	// Гигантский вывод (кириллица — граница режет двухбайтовые руны).
	huge := strings.Repeat("я", MaxOutputBytes)
	got := AppendNote(huge, WaitDelayNote)
	if !strings.HasSuffix(got, WaitDelayNote) {
		t.Fatalf("пометка потеряна на выводе ≥ MaxOutputBytes: хвост %q", got[len(got)-80:])
	}
	if len(got) > MaxOutputBytes {
		t.Errorf("итог %d байт > MaxOutputBytes %d — внешний TruncateOutput срежет пометку", len(got), MaxOutputBytes)
	}
	if TruncateOutput(got) != got {
		t.Error("повторный TruncateOutput поверх AppendNote обязан быть no-op")
	}
	if !utf8.ValidString(got) {
		t.Error("после подрезки строка обязана оставаться валидным UTF-8")
	}
	if !strings.Contains(got, "вывод обрезан") {
		t.Error("подрезка самого вывода должна быть видна человеку")
	}
}

// #1.6: пометка обрезки показывает РЕАЛЬНЫЙ объём вывода (CaptureBuffer.Total),
// а не len уже-урезанной строки. Прежде «отброшено N из M» давало ~4 КиБ из
// ~260 КиБ на любом объёме — 300 КиБ и 5 ГБ выглядели одинаково.
func TestTruncateTotal_ReportsRealSize(t *testing.T) {
	captured := strings.Repeat("a", MaxOutputBytes+100) // то, что осталось после captureCap
	const realTotal = 5_000_000

	got := TruncateTotal(captured, realTotal)
	if !strings.Contains(got, "5000000") {
		t.Errorf("пометка не показала реальный объём %d: %q", realTotal, got[len(got)-120:])
	}
	if strings.Contains(got, "262244") { // = len(captured), старое ложное M
		t.Errorf("пометка показала len урезанной строки вместо реального объёма: %q", got[len(got)-120:])
	}
	// total < len(captured) не должно давать отрицательное «отброшено».
	if got2 := TruncateTotal(captured, 10); strings.Contains(got2, "-") {
		t.Errorf("отрицательный объём отброшенного при total<len: %q", got2[len(got2)-80:])
	}
}

// CaptureBuffer.Total считает ВЕСЬ поток, включая отброшенное сверх captureCap;
// в памяти при этом держится не больше captureCap.
func TestCaptureBuffer_TotalCountsBeyondCap(t *testing.T) {
	var b CaptureBuffer
	huge := make([]byte, captureCap*3)
	n, _ := b.Write(huge)
	if n != len(huge) {
		t.Fatalf("Write вернул %d, ожидали %d (иначе exec сочтёт ошибкой пайпа)", n, len(huge))
	}
	if b.Total() != len(huge) {
		t.Errorf("Total()=%d, ожидали %d (весь поток)", b.Total(), len(huge))
	}
	if len(b.String()) > captureCap {
		t.Errorf("в памяти %d байт > captureCap %d", len(b.String()), captureCap)
	}
}

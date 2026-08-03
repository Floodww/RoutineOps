package api

import (
	"net/http/httptest"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// 🔴 Отчёт печатался по-русски независимо от языка панели. Англоязычный оператор
// работал с английским экраном и скачивал русский файл — документ, который сам
// прочесть не может, и который нечем сверить с тем, что он видел.
func TestReportLocaleFor(t *testing.T) {
	cases := []struct {
		name       string
		query      string
		accept     string
		wantYes    string
		wantComma  rune
		wantHeader string
	}{
		{"по умолчанию русский", "", "", "да", ';', "Устройство"},
		{"явный английский", "?lang=en", "", "yes", ',', "Device"},
		{"явный русский", "?lang=ru", "", "да", ';', "Устройство"},
		// Детектор i18next отдаёт региональные варианты — «en-US», а не «en».
		{"региональный вариант", "?lang=en-US", "", "yes", ',', "Device"},
		{"подчёркивание вместо дефиса", "?lang=en_GB", "", "yes", ',', "Device"},
		{"регистр не важен", "?lang=EN", "", "yes", ',', "Device"},
		// Заголовок — запасной путь: язык интерфейса меняют, не трогая браузер.
		{"откат на Accept-Language", "", "en-GB,en;q=0.9", "yes", ',', "Device"},
		{"параметр важнее заголовка", "?lang=ru", "en-US", "да", ';', "Устройство"},
		// Неизвестный язык не должен ронять выгрузку: отчёт нужнее отказа.
		{"неизвестный язык падает на русский", "?lang=zz", "", "да", ';', "Устройство"},
		{"мусор в заголовке", "", "!!!", "да", ';', "Устройство"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/v1/compliance/report.csv"+c.query, nil)
			if c.accept != "" {
				r.Header.Set("Accept-Language", c.accept)
			}
			loc := reportLocaleFor(r)
			if loc.boolWord(true) != c.wantYes {
				t.Errorf("boolWord(true) = %q, ожидалось %q", loc.boolWord(true), c.wantYes)
			}
			if loc.comma != c.wantComma {
				t.Errorf("разделитель = %q, ожидался %q", loc.comma, c.wantComma)
			}
			if loc.headers[0] != c.wantHeader {
				t.Errorf("первый заголовок = %q, ожидался %q", loc.headers[0], c.wantHeader)
			}
		})
	}
}

// 🔴 Разделитель обязан меняться ВМЕСТЕ с языком. Excel берёт разделитель списка
// из системной локали: зашитая «;» чинила русский Excel и ровно так же ломала
// английский — весь отчёт складывался в одну колонку.
func TestReportLocaleCommaMatchesLanguage(t *testing.T) {
	if reportLocales["ru"].comma == reportLocales["en"].comma {
		t.Fatal("разделитель одинаков для ru и en — одна из локалей откроется в Excel одной колонкой")
	}
}

// Набор причин задаётся в storage; локаль, отставшая от него, молча напечатала бы
// оператору сырой код причины вместо формулировки.
func TestReportLocaleCoversEveryReason(t *testing.T) {
	reasons := []string{
		storage.ComplianceVulnerable,
		storage.ComplianceUnverified,
		storage.ComplianceStale,
		storage.ComplianceOutdatedAgent,
		storage.ComplianceDegraded,
		storage.ComplianceLocked,
	}
	for lang, loc := range reportLocales {
		for _, reason := range reasons {
			if _, ok := loc.reasons[reason]; !ok {
				t.Errorf("локаль %q не переводит причину %q", lang, reason)
			}
		}
		if len(loc.headers) != 11 {
			t.Errorf("локаль %q: заголовков %d, а колонок в выгрузке 11", lang, len(loc.headers))
		}
	}
}

// Незнакомая причина отдаётся как есть: набор расширяется на сервере, и новая
// причина должна быть видна в отчёте, а не исчезнуть из него.
func TestTranslateReasonsKeepsUnknown(t *testing.T) {
	loc := reportLocales["en"]
	got := loc.translateReasons([]string{storage.ComplianceLocked, "brand_new_reason"})
	if len(got) != 2 || got[0] != "locked" || got[1] != "brand_new_reason" {
		t.Fatalf("translateReasons = %v", got)
	}
}

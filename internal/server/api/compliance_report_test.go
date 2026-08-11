package api_test

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

const bom = "\xEF\xBB\xBF"

func getReportJSON(t *testing.T, rtr http.Handler, token string) storage.ComplianceReport {
	t.Helper()
	w := authedDo(t, rtr, http.MethodGet, "/api/v1/compliance/report", nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /compliance/report = %d, body=%s", w.Code, w.Body)
	}
	var report storage.ComplianceReport
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	return report
}

// getReportCSV возвращает разобранный CSV без BOM и сам ответ.
func getReportCSV(t *testing.T, rtr http.Handler, token, query string, comma rune) ([][]string, *http.Response, string) {
	t.Helper()
	w := authedDo(t, rtr, http.MethodGet, "/api/v1/compliance/report.csv"+query, nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /compliance/report.csv%s = %d, body=%s", query, w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.HasPrefix(body, bom) {
		t.Fatalf("выгрузка без BOM — Excel испортит кириллицу; начало: %q", body[:min(12, len(body))])
	}
	rd := csv.NewReader(strings.NewReader(strings.TrimPrefix(body, bom)))
	rd.Comma = comma
	rd.FieldsPerRecord = -1
	rows, err := rd.ReadAll()
	if err != nil {
		t.Fatalf("разбор CSV с разделителем %q: %v", comma, err)
	}
	return rows, w.Result(), body
}

// JSON и CSV обязаны быть одним и тем же отчётом: тенант оба берут из доверенных
// claims через общую функцию именно затем, чтобы выгрузка не разъезжалась с экраном.
// Сверяется числом строк — если один из хендлеров начнёт брать тенант иначе, парк в
// файле перестанет совпадать с парком в панели.
func TestComplianceReport_JSONAndCSVAgree(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	ctx := context.Background()
	token := authToken(t, rtr, db)

	// Хотя бы одна машина в отчёте: пустой отчёт не проверяет ни строку выгрузки.
	//
	// Машина обязана быть ЗАЭНРОЛЛЕННОЙ. Раньше здесь стояло голое CreatePendingDevice —
	// не потому, что тест про pending, а потому что это был самый короткий способ завести
	// строку. С тех пор отчёт перестал показывать невостребованные токены, и строка в
	// статусе pending перестала быть машиной парка: тест сверял бы JSON с CSV на предмете,
	// которого в отчёте нет по построению.
	hostname := "host-compliance-" + t.Name()
	dev, err := db.CreatePendingDevice(ctx, tenancy.DefaultTenantID, hostname, "linux")
	if err != nil {
		t.Fatalf("CreatePendingDevice: %v", err)
	}
	enrollCtx, finish, err := db.BindTenant(ctx, tenancy.DefaultTenantID)
	if err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	if _, err := db.Scoped(enrollCtx).Exec(enrollCtx,
		`UPDATE devices SET status = 'active', last_seen_at = now() WHERE id = $1`, dev.ID); err != nil {
		finish(false)
		t.Fatalf("перевод устройства в active: %v", err)
	}
	finish(true)

	report := getReportJSON(t, rtr, token)
	if report.Summary.Devices != len(report.Devices) {
		t.Fatalf("summary.devices = %d, строк = %d", report.Summary.Devices, len(report.Devices))
	}
	if report.Summary.Devices != report.Summary.Compliant+report.Summary.NonCompliant {
		t.Fatalf("сводка не сходится: %d ≠ %d + %d",
			report.Summary.Devices, report.Summary.Compliant, report.Summary.NonCompliant)
	}
	if report.Summary.StaleAfterDay != 7 {
		t.Errorf("stale_after_days = %d, want 7", report.Summary.StaleAfterDay)
	}
	var found bool
	for _, d := range report.Devices {
		if d.Hostname == hostname {
			found = true
		}
	}
	if !found {
		t.Fatalf("устройство %s не попало в отчёт", hostname)
	}

	// По умолчанию — русская локаль, разделитель «;».
	rows, resp, _ := getReportCSV(t, rtr, token, "", ';')
	if got := len(rows) - 1; got != len(report.Devices) {
		t.Fatalf("строк в CSV = %d, устройств в JSON = %d", got, len(report.Devices))
	}
	if rows[0][0] != "Устройство" {
		t.Fatalf("шапка CSV по умолчанию = %q, want русскую", rows[0][0])
	}

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q", ct)
	}
	wantName := "compliance-" + time.Now().UTC().Format("2006-01-02") + ".csv"
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, wantName) {
		t.Errorf("Content-Disposition = %q, want имя %q", cd, wantName)
	}
}

// 🔴 Разделитель — часть локали, а не константа: Excel берёт его из системной локали,
// и зашитая «;» складывала англоязычную выгрузку в одну колонку. Пара
// «язык + разделитель» обязана меняться вместе, поэтому проверяется вместе.
func TestComplianceReportCSV_LocaleSwitchesLanguageAndSeparator(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	token := authToken(t, rtr, db)

	ru, _, _ := getReportCSV(t, rtr, token, "?lang=ru", ';')
	if ru[0][0] != "Устройство" {
		t.Fatalf("lang=ru: шапка = %q", ru[0][0])
	}

	en, _, enBody := getReportCSV(t, rtr, token, "?lang=en", ',')
	if en[0][0] != "Device" {
		t.Fatalf("lang=en: шапка = %q", en[0][0])
	}
	// Английская выгрузка не должна содержать «;» как разделитель полей шапки —
	// иначе получается ровно тот случай, когда весь отчёт в одной колонке.
	if strings.Contains(strings.SplitN(strings.TrimPrefix(enBody, bom), "\n", 2)[0], ";") {
		t.Fatalf("в английской шапке остался «;»: %q", en[0])
	}
	if len(ru[0]) != len(en[0]) {
		t.Fatalf("колонок ru=%d, en=%d — локали разошлись по составу", len(ru[0]), len(en[0]))
	}

	// Региональный вариант приводится к базовому тегу: панель шлёт то, что отдал
	// детектор i18next, а он различает en-US и en.
	if rows, _, _ := getReportCSV(t, rtr, token, "?lang=EN-US", ','); rows[0][0] != "Device" {
		t.Fatalf("lang=EN-US: шапка = %q, want английскую", rows[0][0])
	}

	// Неизвестный язык — не ошибка: отчёт нужнее отказа, падаем на язык по умолчанию.
	if rows, _, _ := getReportCSV(t, rtr, token, "?lang=klingon", ';'); rows[0][0] != "Устройство" {
		t.Fatalf("неизвестный язык: шапка = %q, want русскую", rows[0][0])
	}
}

// Заголовок браузера — только откат: оператор мог переключить язык интерфейса, не
// трогая настройки браузера, поэтому ?lang= обязан перебивать Accept-Language.
func TestComplianceReportCSV_QueryBeatsAcceptLanguage(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	token := authToken(t, rtr, db)

	do := func(query, acceptLang string) []string {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/report.csv"+query, nil)
		r.Header.Set("Authorization", token)
		if acceptLang != "" {
			r.Header.Set("Accept-Language", acceptLang)
		}
		w := httptest.NewRecorder()
		rtr.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("csv(%s, %s) = %d", query, acceptLang, w.Code)
		}
		line := strings.SplitN(strings.TrimPrefix(w.Body.String(), bom), "\n", 2)[0]
		return strings.FieldsFunc(strings.TrimRight(line, "\r"), func(r rune) bool { return r == ';' || r == ',' })
	}

	// Заголовок один, без ?lang= — язык берётся из него.
	if got := do("", "en-US,en;q=0.9"); got[0] != "Device" {
		t.Fatalf("Accept-Language: en → шапка %q, want английскую", got[0])
	}
	// ?lang= перебивает заголовок.
	if got := do("?lang=ru", "en-US,en;q=0.9"); got[0] != "Устройство" {
		t.Fatalf("?lang=ru при Accept-Language: en → шапка %q, want русскую", got[0])
	}
}

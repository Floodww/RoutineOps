package api_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
)

// Общее число записей едет заголовком, а не в теле: тело осталось массивом ради
// совместимости. Без заголовка интерфейс не может нарисовать «показано 1–50 из N»
// и молча выдал бы страницу за всю выдачу.
func TestListDevices_TotalCountHeader(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/devices?limit=1", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body)
	}
	if got := w.Header().Get("X-Total-Count"); got == "" {
		t.Fatal("X-Total-Count отсутствует")
	} else if _, err := strconv.Atoi(got); err != nil {
		t.Errorf("X-Total-Count = %q, ожидали число", got)
	}
}

// Страница журнала не должна превышать limit, а заголовок обязан считать всю выдачу.
func TestListAuditLog_PageAndTotal(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	// Три устройства = минимум три записи аудита create_device.
	for _, name := range []string{"host-page-1", "host-page-2", "host-page-3"} {
		createDevice(t, rtr, tok, name, "linux")
	}

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/audit-log?action=create_device&limit=2", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body)
	}
	var entries []map[string]any
	if err := json.NewDecoder(w.Body).Decode(&entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) > 2 {
		t.Errorf("страница = %d записей, limit=2 не применён", len(entries))
	}
	total, err := strconv.Atoi(w.Header().Get("X-Total-Count"))
	if err != nil {
		t.Fatalf("X-Total-Count: %v", err)
	}
	if total < 3 {
		t.Errorf("total = %d, ожидали минимум 3 (счётчик считает выдачу, а не страницу)", total)
	}
}

// Битую границу периода отбиваем 400, а не «фильтр молча выключен»: тихо
// проигнорированная дата даёт выдачу шире запрошенной, и оператор об этом не узнает.
func TestListAuditLog_BadDate_Returns400(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	for _, bad := range []string{"2026-07-23", "вчера", "1753200000"} {
		w := authedDo(t, rtr, http.MethodGet, "/api/v1/audit-log?from="+bad, nil, tok)
		if w.Code != http.StatusBadRequest {
			t.Errorf("from=%q: got %d, want 400", bad, w.Code)
		}
	}
}

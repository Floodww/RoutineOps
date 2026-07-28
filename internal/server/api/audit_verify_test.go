package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestVerifyAuditChain_Returns200AndOK: на здоровом журнале ручка отвечает 200 и
// ok=true, а вместе с ним отдаёт голову цепочки — то значение, которое оператор
// сверяет с внешней копией (лог сервера, тикет).
func TestVerifyAuditChain_HealthyChain(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	// Любое мутирующее действие пишет запись аудита → цепочка непустая.
	createDevice(t, rtr, tok, "host-verify", "linux")

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/audit-log/verify", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body)
	}
	var st struct {
		OK        bool   `json:"ok"`
		Chained   int64  `json:"chained"`
		Unchained int64  `json:"unchained"`
		HeadHash  string `json:"head_hash"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(w.Body).Decode(&st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !st.OK {
		t.Errorf("ok=false на нетронутом журнале, причина %q", st.Reason)
	}
	if st.Chained == 0 {
		t.Error("chained=0, хотя аудит писался")
	}
	if st.HeadHash == "" {
		t.Error("пустой head_hash — сверять с внешней копией нечего")
	}
}

// TestVerifyAuditChain_ReportsTamperWith200: обнаруженная подделка — это УСПЕШНО
// выполненная проверка, а не ошибка сервера.
//
// Отдавать на неё 4xx/5xx нельзя: такой ответ неотличим от недоступности сервера,
// то есть противнику достаточно уронить ручку, чтобы результат читался так же, как
// «журнал подделан», — и наоборот, реальная подделка терялась бы среди сбоев.
func TestVerifyAuditChain_ReportsTamperWith200(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	createDevice(t, rtr, tok, "host-verify-tamper", "linux")

	if _, err := db.Pool().Exec(t.Context(),
		`UPDATE audit_log SET action = 'innocent' WHERE seq = (SELECT MAX(seq) FROM audit_log)`); err != nil {
		t.Fatalf("подделка: %v", err)
	}

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/audit-log/verify", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (подделка — это результат проверки, не сбой); body: %s", w.Code, w.Body)
	}
	var st struct {
		OK        bool   `json:"ok"`
		Reason    string `json:"reason"`
		BrokenSeq int64  `json:"broken_seq"`
	}
	if err := json.NewDecoder(w.Body).Decode(&st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if st.OK {
		t.Fatal("подделка не обнаружена")
	}
	if st.Reason != "hash" {
		t.Errorf("причина %q, ждали \"hash\"", st.Reason)
	}
	if st.BrokenSeq == 0 {
		t.Error("не указан номер нарушенной записи — оператору некуда смотреть")
	}
}

// TestVerifyAuditChain_ForbiddenForViewer: состояние контроля безопасности —
// admin-only. Наблюдателю не нужно знать, сломана ли цепочка.
func TestVerifyAuditChain_ForbiddenForViewer(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	admin := authToken(t, rtr, db)
	secret, _ := createToken(t, rtr, admin, "readonly-verify", "viewer", 0)

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/audit-log/verify", nil, "Bearer "+secret)
	if w.Code != http.StatusForbidden {
		t.Errorf("viewer получил %d, ждали 403; body: %s", w.Code, w.Body)
	}
}

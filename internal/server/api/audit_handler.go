package api

import (
	"net/http"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// parseAuditBound разбирает границу периода. Ждём RFC3339 с зоной: границу суток
// считает браузер оператора (у него и часовой пояс), сервер её не выдумывает.
// Мусор — 400, а не «фильтр молча выключен»: тихо проигнорированная граница даёт
// выдачу шире запрошенной, и по журналу это неотличимо от «за период ничего нет».
func parseAuditBound(raw string) (*time.Time, bool) {
	if raw == "" {
		return nil, true
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, false
	}
	return &t, true
}

func (h *Handler) listAuditLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from, okFrom := parseAuditBound(q.Get("from"))
	to, okTo := parseAuditBound(q.Get("to"))
	if !okFrom || !okTo {
		http.Error(w, "from/to: ожидается дата в формате RFC3339", http.StatusBadRequest)
		return
	}
	limit, offset := parsePage(r)
	entries, total, err := h.db.ListAuditLog(r.Context(), storage.AuditFilter{
		Action: q.Get("action"),
		Who:    q.Get("who"),
		From:   from,
		To:     to,
	}, limit, offset)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []storage.AuditEntry{}
	}
	writeTotal(w, total)
	writeJSON(w, http.StatusOK, entries)
}

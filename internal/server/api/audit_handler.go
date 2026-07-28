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

// verifyAuditChain проверяет целостность журнала (миграция 042).
//
// HTTP 200 отдаётся и при обнаруженном нарушении: «проверка выполнена, результат —
// журнал подделан» это успешный ответ, а не ошибка сервера. Различать надо по полю
// ok, и клиент обязан смотреть именно на него. Ответ 4xx/5xx на найденную подделку
// был бы хуже вдвойне: он неотличим от недоступности сервера, то есть противнику
// достаточно уронить ручку, чтобы результат читался так же.
//
// Сама проверка НЕ пишется в аудит: она ничего не меняет, а запись о ней сдвинула бы
// голову цепочки, из-за чего два последовательных запуска давали бы разный HeadHash
// без единого административного действия — и сверка головы с внешней копией
// перестала бы что-либо значить.
func (h *Handler) verifyAuditChain(w http.ResponseWriter, r *http.Request) {
	st, err := h.db.VerifyAuditChain(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

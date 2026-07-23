package api

import (
	"net/http"
	"strconv"
)

// totalCountHeader — общее число записей под фильтром, без учёта limit/offset.
// Заголовком, а не полем в теле: тело остаётся массивом, как было, поэтому
// openapi-схемы и существующие клиенты (в т.ч. routineops CLI) не ломаются.
const totalCountHeader = "X-Total-Count"

// parsePage читает limit/offset из query. Мусор и отсутствие параметров дают нули —
// clamp в storage подставит дефолт. Валидацию потолка намеренно НЕ дублируем здесь:
// один источник правды (storage.clampPage), иначе ручка и слой данных разъезжаются.
func parsePage(r *http.Request) (limit, offset int) {
	limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
	return limit, offset
}

// writeTotal проставляет X-Total-Count. Зовётся ДО writeJSON: после записи тела
// заголовки уже уехали клиенту и молча теряются.
func writeTotal(w http.ResponseWriter, total int) {
	w.Header().Set(totalCountHeader, strconv.Itoa(total))
}

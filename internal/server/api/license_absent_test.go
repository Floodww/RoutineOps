package api_test

import (
	"net/http"
	"testing"
)

// В open-core сборке роута /license нет: он монтируется enterprise-оверлеем через
// WithAdminRoutes, а сюда NewRouter вызывается без опций — ровно как в Free.
//
// Тест закрепляет КОД ответа, а не отсутствие функции: страница «Лицензия» уезжает в
// Free-срез целиком и отличает «этой возможности нет в редакции» от «сервер сломался»
// единственным признаком — 404. Если /api/v1 когда-нибудь обзаведётся своим
// NotFound-хендлером или SPA-фолбэк начнёт перехватывать неизвестные пути (отдавая
// index.html с кодом 200), open-core-админ увидит не «недоступно в этой редакции», а
// пустой статус лицензии — то есть чужую редакцию. Ловится только здесь.
func TestLicenseRouteAbsentInOpenCore(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	token := authToken(t, rtr, db)

	for _, tc := range []struct {
		method string
		body   []byte
	}{
		{http.MethodGet, nil},
		{http.MethodPost, []byte(`{"license":"","activation_password":""}`)},
	} {
		w := authedDo(t, rtr, tc.method, "/api/v1/license", tc.body, token)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s /api/v1/license = %d, want 404 (UI по этому коду показывает «недоступно в этой редакции»)", tc.method, w.Code)
		}
	}
}

//go:build !enterprise

package api_test

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/Floodww/RoutineOps/internal/server/api"
)

// В ОТКРЫТОЙ сборке платных ручек не должно быть вовсе.
//
// Это гейт редакции, а не проверка доступа: разница принципиальна. «Ручка есть, но
// отвечает отказом» снимается правкой одного условия в открытых исходниках —
// сервер-то у клиента свой. «Ручки нет» снять нельзя, не собрав другую редакцию.
//
// Тест сторожит регистрацию: стоит кому-то вернуть эти строки в общий handler.go
// (а именно так они и появились), он покраснеет.
//
// Спрашиваем РОУТЕР, а не ответ по HTTP. Незарегистрированный путь под /api/v1
// отвечает 401, а не 404: миддлвар аутентификации группы отрабатывает раньше, чем
// становится ясно, что роута нет. То есть по коду ответа «ручки нет» и «ручка есть,
// но не пущены» неразличимы — а разница здесь ровно та, ради которой всё делалось.
func TestEnterpriseRoutesAbsentInOpenCore(t *testing.T) {
	rtr := api.NewRouter(nil, nil, []byte("test"), nil, "https://test.local", t.TempDir(), nil, false)
	routes, ok := rtr.(chi.Routes)
	if !ok {
		t.Fatalf("роутер не chi.Routes (%T) — проверить регистрацию иначе нечем", rtr)
	}

	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/auth/saml/00000000-0000-4000-8000-000000000001/begin"},
		{http.MethodGet, "/api/v1/auth/saml/00000000-0000-4000-8000-000000000001/metadata"},
		{http.MethodPost, "/api/v1/auth/saml/00000000-0000-4000-8000-000000000001/acs"},
		{http.MethodGet, "/api/v1/saml/providers"},
		{http.MethodPost, "/api/v1/saml/providers"},
		{http.MethodGet, "/api/v1/saml/providers/00000000-0000-4000-8000-000000000001/sp-metadata"},
		{http.MethodGet, "/api/v1/scim/v2/Users"},
		{http.MethodPost, "/api/v1/scim/v2/Users"},
		{http.MethodGet, "/api/v1/siem"},
		{http.MethodPost, "/api/v1/siem"},
		{http.MethodPost, "/api/v1/siem/00000000-0000-4000-8000-000000000001/test"},
		{http.MethodPost, "/api/v1/provider/cve-feed"},
		{http.MethodGet, "/api/v1/devices/00000000-0000-4000-8000-000000000001/vulnerabilities"},
	}
	for _, c := range cases {
		if routes.Match(chi.NewRouteContext(), c.method, c.path) {
			t.Errorf("%s %s зарегистрирован в open-core — платная ручка уехала во free-сборку",
				c.method, c.path)
		}
	}

	// Контроль на сам тест: открытая ручка обязана находиться тем же способом,
	// иначе Match всегда возвращал бы false и тест был бы зелёным ни от чего.
	if !routes.Match(chi.NewRouteContext(), http.MethodPost, "/api/v1/auth/login") {
		t.Fatal("контрольная ручка /auth/login не найдена — проверка нерабочая")
	}
}

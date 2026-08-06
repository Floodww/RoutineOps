package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/api"
	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// Швы к enterprise-сервисам (OIDC, каталог) — тонкий, но не пустой слой: на нём висят
// проверка роли, разбор тела, коды отказов и отделение «сервис не подключён» от
// «сервис ответил ошибкой». Ни один из этих путей не проверялся, а именно они решают,
// что увидит оператор.

// --- заглушки сервисов ---

type stubOIDC struct {
	providers []api.OIDCProviderView
	created   api.OIDCProviderInput
	createdIn string // tenantID, с которым позвали
	updatedID string
	deletedID string
	failWith  error
}

func (s *stubOIDC) ListProviders(_ context.Context, _ string) ([]api.OIDCProviderView, error) {
	return s.providers, s.failWith
}

func (s *stubOIDC) CreateProvider(_ context.Context, tenantID string, in api.OIDCProviderInput) (api.OIDCProviderView, error) {
	if s.failWith != nil {
		return api.OIDCProviderView{}, s.failWith
	}
	s.created, s.createdIn = in, tenantID
	return api.OIDCProviderView{ID: "new-id", Name: in.Name, ClientID: in.ClientID, Enabled: true, HasSecret: true}, nil
}

func (s *stubOIDC) UpdateProvider(_ context.Context, _, id string, _ api.OIDCProviderInput) error {
	s.updatedID = id
	return s.failWith
}

func (s *stubOIDC) DeleteProvider(_ context.Context, _, id string) error {
	s.deletedID = id
	return s.failWith
}

func (s *stubOIDC) BeginFlow(context.Context, string) (string, error) {
	return "https://idp.test.local/authorize?state=x", s.failWith
}

func (s *stubOIDC) HandleCallback(context.Context, string, string, string) (string, string, string, error) {
	return "", "", "", s.failWith
}

type stubDirectory struct {
	cfg      api.DirectoryConfig
	setCalls int
	lastPass string
	syncRes  api.DirectorySyncResult
	failWith error
}

func (s *stubDirectory) GetConfig(context.Context) (api.DirectoryConfig, error) {
	return s.cfg, s.failWith
}

func (s *stubDirectory) SetConfig(_ context.Context, cfg api.DirectoryConfig, bindPassword, _ string) error {
	if s.failWith != nil {
		return s.failWith
	}
	s.setCalls++
	s.cfg, s.lastPass = cfg, bindPassword
	return nil
}

func (s *stubDirectory) TestConnection(context.Context) error { return s.failWith }

func (s *stubDirectory) SyncNow(context.Context) (api.DirectorySyncResult, error) {
	return s.syncRes, s.failWith
}

func (s *stubDirectory) Authenticate(context.Context, string, string) (bool, error) {
	return false, s.failWith
}

// --- open-core: сервисов нет ---

// Без подключённого сервиса ручки обязаны отвечать 501, а не 500 и не 404: «этой
// возможности в вашей сборке нет» — другой ответ, чем «сломалось» или «нет объекта».
func TestSeamsReturnNotImplementedWithoutService(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/oidc/providers"},
		{http.MethodPost, "/api/v1/oidc/providers"},
		{http.MethodGet, "/api/v1/directory/config"},
		{http.MethodPost, "/api/v1/directory/test"},
		{http.MethodPost, "/api/v1/directory/sync"},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			w := authedDo(t, rtr, c.method, c.path, []byte(`{}`), tok)
			if w.Code != http.StatusNotImplemented && w.Code != http.StatusNotFound {
				t.Fatalf("код %d — сборка без сервиса должна отвечать 501/404, а не так: %s", w.Code, w.Body)
			}
		})
	}
}

// --- OIDC-шов ---

func newOIDCRouter(t *testing.T, db *storage.DB, svc api.OIDCService) http.Handler {
	t.Helper()
	return api.NewRouter(db, nil, []byte("test-secret"), nil, "https://test.local", t.TempDir(), nil, false,
		api.WithOIDCService(svc))
}

// Тенант в шов приходит ИЗ claims, а не из тела: провайдер принадлежит тенанту, и
// возможность указать чужой означала бы заведение IdP в чужой тенант (ADR-6).
func TestOIDCSeamPassesActorTenant(t *testing.T) {
	db := newTestDB(t)
	stub := &stubOIDC{}
	rtr := newOIDCRouter(t, db, stub)
	tok := authToken(t, rtr, db)

	body, _ := json.Marshal(map[string]any{
		"name": "Корп IdP", "client_id": "c1", "client_secret": "s1",
		"issuer_url": "https://idp.test.local", "redirect_uri": "https://app.test.local/cb",
	})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/oidc/providers", body, tok)
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("создание провайдера: код %d %s", w.Code, w.Body)
	}
	if stub.createdIn == "" {
		t.Fatal("сервис вызван без тенанта")
	}
	if stub.created.Name != "Корп IdP" || stub.created.ClientSecret != "s1" {
		t.Fatalf("тело не доехало до сервиса: %+v", stub.created)
	}
}

// Список отдаётся как есть, ошибка сервиса не превращается в пустой список: «провайдеров
// нет» и «мы не смогли их прочитать» — разные ответы для оператора.
func TestOIDCSeamListAndFailure(t *testing.T) {
	db := newTestDB(t)
	stub := &stubOIDC{providers: []api.OIDCProviderView{{ID: "p1", Name: "IdP", Enabled: true, HasSecret: true}}}
	rtr := newOIDCRouter(t, db, stub)
	tok := authToken(t, rtr, db)

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/oidc/providers", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("список: код %d %s", w.Code, w.Body)
	}
	var list []api.OIDCProviderView
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("разбор списка: %v", err)
	}
	if len(list) != 1 || list[0].ID != "p1" {
		t.Fatalf("список разъехался: %+v", list)
	}

	stub.failWith = errors.New("база недоступна")
	if fw := authedDo(t, rtr, http.MethodGet, "/api/v1/oidc/providers", nil, tok); fw.Code == http.StatusOK {
		t.Fatal("ошибка сервиса отдана как успешный пустой список")
	}
}

// Роль: управление IdP — мутация конфигурации входа, viewer её не делает.
func TestOIDCSeamRejectsViewer(t *testing.T) {
	db := newTestDB(t)
	rtr := newOIDCRouter(t, db, &stubOIDC{})
	viewerTok := tokenForRole(t, rtr, db, "viewer", "oidc_viewer_")

	body, _ := json.Marshal(map[string]any{"name": "чужой", "client_id": "c"})
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/oidc/providers", body, viewerTok); w.Code != http.StatusForbidden {
		t.Fatalf("viewer получил %d при заведении IdP: %s", w.Code, w.Body)
	}
}

// --- шов каталога ---

func newDirectoryRouter(t *testing.T, db *storage.DB, svc api.DirectoryService) http.Handler {
	t.Helper()
	return api.NewRouter(db, nil, []byte("test-secret"), nil, "https://test.local", t.TempDir(), nil, false,
		api.WithDirectoryService(svc))
}

// Bind-пароль наружу не отдаётся никогда: в конфиге виден только признак его наличия.
func TestDirectorySeamHidesBindPassword(t *testing.T) {
	db := newTestDB(t)
	stub := &stubDirectory{cfg: api.DirectoryConfig{
		Enabled: true, URL: "ldaps://dc.test.local", BindDN: "CN=svc,DC=test,DC=local",
		BaseDN: "DC=test,DC=local", HasPassword: true,
	}}
	rtr := newDirectoryRouter(t, db, stub)
	tok := authToken(t, rtr, db)

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/directory/config", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("конфиг: код %d %s", w.Code, w.Body)
	}
	if !json.Valid(w.Body.Bytes()) {
		t.Fatalf("ответ не JSON: %s", w.Body)
	}
	var cfg map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if _, leaked := cfg["bind_password"]; leaked {
		t.Fatal("bind-пароль отдан наружу")
	}
	if cfg["has_password"] != true {
		t.Errorf("признак наличия пароля потерян: %v", cfg["has_password"])
	}
}

// Синк руками отдаёт оператору счётчики: «нажал и ничего не произошло» — худший
// возможный ответ на кнопку синхронизации.
func TestDirectorySeamSyncReportsCounters(t *testing.T) {
	db := newTestDB(t)
	stub := &stubDirectory{syncRes: api.DirectorySyncResult{Synced: 5, Disabled: 1, Matched: 3}}
	rtr := newDirectoryRouter(t, db, stub)
	tok := authToken(t, rtr, db)

	w := authedDo(t, rtr, http.MethodPost, "/api/v1/directory/sync", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("синк: код %d %s", w.Code, w.Body)
	}
	var res api.DirectorySyncResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if res.Synced != 5 || res.Disabled != 1 || res.Matched != 3 {
		t.Fatalf("счётчики синка разъехались: %+v", res)
	}

	stub.failWith = errors.New("контроллер домена недоступен")
	if fw := authedDo(t, rtr, http.MethodPost, "/api/v1/directory/sync", nil, tok); fw.Code == http.StatusOK {
		t.Fatal("недоступный контроллер домена отдан как успешный синк")
	}
}

// Проверка подключения отдаёт 200 в ОБОИХ случаях, а различие несёт поле status.
// Это не небрежность: сама ручка отработала, а «bind отклонён» — её РЕЗУЛЬТАТ, и
// оператору нужен текст ошибки от контроллера домена, а не пустая пятисотка.
func TestDirectorySeamTestConnectionReportsResultInBody(t *testing.T) {
	db := newTestDB(t)
	stub := &stubDirectory{}
	rtr := newDirectoryRouter(t, db, stub)
	tok := authToken(t, rtr, db)

	w := authedDo(t, rtr, http.MethodPost, "/api/v1/directory/test", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("успешная проверка: код %d %s", w.Code, w.Body)
	}
	var ok map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &ok); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if ok["status"] != "ok" {
		t.Fatalf("успех отдан как %+v", ok)
	}

	stub.failWith = errors.New("bind отклонён контроллером домена")
	fw := authedDo(t, rtr, http.MethodPost, "/api/v1/directory/test", nil, tok)
	if fw.Code != http.StatusOK {
		t.Fatalf("неудачная проверка: код %d, ожидался 200 с status=error", fw.Code)
	}
	var bad map[string]string
	if err := json.Unmarshal(fw.Body.Bytes(), &bad); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if bad["status"] != "error" {
		t.Fatalf("неудача не помечена: %+v", bad)
	}
	if bad["error"] == "" {
		t.Fatal("текст ошибки от контроллера домена потерян — оператору нечего чинить")
	}
}

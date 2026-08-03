package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

// Шов enterprise OIDC/SSO. Паттерн идентичен directory_seam.go: интерфейс во free-пакете,
// реализация в enterprise-оверлее (internal/server/oidc, //go:build enterprise),
// регистрация через RouterOption в enterprise composition-root (cmd/server/enterprise.go).
// Open-core (oidcSvc==nil) → /oidc/* и /auth/oidc/* отвечают 501.
// go-jose/go-oidc живут ТОЛЬКО в enterprise-оверлее (leak-guard).

// OIDCProviderView — данные провайдера для UI. client_secret никогда не отдаётся наружу;
// HasSecret показывает, задан ли он.
type OIDCProviderView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ClientID    string `json:"client_id"`
	IssuerURL   string `json:"issuer_url"`
	RedirectURI string `json:"redirect_uri"`
	Enabled     bool   `json:"enabled"`
	HasSecret   bool   `json:"has_secret"` // секрет задан; сам PEM/secret не отдаётся
}

// OIDCProviderInput — тело запроса создания/обновления.
type OIDCProviderInput struct {
	Name         string `json:"name"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"` // "" при обновлении = не менять
	IssuerURL    string `json:"issuer_url"`
	RedirectURI  string `json:"redirect_uri"`
	Enabled      bool   `json:"enabled"`
}

// OIDCService — enterprise-SSO. Реализация — internal/server/oidc (//go:build enterprise).
//
// Управление провайдерами принимает tenantID явно (контракт §4): IdP принадлежит
// тенанту, чужой по id не найдётся. begin/callback тенант НЕ принимают — они
// анонимные, и тенант там резолвится из самой строки провайдера (051).
type OIDCService interface {
	// ListProviders возвращает провайдеров тенанта (без секретов).
	ListProviders(ctx context.Context, tenantID string) ([]OIDCProviderView, error)
	// CreateProvider создаёт нового IdP в тенанте. clientSecret шифруется внутри.
	CreateProvider(ctx context.Context, tenantID string, in OIDCProviderInput) (OIDCProviderView, error)
	// UpdateProvider обновляет провайдера тенанта. Если in.ClientSecret == "", секрет не меняется.
	UpdateProvider(ctx context.Context, tenantID, id string, in OIDCProviderInput) error
	// DeleteProvider удаляет провайдера тенанта.
	DeleteProvider(ctx context.Context, tenantID, id string) error
	// BeginFlow генерирует PKCE + state, сохраняет в Redis (TTL 10мин), возвращает URL
	// авторизации IdP, на который нужно перенаправить пользователя.
	BeginFlow(ctx context.Context, providerID string) (authURL string, err error)
	// HandleCallback принимает code+state из IdP, верифицирует state, обменивает code
	// на ID-token, извлекает email и ищет пользователя В ТЕНАНТЕ ПРОВАЙДЕРА.
	// Возвращает (userID, email, role) для выдачи JWT, или error.
	// ErrNotRegistered — email не найден в users (аккаунты OIDC не создаёт).
	HandleCallback(ctx context.Context, providerID, code, state string) (userID, email, role string, err error)
}

// ErrOIDCNotRegistered — пользователь аутентифицирован в IdP, но строки в users нет.
// Сигнализирует хендлеру выдать 401 (не 500).
var ErrOIDCNotRegistered = oidcNotRegisteredError{}

type oidcNotRegisteredError struct{}

func (oidcNotRegisteredError) Error() string { return "user not registered in panel" }

// ErrOIDCProviderUnavailable — провайдера нет либо он выключен. Хендлеру это 404, а не
// 500: выключенный IdP — штатное состояние настройки, а не сбой сервера.
var ErrOIDCProviderUnavailable = errors.New("oidc provider not found or disabled")

// RequireHTTPSURL требует https:// у адреса IdP. По этому адресу едут discovery и, через
// него, JWKS — то есть ключи, которыми проверяется подпись id_token. Посредник на
// открытом канале подменяет их и выдаёт себя за IdP целиком, так что http здесь
// обесценивает всю проверку токена.
//
// Loopback оставлен открытым осознанно: локальный стенд IdP поднимают без сертификата,
// а подслушивать петлю снаружи некому.
func RequireHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("некорректный URL: %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if h := u.Hostname(); h == "localhost" {
			return nil
		} else if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("требуется https:// (http допустим только на loopback): %q", raw)
}

// WithOIDCService подключает enterprise-SSO. Зовётся ТОЛЬКО в enterprise composition-root.
func WithOIDCService(svc OIDCService) RouterOption {
	return func(h *Handler) {
		h.oidcSvc = svc
		// Роуты не монтируем здесь: опции применяются ДО объявления групп, и роутера
		// на этот момент ещё нет. Копим функцию — NewRouter развесит её в authed-группе.
		h.authedMounts = append(h.authedMounts, func(h *Handler, r chi.Router) {
			// Управление провайдерами — только it_admin, только человек.
			r.With(h.requireRole("it_admin"), requireHuman).Route("/oidc", func(r chi.Router) {
				r.Get("/providers", h.listOIDCProviders)
				r.Post("/providers", h.createOIDCProvider)
				r.Put("/providers/{id}", h.updateOIDCProvider)
				r.Delete("/providers/{id}", h.deleteOIDCProvider)
			})
		})
	}
}

// oidcUnavailable — единый 501 для open-core.
func (h *Handler) oidcUnavailable(w http.ResponseWriter) bool {
	if h.oidcSvc == nil {
		http.Error(w, "SSO/OIDC is an enterprise feature (not built)", http.StatusNotImplemented)
		return true
	}
	return false
}

// --- Handlers ---

func (h *Handler) listOIDCProviders(w http.ResponseWriter, r *http.Request) {
	if h.oidcUnavailable(w) {
		return
	}
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	providers, err := h.oidcSvc.ListProviders(r.Context(), tenantID)
	if err != nil {
		slog.Error("oidc: list providers", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, providers)
}

func (h *Handler) createOIDCProvider(w http.ResponseWriter, r *http.Request) {
	if h.oidcUnavailable(w) {
		return
	}
	var in OIDCProviderInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if in.Name == "" || in.ClientID == "" || in.ClientSecret == "" || in.IssuerURL == "" || in.RedirectURI == "" {
		http.Error(w, "name, client_id, client_secret, issuer_url, redirect_uri are required", http.StatusBadRequest)
		return
	}
	if err := RequireHTTPSURL(in.IssuerURL); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	claims, _ := r.Context().Value(claimsKey).(*jwtClaims)
	p, err := h.oidcSvc.CreateProvider(r.Context(), tenantID, in)
	if err != nil {
		slog.Error("oidc: create provider", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.audit(r.Context(), claims.UserID, claims.Email, "create_oidc_provider", "oidc_provider", p.ID, map[string]any{"name": p.Name})
	writeJSON(w, http.StatusCreated, p)
}

func (h *Handler) updateOIDCProvider(w http.ResponseWriter, r *http.Request) {
	if h.oidcUnavailable(w) {
		return
	}
	id := chi.URLParam(r, "id")
	var in OIDCProviderInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	// Обновление затирает поля целиком (client_secret — исключение, пустой = не менять),
	// поэтому неполное тело молча стёрло бы настройку IdP.
	if in.Name == "" || in.ClientID == "" || in.IssuerURL == "" || in.RedirectURI == "" {
		http.Error(w, "name, client_id, issuer_url, redirect_uri are required", http.StatusBadRequest)
		return
	}
	if err := RequireHTTPSURL(in.IssuerURL); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	claims, _ := r.Context().Value(claimsKey).(*jwtClaims)
	if err := h.oidcSvc.UpdateProvider(r.Context(), tenantID, id, in); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		slog.Error("oidc: update provider", "id", id, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.audit(r.Context(), claims.UserID, claims.Email, "update_oidc_provider", "oidc_provider", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) deleteOIDCProvider(w http.ResponseWriter, r *http.Request) {
	if h.oidcUnavailable(w) {
		return
	}
	id := chi.URLParam(r, "id")
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	claims, _ := r.Context().Value(claimsKey).(*jwtClaims)
	if err := h.oidcSvc.DeleteProvider(r.Context(), tenantID, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		slog.Error("oidc: delete provider", "id", id, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.audit(r.Context(), claims.UserID, claims.Email, "delete_oidc_provider", "oidc_provider", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

// oidcBegin инициирует Authorization Code Flow: редиректит пользователя на IdP.
func (h *Handler) oidcBegin(w http.ResponseWriter, r *http.Request) {
	if h.oidcUnavailable(w) {
		return
	}
	id := chi.URLParam(r, "id")
	authURL, err := h.oidcSvc.BeginFlow(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrOIDCProviderUnavailable) {
			http.Error(w, "SSO provider not found or disabled", http.StatusNotFound)
			return
		}
		slog.Error("oidc: begin flow", "provider", id, "err", err)
		http.Error(w, "failed to start SSO flow", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// oidcCallback принимает code+state от IdP, верифицирует и выдаёт JWT cookie.
func (h *Handler) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if h.oidcUnavailable(w) {
		return
	}
	id := chi.URLParam(r, "id")
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	userID, email, role, err := h.oidcSvc.HandleCallback(r.Context(), id, code, state)
	if err != nil {
		if err == ErrOIDCNotRegistered {
			// Редирект на логин с понятной ошибкой в query-параметре.
			http.Redirect(w, r, "/?sso_error=not_registered", http.StatusFound)
			return
		}
		slog.Error("oidc: callback error", "provider", id, "err", err)
		http.Redirect(w, r, "/?sso_error=auth_failed", http.StatusFound)
		return
	}

	if err := h.issueToken(w, userID, email, role); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.audit(r.Context(), userID, email, "login", "user", userID, map[string]any{"method": "oidc", "provider": id})
	http.Redirect(w, r, "/", http.StatusFound)
}

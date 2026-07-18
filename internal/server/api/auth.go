package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type contextKey string

const claimsKey contextKey = "claims"

// newJTI генерирует случайный идентификатор токена (jti) для блок-листа отзыва (M-7).
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type jwtClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func (h *Handler) jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var tokenStr string
		if c, err := r.Cookie("token"); err == nil {
			tokenStr = c.Value
		} else if hdr := r.Header.Get("Authorization"); strings.HasPrefix(hdr, "Bearer ") {
			tokenStr = strings.TrimPrefix(hdr, "Bearer ")
		}
		if tokenStr == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims := &jwtClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return h.jwtSecret, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// M-7: токен мог быть отозван на logout — проверяем блок-лист по jti.
		// Fail-closed: ошибка проверки не должна давать доступ.
		if claims.ID != "" {
			revoked, rerr := h.db.IsTokenRevoked(r.Context(), claims.ID)
			if rerr != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if revoked {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		} else {
			// Токены, выпущенные до M-7, не имеют jti и неотзываемы. Окно ≤24ч после
			// деплоя — логируем, чтобы было видно, что старые сессии ещё в ходу.
			slog.Warn("jwtMiddleware: token without jti, revocation check skipped", "user", claims.Email)
		}
		// Token-epoch: смена/сброс пароля инвалидирует все ранее выпущенные токены.
		// Fail-closed. Токен без iat или с iat раньше password_changed_at — отвергаем.
		pwChangedAt, exists, perr := h.db.GetUserPasswordChangedAt(r.Context(), claims.UserID)
		if perr != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			// Пользователь удалён — живой токен больше не действителен.
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if claims.IssuedAt == nil || claims.IssuedAt.Unix() < pwChangedAt.Unix() {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// issueToken минтит JWT (jti для отзыва на logout + iat для token-epoch) и ставит
// httpOnly-cookie. Общий путь для login и changePassword: последний переминчивает
// токен после смены пароля, чтобы не разлогинить владельца — его свежий iat >=
// нового password_changed_at, а все прежние токены отваливаются по epoch.
func (h *Handler) issueToken(w http.ResponseWriter, userID, email, role string) error {
	jti, err := newJTI()
	if err != nil {
		return err
	}
	claims := &jwtClaims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ID: jti,
			// TTL 8ч: симметричный HS256-секрет — единственный корень доверия;
			// короче окно = меньше живёт украденный/утёкший токен (JWT-гигиена).
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(8 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(h.jwtSecret)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Status string `json:"status"`
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Email == "" || req.Password == "" {
		http.Error(w, "email and password are required", http.StatusBadRequest)
		return
	}

	// D: per-account backoff поверх per-IP rate-limit — тормозит распределённый
	// брутфорс одного аккаунта с разных IP. Ключ — email в нижнем регистре.
	acctKey := strings.ToLower(req.Email)
	if locked, _ := h.loginLimiter.locked(acctKey, time.Now()); locked {
		http.Error(w, "too many failed login attempts, try again later", http.StatusTooManyRequests)
		return
	}

	user, err := h.db.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if user == nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		h.loginLimiter.fail(acctKey, time.Now())
		h.audit(r.Context(), "", req.Email, "login_failed", "user", "", nil)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	h.loginLimiter.success(acctKey)

	if err := h.issueToken(w, user.ID, user.Email, user.Role); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.audit(r.Context(), user.ID, user.Email, "login", "user", user.ID, nil)
	writeJSON(w, http.StatusOK, loginResponse{Status: "ok"})
}

// Actor извлекает аутентифицированного пользователя из контекста запроса (за
// jwtMiddleware). Экспорт для enterprise-хендлеров (напр. аудит применения лицензии),
// которым нужен актор, но недоступен внутренний claimsKey. ok=false вне authed-группы.
func Actor(ctx context.Context) (userID, email string, ok bool) {
	c, ok := ctx.Value(claimsKey).(*jwtClaims)
	if !ok {
		return "", "", false
	}
	return c.UserID, c.Email, true
}

func (h *Handler) requireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := r.Context().Value(claimsKey).(*jwtClaims)
			if claims.Role != role {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	// logout вне jwtMiddleware → claims в контексте нет; best-effort парсим куку,
	// чтобы записать в аудит, кто вышел (F-4).
	if c, err := r.Cookie("token"); err == nil {
		claims := &jwtClaims{}
		if _, perr := jwt.ParseWithClaims(c.Value, claims, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return h.jwtSecret, nil
		}); perr == nil {
			// M-7: гасим токен в блок-листе, чтобы он не работал до естественной
			// экспирации. Fail-closed: если отзыв не записался (БД недоступна), нельзя
			// отдавать успешный logout — иначе перехваченный токен живёт до 24ч.
			if claims.ID != "" {
				exp := time.Now().Add(24 * time.Hour)
				if claims.ExpiresAt != nil {
					exp = claims.ExpiresAt.Time
				}
				if rerr := h.db.RevokeToken(r.Context(), claims.ID, exp); rerr != nil {
					slog.Error("revoke token on logout failed", "jti", claims.ID, "err", rerr)
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
			}
			h.audit(r.Context(), claims.UserID, claims.Email, "logout", "user", claims.UserID, nil)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

// me возвращает текущего пользователя (id/email/name/role) — источник роли для
// гейтинга UI по роли (фронт скрывает admin-действия для viewer).
func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	user, err := h.db.GetUserByID(r.Context(), claims.UserID)
	if err != nil || user == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"id":    user.ID,
		"email": user.Email,
		"name":  user.Name,
		"role":  user.Role,
	})
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// changePassword — in-app смена пароля залогиненным пользователем: сверяем текущий
// пароль, валидируем новый политикой сложности, обновляем хэш. Доступно любой роли.
func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	user, err := h.db.GetUserByID(r.Context(), claims.UserID)
	if err != nil || user == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)) != nil {
		http.Error(w, "текущий пароль неверный", http.StatusUnauthorized)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcryptCost)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.db.UpdateUserPassword(r.Context(), user.ID, string(hash)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Смена пароля сдвинула token-epoch → все прежние токены (в т.ч. текущая кука)
	// теперь недействительны. Переминчиваем свежий токен, чтобы НЕ разлогинить
	// владельца, сменившего собственный пароль (его новый iat >= epoch); прочие
	// сессии отваливаются. Best-effort: при сбое юзер просто перелогинится.
	if err := h.issueToken(w, user.ID, user.Email, user.Role); err != nil {
		slog.Error("changePassword: re-issue token failed (user will need to re-login)", "user", user.Email, "err", err)
	}
	h.audit(r.Context(), user.ID, user.Email, "change_password", "user", user.ID, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

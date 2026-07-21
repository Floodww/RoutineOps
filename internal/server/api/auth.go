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

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

type contextKey string

const claimsKey contextKey = "claims"

// validRoles — полный список ролей системы. Иерархии нет: requireRole сравнивает
// точным равенством, поэтому "выше/ниже" здесь не выражается и не подразумевается.
// Один список на пакет намеренно: раньше он жил локальной переменной в inviteUser,
// и добавление роли требовало помнить про все остальные места проверки.
var validRoles = map[string]bool{"it_admin": true, "viewer": true}

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
	// TokenID непустой ⇔ запрос пришёл по СЕРВИСНОМУ токену, а не от человека.
	// `json:"-"` обязателен: структура сериализуется в JWT, и поле не должно ни
	// попадать в выпускаемые токены, ни читаться из присланных — иначе признак
	// «я человек/я токен» стал бы управляемым извне.
	TokenID string `json:"-"`
	jwt.RegisteredClaims
}

// requireHuman отбивает сервисные токены на «личных» ручках.
//
// У токена НЕТ своего аккаунта: claims.UserID — это id создавшего админа (нужен, чтобы
// аудит связывался с живым пользователем). Поэтому любой хендлер, трактующий UserID как
// «текущего человека», под токеном работает с ЧУЖОЙ учёткой. Адверс-ревью нашло это как
// настоящую дыру: viewer-токен, выданный для CI, читал telegram link_token создавшего
// админа (→ перехват его алертов) и менял ему пароль, инвалидируя все живые сессии.
//
// Правильная модель: у сервисного токена личного аккаунта нет, значит личные ручки для
// него не «работают с чужим», а недоступны. Для автоматизации они и бессмысленны.
//
// Отсюда общее правило, по которому и надо решать, вешать ли гард на новую ручку:
//
//	ВСЁ, ЧТО ВЫПУСКАЕТ ИЛИ ПОВЫШАЕТ ПРАВА — ТОЛЬКО ЧЕЛОВЕКОМ.
//
// Иначе модель отзыва («удалили строку токена — доступа нет») превращается в фикцию:
// утёкший токен успевает выписать себе что-нибудь, переживающее отзыв. Первый раунд
// ревью поймал теневой токен через /api-tokens; второй — приглашение живого админа
// через /users/invite, и это было ХУЖЕ, потому что строки в users нет в списке
// токенов и при разборе инцидента её не находят.
//
// 🔴 Искать такие ручки по «где claims.UserID трактуется как личность» НЕДОСТАТОЧНО —
// именно так /users/invite и был пропущен: там UserID идёт лишь в аудит и invited_by.
// Опасность не в том, ЧЬЮ личность ручка записывает, а в том, ЧТО она выпускает.
//
// Сознательно НЕ закрыты: энроллмент и переэнроллмент устройств (это и есть штатная
// работа автоматизации) и отзыв admin-access (защитное действие, запрещать вредно).
func requireHuman(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, ok := r.Context().Value(claimsKey).(*jwtClaims); ok && c.TokenID != "" {
			http.Error(w, "недоступно для сервисного токена", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
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
		// Сервисный токен — ОТДЕЛЬНАЯ ветка до разбора JWT: это не JWT, и парсер
		// на нём вернул бы просто «unauthorized», без шанса отличить неверный
		// токен от испорченной сессии. Различаем по префиксу (storage.APITokenPrefix).
		//
		// Ниже по коду идут проверки, которые к сервисному токену НЕ применимы и
		// применяться не должны: блок-лист jti (у токена нет jti, отзыв — удаление
		// строки) и token-epoch по password_changed_at (смена пароля админом не
		// обязана ронять работающую автоматизацию — для этого есть явный отзыв).
		// Поэтому ветка возвращает управление сразу, а не проваливается вниз.
		if strings.HasPrefix(tokenStr, storage.APITokenPrefix) {
			tok, terr := h.db.AuthenticateAPIToken(r.Context(), tokenStr)
			if terr != nil {
				// Fail-closed, как и остальные проверки в этом миддлваре.
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if tok == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			// Роль берём ИЗ ТОКЕНА, а не из users: она зафиксирована при выпуске.
			// Email в формате "token:<имя>" — чтобы в журнале аудита действие
			// автоматизации нельзя было спутать с действием человека.
			// UserID = создатель: нужен, чтобы аудит связывался с живым пользователем.
			// 🔴 Но это НЕ личность актора: под токеном действует автоматизация, а не
			// админ. Все «личные» ручки закрыты от токена requireHuman — см. его док.
			ctx := context.WithValue(r.Context(), claimsKey, &jwtClaims{
				UserID:  tok.CreatedBy,
				Email:   "token:" + tok.Name,
				Role:    tok.Role,
				TokenID: tok.ID,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
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
	// Сервисный токен отдаёт СВОЮ личность и СВОЮ роль. Чтение user-строки создателя
	// вернуло бы роль админа (it_admin) для viewer-токена — ровно противоположное тому,
	// что энфорсит requireRole, — и заодно раздало бы email и id админа любому
	// держателю токена. /me объявлен источником роли для гейтинга UI, так что врать
	// здесь особенно дорого: клиент включил бы админские действия, которые все 403'ят.
	if claims.TokenID != "" {
		writeJSON(w, http.StatusOK, map[string]string{
			"id":    claims.TokenID,
			"email": claims.Email, // "token:<имя>"
			"name":  strings.TrimPrefix(claims.Email, "token:"),
			"role":  claims.Role,
		})
		return
	}
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

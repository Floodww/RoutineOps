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

// validRoles — роли ЧЛЕНСТВА в тенанте. Иерархии нет: requireRole сравнивает
// точным равенством, поэтому «выше/ниже» здесь не выражается и не подразумевается.
// Один список на пакет намеренно: раньше он жил локальной переменной в inviteUser,
// и добавление роли требовало помнить про все остальные места проверки.
//
// provider_admin убран из этого списка (053/ADR-7): надзор над инсталляцией — это
// флаг личности (identities.is_provider_admin), а не роль в тенанте. Гард —
// requireProviderAdmin. 052 понизила все строки users с role='provider_admin' до
// viewer; попытка создать инвайт/API-токен с ролью provider_admin теперь даёт 400.
var validRoles = map[string]bool{
	"it_admin": true,
	"viewer":   true,
}

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
	// TokenScope — область СЕРВИСНОГО токена (storage.APITokenScope*). Пустая =
	// без сужения. `json:"-"` по той же причине, что и TokenID: иначе держатель
	// токена присылал бы себе любую область в теле JWT.
	TokenScope string `json:"-"`
	// TenantID читается из БД на каждый запрос (ADR-6): в JWT не кладём — иначе
	// перевод админа в другой тенант ждал бы истечения токена до 8 часов.
	// При мульти-членстве (ADR-7) активный тенант задан тем, НА КАКОЕ ЧЛЕНСТВО
	// выпущен токен: UserID — это строка users, а она принадлежит ровно одному
	// тенанту. Отдельного claim'а с тенантом поэтому не появилось.
	TenantID string `json:"-"`
	// IdentityID и IsProviderAdmin — свойства ЛИЧНОСТИ (ADR-7 §11.3). Тоже из БД:
	// снятый признак надзора обязан действовать сразу, а не через 8 часов.
	IdentityID      string `json:"-"`
	IsProviderAdmin bool   `json:"-"`
	MfaPending      bool   `json:"mfa_pending,omitempty"`
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

// scimPathPrefix — единственный префикс, куда пускается токен области scim.
// Со слэшем на конце намеренно: без него `/api/v1/scimulator` тоже совпал бы.
const scimPathPrefix = "/api/v1/scim/"

// scopeAllowsPath решает, пускать ли токен с областью scope на путь path.
//
// 🔴 Белый список, а не чёрный. Q-61 закрывал ровно то, что SCIM — единственное
// место, где сознательно снят requireHuman: провизионинг ходит машиной. Пока
// области не было, туда проходил ЛЮБОЙ сервисный токен с ролью it_admin, то есть
// токен для сборки умел заводить и удалять пользователей панели.
//
// Обратное направление не менее важно: SCIM-токен не должен ходить НИКУДА, кроме
// SCIM. Иначе «отдельная область» была бы косметикой — держатель просто пользовался
// бы им как обычным админским.
func scopeAllowsPath(scope, path string) bool {
	switch scope {
	case "":
		// Токен без сужения — прежнее поведение. Ограничивает только роль.
		return true
	case storage.APITokenScopeSCIM:
		return strings.HasPrefix(path, scimPathPrefix)
	default:
		// Неизвестная область = fail-closed. Сюда можно попасть только если в БД
		// оказалось значение, о котором этот код не знает (откат кода при накаченной
		// миграции), и пускать «на всякий случай» в таком состоянии нельзя.
		return false
	}
}

// isMFASetupPath — ровно две ручки, куда пускается ПОЛУаутентифицированный токен
// (пароль сверен, второй фактор ещё нет).
//
// Без этого исключения политика «тенант требует MFA» становится ловушкой: сервер
// отвечает `mfa_setup_required`, отправляет человека привязывать TOTP — и сам же
// закрывает ему привязку 403-м, потому что MFA ещё не пройдена. Войти невозможно
// в принципе.
//
// Сравнение ТОЧНОЕ и по методу тоже: префикс пустил бы полуаутентифицированный
// токен во всё, что начинается на /auth/mfa, включая будущие ручки.
func isMFASetupPath(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	return r.URL.Path == "/api/v1/auth/mfa/enroll" || r.URL.Path == "/api/v1/auth/mfa/verify"
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
			// 🔴 Область проверяется ЗДЕСЬ, до всякой маршрутизации, и работает как
			// белый список: токен с областью не пускается никуда, кроме её путей.
			// Проверка на входе, а не гардом на конкретной группе, — потому что
			// гард надо не забыть повесить на КАЖДУЮ новую ручку, а забывают всегда.
			// Здесь новая ручка по умолчанию закрыта для суженного токена.
			if !scopeAllowsPath(tok.Scope, r.URL.Path) {
				http.Error(w, "токен выпущен с ограниченной областью и сюда не пускается", http.StatusForbidden)
				return
			}
			// Роль берём ИЗ ТОКЕНА, а не из users: она зафиксирована при выпуске.
			// Email в формате "token:<имя>" — чтобы в журнале аудита действие
			// автоматизации нельзя было спутать с действием человека.
			// UserID = создатель: нужен, чтобы аудит связывался с живым пользователем.
			// 🔴 Но это НЕ личность актора: под токеном действует автоматизация, а не
			// админ. Все «личные» ручки закрыты от токена requireHuman — см. его док.
			ctx := context.WithValue(r.Context(), claimsKey, &jwtClaims{
				UserID:     tok.CreatedBy,
				Email:      "token:" + tok.Name,
				Role:       tok.Role,
				TokenID:    tok.ID,
				TokenScope: tok.Scope,
				TenantID:   tok.TenantID,
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
		epoch, perr := h.db.GetUserEpoch(r.Context(), claims.UserID)
		if perr != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if epoch == nil {
			// Членство удалено — живой токен больше не действителен. Сюда же попадает
			// исключение человека из тенанта: токен был выпущен на конкретное членство.
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if claims.IssuedAt == nil || claims.IssuedAt.Unix() < epoch.PasswordChangedAt.Unix() {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if claims.MfaPending && !isMFASetupPath(r) {
			http.Error(w, "mfa verification required", http.StatusForbidden)
			return
		}
		if epoch.TenantID == "" {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		claims.TenantID = epoch.TenantID
		// ADR-7: надзор — признак ЛИЧНОСТИ, поэтому читается из БД, а не из роли
		// членства в токене. Иначе он менялся бы при переключении тенанта.
		claims.IdentityID = epoch.IdentityID
		claims.IsProviderAdmin = epoch.IsProviderAdmin
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

// issueMfaToken выпускает временный JWT для прохождения второго фактора.
func (h *Handler) issueMfaToken(w http.ResponseWriter, userID, email, role string) error {
	jti, err := newJTI()
	if err != nil {
		return err
	}
	claims := &jwtClaims{
		UserID:     userID,
		Email:      email,
		Role:       role,
		MfaPending: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(h.jwtSecret)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "mfa_token",
		Value:    token,
		Path:     "/",
		MaxAge:   900,
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

	// ADR-7: по e-mail резолвится ЛИЧНОСТЬ (пароль общий), членство выбирается после.
	identity, err := h.db.GetIdentityByEmail(r.Context(), req.Email)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Локальный пароль проверяем ПЕРВЫМ и независимо от каталога. Порядок тут — не
	// оптимизация, а требование: пароль из users обязан работать, даже когда учётку
	// отключили в AD или сам AD недоступен. Иначе падение DC запирает всех, включая
	// админа, которому в этот момент и надо чинить (а роль у нас всё равно локальная).
	// Отзыв доступа поэтому делается удалением пользователя, а не отключением в домене.
	method := "local"
	authed := identity != nil && bcrypt.CompareHashAndPassword([]byte(identity.PasswordHash), []byte(req.Password)) == nil
	// identity != nil обязателен: каталог отвечает лишь «пароль верный», аккаунтов вход по
	// LDAP не заводит и права не выдаёт — нет личности, нет входа.
	if !authed && identity != nil && h.directoryLogin(r.Context(), req.Email, req.Password) {
		authed, method = true, "ldap"
	}
	if !authed {
		h.loginLimiter.fail(acctKey, time.Now())
		h.audit(r.Context(), "", req.Email, "login_failed", "user", "", nil)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Пароль верен — выбираем членство. Токен выпускается НА ЧЛЕНСТВО: тенант в нём
	// не отдельным полем, а следствием того, какая строка users в UserID (ADR-7).
	memberships, err := h.db.ListMemberships(r.Context(), identity.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if len(memberships) == 0 {
		// Личность есть, а тенанта нет: работать не в чем, включая надзор — он тоже
		// требует активного тенанта для тенантных ручек. Fail-closed, и намеренно тем
		// же ответом, что неверный пароль: иначе ручка логина отвечала бы, существует
		// ли такой e-mail.
		h.loginLimiter.fail(acctKey, time.Now())
		h.audit(r.Context(), "", req.Email, "login_failed", "user", "", map[string]any{"reason": "no_membership"})
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	h.loginLimiter.success(acctKey)

	// Первый по алфавиту тенант. Порядок задан в auth_identity_memberships и
	// детерминирован: человек попадает туда же, куда в прошлый раз, а дальше
	// переключается сам через /auth/tenant.
	active := memberships[0]

	// Q-44: Check MFA requirement
	tenant, err := h.db.GetTenant(r.Context(), active.TenantID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	mfaRequired := identity.MfaEnabled || (tenant != nil && tenant.RequireMFA)
	if mfaRequired {
		if err := h.issueMfaToken(w, active.UserID, identity.Email, active.Role); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		h.audit(r.Context(), active.UserID, identity.Email, "login_mfa_pending", "user", active.UserID,
			map[string]any{"method": method, "tenants": len(memberships)})
		status := "mfa_required"
		if !identity.MfaEnabled {
			status = "mfa_setup_required"
		}
		writeJSON(w, http.StatusOK, loginResponse{Status: status})
		return
	}

	if err := h.issueToken(w, active.UserID, identity.Email, active.Role); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// method в аудит: при разборе инцидента нужно знать, чем именно вошли — локальным
	// паролем или доменным. По одной записи «login» это неразличимо, а вопрос первый.
	h.audit(r.Context(), active.UserID, identity.Email, "login", "user", active.UserID,
		map[string]any{"method": method, "tenants": len(memberships)})
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

// tenantID достаёт скоуп из claims (заполнен jwtMiddleware из БД). ok=false уже
// ответил 500 — вызывающий просто return.
func (h *Handler) tenantID(w http.ResponseWriter, r *http.Request) (string, bool) {
	claims, ok := r.Context().Value(claimsKey).(*jwtClaims)
	if !ok || claims.TenantID == "" {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return "", false
	}
	return claims.TenantID, true
}

// ActorTenant — скоуп для enterprise-хендлеров (рядом с Actor).
func ActorTenant(ctx context.Context) (tenantID string, ok bool) {
	c, ok := ctx.Value(claimsKey).(*jwtClaims)
	if !ok || c.TenantID == "" {
		return "", false
	}
	return c.TenantID, true
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

// requireProviderAdmin — гард надзора над всей инсталляцией (ADR-7 §11.3).
//
// Заменяет requireRole("provider_admin"): после 052 надзор перестал быть ролью в
// тенанте и стал признаком личности, поэтому сравнивать claims.Role с ним больше
// нельзя — роль membership'а теперь всегда it_admin/viewer. Признак читается из БД
// в jwtMiddleware, а не из токена.
//
// Иерархии это по-прежнему не вводит: доступ внутри тенанта проверяется отдельно
// и требует роли членства, флаг её не заменяет.
func (h *Handler) requireProviderAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(claimsKey).(*jwtClaims)
		if !ok || !claims.IsProviderAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// tenantMembershipView — элемент селектора тенантов в панели.
type tenantMembershipView struct {
	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name"`
	Role       string `json:"role"`
	Active     bool   `json:"active"`
}

// listMyTenants — тенанты, в которых состоит текущая личность (ADR-7 §11.4).
// Тенант, где человека нет, в списке не появляется — это же и есть источник
// правды для UI: селектор не может предложить то, чего в ответе не было.
func (h *Handler) listMyTenants(w http.ResponseWriter, r *http.Request) {
	claims, _ := r.Context().Value(claimsKey).(*jwtClaims)
	memberships, err := h.db.ListMemberships(r.Context(), claims.IdentityID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := make([]tenantMembershipView, 0, len(memberships))
	for _, m := range memberships {
		out = append(out, tenantMembershipView{
			TenantID:   m.TenantID,
			TenantName: m.TenantName,
			Role:       m.Role,
			Active:     m.TenantID == claims.TenantID,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type switchTenantRequest struct {
	TenantID string `json:"tenant_id"`
}

// switchTenant переключает активный тенант без перелогина (ADR-7 §11.4).
//
// Новый токен выпускается на ДРУГОЕ ЧЛЕНСТВО той же личности, и роль берётся из
// него же — она у человека своя в каждом тенанте. Членство проверяется в БД: чужой
// tenant_id в теле запроса даёт 403, а не доступ.
//
// Старый jti гасится в блок-листе: иначе после переключения оставался бы годный
// токен на прежний тенант, и «сменил тенант» означало бы «получил два».
func (h *Handler) switchTenant(w http.ResponseWriter, r *http.Request) {
	claims, _ := r.Context().Value(claimsKey).(*jwtClaims)
	var req switchTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TenantID == "" {
		http.Error(w, "tenant_id is required", http.StatusBadRequest)
		return
	}
	if req.TenantID == claims.TenantID {
		writeJSON(w, http.StatusOK, loginResponse{Status: "ok"})
		return
	}
	m, err := h.db.FindMembership(r.Context(), claims.IdentityID, req.TenantID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if m == nil {
		h.audit(r.Context(), claims.UserID, claims.Email, "switch_tenant_denied", "tenant", req.TenantID, nil)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Гасим прежний токен ДО выдачи нового: fail-closed, иначе при ошибке записи в
	// блок-лист человек уходит с двумя рабочими токенами.
	if claims.ID != "" {
		exp := time.Now().Add(8 * time.Hour)
		if claims.ExpiresAt != nil {
			exp = claims.ExpiresAt.Time
		}
		if err := h.db.RevokeToken(r.Context(), claims.ID, exp); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	if err := h.issueToken(w, m.UserID, claims.Email, m.Role); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.audit(r.Context(), m.UserID, claims.Email, "switch_tenant", "tenant", m.TenantID,
		map[string]any{"from_tenant": claims.TenantID, "role": m.Role})
	writeJSON(w, http.StatusOK, loginResponse{Status: "ok"})
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
	user, err := h.db.GetUserByID(r.Context(), claims.TenantID, claims.UserID)
	if err != nil || user == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	identity, err := h.db.GetIdentityByEmail(r.Context(), claims.Email)
	if err != nil || identity == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// is_provider_admin отдаём отдельным полем, а не ролью: после ADR-7 надзор —
	// признак личности, и UI, гейтившийся на role === "provider_admin", иначе
	// молча перестал бы показывать кросс-тенантные разделы тому, у кого доступ есть.
	writeJSON(w, http.StatusOK, map[string]any{
		"id":                user.ID,
		"email":             user.Email,
		"name":              user.Name,
		"role":              user.Role,
		"is_provider_admin": claims.IsProviderAdmin,
		"mfa_enabled":       identity.MfaEnabled,
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
	user, err := h.db.GetUserByID(r.Context(), claims.TenantID, claims.UserID)
	if err != nil || user == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// ADR-7: пароль — свойство личности, а не членства. Проверяем и меняем его там,
	// поэтому смена гасит сессии человека во ВСЕХ его тенантах, а не только в текущем.
	identity, err := h.db.GetIdentityByEmail(r.Context(), user.Email)
	if err != nil || identity == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(identity.PasswordHash), []byte(req.CurrentPassword)) != nil {
		http.Error(w, "текущий пароль неверный", http.StatusUnauthorized)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcryptCost)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.db.UpdateIdentityPassword(r.Context(), identity.ID, string(hash)); err != nil {
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

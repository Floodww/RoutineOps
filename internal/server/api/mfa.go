package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"

	"github.com/Floodww/RoutineOps/internal/server/secretbox"
)

const mfaHkdfInfo = "routineops:mfa:secret:v1"

// secretCipher — конверт секретов под меткой info. Реализация одна на весь сервер
// (internal/server/secretbox): её читает не только HTTP-слой, но и фоновый воркер
// SIEM, а формат конверта обязан жить в одном месте.
//
// Метка разделяет назначения: секрет MFA, приватник SP и подпись webhook'а
// шифруются РАЗНЫМИ ключами, выведенными из одного корня, поэтому утечка одного не
// открывает остальные.
func (h *Handler) secretCipher(info string) (*secretbox.Box, error) {
	return secretbox.New(h.jwtSecret, info)
}

// encryptEnvelope/decryptEnvelope — тонкие обёртки: вызывающих много, а менять их
// сигнатуру ради переезда реализации незачем.
func encryptEnvelope(b *secretbox.Box, plain string) (string, error) { return b.Seal(plain) }

func decryptEnvelope(b *secretbox.Box, enc string) (string, error) { return b.Open(enc) }

func (h *Handler) encryptMFASecret(secret string) (string, error) {
	aead, err := h.secretCipher(mfaHkdfInfo)
	if err != nil {
		return "", err
	}
	return encryptEnvelope(aead, secret)
}

func (h *Handler) decryptMFASecret(enc string) (string, error) {
	aead, err := h.secretCipher(mfaHkdfInfo)
	if err != nil {
		return "", err
	}
	return decryptEnvelope(aead, enc)
}

// Recovery-коды: в БД лежат ХЕШИ, наружу код показывается ровно один раз.
//
// 🔴 Код восстановления эквивалентен второму фактору: тот, кто его знает, входит.
// Хранить его в открытом виде значит сложить в таблицу рабочие вторые факторы —
// одного чтения БД (бэкап, дамп, дыра в выборке) хватит, чтобы обойти MFA у всех.
//
// Хеш — SHA-256 без соли и без KDF, и это осознанно: код генерируется НАМИ и имеет
// 100 бит энтропии, перебирать такой бессмысленно, а bcrypt на десяти кодах давал бы
// секунду CPU на каждую попытку входа. Соль не нужна там, где нет словаря.
const (
	recoveryCodeCount  = 10
	recoveryCodeBytes  = 13 // 13 байт → 21 символ base32 без паддинга, ~104 бита
	recoveryHashPrefix = "s256:"
)

func newRecoveryCodes() ([]string, []string, error) {
	plain := make([]string, 0, recoveryCodeCount)
	hashed := make([]string, 0, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		raw := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, err
		}
		code := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
		plain = append(plain, code)
		hashed = append(hashed, hashRecoveryCode(code))
	}
	return plain, hashed, nil
}

func hashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(strings.ToLower(code))))
	return recoveryHashPrefix + hex.EncodeToString(sum[:])
}

// takeRecoveryCode ищет предъявленный код среди хешей и возвращает остаток списка.
// Сравнение постоянное по времени: иначе по времени ответа восстанавливается префикс.
// Использованный код НЕ возвращается в остаток — одноразовость и есть его смысл.
func takeRecoveryCode(stored []string, presented string) (rest []string, matched bool) {
	want := hashRecoveryCode(presented)
	for _, h := range stored {
		if !matched && subtle.ConstantTimeCompare([]byte(h), []byte(want)) == 1 {
			matched = true
			continue
		}
		rest = append(rest, h)
	}
	return rest, matched
}

type mfaLoginRequest struct {
	Code string `json:"code"` // TOTP code or recovery code
}

// mfaLogin проверяет TOTP код, если login вернул mfa_required
func (h *Handler) mfaLogin(w http.ResponseWriter, r *http.Request) {
	var tokenStr string
	if c, err := r.Cookie("mfa_token"); err == nil {
		tokenStr = c.Value
	} else if hdr := r.Header.Get("Authorization"); strings.HasPrefix(hdr, "Bearer ") {
		tokenStr = strings.TrimPrefix(hdr, "Bearer ")
	}
	if tokenStr == "" {
		http.Error(w, "mfa_token required", http.StatusUnauthorized)
		return
	}

	claims := &jwtClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return h.jwtSecret, nil
	})
	if err != nil || !token.Valid || !claims.MfaPending {
		http.Error(w, "invalid mfa token", http.StatusUnauthorized)
		return
	}

	var req mfaLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	identity, err := h.db.GetIdentityByEmail(r.Context(), claims.Email)
	if err != nil || identity == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !identity.MfaEnabled || identity.MfaSecret == nil {
		http.Error(w, "MFA not configured for user", http.StatusConflict)
		return
	}

	secretPlain, err := h.decryptMFASecret(*identity.MfaSecret)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	valid := totp.Validate(req.Code, secretPlain)
	if !valid {
		// Второй путь — одноразовый код восстановления. Списывается ДО выдачи сессии:
		// иначе сбой выдачи оставлял бы код действующим при уже состоявшемся входе.
		rest, matched := takeRecoveryCode(identity.RecoveryCodes, req.Code)
		if matched {
			if err := h.db.SetMFA(r.Context(), identity.ID, true, identity.MfaSecret, rest); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			valid = true
			h.audit(r.Context(), claims.UserID, claims.Email, "mfa_recovery_code_used", "user", claims.UserID,
				map[string]any{"codes_left": len(rest)})
		}
	}

	if !valid {
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}

	if err := h.issueToken(w, claims.UserID, claims.Email, claims.Role); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Очищаем временный mfa_token
	http.SetCookie(w, &http.Cookie{
		Name:     "mfa_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteStrictMode,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type mfaEnrollResponse struct {
	URI           string   `json:"uri"`
	RecoveryCodes []string `json:"recovery_codes"`
}

// mfaEnroll инициирует привязку MFA для текущего пользователя.
func (h *Handler) mfaEnroll(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(claimsKey).(*jwtClaims)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "RoutineOps",
		AccountName: claims.Email,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	encSecret, err := h.encryptMFASecret(key.Secret())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	plainCodes, hashedCodes, err := newRecoveryCodes()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	identity, err := h.db.GetIdentityByEmail(r.Context(), claims.Email)
	if err != nil || identity == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if identity.MfaEnabled {
		http.Error(w, "MFA is already enabled. Disable it first to enroll again.", http.StatusConflict)
		return
	}

	// Устанавливаем mfa_enabled = false, пока не будет проверен код
	if err := h.db.SetMFA(r.Context(), identity.ID, false, &encSecret, hashedCodes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Плейнтекст кодов уходит клиенту ЕДИНСТВЕННЫЙ раз: в БД лежат только хеши,
	// восстановить их потом неоткуда — это свойство, а не недоделка.
	writeJSON(w, http.StatusOK, mfaEnrollResponse{
		URI:           key.URL(),
		RecoveryCodes: plainCodes,
	})
}

type mfaVerifyEnrollRequest struct {
	Code string `json:"code"`
}

// mfaVerifyEnroll завершает привязку MFA, проверяя первый код.
func (h *Handler) mfaVerifyEnroll(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(claimsKey).(*jwtClaims)

	var req mfaVerifyEnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	identity, err := h.db.GetIdentityByEmail(r.Context(), claims.Email)
	if err != nil || identity == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if identity.MfaSecret == nil {
		http.Error(w, "MFA not enrolled", http.StatusConflict)
		return
	}

	secretPlain, err := h.decryptMFASecret(*identity.MfaSecret)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if !totp.Validate(req.Code, secretPlain) {
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}

	// Код верный — включаем MFA
	if err := h.db.SetMFA(r.Context(), identity.ID, true, identity.MfaSecret, identity.RecoveryCodes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if claims.MfaPending {
		if err := h.issueToken(w, claims.UserID, claims.Email, claims.Role); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "mfa_token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   h.cookieSecure,
			SameSite: http.SameSiteStrictMode,
		})
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// mfaDisable отключает MFA — ТОЛЬКО против свежего кода второго фактора.
//
// Снятие второго фактора — операция того же веса, что и его выдача: без
// подтверждения одной угнанной сессии (или незапертого ноутбука) хватало бы, чтобы
// разоружить учётку и войти потом одним паролем. Поэтому спрашиваем ровно то, чем
// человек владеет: код из приложения либо код восстановления.
//
// Тенантскую политику «требовать MFA» это не обходит: следующий вход всё равно
// упрётся в mfa_setup_required — снятие лишь возвращает к привязке заново.
func (h *Handler) mfaDisable(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(claimsKey).(*jwtClaims)

	var req mfaLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "нужен код подтверждения", http.StatusBadRequest)
		return
	}

	identity, err := h.db.GetIdentityByEmail(r.Context(), claims.Email)
	if err != nil || identity == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !identity.MfaEnabled || identity.MfaSecret == nil {
		http.Error(w, "MFA не включена", http.StatusConflict)
		return
	}

	secretPlain, err := h.decryptMFASecret(*identity.MfaSecret)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !totp.Validate(req.Code, secretPlain) {
		if _, matched := takeRecoveryCode(identity.RecoveryCodes, req.Code); !matched {
			http.Error(w, "неверный код", http.StatusUnauthorized)
			return
		}
	}

	if err := h.db.SetMFA(r.Context(), identity.ID, false, nil, nil); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.audit(r.Context(), claims.UserID, claims.Email, "mfa_disabled", "user", claims.UserID, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

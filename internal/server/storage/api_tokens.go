package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// APITokenPrefix — префикс плейнтекста сервисного токена. Нужен, чтобы
// jwtMiddleware мог отличить его от JWT ДО попытки разбора (API-токен — не JWT,
// и парсер на нём просто вернул бы «unauthorized» без объяснений). Заодно даёт
// сканерам секретов узнаваемый шаблон для поиска утечек в git и CI-логах.
const APITokenPrefix = "rops_"

// APIToken — сервисный токен без плейнтекста: он существует ровно один раз,
// в ответе на создание, и больше нигде (ни в БД, ни в списке, ни в логах).
type APIToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Role       string     `json:"role"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// hashAPIToken — SHA-256(hex), как hashEnrollToken для enrollment-токенов (028).
// Детерминированный хеш без соли: 32 случайных байта не подбираются словарём, а
// искать по равенству иначе нельзя.
func hashAPIToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NewAPITokenSecret генерирует плейнтекст токена: префикс + 32 случайных байта hex.
func NewAPITokenSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return APITokenPrefix + hex.EncodeToString(b), nil
}

// CreateAPIToken сохраняет ХЕШ токена и возвращает метаданные. Плейнтекст сюда
// приходит уже сгенерированным и наружу не возвращается — вызывающий показывает
// его пользователю сам, ровно один раз.
func (db *DB) CreateAPIToken(ctx context.Context, name, role, createdBy, secret string, expiresAt *time.Time) (*APIToken, error) {
	var t APIToken
	err := db.pool.QueryRow(ctx, `
		INSERT INTO api_tokens (name, token_hash, role, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, name, role, created_by::text, created_at, expires_at, last_used_at
	`, name, hashAPIToken(secret), role, createdBy, expiresAt).Scan(
		&t.ID, &t.Name, &t.Role, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// AuthenticateAPIToken проверяет токен и отмечает факт использования ОДНИМ запросом.
//
// Срок проверяется здесь же, в SQL (`expires_at IS NULL OR expires_at > now()`), а не
// в Go после выборки: иначе истёкший токен всё равно обновил бы last_used_at и выглядел
// бы в UI живым. Заодно это исключает расхождение часов приложения и БД.
//
// last_used_at обновляется на КАЖДЫЙ успешный запрос — нужно, чтобы находить забытые
// токены. Это одна запись в строку на запрос; для автоматизации (десятки-тысячи
// вызовов в день) это ничто, но при параллельных вызовах ОДНИМ токеном строка
// становится точкой сериализации.
// ponytail: обновление на каждый вызов; если один токен начнут долбить сотнями
// параллельных запросов — обновлять раз в N минут (WHERE last_used_at < now()-interval).
//
// Возвращает (nil, nil) на неизвестный/истёкший токен — вызывающий отдаёт 401.
func (db *DB) AuthenticateAPIToken(ctx context.Context, secret string) (*APIToken, error) {
	var t APIToken
	err := db.pool.QueryRow(ctx, `
		UPDATE api_tokens SET last_used_at = now()
		WHERE token_hash = $1 AND (expires_at IS NULL OR expires_at > now())
		RETURNING id, name, role, created_by::text, created_at, expires_at, last_used_at
	`, hashAPIToken(secret)).Scan(
		&t.ID, &t.Name, &t.Role, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

// ListAPITokens отдаёт токены без хешей — плейнтекст невосстановим by design.
func (db *DB) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, name, role, created_by::text, created_at, expires_at, last_used_at
		FROM api_tokens ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []APIToken{}
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.Name, &t.Role, &t.CreatedBy,
			&t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteAPIToken отзывает токен. Отзыв — это удаление строки, а не флаг: блок-лист
// по jti (M-7) тут не нужен, потому что проверка идёт по самой строке, и её
// отсутствие уже означает отказ. Возвращает found=false, если токена нет.
func (db *DB) DeleteAPIToken(ctx context.Context, id string) (bool, error) {
	tag, err := db.pool.Exec(ctx, `DELETE FROM api_tokens WHERE id::text = $1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

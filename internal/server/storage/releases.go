package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Каналы обновлений (миграция 065). Значения совпадают с CHECK'ом в схеме —
// расхождение здесь означало бы 23514 из глубины вместо понятного отказа.
const (
	ChannelStable = "stable"
	ChannelBeta   = "beta"
)

// ValidChannel — известен ли канал. Пустая строка НЕ канал: место, где канал
// потерялся по дороге, должно падать, а не молча превращаться в stable.
func ValidChannel(ch string) bool {
	return ch == ChannelStable || ch == ChannelBeta
}

// channelsVisibleTo — какие каналы релизов видит устройство этого канала.
//
// 🔴 beta — НАДМНОЖЕСТВО stable, а не отдельная ветка. Канарейка обязана быть не
// старее парка: если бы beta видел только beta-строки, продвижение обкатанной
// версии в stable отбирало бы её у канареечной группы (строка меняет канал, beta
// пустеет) и та откатилась бы на предыдущий манифест.
func channelsVisibleTo(ch string) []string {
	if ch == ChannelBeta {
		return []string{ChannelStable, ChannelBeta}
	}
	return []string{ChannelStable}
}

type AgentRelease struct {
	ID                string
	OS                string
	Arch              string
	Version           string
	Filename          string
	SHA256            string
	Signature         string // ed25519 над sha256(бинарь) — совместимость со старыми агентами
	ManifestSignature string // ed25519 над каноном version\nos\narch\nsha256 (SEC-3, anti-downgrade)
	Channel           string // stable|beta (065)
	CreatedAt         time.Time
}

// GetLatestAgentRelease — последний релиз канала stable. Оставлен под тем же именем,
// потому что по нему ходит публичная REST-ручка /api/v1/agent/version: у неё нет
// личности спрашивающего (аутентификации там нет вовсе), значит нет и канала, и
// единственный безопасный ответ — стабильный. Агенты до 065 ходят только сюда и
// поэтому канарейкой не задеваются, что и требуется.
func (db *DB) GetLatestAgentRelease(ctx context.Context, os, arch string) (*AgentRelease, error) {
	return db.GetLatestAgentReleaseForChannel(ctx, os, arch, ChannelStable)
}

// GetLatestAgentReleaseForChannel — последний релиз, ВИДИМЫЙ каналу channel.
// Таблица глобальная (tenancy: ScopeGlobal) — скоуп тенанта здесь не нужен.
func (db *DB) GetLatestAgentReleaseForChannel(ctx context.Context, os, arch, channel string) (*AgentRelease, error) {
	if !ValidChannel(channel) {
		return nil, fmt.Errorf("неизвестный канал обновлений %q", channel)
	}
	var r AgentRelease
	err := db.pool.QueryRow(ctx, `
		SELECT id, os, arch, version, filename, sha256, signature,
		       COALESCE(manifest_signature, ''), channel, created_at
		FROM agent_releases
		WHERE os = $1 AND arch = $2 AND channel = ANY($3)
		ORDER BY created_at DESC LIMIT 1
	`, os, arch, channelsVisibleTo(channel)).
		Scan(&r.ID, &r.OS, &r.Arch, &r.Version, &r.Filename, &r.SHA256, &r.Signature,
			&r.ManifestSignature, &r.Channel, &r.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

// ListAgentReleases — весь реестр публикаций для панели (последние сверху).
func (db *DB) ListAgentReleases(ctx context.Context) ([]AgentRelease, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, os, arch, version, filename, sha256, signature,
		       COALESCE(manifest_signature, ''), channel, created_at
		FROM agent_releases
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentRelease{}
	for rows.Next() {
		var r AgentRelease
		if err := rows.Scan(&r.ID, &r.OS, &r.Arch, &r.Version, &r.Filename, &r.SHA256,
			&r.Signature, &r.ManifestSignature, &r.Channel, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RegisterAgentRelease публикует сборку в канал channel.
//
// UPSERT по UNIQUE(os,arch,version): повторная публикация той же версии (повтор
// update.sh, ретрай после сбоя сборки одной из платформ) — не падение на
// unique-violation, а обновление артефакта/подписи (пересобранный бинарь той же
// версии). created_at не трогаем — порядок «latest» стабилен.
//
// Тем же UPSERT'ом делается ПРОДВИЖЕНИЕ обкатанного билда: publish-release той же
// версии с -channel stable переводит строку из beta в stable. Канарейка при этом
// ничего не теряет — beta видит и stable-строки (channelsVisibleTo).
func (db *DB) RegisterAgentRelease(ctx context.Context, os, arch, version, filename, sha256, signature, manifestSignature, channel string) error {
	if !ValidChannel(channel) {
		return fmt.Errorf("неизвестный канал обновлений %q", channel)
	}
	_, err := db.pool.Exec(ctx, `
		INSERT INTO agent_releases (os, arch, version, filename, sha256, signature, manifest_signature, channel)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (os, arch, version) DO UPDATE SET
			filename           = EXCLUDED.filename,
			sha256             = EXCLUDED.sha256,
			signature          = EXCLUDED.signature,
			manifest_signature = EXCLUDED.manifest_signature,
			channel            = EXCLUDED.channel
	`, os, arch, version, filename, sha256, signature, manifestSignature, channel)
	return err
}

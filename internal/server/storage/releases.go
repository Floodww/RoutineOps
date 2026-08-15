package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Floodww/RoutineOps/internal/version"
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

// GetLatestAgentReleaseForChannel — САМАЯ НОВАЯ ПО ВЕРСИИ сборка, ВИДИМАЯ каналу channel.
// Таблица глобальная (tenancy: ScopeGlobal) — скоуп тенанта здесь не нужен.
//
// 🔴 «Последний» здесь означает старшую ВЕРСИЮ, а не последнюю по времени строку, и это
// исправление, а не оформление. Порядок по created_at хоронил канарейку молча: beta видит
// и stable-строки, поэтому ЛЮБАЯ публикация в stable, случившаяся после канарейки,
// становилась для канареечных машин целью. Поймано 13.08.2026 — канарейка 2.6.10 уехала в
// beta в 11:00, штатный `update.sh` опубликовал 2.6.9 в stable в 11:05, и стенд забрал
// 2.6.9, подняв пол анти-отката до неё. Ни одна сторона при этом не отказала: и публикация,
// и обновление отработали «успешно».
//
// Повторная публикация канарейки этого не лечила: UPSERT намеренно не трогает created_at,
// значит вернуть похороненную сборку было нечем вовсе, кроме выпуска нового номера.
//
// Что мы этим теряем: откат выпуском СТАРОЙ версии поверх новой. Он и не работал — агент
// не берёт версию ниже пола анти-отката (SEC-3), то есть в поле откат был иллюзией и до
// этой правки. Настоящий откат — новый номер с прежним содержимым.
//
// Непарсибельные версии не выбрасываем: если ни одна строка не разобралась, отдаём самую
// позднюю по времени. Иначе платформа с кривым номером осталась бы БЕЗ обновлений молча —
// ровно тот класс отказа, который здесь и чинится.
func (db *DB) GetLatestAgentReleaseForChannel(ctx context.Context, os, arch, channel string) (*AgentRelease, error) {
	if !ValidChannel(channel) {
		return nil, fmt.Errorf("неизвестный канал обновлений %q", channel)
	}
	rows, err := db.pool.Query(ctx, `
		SELECT id, os, arch, version, filename, sha256, signature,
		       COALESCE(manifest_signature, ''), channel, created_at
		FROM agent_releases
		WHERE os = $1 AND arch = $2 AND channel = ANY($3)
		ORDER BY created_at DESC
	`, os, arch, channelsVisibleTo(channel))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var best, fallback *AgentRelease
	for rows.Next() {
		var r AgentRelease
		if err := rows.Scan(&r.ID, &r.OS, &r.Arch, &r.Version, &r.Filename, &r.SHA256, &r.Signature,
			&r.ManifestSignature, &r.Channel, &r.CreatedAt); err != nil {
			return nil, err
		}
		if fallback == nil {
			fallback = &r // строки идут по времени убыванием: первая — самая поздняя
		}
		if !version.Valid(r.Version) {
			continue
		}
		if best == nil {
			best = &r
			continue
		}
		newer, err := version.IsNewer(best.Version, r.Version)
		if err == nil && newer {
			best = &r
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if best != nil {
		return best, nil
	}
	return fallback, nil
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
	// Версия НЕИЗМЕНЯЕМА: под одним (os, arch, version) байты закрепляются первой публикацией.
	// Повтор с тем же sha256 меняет ТОЛЬКО канал — это и есть продвижение beta→stable (Q-52),
	// единственная законная мутация опубликованной строки. Повтор с ДРУГИМ sha256 — отказ, а не
	// upsert: прежний код перезаписывал и байты, и подпись (так 12.08 windows 2.6.8 переехала из
	// beta в stable с новыми байтами под тем же номером), и подпись манифеста, которая ловит
	// downgrade-relabel ИЗВНЕ, была бессильна против самонанесённого изнутри.
	//
	// Атомарно и fail-closed: WHERE на DO UPDATE пропускает смену канала только при совпадении
	// sha256. При расхождении конфликт не даёт ни INSERT, ни UPDATE — RETURNING пуст, Scan
	// возвращает ErrNoRows, и это единственный сигнал «номер занят другими байтами». Ретраи
	// публикации не ломаются: повтор того же коммита под -trimpath даёт тот же бинарь, sha256
	// совпадает, и WHERE пропускает. filename/signature/manifest_signature при совпадении sha256
	// детерминированно те же (ed25519 детерминирован), поэтому в SET их нет — меняется лишь канал.
	var dummy string
	err := db.pool.QueryRow(ctx, `
		INSERT INTO agent_releases (os, arch, version, filename, sha256, signature, manifest_signature, channel)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (os, arch, version) DO UPDATE SET channel = EXCLUDED.channel
			WHERE agent_releases.sha256 = EXCLUDED.sha256
		RETURNING version
	`, os, arch, version, filename, sha256, signature, manifestSignature, channel).Scan(&dummy)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("версия %s %s/%s уже опубликована с другим sha256: версии неизменяемы, "+
			"перевыпуск под тем же номером запрещён (продвижение меняет только канал)", version, os, arch)
	}
	return err
}

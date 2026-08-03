package storage

import (
	"context"
	"time"
)

// Отчёт соответствия (Q-62, вторая половина).
//
// 🔴 До этой правки дашборд рисовал каждому активному устройству бейдж «Compliant»
// БЕЗ ЕДИНОЙ ПРОВЕРКИ — фронт просто печатал слово на каждой строке. Для демонстрации
// этого хватало; отчёт, который показывают аудитору, так выглядеть не может: он не
// просто беден, он утверждает неправду. Здесь соответствие считается из данных.

// Причины несоответствия. Строковые константы, потому что уезжают в JSON, CSV и в
// интерфейс — числовой код пришлось бы переводить в трёх местах.
const (
	// ComplianceVulnerable — на устройстве есть подтверждённая уязвимость.
	ComplianceVulnerable = "vulnerable"
	// ComplianceUnverified — есть уязвимости, которые сопоставить НЕ УДАЛОСЬ (Q-62).
	// Отдельная причина, а не разновидность vulnerable: «мы не смогли посмотреть» —
	// это не то же самое, что «мы посмотрели и там дыра», и действия разные.
	ComplianceUnverified = "unverified"
	// ComplianceStale — устройство давно не выходило на связь: всё, что мы о нём
	// знаем, устарело, и любое утверждение о его состоянии — про прошлое.
	ComplianceStale = "stale"
	// ComplianceOutdatedAgent — версия агента ниже той, что канал устройства уже
	// предлагает (Q-52). Значит исправления до машины не доехали.
	ComplianceOutdatedAgent = "outdated_agent"
	// ComplianceDegraded — durable-очередь агента недоступна: отчёты с машины НЕ
	// доходят, то есть её «чистота» ничем не подтверждена.
	ComplianceDegraded = "degraded"
	// ComplianceLocked — устройство заблокировано администратором.
	ComplianceLocked = "locked"
)

// staleAfter — через сколько молчания устройство считается устаревшим.
// Неделя: короче — ловим отпуска и выключенные ноутбуки, длиннее — отчёт начинает
// ручаться за машины, о которых ничего не знает почти месяц.
const staleAfter = 7 * 24 * time.Hour

// DeviceCompliance — строка отчёта по одному устройству.
type DeviceCompliance struct {
	DeviceID     string     `json:"device_id"`
	Hostname     string     `json:"hostname"`
	OS           string     `json:"os"`
	OSVersion    string     `json:"os_version"`
	AgentVersion string     `json:"agent_version"`
	Channel      string     `json:"update_channel"`
	Status       string     `json:"status"`
	LastSeenAt   *time.Time `json:"last_seen_at"`
	Vulnerable   int        `json:"vulnerable_count"`
	Unverified   int        `json:"unverified_count"`
	Compliant    bool       `json:"compliant"`
	Reasons      []string   `json:"reasons"`
}

// ComplianceSummary — сводка для шапки отчёта.
type ComplianceSummary struct {
	Devices       int            `json:"devices"`
	Compliant     int            `json:"compliant"`
	NonCompliant  int            `json:"non_compliant"`
	ByReason      map[string]int `json:"by_reason"`
	GeneratedAt   time.Time      `json:"generated_at"`
	StaleAfterDay int            `json:"stale_after_days"`
}

// ComplianceReport — сводка плюс построчный разрез.
type ComplianceReport struct {
	Summary ComplianceSummary  `json:"summary"`
	Devices []DeviceCompliance `json:"devices"`
}

// BuildComplianceReport считает соответствие парка тенанта.
//
// Целевые версии каналов передаются аргументом, а не читаются здесь: правило
// видимости каналов (beta ⊇ stable) живёт в коде, и дублировать его в SQL значило бы
// завести второе место, где оно может разойтись. Пустая карта = сравнивать не с чем,
// причина outdated_agent тогда не выставляется вовсе (а не выставляется всем подряд).
func (db *DB) BuildComplianceReport(ctx context.Context, tenantID string, targets map[string]string) (*ComplianceReport, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}

	rows, err := db.Q(ctx).Query(ctx, `
		SELECT d.id,
		       COALESCE(d.hostname, ''),
		       COALESCE(d.os, ''),
		       COALESCE(d.os_version, ''),
		       COALESCE(d.agent_version, ''),
		       COALESCE(d.status, ''),
		       d.last_seen_at,
		       COALESCE(d.lock_status, ''),
		       COALESCE(d.outbox_unavailable, false),
		       CASE WHEN EXISTS (
		           SELECT 1 FROM device_group_members m
		           JOIN device_groups g ON g.id = m.group_id
		           WHERE m.device_id = d.id AND g.update_channel = 'beta'
		       ) THEN 'beta' ELSE 'stable' END,
		       COALESCE((SELECT count(*) FROM device_vulnerabilities v
		                 WHERE v.device_id = d.id AND v.match_status = 'matched'), 0),
		       COALESCE((SELECT count(*) FROM device_vulnerabilities v
		                 WHERE v.device_id = d.id AND v.match_status = 'unknown'), 0)
		FROM devices d
		WHERE d.tenant_id = $1
		ORDER BY d.hostname NULLS LAST, d.id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	report := &ComplianceReport{
		Devices: []DeviceCompliance{},
		Summary: ComplianceSummary{
			ByReason:      map[string]int{},
			GeneratedAt:   time.Now().UTC(),
			StaleAfterDay: int(staleAfter / (24 * time.Hour)),
		},
	}
	now := time.Now()
	for rows.Next() {
		var d DeviceCompliance
		var lockStatus string
		var degraded bool
		if err := rows.Scan(&d.DeviceID, &d.Hostname, &d.OS, &d.OSVersion, &d.AgentVersion,
			&d.Status, &d.LastSeenAt, &lockStatus, &degraded, &d.Channel,
			&d.Vulnerable, &d.Unverified); err != nil {
			return nil, err
		}

		d.Reasons = []string{}
		if d.Vulnerable > 0 {
			d.Reasons = append(d.Reasons, ComplianceVulnerable)
		}
		if d.Unverified > 0 {
			d.Reasons = append(d.Reasons, ComplianceUnverified)
		}
		if d.LastSeenAt == nil || now.Sub(*d.LastSeenAt) > staleAfter {
			d.Reasons = append(d.Reasons, ComplianceStale)
		}
		if degraded {
			d.Reasons = append(d.Reasons, ComplianceDegraded)
		}
		if lockStatus == "locked" {
			d.Reasons = append(d.Reasons, ComplianceLocked)
		}
		if target := targets[d.Channel]; target != "" && d.AgentVersion != "" && d.AgentVersion != target {
			// Сравнение строгое по неравенству, а не по «старше»: версия, которой
			// канал не предлагает, — это либо отставание, либо самосбор, и то и
			// другое стоит показать. Пустая версия сюда не попадает — это отдельная
			// история (агент ни разу не отчитался), её ловит stale.
			d.Reasons = append(d.Reasons, ComplianceOutdatedAgent)
		}

		d.Compliant = len(d.Reasons) == 0
		if d.Compliant {
			report.Summary.Compliant++
		} else {
			report.Summary.NonCompliant++
			for _, r := range d.Reasons {
				report.Summary.ByReason[r]++
			}
		}
		report.Summary.Devices++
		report.Devices = append(report.Devices, d)
	}
	return report, rows.Err()
}

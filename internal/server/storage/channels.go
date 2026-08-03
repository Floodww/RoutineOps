package storage

import (
	"context"
)

// Канал обновлений устройства и картина выкатки для панели (Q-52, миграция 065).

// ResolveDeviceUpdateChannel — канал, по которому обновляется это устройство.
//
// Разрешение по МАКСИМУМУ: устройство состоит в нескольких группах, и достаточно
// одной beta-группы, чтобы машина стала канарейкой. Канареечная группа —
// добавляемая метка поверх рабочих групп; правило «минимум» сделало бы её
// бессмысленной, потому что любая обычная группа возвращала бы машину на stable.
//
// Скоуп открывает сама (BindTenantForDevice), как GetDesiredLockState: зовётся с
// gRPC-пути, где известен только device_id из mTLS-серта.
func (db *DB) ResolveDeviceUpdateChannel(ctx context.Context, deviceID string) (string, error) {
	ctx, finish, err := db.BindTenantForDevice(ctx, deviceID)
	if err != nil {
		return "", err
	}
	defer finish(true)

	var beta bool
	err = db.Q(ctx).QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM device_group_members m
			JOIN device_groups g ON g.id = m.group_id
			WHERE m.device_id = $1 AND g.update_channel = $2
		)`, deviceID, ChannelBeta).Scan(&beta)
	if err != nil {
		return "", err
	}
	if beta {
		return ChannelBeta, nil
	}
	return ChannelStable, nil
}

// VersionCount — сколько устройств канала сидит на этой версии агента.
type VersionCount struct {
	Version string `json:"version"` // "" = агент ещё ни разу не отчитался
	Count   int    `json:"count"`
}

// ChannelTarget — что канал ОТДАСТ агенту этой платформы прямо сейчас.
type ChannelTarget struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Version string `json:"version"`
}

// ChannelRollout — срез одного канала: сколько групп и устройств в нём, на чём они
// сидят по факту и что канал им предлагает.
type ChannelRollout struct {
	Channel  string          `json:"channel"`
	Groups   int             `json:"groups"`
	Devices  int             `json:"devices"`
	Versions []VersionCount  `json:"versions"`
	Targets  []ChannelTarget `json:"targets"`
}

// UpdateRollout — картина выкатки для панели: по каналу видно и целевую версию, и
// реальное распределение. Без второй половины «канарейка поехала» неотличимо от
// «канарейка поехала и упала, не доложив» — а именно ради этого различия канал и
// заводился.
func (db *DB) UpdateRollout(ctx context.Context, tenantID string) ([]ChannelRollout, error) {
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

	// Канал устройства выводится тем же правилом, что в ResolveDeviceUpdateChannel:
	// одна beta-группа делает машину канарейкой. Правило живёт в двух местах (здесь и
	// в EXISTS выше) осознанно — панель считает его на весь парк одним проходом, а
	// gRPC-путь по одному устройству; тест TestUpdateRollout_MatchesResolver держит их
	// в согласии.
	rows, err := db.Q(ctx).Query(ctx, `
		WITH dev AS (
			SELECT d.id,
			       COALESCE(d.agent_version, '') AS version,
			       CASE WHEN EXISTS (
			           SELECT 1 FROM device_group_members m
			           JOIN device_groups g ON g.id = m.group_id
			           WHERE m.device_id = d.id AND g.update_channel = $2
			       ) THEN $2 ELSE $3 END AS channel
			FROM devices d
			WHERE d.tenant_id = $1
		)
		SELECT channel, version, COUNT(*) FROM dev GROUP BY 1, 2
		ORDER BY 1, 3 DESC, 2
	`, tenantID, ChannelBeta, ChannelStable)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byChannel := map[string]*ChannelRollout{}
	for _, ch := range []string{ChannelStable, ChannelBeta} {
		byChannel[ch] = &ChannelRollout{Channel: ch, Versions: []VersionCount{}, Targets: []ChannelTarget{}}
	}
	for rows.Next() {
		var ch string
		var vc VersionCount
		if err := rows.Scan(&ch, &vc.Version, &vc.Count); err != nil {
			return nil, err
		}
		c, ok := byChannel[ch]
		if !ok {
			continue
		}
		c.Versions = append(c.Versions, vc)
		c.Devices += vc.Count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	groups, err := db.Q(ctx).Query(ctx,
		`SELECT update_channel, COUNT(*) FROM device_groups WHERE tenant_id = $1 GROUP BY 1`, tenantID)
	if err != nil {
		return nil, err
	}
	defer groups.Close()
	for groups.Next() {
		var ch string
		var n int
		if err := groups.Scan(&ch, &n); err != nil {
			return nil, err
		}
		if c, ok := byChannel[ch]; ok {
			c.Groups = n
		}
	}
	if err := groups.Err(); err != nil {
		return nil, err
	}

	// Целевые версии. Считаются в Go, а не в SQL, ровно потому, что видимость каналов
	// (beta = stable ∪ beta) — правило кода, а не схемы: дублировать его в SQL значило
	// бы завести второе место, где оно может разойтись.
	platforms, err := db.Q(ctx).Query(ctx, `SELECT DISTINCT os, arch FROM agent_releases ORDER BY 1, 2`)
	if err != nil {
		return nil, err
	}
	defer platforms.Close()
	type platform struct{ os, arch string }
	var plats []platform
	for platforms.Next() {
		var p platform
		if err := platforms.Scan(&p.os, &p.arch); err != nil {
			return nil, err
		}
		plats = append(plats, p)
	}
	if err := platforms.Err(); err != nil {
		return nil, err
	}
	for _, ch := range []string{ChannelStable, ChannelBeta} {
		for _, p := range plats {
			rel, err := db.GetLatestAgentReleaseForChannel(ctx, p.os, p.arch, ch)
			if err != nil {
				return nil, err
			}
			if rel == nil {
				continue
			}
			byChannel[ch].Targets = append(byChannel[ch].Targets,
				ChannelTarget{OS: p.os, Arch: p.arch, Version: rel.Version})
		}
	}

	return []ChannelRollout{*byChannel[ChannelStable], *byChannel[ChannelBeta]}, nil
}

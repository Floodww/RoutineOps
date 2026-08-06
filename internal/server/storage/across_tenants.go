package storage

import (
	"context"
)

// ListDevicesAcrossTenants — кросс-тенантный список через SECURITY DEFINER (миграция 048).
//
// Идёт прямо в пул, а не через TenantScope, и это не обход, а суть ручки: она отвечает на
// вопрос надзора «покажи парк всей инсталляции», ответ на который одним тенантом в GUC не
// выражается. Изоляцию здесь держит не RLS, а сама функция (SECURITY DEFINER, фиксированный
// search_path) плюс гард роли у вызывающего. Запись — в pool_bypass_test.go.
func (db *DB) ListDevicesAcrossTenants(ctx context.Context, query, groupID string, limit, offset int) ([]Device, int, error) {
	limit, offset = clampPage(limit, offset)
	rows, err := db.pool.Query(ctx, `SELECT * FROM list_devices_across_tenants($1, $2, $3, $4)`,
		query, groupID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var devices []Device
	total := 0
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Hostname, &d.OS, &d.OSVersion,
			&d.IPAddress, &d.Status, &d.LastSeenAt, &d.CreatedAt, &d.AgentVersion,
			&d.MACAddress, &d.SerialNumber, &d.PublicIP,
			&d.OutboxUnavailable, &d.DegradedDetail, &d.DegradedSince,
			&d.TenantID, &total); err != nil {
			return nil, 0, err
		}
		d.Groups = []DeviceGroupRef{}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if err := db.attachDeviceGroupsAcrossTenants(ctx, devices); err != nil {
		return nil, 0, err
	}
	return devices, total, nil
}

// attachDeviceGroupsAcrossTenants — группы по tenant_id: RLS на members/groups без BindTenant пустой.
func (db *DB) attachDeviceGroupsAcrossTenants(ctx context.Context, devices []Device) error {
	if len(devices) == 0 {
		return nil
	}
	byTenant := make(map[string][]*Device)
	for i := range devices {
		tid := devices[i].TenantID
		byTenant[tid] = append(byTenant[tid], &devices[i])
	}
	for tenantID, devs := range byTenant {
		tctx, finish, err := db.BindTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		ids := make([]string, len(devs))
		byID := make(map[string]*Device, len(devs))
		for i, d := range devs {
			ids[i] = d.ID
			byID[d.ID] = d
		}
		rows, err := db.Scoped(tctx).Query(tctx, `
			SELECT m.device_id, g.id, g.name, g.color
			FROM device_group_members m
			JOIN device_groups g ON g.id = m.group_id
			WHERE m.device_id = ANY($1::uuid[])
			ORDER BY g.name
		`, ids)
		if err != nil {
			finish(false)
			return err
		}
		for rows.Next() {
			var deviceID string
			var ref DeviceGroupRef
			if err := rows.Scan(&deviceID, &ref.ID, &ref.Name, &ref.Color); err != nil {
				rows.Close()
				finish(false)
				return err
			}
			if d := byID[deviceID]; d != nil {
				d.Groups = append(d.Groups, ref)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			finish(false)
			return err
		}
		finish(true)
	}
	return nil
}

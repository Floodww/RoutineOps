package storage

import "github.com/Floodww/RoutineOps/internal/server/tenancy"

// requireTenant — fail-closed скоуп для panel-путей. Пустой/нулевой тенант не
// означает «все»: это ошибка (контракт §4). Агентские пути тенант извне не
// принимают — они резолвят его из строки devices по fingerprint/CN.
func requireTenant(tenantID string) (string, error) {
	return tenancy.Require(tenantID)
}

package gateway_test

import (
	"context"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// tenantCtx — контекст «как в бою»: тенант в нём уже лежит. На панельных путях его
// кладёт jwtMiddleware, на агентских — gateway после резолва по отпечатку серта.
// Тесты сеют данные прямо через storage, и голый context.Background() означал бы
// запрос мимо тенантского скоупа — путь, которого в проде нет (см. storage.TenantScope).
func tenantCtx() context.Context {
	return storage.WithTenantID(context.Background(), tenancy.DefaultTenantID)
}

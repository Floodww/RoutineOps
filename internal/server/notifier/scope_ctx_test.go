package notifier

import (
	"context"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// tenantCtx — контекст «как в бою» для сева данных прямо через storage. У самого бота
// тенанта в контексте нет и быть не может (сообщение приходит из мессенджера), но
// подготовка теста — это панельная половина, где тенант известен всегда.
func tenantCtx() context.Context {
	return storage.WithTenantID(context.Background(), tenancy.DefaultTenantID)
}

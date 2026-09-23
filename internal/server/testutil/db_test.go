package testutil

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
)

// Пакеты тестов в CI идут параллельно, каждый в своей БД, но на ОДНОМ сервере
// (TEST_POSTGRES_DSN), а роль mdm_app — кластерная. Воспроизводит то, чем публичный CI
// покраснел 23.09 на 07fdd4d: «ALTER ROLE mdm_app … tuple concurrently updated».
func TestCreateAppRole_ParallelPackages(t *testing.T) {
	adminDSN := os.Getenv("TEST_POSTGRES_DSN")
	if adminDSN == "" {
		t.Skip("гонка есть только на общем сервере — нужен TEST_POSTGRES_DSN")
	}
	const n = 8
	dsns := make([]string, n)
	for i := range dsns {
		dsn, drop := createTempDatabase(adminDSN)
		t.Cleanup(drop)
		dsns[i] = dsn
	}

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for _, dsn := range dsns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// createAppRole паникует (её зовут из TestMain) — ловим, чтобы тест упал с
			// причиной, а не уронил весь бинарь.
			defer func() {
				if r := recover(); r != nil {
					errs <- fmt.Errorf("%v", r)
				}
			}()
			createAppRole(context.Background(), dsn)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

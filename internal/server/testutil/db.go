package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// NewDSNWithCleanup возвращает DSN и функцию очистки — для использования в TestMain.
// Если установлена TEST_POSTGRES_DSN (admin DSN), создаёт уникальную БД и возвращает
// DSN на неё; cleanup дропает БД. Это даёт изоляцию между пакетами при общем сервере.
//
// Миграции катятся под owner'ом (mdm / superuser). После миграций создаётся роль
// mdm_app (NOSUPERUSER NOBYPASSRLS) и DSN переключается на неё — тесты видят RLS
// ровно так, как видит его приложение в проде (Q-14).
func NewDSNWithCleanup() (dsn string, cleanup func()) {
	if adminDSN := os.Getenv("TEST_POSTGRES_DSN"); adminDSN != "" {
		dsn, drop := createTempDatabase(adminDSN)
		runMigrationsCtx(context.Background(), dsn)
		dsn = createAppRole(context.Background(), dsn)
		return dsn, drop
	}

	ctx := context.Background()
	c, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("mdm_test"),
		postgres.WithUsername("mdm"),
		postgres.WithPassword("mdm"),
		// trust для всех локальных подключений: mdm_app (049) может подключаться
		// без пароля. В проде pg_hba.conf управляется отдельно.
		testcontainers.WithEnv(map[string]string{"POSTGRES_HOST_AUTH_METHOD": "trust"}),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
		),
	)
	if err != nil {
		panic("testcontainers postgres: " + err.Error())
	}
	dsn, err = c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		panic("connection string: " + err.Error())
	}
	runMigrationsCtx(ctx, dsn)
	dsn = createAppRole(ctx, dsn)
	return dsn, func() { _ = c.Terminate(ctx) }
}

// createTempDatabase создаёт уникальную БД на сервере, указанном в adminDSN,
// и возвращает DSN на неё + функцию-дропалку.
func createTempDatabase(adminDSN string) (dsn string, drop func()) {
	ctx := context.Background()
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		panic("rand: " + err.Error())
	}
	dbName := "mdm_test_" + hex.EncodeToString(buf)

	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		panic("admin connect: " + err.Error())
	}
	if _, err := conn.Exec(ctx, fmt.Sprintf("CREATE DATABASE %q", dbName)); err != nil {
		_ = conn.Close(ctx)
		panic("CREATE DATABASE: " + err.Error())
	}
	_ = conn.Close(ctx)

	u, err := url.Parse(adminDSN)
	if err != nil {
		panic("parse adminDSN: " + err.Error())
	}
	u.Path = "/" + dbName
	dsn = u.String()

	drop = func() {
		c, err := pgx.Connect(ctx, adminDSN)
		if err != nil {
			return
		}
		defer c.Close(ctx)
		_, _ = c.Exec(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %q WITH (FORCE)", dbName))
	}
	return dsn, drop
}

// createAppRole создаёт роль mdm_app (NOSUPERUSER NOBYPASSRLS) в тестовой БД и
// возвращает DSN с этой ролью. Зеркалит миграцию 049_app_role.sql: тесты ходят
// под ограниченной ролью → RLS действует, rls_test не скипает.
func createAppRole(ctx context.Context, ownerDSN string) string {
	conn, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		panic("createAppRole connect: " + err.Error())
	}
	defer conn.Close(ctx)

	// Имя БД нужно для GRANT CONNECT. Узнаём из текущего подключения.
	var dbName string
	if err := conn.QueryRow(ctx, "SELECT current_database()").Scan(&dbName); err != nil {
		panic("createAppRole current_database: " + err.Error())
	}

	stmts := []string{
		"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mdm_app') THEN CREATE ROLE mdm_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE; END IF; END $$",
		fmt.Sprintf("GRANT CONNECT ON DATABASE %q TO mdm_app", dbName),
		"GRANT USAGE ON SCHEMA public TO mdm_app",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO mdm_app",
		"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mdm_app",
		"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO mdm_app",
		// Дефолтный GUC: тесты, не использующие BindTenant явно, попадают в скоуп
		// DefaultTenantID. На проде BindTenant вызывается всегда; ALTER ROLE SET —
		// страховка от забытого скоупа (fail-safe → видеть только свой тенант, а не всё).
		"ALTER ROLE mdm_app SET routineops.tenant_id = '" + tenancy.DefaultTenantID + "'",
	}
	for _, s := range stmts {
		if _, err := conn.Exec(ctx, s); err != nil {
			panic("createAppRole: " + s[:40] + "…: " + err.Error())
		}
	}

	// Переписываем userinfo в DSN на mdm_app.
	u, err := url.Parse(ownerDSN)
	if err != nil {
		panic("createAppRole parse DSN: " + err.Error())
	}
	u.User = url.User("mdm_app")
	return u.String()
}

func runMigrationsCtx(ctx context.Context, dsn string) {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		panic("connect for migrations: " + err.Error())
	}
	defer conn.Close(ctx)

	root := findRoot()
	entries, _ := os.ReadDir(filepath.Join(root, "migrations"))
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, filepath.Join(root, "migrations", e.Name()))
		}
	}
	sort.Strings(files)
	for _, f := range files {
		sql, _ := os.ReadFile(f)
		if _, err := conn.Exec(ctx, string(sql)); err != nil {
			panic("migration " + filepath.Base(f) + ": " + err.Error())
		}
	}
}

func findRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("go.mod not found")
		}
		dir = parent
	}
}

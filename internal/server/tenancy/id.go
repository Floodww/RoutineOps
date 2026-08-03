package tenancy

import (
	"errors"

	"github.com/google/uuid"
)

// DefaultTenantID — тенант, в который бэкфилл 045 кладёт весь существующий парк.
// Фиксированный UUID; смена = переезд всех строк. Совпадает с INSERT в
// migrations/045_tenants.sql.
const DefaultTenantID = "00000000-0000-4000-8000-000000000001"

// InstallationSettingsTenantID — маркер install-default в system_settings (контракт §3.4).
// Не путать с DefaultTenantID. Не является строкой в tenants.
const InstallationSettingsTenantID = "00000000-0000-0000-0000-000000000000"

// ErrTenantScopeMissing — обычный путь storage/API получил пустой тенант.
// Не «все тенанты»: пустой скоуп — ошибка (контракт §4), иначе забытый
// предикат маскируется тишиной или превращается в утечку.
var ErrTenantScopeMissing = errors.New("tenant scope missing")

// ParseID разбирает UUID тенанта. Пустая/нулевая строка → ErrTenantScopeMissing.
func ParseID(s string) (uuid.UUID, error) {
	if s == "" {
		return uuid.Nil, ErrTenantScopeMissing
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, ErrTenantScopeMissing
	}
	if id == uuid.Nil {
		return uuid.Nil, ErrTenantScopeMissing
	}
	return id, nil
}

// Require возвращает s или ErrTenantScopeMissing, если скоуп пустой/нулевой.
func Require(s string) (string, error) {
	id, err := ParseID(s)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

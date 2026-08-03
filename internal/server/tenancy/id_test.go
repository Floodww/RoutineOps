package tenancy_test

import (
	"errors"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

func TestDefaultTenantIDStable(t *testing.T) {
	// Совпадает с INSERT в migrations/045_tenants.sql — смена ломает бэкфилл.
	const want = "00000000-0000-4000-8000-000000000001"
	if tenancy.DefaultTenantID != want {
		t.Fatalf("DefaultTenantID = %q, want %q", tenancy.DefaultTenantID, want)
	}
}

func TestRequireRejectsEmpty(t *testing.T) {
	for _, s := range []string{"", "00000000-0000-0000-0000-000000000000", "not-a-uuid"} {
		if _, err := tenancy.Require(s); !errors.Is(err, tenancy.ErrTenantScopeMissing) {
			t.Errorf("Require(%q) err = %v, want ErrTenantScopeMissing", s, err)
		}
	}
	got, err := tenancy.Require(tenancy.DefaultTenantID)
	if err != nil || got != tenancy.DefaultTenantID {
		t.Fatalf("Require(default) = %q, %v", got, err)
	}
}

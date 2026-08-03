package api_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestAPI_CrossTenantIsolation(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)

	ctx := context.Background()
	tenantA := "tenant_" + uuid.New().String()
	tenantB := "tenant_" + uuid.New().String()

	tA, err := db.CreateTenant(ctx, tenantA)
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	tB, err := db.CreateTenant(ctx, tenantB)
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}

	dev, err := db.CreatePendingDevice(ctx, tA.ID, "Host-A", "Darwin")
	if err != nil {
		t.Fatalf("create device in A: %v", err)
	}
	_ = db.UpdateDeviceStatus(ctx, tA.ID, dev.ID, "active")

	_, err = db.CreateAlert(ctx, dev.ID, "test_alert", "test", "")
	if err != nil {
		t.Fatalf("create alert in A: %v", err)
	}
	alerts, _ := db.ListAlerts(ctx, tA.ID, dev.ID, 10)
	alertID := alerts[0].ID

	adminB, err := db.CreateUser(ctx, tB.ID, "Admin B", "admin_b@example.com", "$2a$10$xyz", "it_admin")
	if err != nil {
		t.Fatalf("create admin B: %v", err)
	}

	claims := jwt.MapClaims{
		"sub":    adminB.ID,
		"email":  adminB.Email,
		"name":   adminB.Name,
		"role":   adminB.Role,
		"tenant": tB.ID,
		"exp":    time.Now().Add(time.Hour).Unix(),
	}
	tokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := tokenObj.SignedString([]byte("test-secret"))
	token := "Bearer " + tokenStr

	tests := []struct {
		method string
		path   string
		body   string
	}{
		{"POST", "/api/v1/devices/" + dev.ID + "/lock", `{"reason":"test"}`},
		{"POST", "/api/v1/devices/" + dev.ID + "/unlock", ""},
		{"POST", "/api/v1/devices/" + dev.ID + "/reenroll", ""},
		{"POST", "/api/v1/alerts/" + alertID + "/acknowledge", ""},
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := authedDo(t, rtr, tc.method, tc.path, []byte(tc.body), token)
			if w.Code == http.StatusOK {
				t.Errorf("expected non-200 for cross-tenant access, got %d", w.Code)
			}
			if w.Code != http.StatusNotFound && w.Code != http.StatusBadRequest && w.Code != http.StatusConflict && w.Code != http.StatusInternalServerError {
				t.Errorf("unexpected status code %d", w.Code)
			}
		})
	}
}

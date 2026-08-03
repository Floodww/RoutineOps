package admin

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	pb "github.com/Floodww/RoutineOps/proto"
)

type fakePriv struct {
	granted []string
	revoked []string
	isAdmin bool // членство, которое вернёт IsAdmin (снимок «был ли админом до гранта»)
}

func (f *fakePriv) Grant(u string) error         { f.granted = append(f.granted, u); return nil }
func (f *fakePriv) Revoke(u string) error        { f.revoked = append(f.revoked, u); return nil }
func (f *fakePriv) IsAdmin(string) (bool, error) { return f.isAdmin, nil }

type harness struct {
	m       *Manager
	priv    *fakePriv
	user    string
	resp    *pb.FetchAdminStatusResponse
	reports []*pb.ReportAdminAccessRequest
}

func newHarness() *harness {
	h := &harness{priv: &fakePriv{}, user: "alice"}
	h.m = &Manager{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		priv:        h.priv,
		consoleUser: func() (string, bool) { return h.user, true },
		fetch:       func(context.Context) (*pb.FetchAdminStatusResponse, error) { return h.resp, nil },
		report: func(_ context.Context, r *pb.ReportAdminAccessRequest) error {
			h.reports = append(h.reports, r)
			return nil
		},
	}
	return h
}

func approved(reqID string, expires time.Time) *pb.FetchAdminStatusResponse {
	return &pb.FetchAdminStatusResponse{
		RequestId: reqID,
		Status:    pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_APPROVED,
		ExpiresAt: expires.Unix(),
	}
}

func lastReport(h *harness) *pb.ReportAdminAccessRequest {
	if len(h.reports) == 0 {
		return nil
	}
	return h.reports[len(h.reports)-1]
}

func TestGrantOnApproved(t *testing.T) {
	h := newHarness()
	h.resp = approved("r1", time.Now().Add(time.Hour))
	h.m.poll(context.Background())

	if len(h.priv.granted) != 1 || h.priv.granted[0] != "alice" {
		t.Fatalf("ожидали grant alice, got %v", h.priv.granted)
	}
	if r := lastReport(h); r == nil || r.GetStatus() != pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_APPROVED || r.GetRequestId() != "r1" {
		t.Fatalf("ожидали отчёт APPROVED r1, got %+v", r)
	}
	// Повторный poll с той же заявкой — без повторной выдачи.
	h.m.poll(context.Background())
	if len(h.priv.granted) != 1 {
		t.Fatalf("повторная выдача той же заявки: %v", h.priv.granted)
	}
}

func TestRevokeOnLogout(t *testing.T) {
	h := newHarness()
	h.resp = approved("r1", time.Now().Add(time.Hour))
	h.m.poll(context.Background()) // выдали alice

	h.user = "" // логаут
	h.m.poll(context.Background())

	if len(h.priv.revoked) != 1 || h.priv.revoked[0] != "alice" {
		t.Fatalf("ожидали revoke alice на логауте, got %v", h.priv.revoked)
	}
	if r := lastReport(h); r == nil || r.GetStatus() != pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_REVOKED {
		t.Fatalf("ожидали отчёт REVOKED, got %+v", r)
	}
	if h.m.grantedUser != "" {
		t.Fatalf("состояние не очищено: %q", h.m.grantedUser)
	}
}

func TestRevokeOnExpiry(t *testing.T) {
	h := newHarness()
	h.resp = approved("r1", time.Now().Add(time.Hour))
	h.m.poll(context.Background()) // выдали

	h.m.grantedExpires = time.Now().Add(-time.Minute) // имитируем истечение
	h.m.poll(context.Background())

	if len(h.priv.revoked) != 1 {
		t.Fatalf("ожидали revoke по истечению, got %v", h.priv.revoked)
	}
}

// Регрессия (полевой баг): если пользователь был администратором ДО выдачи гранта
// (например, основная учётка машины test-mac), при истечении срока его собственные
// постоянные права снимать нельзя — иначе он «вылетает» из админов.
func TestRevokeKeepsPreexistingAdmin(t *testing.T) {
	h := newHarness()
	h.priv.isAdmin = true // alice уже админ ДО гранта
	h.resp = approved("r1", time.Now().Add(time.Hour))
	h.m.poll(context.Background()) // выдали поверх существующего членства

	h.m.grantedExpires = time.Now().Add(-time.Minute) // имитируем истечение
	h.m.poll(context.Background())

	if len(h.priv.revoked) != 0 {
		t.Fatalf("pre-existing админа нельзя удалять из группы, got revoked=%v", h.priv.revoked)
	}
	if h.m.grantedUser != "" {
		t.Fatalf("состояние гранта должно быть очищено, grantedUser=%q", h.m.grantedUser)
	}
	if r := lastReport(h); r == nil || r.GetStatus() != pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_REVOKED {
		t.Fatalf("ожидали отчёт REVOKED серверу, got %+v", r)
	}
}

func TestRevokeOnServerClose(t *testing.T) {
	h := newHarness()
	h.resp = approved("r1", time.Now().Add(time.Hour))
	h.m.poll(context.Background()) // выдали

	h.resp = &pb.FetchAdminStatusResponse{RequestId: "r1", Status: pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_REVOKED}
	h.m.poll(context.Background())

	if len(h.priv.revoked) != 1 {
		t.Fatalf("ожидали revoke при закрытии заявки сервером, got %v", h.priv.revoked)
	}
}

func TestRevokeWhenNoActiveRequest(t *testing.T) {
	h := newHarness()
	h.resp = approved("r1", time.Now().Add(time.Hour))
	h.m.poll(context.Background()) // выдали

	// Сервер закрыл заявку → FetchAdminStatus больше не возвращает активную
	// (request_id="", UNSPECIFIED). Права должны быть сняты.
	h.resp = &pb.FetchAdminStatusResponse{RequestId: "", Status: pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_UNSPECIFIED}
	h.m.poll(context.Background())

	if len(h.priv.revoked) != 1 {
		t.Fatalf("ожидали revoke при исчезновении активной заявки, got %v", h.priv.revoked)
	}
}

func TestNoActiveRequest(t *testing.T) {
	h := newHarness()
	h.resp = &pb.FetchAdminStatusResponse{RequestId: "", Status: pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_UNSPECIFIED}
	h.m.poll(context.Background())
	if len(h.priv.granted) != 0 || len(h.priv.revoked) != 0 {
		t.Fatalf("без активной заявки не должно быть действий: granted=%v revoked=%v", h.priv.granted, h.priv.revoked)
	}
}

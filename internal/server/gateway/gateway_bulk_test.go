package gateway_test

import (
	"context"
	"testing"

	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Гейт очереди одобрения: неодобренное устройство (pending_approval) НЕ получает
// скрипт-политик, даже когда они назначены его группе; после approve — получает.
// Это доказывает, что пусто именно из-за гейта, а не из-за отсутствия политики.
func TestFetchScriptPolicies_GatedForPendingApproval(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	ctx := context.Background()

	certCtx, fp := makeCertCtx(t, "pending-approval-dev")
	registerDevice(t, db, "pending-approval-dev", fp)
	devID, _ := db.GetDeviceIDByFingerprint(ctx, fp)

	// скрипт → политика → группа → устройство в группе → политика группе
	suffix := devID[:8]
	script, err := db.CreateScript(ctx, "bulk-script-"+suffix, "Windows", "Write-Host hi")
	if err != nil {
		t.Fatalf("CreateScript: %v", err)
	}
	policy, err := db.CreateScriptPolicy(ctx, "bulk-policy-"+suffix, script.ID, "schedule",
		[]byte(`{"cron":"*/5 * * * *"}`), nil)
	if err != nil {
		t.Fatalf("CreateScriptPolicy: %v", err)
	}
	group, err := db.CreateDeviceGroup(ctx, "bulk-gate-grp-"+suffix, "")
	if err != nil {
		t.Fatalf("CreateDeviceGroup: %v", err)
	}
	if err := db.AddDeviceToGroup(ctx, devID, group.ID); err != nil {
		t.Fatalf("AddDeviceToGroup: %v", err)
	}
	if err := db.AssignPolicyToGroup(ctx, policy.ID, group.ID); err != nil {
		t.Fatalf("AssignPolicyToGroup: %v", err)
	}

	// active (registerDevice) → политика видна
	resp, err := gw.FetchScriptPolicies(certCtx, &pb.FetchScriptPoliciesRequest{})
	if err != nil {
		t.Fatalf("FetchScriptPolicies (active): %v", err)
	}
	if len(resp.Policies) != 1 {
		t.Fatalf("до гейта ждали 1 политику, got %d", len(resp.Policies))
	}

	// pending_approval → гейт → пусто (машина в очереди не исполняет скрипты)
	if err := db.UpdateDeviceStatus(ctx, devID, "pending_approval"); err != nil {
		t.Fatalf("UpdateDeviceStatus pending_approval: %v", err)
	}
	resp, err = gw.FetchScriptPolicies(certCtx, &pb.FetchScriptPoliciesRequest{})
	if err != nil {
		t.Fatalf("FetchScriptPolicies (pending_approval): %v", err)
	}
	if len(resp.Policies) != 0 {
		t.Fatalf("pending_approval должен гейтить скрипты, got %d политик", len(resp.Policies))
	}

	// approve → active → снова видна
	if ok, err := db.ApproveDevice(ctx, devID); err != nil || !ok {
		t.Fatalf("ApproveDevice: ok=%v err=%v", ok, err)
	}
	resp, err = gw.FetchScriptPolicies(certCtx, &pb.FetchScriptPoliciesRequest{})
	if err != nil {
		t.Fatalf("FetchScriptPolicies (approved): %v", err)
	}
	if len(resp.Policies) != 1 {
		t.Errorf("после approve ждали 1 политику, got %d", len(resp.Policies))
	}
}

// FetchPolicy (софт-политики) тоже гейтится для pending_approval.
func TestFetchPolicy_EmptyForPendingApproval(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	ctx := context.Background()

	certCtx, fp := makeCertCtx(t, "pending-softpolicy-dev")
	registerDevice(t, db, "pending-softpolicy-dev", fp)
	devID, _ := db.GetDeviceIDByFingerprint(ctx, fp)
	if err := db.UpdateDeviceStatus(ctx, devID, "pending_approval"); err != nil {
		t.Fatalf("UpdateDeviceStatus: %v", err)
	}

	resp, err := gw.FetchPolicy(certCtx, &pb.FetchPolicyRequest{})
	if err != nil {
		t.Fatalf("FetchPolicy (pending_approval): %v", err)
	}
	if len(resp.Rules) != 0 {
		t.Errorf("pending_approval должен гейтить софт-политики, got %d правил", len(resp.Rules))
	}
}

// Отклонённое устройство режется на Connect (isCutOff), как blocked/decommissioned.
func TestConnect_RejectedDevice(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	ctx := context.Background()

	c, fp := makeCertCtx(t, "rejected-dev")
	registerDevice(t, db, "rejected-dev", fp)
	devID, _ := db.GetDeviceIDByFingerprint(ctx, fp)
	if err := db.UpdateDeviceStatus(ctx, devID, "rejected"); err != nil {
		t.Fatalf("UpdateDeviceStatus rejected: %v", err)
	}

	stream := &mockStream{ctx: c}
	if code := status.Code(gw.Connect(stream)); code != codes.PermissionDenied {
		t.Errorf("got %v, want PermissionDenied для rejected", code)
	}
}

package gateway

import (
	"log/slog"
	"testing"
	"time"
)

func testGateway() *Gateway {
	return &Gateway{logger: slog.Default()}
}

func TestClampAgentEvidenceTime_PreservesStalePast(t *testing.T) {
	g := testGateway()
	weekAgo := time.Now().Add(-7 * 24 * time.Hour).Unix()
	got := g.clampAgentEvidenceTime("window_end", weekAgo)
	if got.Unix() != weekAgo {
		t.Fatalf("stale past rewritten: want %d got %d", weekAgo, got.Unix())
	}
}

func TestClampAgentEvidenceTime_ClampsFuture(t *testing.T) {
	g := testGateway()
	future := time.Now().Add(time.Hour).Unix()
	before := time.Now()
	got := g.clampAgentEvidenceTime("window_end", future)
	if got.Before(before.Add(-time.Second)) || got.After(time.Now().Add(time.Minute)) {
		t.Fatalf("future not clamped to now: %v", got)
	}
}

func TestClampAgentTime_StillClampsDayOld(t *testing.T) {
	g := testGateway()
	old := time.Now().Add(-48 * time.Hour).Unix()
	got := g.clampAgentTime("requested_at", old)
	if got.Unix() == old {
		t.Fatalf("audit clamp should still rewrite >24h past")
	}
}

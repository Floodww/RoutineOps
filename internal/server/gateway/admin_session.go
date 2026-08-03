package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/alerting"
	"github.com/Floodww/RoutineOps/internal/server/notifier"
	"github.com/Floodww/RoutineOps/internal/server/storage"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	settingCollectAdminSessionChanges = "collect_admin_session_changes"
	settingAdminSessionSnapshotSec    = "admin_session_snapshot_interval_sec"
	minSnapshotIntervalSec            = 300
	alertTypeAdminSessionEvidenceGap  = "admin_session_evidence_gap"
)

// adminCollectFlags читает глобальные настройки сбора улик. Ключа нет / пусто /
// всё кроме явного true → не собирать (совпадает с нулём в proto для старого сервера).
func (g *Gateway) adminCollectFlags(ctx context.Context, tenantID string) (collect bool, intervalSec int32) {
	v, err := g.db.GetSystemSetting(ctx, tenantID, settingCollectAdminSessionChanges)
	if err != nil {
		g.logger.Warn("admin session: collect setting", "err", err)
	}
	collect = strings.EqualFold(strings.TrimSpace(v), "true") || strings.TrimSpace(v) == "1"

	raw, err := g.db.GetSystemSetting(ctx, tenantID, settingAdminSessionSnapshotSec)
	if err != nil {
		g.logger.Warn("admin session: interval setting", "err", err)
	}
	if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n > 0 {
		intervalSec = int32(n)
		if intervalSec < minSnapshotIntervalSec {
			intervalSec = minSnapshotIntervalSec
		}
	}
	return collect, intervalSec
}

func (g *Gateway) ReportAdminSessionChanges(ctx context.Context, req *pb.ReportAdminSessionChangesRequest) (*pb.ReportAdminSessionChangesResponse, error) {
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
	deviceID, err := g.db.GetDeviceIDByFingerprint(ctx, fingerprint)
	if err != nil {
		g.logger.Error("admin session changes: device lookup", "err", err)
		return nil, status.Errorf(codes.Unavailable, "device lookup: %v", err)
	}
	if deviceID == "" {
		g.logger.Warn("admin session changes from unknown device, dropping", "fingerprint", fingerprint)
		return &pb.ReportAdminSessionChangesResponse{Received: true}, nil
	}
	if req.GetRequestId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "request_id required")
	}
	if len(req.GetChanges()) > storage.MaxAdminSessionChanges {
		return nil, status.Errorf(codes.InvalidArgument, "changes exceed %d", storage.MaxAdminSessionChanges)
	}

	changes := make([]storage.AdminSessionChange, 0, len(req.GetChanges()))
	for _, c := range req.GetChanges() {
		observed := g.clampAgentEvidenceTime("observed_at", c.GetObservedAt())
		changes = append(changes, storage.AdminSessionChange{
			Kind:              adminChangeKindString(c.GetKind()),
			Subject:           c.GetSubject(),
			DisplayName:       c.GetDisplayName(),
			IdentityKey:       c.GetIdentityKey(),
			OldValue:          c.GetOldValue(),
			NewValue:          c.GetNewValue(),
			Vendor:            c.GetVendor(),
			Scope:             c.GetScope(),
			Attribution:       changeAttributionString(c.GetAttribution()),
			AttributionReason: c.GetAttributionReason(),
			ObservedAt:        observed,
		})
	}
	win := storage.AdminSessionWindow{
		RequestID:      req.GetRequestId(),
		DeviceID:       deviceID,
		WindowSeq:      req.GetWindowSeq(),
		WindowStart:    g.clampAgentEvidenceTime("window_start", req.GetWindowStart()),
		WindowEnd:      g.clampAgentEvidenceTime("window_end", req.GetWindowEnd()),
		Changes:        changes,
		Final:          req.GetFinal(),
		Truncated:      req.GetTruncated(),
		TotalChanges:   req.GetTotalChanges(),
		Rebooted:       req.GetRebooted(),
		BaselineLost:   req.GetBaselineLost(),
		SoftwareHealth: collectionHealthString(req.GetSoftwareHealth()),
		ServicesHealth: collectionHealthString(req.GetServicesHealth()),
		Completeness:   evidenceCompletenessString(req.GetCompleteness()),
		SnapshotAt:     g.clampAgentEvidenceTime("snapshot_at", req.GetSnapshotAt()),
	}
	if err := g.db.AcceptAdminSessionWindow(ctx, win); err != nil {
		switch {
		case errors.Is(err, storage.ErrAdminRequestNotFound):
			g.logger.Warn("admin session changes for unknown request, dropping",
				"request_id", req.GetRequestId(), "device_id", deviceID)
			return &pb.ReportAdminSessionChangesResponse{Received: true}, nil
		case errors.Is(err, storage.ErrAdminSessionTooManyChanges):
			return nil, status.Errorf(codes.InvalidArgument, "changes exceed %d", storage.MaxAdminSessionChanges)
		case errors.Is(err, storage.ErrAdminSessionSeqJump):
			return nil, status.Errorf(codes.InvalidArgument, "window_seq jump too large")
		case errors.Is(err, storage.ErrForeignKeyViolation):
			g.logger.Warn("admin session changes references deleted row, dropping", "err", err)
			return &pb.ReportAdminSessionChangesResponse{Received: true}, nil
		default:
			g.logger.Error("accept admin session window", "request_id", req.GetRequestId(), "err", err)
			return nil, status.Errorf(codes.Unavailable, "accept: %v", err)
		}
	}

	if req.GetFinal() {
		g.writeAdminSessionFinalDigest(ctx, win)
	}
	return &pb.ReportAdminSessionChangesResponse{Received: true}, nil
}

func (g *Gateway) writeAdminSessionFinalDigest(ctx context.Context, win storage.AdminSessionWindow) {
	h := sha256.New()
	for _, c := range win.Changes {
		fmt.Fprintf(h, "%s\x00%s\x00%s\n", c.Kind, c.IdentityKey, c.Attribution)
	}
	details := map[string]any{
		"request_id":    win.RequestID,
		"device_id":     win.DeviceID,
		"window_seq":    win.WindowSeq,
		"total_changes": win.TotalChanges,
		"stored":        len(win.Changes),
		"truncated":     win.Truncated,
		"rebooted":      win.Rebooted,
		"completeness":  win.Completeness,
		"digest":        hex.EncodeToString(h.Sum(nil)),
	}
	if err := g.db.WriteAuditLog(context.WithoutCancel(ctx), "", "agent",
		"admin_session_changes_final", "admin_request", win.RequestID, details); err != nil {
		g.logger.Error("admin session final digest", "request_id", win.RequestID, "err", err)
	}
}

// SweepAdminSessionEvidenceGaps поднимает алерты по закрытым сессиям без финала.
func (g *Gateway) SweepAdminSessionEvidenceGaps(ctx context.Context) (int, error) {
	gaps, err := g.db.ListAdminEvidenceGaps(ctx, storage.AdminSessionEvidenceGrace)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, gap := range gaps {
		details := fmt.Sprintf("request_id=%s status=%s closed_at=%s agent_version=%s",
			gap.RequestID, gap.Status, gap.ClosedAt.UTC().Format(time.RFC3339), gap.AgentVersion)
		created, err := g.db.CreateAlert(ctx, gap.DeviceID, alertTypeAdminSessionEvidenceGap, details, gap.RequestID)
		if err != nil {
			if errors.Is(err, storage.ErrForeignKeyViolation) {
				continue
			}
			g.logger.Error("admin evidence gap alert", "request_id", gap.RequestID, "err", err)
			continue
		}
		if !created {
			continue
		}
		n++
		if g.bot != nil {
			hostname, _ := g.db.GetDeviceHostname(ctx, gap.DeviceID)
			sev := alerting.DefaultFor(alertTypeAdminSessionEvidenceGap)
			text := notifier.HTMLf("%s <b>Алерт безопасности</b>\nТип: %s\nКритичность: %s\nУстройство: <code>%s</code>\nДетали: %s",
				alerting.Emoji(sev), "Улики сессии админ-прав не пришли", alerting.Label(sev), hostname, details)
			go g.bot.NotifyAlert(context.Background(), sev, text)
		}
	}
	return n, nil
}

func adminChangeKindString(k pb.AdminChangeKind) string {
	s := strings.TrimPrefix(k.String(), "ADMIN_CHANGE_KIND_")
	return strings.ToLower(s)
}

func changeAttributionString(a pb.ChangeAttribution) string {
	s := strings.TrimPrefix(a.String(), "CHANGE_ATTRIBUTION_")
	s = strings.ToLower(s)
	if s == "" || s == "unspecified" {
		return "unknown"
	}
	return s
}

func collectionHealthString(h pb.CollectionHealth) string {
	return strings.ToLower(strings.TrimPrefix(h.String(), "COLLECTION_HEALTH_"))
}

func evidenceCompletenessString(c pb.EvidenceCompleteness) string {
	return strings.ToLower(strings.TrimPrefix(c.String(), "EVIDENCE_COMPLETENESS_"))
}

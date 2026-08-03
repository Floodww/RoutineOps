package gateway

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/Floodww/RoutineOps/proto"
)

// ScreenService — шов для удалённого рабочего стола. Реализуется enterprise-оверлеем
// (internal/server/screen, //go:build enterprise). Open-core НИКОГДА его не регистрирует →
// ScreenSession и ReportScreenEvent отвечают Unimplemented, а ручек /screen-* не
// существует вовсе: обходить нечего.
type ScreenService interface {
	// Stream обслуживает медиастрим сеанса. fingerprint — идентичность устройства из
	// mTLS-сертификата (ADR-1); session_id из тела не авторизует никогда (ADR-8 п.2).
	Stream(fingerprint string, stream pb.AgentService_ScreenSessionServer) error
	// Event принимает durable-событие сеанса из очереди агента.
	Event(ctx context.Context, fingerprint string, ev *pb.ScreenEvent) (*pb.ScreenEventAck, error)
}

// RegisterScreenService подключает enterprise-реализацию. Зовётся только в
// enterprise-composition-root (cmd/server, //go:build enterprise).
func (g *Gateway) RegisterScreenService(svc ScreenService) { g.screenSvc = svc }

// ScreenSession — тонкий nil-guarded диспатчер. Обязан существовать во free (часть общего
// pb.AgentServiceServer).
//
// Отдельный стрим на отдельном соединении — это ADR-8 п.1: кадры не делят HTTP/2-соединение
// с heartbeat, иначе крупные DATA-фреймы дают head-of-line blocking и heartbeat начинает
// опаздывать ровно тогда, когда идёт сеанс.
func (g *Gateway) ScreenSession(stream pb.AgentService_ScreenSessionServer) error {
	_, fingerprint, err := extractCertInfo(stream.Context())
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
	if g.screenSvc == nil {
		return status.Error(codes.Unimplemented, "remote desktop is an enterprise feature (not built)")
	}
	return g.screenSvc.Stream(fingerprint, stream)
}

// ReportScreenEvent — durable-события сеанса (чем кончился, было ли согласие, телеметрия).
func (g *Gateway) ReportScreenEvent(ctx context.Context, ev *pb.ScreenEvent) (*pb.ScreenEventAck, error) {
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
	if g.screenSvc == nil {
		return nil, status.Error(codes.Unimplemented, "remote desktop is an enterprise feature (not built)")
	}
	return g.screenSvc.Event(ctx, fingerprint, ev)
}

package gateway

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/Floodww/RoutineOps/proto"
)

// Канареечная выкатка (Q-52): манифест обновления зависит от канала УСТРОЙСТВА, а
// канал — свойство его групп. Значит ответ зависит от того, кто спрашивает, и
// спрашивающего надо знать достоверно — отсюда gRPC под mTLS, а не публичная
// REST-ручка, где личности нет вовсе.

// SetPublicWebURL задаёт базовый адрес, по которому агент качает бинарь. Тот же
// PublicWebURL, что у REST-слоя: раздаёт файлы один и тот же сервер.
//
// Пустой адрес — не «выключено», а поломка конфигурации: манифест с относительным
// URL агент скачать не сможет. Поэтому FetchUpdateManifest в этом случае честно
// отвечает ошибкой вместо того, чтобы отдать заведомо неработающую ссылку.
func (g *Gateway) SetPublicWebURL(u string) { g.publicWebURL = strings.TrimRight(u, "/") }

// FetchUpdateManifest отдаёт агенту манифест ЕГО канала.
//
// Порядок тот же, что в остальных pull-RPC: серт → отпечаток → скоуп тенанта →
// device_id. os/arch берутся из запроса (GOOS/GOARCH работающего бинаря, из
// инвентаря их не вывести — под Rosetta они расходятся с железом), и привилегий
// они не несут: канал ими не выбирается.
func (g *Gateway) FetchUpdateManifest(ctx context.Context, req *pb.FetchUpdateManifestRequest) (*pb.FetchUpdateManifestResponse, error) {
	osName, arch := strings.TrimSpace(req.GetOs()), strings.TrimSpace(req.GetArch())
	if osName == "" || arch == "" {
		return nil, status.Error(codes.InvalidArgument, "os и arch обязательны")
	}

	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
	ctx, scopeDone, err := g.scopeByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "scope tenant: %v", err)
	}
	defer scopeDone(true)

	deviceID, err := g.db.GetDeviceIDByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup device: %v", err)
	}
	if deviceID == "" {
		return nil, status.Error(codes.NotFound, "device not found")
	}

	channel, err := g.db.ResolveDeviceUpdateChannel(ctx, deviceID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "resolve channel: %v", err)
	}

	rel, err := g.db.GetLatestAgentReleaseForChannel(ctx, osName, arch, channel)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fetch release: %v", err)
	}
	if rel == nil {
		// Публикаций под эту платформу нет. NotFound, а не пустой ответ: агент
		// обязан отличить «обновляться нечем» от «сервер ответил, ставь ничего».
		return nil, status.Errorf(codes.NotFound, "нет релиза для %s/%s в канале %s", osName, arch, channel)
	}

	if g.publicWebURL == "" {
		g.logger.Error("манифест обновления: PUBLIC_WEB_URL не задан — агент не сможет скачать бинарь",
			"device_id", deviceID)
		return nil, status.Error(codes.FailedPrecondition, "публичный адрес сервера не настроен")
	}

	return &pb.FetchUpdateManifestResponse{
		Version:           rel.Version,
		Url:               fmt.Sprintf("%s/downloads/%s", g.publicWebURL, rel.Filename),
		Sha256:            rel.SHA256,
		Signature:         rel.Signature,
		ManifestSignature: rel.ManifestSignature,
		Channel:           channel,
	}, nil
}

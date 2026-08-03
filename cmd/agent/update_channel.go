package main

import (
	"context"
	"runtime"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/selfupdate"
	"github.com/Floodww/RoutineOps/internal/agent/transport"
	pb "github.com/Floodww/RoutineOps/proto"
)

// channelManifestTimeout — тот же порядок, что у остальных pull-вызовов агента:
// манифест берётся редко, но висеть на нём в цикле обновления незачем.
const channelManifestTimeout = 15 * time.Second

// fetchChannelManifest берёт манифест обновления для КАНАЛА этого устройства
// (Q-52). Соединение поднимается на вызов и закрывается сразу — как в
// lock.NewReconciler: обрыв просто повторится на следующем тике, держать ради
// одного запроса в шесть часов постоянный конн незачем.
//
// os/arch — GOOS/GOARCH РАБОТАЮЩЕГО бинаря, не машины: под Rosetta это разные
// вещи, и обновить amd64-агента на arm64-сборку значило бы сломать его насмерть.
func fetchChannelManifest(ctx context.Context, dialer *transport.Dialer) (*selfupdate.Manifest, error) {
	conn, err := dialer.Dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(ctx, channelManifestTimeout)
	defer cancel()

	resp, err := pb.NewAgentServiceClient(conn).FetchUpdateManifest(ctx, &pb.FetchUpdateManifestRequest{
		Os:   runtime.GOOS,
		Arch: runtime.GOARCH,
	})
	if err != nil {
		return nil, err
	}
	return &selfupdate.Manifest{
		Version:           resp.GetVersion(),
		URL:               resp.GetUrl(),
		SHA256:            resp.GetSha256(),
		Signature:         resp.GetSignature(),
		ManifestSignature: resp.GetManifestSignature(),
	}, nil
}

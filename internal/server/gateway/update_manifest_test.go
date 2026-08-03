package gateway_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	pb "github.com/Floodww/RoutineOps/proto"
)

// Канареечная выкатка, серверная половина (Q-52).
//
// Смысл RPC ровно один: ответ ЗАВИСИТ ОТ ТОГО, КТО СПРОСИЛ. Поэтому и тесты здесь
// парные — одно и то же обращение с двух разных устройств обязано дать разные версии.

// publishPair публикует под уникальной платформой две версии: старшую в beta,
// младшую в stable. Уникальный os нужен, чтобы чужие строки общей БД не попали в
// выборку «последний релиз».
func publishPair(t *testing.T, db *storage.DB, stableVer, betaVer string) (osName, arch string) {
	t.Helper()
	osName = fmt.Sprintf("testos%d", time.Now().UnixNano())
	arch = "amd64"
	ctx := context.Background()
	if err := db.RegisterAgentRelease(ctx, osName, arch, stableVer, "agent_stable", "sha-stable",
		"sig", "msig", storage.ChannelStable); err != nil {
		t.Fatalf("публикация stable: %v", err)
	}
	if err := db.RegisterAgentRelease(ctx, osName, arch, betaVer, "agent_beta", "sha-beta",
		"sig", "msig", storage.ChannelBeta); err != nil {
		t.Fatalf("публикация beta: %v", err)
	}
	return osName, arch
}

// putInChannel заводит группу нужного канала и кладёт в неё устройство.
func putInChannel(t *testing.T, db *storage.DB, fingerprint, channel string) {
	t.Helper()
	ctx := context.Background()
	deviceID, err := db.GetDeviceIDByFingerprint(ctx, fingerprint)
	if err != nil || deviceID == "" {
		t.Fatalf("резолв устройства: id=%q err=%v", deviceID, err)
	}
	g, err := db.CreateDeviceGroup(ctx, tenancy.DefaultTenantID,
		fmt.Sprintf("grp-%s-%d", channel, time.Now().UnixNano()), "", channel)
	if err != nil {
		t.Fatalf("CreateDeviceGroup: %v", err)
	}
	if err := db.AddDeviceToGroup(ctx, tenancy.DefaultTenantID, deviceID, g.ID); err != nil {
		t.Fatalf("AddDeviceToGroup: %v", err)
	}
}

// 🔴 Одна публикация — два разных ответа. Канареечное устройство получает beta,
// соседнее по инсталляции — прежний stable. Без этого различия канала нет вовсе:
// релиз уезжал бы на весь парк, как до Q-52.
func TestFetchUpdateManifest_CanaryGetsBetaParkStaysStable(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	gw.SetPublicWebURL("https://test.local:8443")

	osName, arch := publishPair(t, db, "v1.0.0", "v1.1.0")

	canaryCtx, canaryFP := makeCertCtx(t, fmt.Sprintf("canary-%d", time.Now().UnixNano()))
	registerDevice(t, db, "canary-cn-"+canaryFP[:8], canaryFP)
	putInChannel(t, db, canaryFP, storage.ChannelBeta)

	plainCtx, plainFP := makeCertCtx(t, fmt.Sprintf("plain-%d", time.Now().UnixNano()))
	registerDevice(t, db, "plain-cn-"+plainFP[:8], plainFP)

	req := &pb.FetchUpdateManifestRequest{Os: osName, Arch: arch}

	canary, err := gw.FetchUpdateManifest(canaryCtx, req)
	if err != nil {
		t.Fatalf("канарейка: %v", err)
	}
	if canary.GetVersion() != "v1.1.0" {
		t.Fatalf("канарейка получила %q, ожидали v1.1.0 — канареечная выкатка до неё не доехала", canary.GetVersion())
	}
	if canary.GetChannel() != storage.ChannelBeta {
		t.Errorf("канал в ответе = %q, ожидали beta", canary.GetChannel())
	}

	plain, err := gw.FetchUpdateManifest(plainCtx, req)
	if err != nil {
		t.Fatalf("обычное устройство: %v", err)
	}
	if plain.GetVersion() != "v1.0.0" {
		t.Fatalf("обычное устройство получило %q, ожидали v1.0.0 — beta-релиз уехал на парк", plain.GetVersion())
	}
	if plain.GetChannel() != storage.ChannelStable {
		t.Errorf("канал в ответе = %q, ожидали stable", plain.GetChannel())
	}

	// Ссылка должна вести на публичный адрес сервера, а не быть относительной:
	// агент качает бинарь отдельным HTTP-запросом.
	if !strings.HasPrefix(plain.GetUrl(), "https://test.local:8443/downloads/") {
		t.Errorf("url = %q, ожидали ссылку на публичный адрес", plain.GetUrl())
	}
}

// Устройства нет — NotFound. Неизвестный серт не должен получать манифест «по
// умолчанию»: это единственное место, где сервер решает, какой бинарь ставить.
func TestFetchUpdateManifest_UnknownDevice(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	gw.SetPublicWebURL("https://test.local:8443")

	ctx, _ := makeCertCtx(t, fmt.Sprintf("ghost-%d", time.Now().UnixNano()))
	_, err := gw.FetchUpdateManifest(ctx, &pb.FetchUpdateManifestRequest{Os: "linux", Arch: "amd64"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("код = %v (err=%v), ожидали NotFound", status.Code(err), err)
	}
}

// Публикаций под платформу нет — NotFound, а не пустой ответ: агент обязан отличить
// «обновляться нечем» от «сервер ответил, ставь ничего».
func TestFetchUpdateManifest_NoRelease(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	gw.SetPublicWebURL("https://test.local:8443")

	ctx, fp := makeCertCtx(t, fmt.Sprintf("norel-%d", time.Now().UnixNano()))
	registerDevice(t, db, "norel-cn-"+fp[:8], fp)

	_, err := gw.FetchUpdateManifest(ctx, &pb.FetchUpdateManifestRequest{
		Os: fmt.Sprintf("nosuchos%d", time.Now().UnixNano()), Arch: "amd64"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("код = %v (err=%v), ожидали NotFound", status.Code(err), err)
	}
}

// Без os/arch — InvalidArgument. Пустые значения означали бы «отдай хоть что-нибудь»,
// а «хоть что-нибудь» здесь это бинарь под чужую платформу.
func TestFetchUpdateManifest_RequiresPlatform(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	ctx, fp := makeCertCtx(t, fmt.Sprintf("noplat-%d", time.Now().UnixNano()))
	registerDevice(t, db, "noplat-cn-"+fp[:8], fp)

	for _, req := range []*pb.FetchUpdateManifestRequest{
		{Arch: "amd64"},
		{Os: "linux"},
		{},
	} {
		if _, err := gw.FetchUpdateManifest(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("req=%v: код = %v, ожидали InvalidArgument", req, status.Code(err))
		}
	}
}

// PUBLIC_WEB_URL не настроен — отказ, а не манифест с относительной ссылкой. Такой
// манифест агент принял бы за валидный и упал бы уже на скачивании, где разбираться
// куда сложнее.
func TestFetchUpdateManifest_RequiresPublicURL(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db) // SetPublicWebURL намеренно не зовём
	osName, arch := publishPair(t, db, "v1.0.0", "v1.1.0")

	ctx, fp := makeCertCtx(t, fmt.Sprintf("nourl-%d", time.Now().UnixNano()))
	registerDevice(t, db, "nourl-cn-"+fp[:8], fp)

	_, err := gw.FetchUpdateManifest(ctx, &pb.FetchUpdateManifestRequest{Os: osName, Arch: arch})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("код = %v (err=%v), ожидали FailedPrecondition", status.Code(err), err)
	}
}

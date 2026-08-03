package storage_test

import (
	"context"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// Каналы обновлений и канареечная выкатка (Q-52, миграция 065).

// newDeviceInGroups заводит устройство и кладёт его в группы указанных каналов.
// Возвращает device_id.
func newDeviceInGroups(t *testing.T, db *storage.DB, suffix string, channels ...string) string {
	t.Helper()
	ctx := context.Background()
	fp := "fp-chan-" + suffix
	if err := db.UpsertDeviceHeartbeat(ctx, storageHeartbeatData(fp, "cn-"+suffix, "cn-"+suffix, "192.0.2.10")); err != nil {
		t.Fatalf("UpsertDeviceHeartbeat: %v", err)
	}
	deviceID, err := db.GetDeviceIDByFingerprint(ctx, fp)
	if err != nil || deviceID == "" {
		t.Fatalf("GetDeviceIDByFingerprint: id=%q err=%v", deviceID, err)
	}
	for i, ch := range channels {
		g, err := db.CreateDeviceGroup(ctx, tenancy.DefaultTenantID,
			"grp-"+ch+"-"+suffix+string(rune('a'+i)), "", ch)
		if err != nil {
			t.Fatalf("CreateDeviceGroup(%s): %v", ch, err)
		}
		if g.UpdateChannel != ch {
			t.Fatalf("группа создана в канале %q, просили %q", g.UpdateChannel, ch)
		}
		if err := db.AddDeviceToGroup(ctx, tenancy.DefaultTenantID, deviceID, g.ID); err != nil {
			t.Fatalf("AddDeviceToGroup: %v", err)
		}
	}
	return deviceID
}

// Устройство без групп — stable. Дефолт обязан быть именно таким: машина, о канале
// которой никто ничего не сказал, не может оказаться канарейкой.
func TestResolveDeviceUpdateChannel_DefaultStable(t *testing.T) {
	db := newDB(t)
	deviceID := newDeviceInGroups(t, db, uniq(t))

	got, err := db.ResolveDeviceUpdateChannel(context.Background(), deviceID)
	if err != nil {
		t.Fatalf("ResolveDeviceUpdateChannel: %v", err)
	}
	if got != storage.ChannelStable {
		t.Fatalf("канал = %q, ожидали stable", got)
	}
}

// 🔴 Одна beta-группа делает машину канарейкой, даже если она состоит и в обычных.
// Правило «минимум» сделало бы канареечную группу бесполезной: любая рабочая группа
// возвращала бы машину на stable, и пометить её было бы нечем.
func TestResolveDeviceUpdateChannel_BetaWinsOverStable(t *testing.T) {
	db := newDB(t)
	suffix := uniq(t)
	deviceID := newDeviceInGroups(t, db, suffix, storage.ChannelStable, storage.ChannelBeta, storage.ChannelStable)

	got, err := db.ResolveDeviceUpdateChannel(context.Background(), deviceID)
	if err != nil {
		t.Fatalf("ResolveDeviceUpdateChannel: %v", err)
	}
	if got != storage.ChannelBeta {
		t.Fatalf("канал = %q, ожидали beta: устройство состоит в beta-группе", got)
	}
}

// Канал группы меняется и обратно — снятие метки возвращает машину на парковую версию.
func TestResolveDeviceUpdateChannel_FollowsGroupEdit(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	suffix := uniq(t)
	deviceID := newDeviceInGroups(t, db, suffix, storage.ChannelBeta)

	groups, err := db.ListDeviceGroups(ctx, tenancy.DefaultTenantID)
	if err != nil {
		t.Fatalf("ListDeviceGroups: %v", err)
	}
	var groupID string
	for _, g := range groups {
		for _, d := range g.DeviceIDs {
			if d == deviceID {
				groupID = g.ID
			}
		}
	}
	if groupID == "" {
		t.Fatal("группа устройства не найдена в списке")
	}

	if _, err := db.UpdateDeviceGroup(ctx, tenancy.DefaultTenantID, groupID, "", "", storage.ChannelStable); err != nil {
		t.Fatalf("UpdateDeviceGroup: %v", err)
	}
	got, err := db.ResolveDeviceUpdateChannel(ctx, deviceID)
	if err != nil {
		t.Fatalf("ResolveDeviceUpdateChannel: %v", err)
	}
	if got != storage.ChannelStable {
		t.Fatalf("канал = %q после снятия метки beta, ожидали stable", got)
	}
}

// Опечатка в канале — ошибка на входе, а не 23514 из глубины БД.
func TestDeviceGroup_RejectsUnknownChannel(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	if _, err := db.CreateDeviceGroup(ctx, tenancy.DefaultTenantID, "grp-bad-"+uniq(t), "", "BETA"); err == nil {
		t.Fatal("группа создана с неизвестным каналом")
	}
}

// 🔴 Главное правило видимости: stable НЕ видит beta-релизов, beta видит ОБА.
//
// Первая половина — ради чего задача существует: если бы stable подхватывал
// beta-строку, канареечная выкатка уезжала бы на весь парк, то есть канала бы не было.
// Вторая — чтобы канарейка не оказалась СТАРЕЕ парка: без неё продвижение обкатанной
// версии в stable отбирало бы её у beta-групп.
func TestAgentRelease_ChannelVisibility(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	osName := "testos" + uniq(t) // свой os → в выборку попадут только наши строки
	arch := "amd64"

	if err := db.RegisterAgentRelease(ctx, osName, arch, "v1.0.0", "agent_stable", "sha1", "sig1", "msig1",
		storage.ChannelStable); err != nil {
		t.Fatalf("публикация stable: %v", err)
	}
	if err := db.RegisterAgentRelease(ctx, osName, arch, "v1.1.0", "agent_beta", "sha2", "sig2", "msig2",
		storage.ChannelBeta); err != nil {
		t.Fatalf("публикация beta: %v", err)
	}

	stable, err := db.GetLatestAgentReleaseForChannel(ctx, osName, arch, storage.ChannelStable)
	if err != nil {
		t.Fatalf("stable: %v", err)
	}
	if stable == nil || stable.Version != "v1.0.0" {
		t.Fatalf("канал stable отдал %v, ожидали v1.0.0 — beta-релиз не должен уезжать на парк", stable)
	}

	beta, err := db.GetLatestAgentReleaseForChannel(ctx, osName, arch, storage.ChannelBeta)
	if err != nil {
		t.Fatalf("beta: %v", err)
	}
	if beta == nil || beta.Version != "v1.1.0" {
		t.Fatalf("канал beta отдал %v, ожидали v1.1.0", beta)
	}

	// Публичная REST-ручка ходит сюда и обязана остаться на stable: у неё нет
	// личности спрашивающего, а значит и права выдать канареечную версию.
	public, err := db.GetLatestAgentRelease(ctx, osName, arch)
	if err != nil {
		t.Fatalf("GetLatestAgentRelease: %v", err)
	}
	if public == nil || public.Version != "v1.0.0" {
		t.Fatalf("публичный манифест отдал %v, ожидали v1.0.0", public)
	}
}

// Продвижение обкатанного билда: та же версия публикуется в stable. Канарейка при
// этом НЕ откатывается — beta видит stable-строки.
func TestAgentRelease_PromoteBetaToStable(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	osName := "testos" + uniq(t)
	arch := "arm64"

	if err := db.RegisterAgentRelease(ctx, osName, arch, "v2.0.0", "a", "sha", "sig", "msig",
		storage.ChannelBeta); err != nil {
		t.Fatalf("публикация в beta: %v", err)
	}
	if rel, err := db.GetLatestAgentReleaseForChannel(ctx, osName, arch, storage.ChannelStable); err != nil || rel != nil {
		t.Fatalf("до продвижения stable обязан быть пуст, получили %v (err=%v)", rel, err)
	}

	if err := db.RegisterAgentRelease(ctx, osName, arch, "v2.0.0", "a", "sha", "sig", "msig",
		storage.ChannelStable); err != nil {
		t.Fatalf("продвижение: %v", err)
	}
	for _, ch := range []string{storage.ChannelStable, storage.ChannelBeta} {
		rel, err := db.GetLatestAgentReleaseForChannel(ctx, osName, arch, ch)
		if err != nil {
			t.Fatalf("%s: %v", ch, err)
		}
		if rel == nil || rel.Version != "v2.0.0" {
			t.Fatalf("канал %s после продвижения отдал %v, ожидали v2.0.0", ch, rel)
		}
	}
}

// Неизвестный канал не превращается молча в stable: место, где канал потерялся по
// дороге, обязано падать, иначе канареечная машина тихо поедет на парковую версию.
func TestGetLatestAgentReleaseForChannel_RejectsUnknown(t *testing.T) {
	db := newDB(t)
	if _, err := db.GetLatestAgentReleaseForChannel(context.Background(), "linux", "amd64", ""); err == nil {
		t.Fatal("пустой канал принят")
	}
}

// 🔴 Панель считает канал устройства ТЕМ ЖЕ правилом, что gRPC-путь. Правило живёт в
// двух SQL (обход одного устройства и агрегат по парку), и разъехаться они могут
// незаметно: картина выкатки показывала бы машину в stable, пока та обновляется по beta.
func TestUpdateRollout_MatchesResolver(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	suffix := uniq(t)

	canary := newDeviceInGroups(t, db, "canary-"+suffix, storage.ChannelStable, storage.ChannelBeta)
	plain := newDeviceInGroups(t, db, "plain-"+suffix, storage.ChannelStable)

	rollout, err := db.UpdateRollout(ctx, tenancy.DefaultTenantID)
	if err != nil {
		t.Fatalf("UpdateRollout: %v", err)
	}
	if len(rollout) != 2 {
		t.Fatalf("каналов в срезе %d, ожидали 2", len(rollout))
	}

	// Сверяем не абсолютные числа (тенант общий на пакет — там чужие устройства), а
	// согласие двух реализаций правила по КАЖДОМУ из наших устройств.
	for _, deviceID := range []string{canary, plain} {
		want, err := db.ResolveDeviceUpdateChannel(ctx, deviceID)
		if err != nil {
			t.Fatalf("ResolveDeviceUpdateChannel: %v", err)
		}
		var total int
		for _, c := range rollout {
			if c.Channel != want {
				continue
			}
			for _, v := range c.Versions {
				total += v.Count
			}
		}
		if total == 0 {
			t.Fatalf("устройство %s резолвится в канал %s, но в срезе этого канала нет ни одного устройства",
				deviceID, want)
		}
	}

	byChannel := map[string]storage.ChannelRollout{}
	for _, c := range rollout {
		byChannel[c.Channel] = c
	}
	if byChannel[storage.ChannelBeta].Groups == 0 {
		t.Fatal("в срезе beta ноль групп, хотя канареечная группа заведена")
	}
	if byChannel[storage.ChannelBeta].Devices == 0 {
		t.Fatal("в срезе beta ноль устройств, хотя канареечная машина заведена")
	}
}

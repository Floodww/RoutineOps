package selfupdate

import (
	"context"
	"errors"
	"testing"
)

// Канальный источник манифеста и откат на публичный stable (Q-52).

// newTestUpdater собирает Updater без сети: сеймы check/download/replace ставятся
// вызывающим. Нужен, потому что New() сразу лезет за HTTP-клиентом.
func newTestUpdater(t *testing.T) *Updater {
	t.Helper()
	return &Updater{current: "v1.0.0", log: discardLog()}
}

// 🔴 Канальный источник имеет ПРИОРИТЕТ: пока он отвечает, публичный stable не
// спрашивается вовсе. Иначе канареечная машина брала бы парковую версию, и весь
// таргетинг превращался бы в украшение.
func TestFetchManifest_PrefersChannelSource(t *testing.T) {
	u := newTestUpdater(t)
	publicAsked := false
	u.check = func(context.Context) (*Manifest, error) {
		publicAsked = true
		return &Manifest{Version: "v1.0.0"}, nil
	}
	u.SetChannelSource(func(context.Context) (*Manifest, error) {
		return &Manifest{Version: "v1.1.0-beta"}, nil
	})

	m, err := u.fetchManifest(context.Background())
	if err != nil {
		t.Fatalf("fetchManifest: %v", err)
	}
	if m.Version != "v1.1.0-beta" {
		t.Fatalf("версия = %q, ожидали канальную v1.1.0-beta", m.Version)
	}
	if publicAsked {
		t.Error("публичный манифест спрошен при живом канальном источнике")
	}
}

// Канальный источник недоступен (старый сервер без этого RPC, обрыв gRPC) — берём
// публичный stable. Откат безопасен по построению: он может только не додать
// канарейке beta-версию, но никогда не отдаст beta обычной машине.
func TestFetchManifest_FallsBackToPublic(t *testing.T) {
	u := newTestUpdater(t)
	u.check = func(context.Context) (*Manifest, error) {
		return &Manifest{Version: "v1.0.0"}, nil
	}
	u.SetChannelSource(func(context.Context) (*Manifest, error) {
		return nil, errors.New("rpc недоступен")
	})

	m, err := u.fetchManifest(context.Background())
	if err != nil {
		t.Fatalf("fetchManifest: %v", err)
	}
	if m.Version != "v1.0.0" {
		t.Fatalf("версия = %q, ожидали публичную v1.0.0", m.Version)
	}
}

// Оба источника молчат — ошибка наружу, а не тихое «обновляться нечем». Молчание
// здесь означало бы, что мёртвый self-update выглядит как актуальная версия.
func TestFetchManifest_BothFail(t *testing.T) {
	u := newTestUpdater(t)
	u.check = func(context.Context) (*Manifest, error) { return nil, errors.New("http сдох") }
	u.SetChannelSource(func(context.Context) (*Manifest, error) { return nil, errors.New("rpc сдох") })

	if _, err := u.fetchManifest(context.Background()); err == nil {
		t.Fatal("отказ обоих источников не дал ошибки")
	}
}

// Без канального источника (агент до подключения RPC) поведение прежнее.
func TestFetchManifest_NoChannelSource(t *testing.T) {
	u := newTestUpdater(t)
	u.check = func(context.Context) (*Manifest, error) { return &Manifest{Version: "v9.9.9"}, nil }

	m, err := u.fetchManifest(context.Background())
	if err != nil {
		t.Fatalf("fetchManifest: %v", err)
	}
	if m.Version != "v9.9.9" {
		t.Fatalf("версия = %q", m.Version)
	}
}

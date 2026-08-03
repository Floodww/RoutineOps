package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// Канал группы и картина выкатки в панели (Q-52).

type rolloutChannel struct {
	Channel  string `json:"channel"`
	Groups   int    `json:"groups"`
	Devices  int    `json:"devices"`
	Versions []struct {
		Version string `json:"version"`
		Count   int    `json:"count"`
	} `json:"versions"`
	Targets []struct {
		OS      string `json:"os"`
		Arch    string `json:"arch"`
		Version string `json:"version"`
	} `json:"targets"`
}

func fetchRollout(t *testing.T, rtr http.Handler, tok string) map[string]rolloutChannel {
	t.Helper()
	w := authedDo(t, rtr, http.MethodGet, "/api/v1/update-rollout", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("update-rollout: %d %s", w.Code, w.Body)
	}
	var res struct {
		Channels []rolloutChannel `json:"channels"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	out := map[string]rolloutChannel{}
	for _, c := range res.Channels {
		out[c.Channel] = c
	}
	return out
}

// Группа заводится сразу канареечной, и это видно и в самой группе, и в срезе выкатки.
func TestDeviceGroup_ChannelRoundTrip(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	before := fetchRollout(t, rtr, tok)

	body, _ := json.Marshal(map[string]string{"name": "canary-" + t.Name(), "update_channel": "beta"})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups", body, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("создание канареечной группы: %d %s", w.Code, w.Body)
	}
	var g map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &g); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if g["update_channel"] != "beta" {
		t.Fatalf("канал группы = %v, ожидали beta", g["update_channel"])
	}

	after := fetchRollout(t, rtr, tok)
	if after["beta"].Groups != before["beta"].Groups+1 {
		t.Fatalf("групп в beta было %d, стало %d — новая канареечная группа в срез не попала",
			before["beta"].Groups, after["beta"].Groups)
	}

	// Перевод обратно в stable — тем же PATCH'ем, что имя и цвет.
	body, _ = json.Marshal(map[string]string{"update_channel": "stable"})
	w = authedDo(t, rtr, http.MethodPatch, "/api/v1/device-groups/"+g["id"].(string), body, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("снятие метки beta: %d %s", w.Code, w.Body)
	}
	var patched map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &patched); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if patched["update_channel"] != "stable" {
		t.Fatalf("канал после PATCH = %v, ожидали stable", patched["update_channel"])
	}
	// Имя не задавали — оно обязано остаться прежним, а не обнулиться.
	if patched["name"] != g["name"] {
		t.Errorf("PATCH одного канала изменил имя: было %v, стало %v", g["name"], patched["name"])
	}
}

// Опечатка в канале — 400, а не 500 из-за CHECK'а миграции.
func TestDeviceGroup_RejectsUnknownChannel(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	body, _ := json.Marshal(map[string]string{"name": "bad-" + t.Name(), "update_channel": "BETA"})
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups", body, tok); w.Code != http.StatusBadRequest {
		t.Fatalf("создание с неизвестным каналом: %d %s", w.Code, w.Body)
	}

	id := createGroup(t, rtr, tok, "ok-"+t.Name())
	body, _ = json.Marshal(map[string]string{"update_channel": "нестабильный"})
	if w := authedDo(t, rtr, http.MethodPatch, "/api/v1/device-groups/"+id, body, tok); w.Code != http.StatusBadRequest {
		t.Fatalf("PATCH с неизвестным каналом: %d %s", w.Code, w.Body)
	}
}

// Группа без явного канала — stable. Дефолт обязан быть именно таким: машина, о
// канале которой никто ничего не сказал, не может оказаться канарейкой.
func TestDeviceGroup_DefaultChannelIsStable(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	id := createGroup(t, rtr, tok, "plain-"+t.Name())

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/device-groups", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("список групп: %d %s", w.Code, w.Body)
	}
	var groups []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &groups); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	for _, g := range groups {
		if g["id"] == id {
			if g["update_channel"] != "stable" {
				t.Fatalf("канал группы по умолчанию = %v, ожидали stable", g["update_channel"])
			}
			return
		}
	}
	t.Fatal("созданная группа не найдена в списке")
}

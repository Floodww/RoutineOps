package api

import (
	"log/slog"
	"net/http"
)

// updateRollout — что видит оператор во время канареечной выкатки (Q-52): по
// каждому каналу его целевая версия и реальное распределение версий агентов.
//
// Обе половины нужны вместе. «Опубликовал в beta» без второй половины неотличимо
// от «опубликовал, канарейка не доехала»: агент обновляется сам и молча, и
// единственный признак успеха — что версии в парке поехали. Ровно ради этого
// различия каналы и заводились.
func (h *Handler) updateRollout(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	channels, err := h.db.UpdateRollout(r.Context(), tenantID)
	if err != nil {
		slog.Error("картина выкатки: чтение", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Реестр публикаций общий на инсталляцию (agent_releases: ScopeGlobal) — это
	// не утечка между тенантами: версия опубликованного бинаря не тенантский факт,
	// а свойство самой инсталляции, и её и так отдаёт публичный манифест.
	releases, err := h.db.ListAgentReleases(r.Context())
	if err != nil {
		slog.Error("картина выкатки: реестр релизов", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	type releaseView struct {
		OS        string `json:"os"`
		Arch      string `json:"arch"`
		Version   string `json:"version"`
		Channel   string `json:"channel"`
		SHA256    string `json:"sha256"`
		CreatedAt string `json:"created_at"`
	}
	views := make([]releaseView, 0, len(releases))
	for _, rel := range releases {
		views = append(views, releaseView{
			OS: rel.OS, Arch: rel.Arch, Version: rel.Version, Channel: rel.Channel,
			SHA256: rel.SHA256, CreatedAt: rel.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"channels": channels,
		"releases": views,
	})
}

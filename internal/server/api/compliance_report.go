package api

import (
	"encoding/csv"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Отчёт соответствия: JSON для панели и CSV для выгрузки (Q-62).
//
// PDF намеренно не генерируется на сервере. Печать страницы отчёта в PDF делает сам
// браузер (в панели есть кнопка), а серверный рендер потребовал бы тащить движок
// вёрстки ради артефакта, который всё равно печатают глазами. CSV — то, что реально
// открывают в таблице и подшивают.

// complianceTargets — целевая версия каждого канала. Считается в Go по тем же
// правилам видимости, что в манифесте обновления (beta ⊇ stable): иначе отчёт
// объявил бы канареечные машины отставшими на ровном месте.
func (h *Handler) complianceTargets(r *http.Request) map[string]string {
	channels, err := h.db.UpdateRollout(r.Context(), tenantFromRequest(r))
	if err != nil {
		// Отчёт без целевых версий беднее, но правдив: причина outdated_agent просто
		// не выставляется. Ронять весь отчёт из-за этого нечестно.
		slog.Warn("отчёт соответствия: целевые версии каналов недоступны", "err", err)
		return nil
	}
	out := map[string]string{}
	for _, c := range channels {
		// Версий может быть несколько (разные платформы). Совпадение по любой из них
		// считаем актуальностью — иначе mac и windows в одном тенанте всегда
		// объявляли бы друг друга устаревшими.
		for _, t := range c.Targets {
			if out[c.Channel] == "" {
				out[c.Channel] = t.Version
			}
		}
	}
	return out
}

// tenantFromRequest — тенант из уже доверенных claims (ADR-6). Отдельная функция,
// чтобы CSV и JSON точно брали его одинаково.
func tenantFromRequest(r *http.Request) string {
	c, ok := r.Context().Value(claimsKey).(*jwtClaims)
	if !ok {
		return ""
	}
	return c.TenantID
}

func (h *Handler) complianceReport(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	report, err := h.db.BuildComplianceReport(r.Context(), tenantID, h.complianceTargets(r))
	if err != nil {
		slog.Error("отчёт соответствия", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// complianceReportCSV отдаёт тот же отчёт файлом.
//
// Кодировка с BOM: без него Excel портит кириллицу, а отчёт, который открывается
// нечитаемым, равносилен отсутствующему. Язык и разделитель берутся из локали
// запроса — см. report_locale.go.
func (h *Handler) complianceReportCSV(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	report, err := h.db.BuildComplianceReport(r.Context(), tenantID, h.complianceTargets(r))
	if err != nil {
		slog.Error("отчёт соответствия (csv)", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("compliance-%s.csv", time.Now().UTC().Format("2006-01-02"))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	if _, err := w.Write([]byte("\xEF\xBB\xBF")); err != nil {
		return
	}

	loc := reportLocaleFor(r)
	cw := csv.NewWriter(w)
	cw.Comma = loc.comma
	_ = cw.Write(loc.headers)
	for _, d := range report.Devices {
		lastSeen := ""
		if d.LastSeenAt != nil {
			lastSeen = d.LastSeenAt.UTC().Format(time.RFC3339)
		}
		_ = cw.Write([]string{
			d.Hostname, d.OS, d.OSVersion, d.AgentVersion, d.Channel, d.Status, lastSeen,
			strconv.Itoa(d.Vulnerable), strconv.Itoa(d.Unverified),
			loc.boolWord(d.Compliant), strings.Join(loc.translateReasons(d.Reasons), ", "),
		})
	}
	cw.Flush()
}

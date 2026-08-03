import i18n from "@/i18n/config"
import { useEffect, useState } from "react"
import { useTranslation, Trans } from "react-i18next"
import api, { AdminAccessRequest, AdminSessionChange, AdminSessionChangesResponse } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Select } from "@/components/ui/select"
import { formatDistanceToNow } from "@/lib/time"
import { toast } from "@/lib/toast"

// Границы совпадают с серверными (respondAdminRequest): 1 минута .. 30 суток.
const MIN_DURATION_SECONDS = 60
const MAX_DURATION_SECONDS = 30 * 24 * 3600

type DurationUnit = "minutes" | "hours"

const unitSeconds: Record<DurationUnit, number> = { minutes: 60, hours: 3600 }

// Значения — КЛЮЧИ словаря: t() на уровне модуля недоступен.
const statusLabel: Record<string, string> = {
  pending: "adminAccess.pending",
  approved: "adminAccess.approved",
  rejected: "adminAccess.rejected",
  expired: "adminAccess.expired",
  revoked: "adminAccess.revoked",
}

const statusVariant: Record<string, "default" | "secondary" | "success" | "destructive" | "outline"> = {
  pending: "secondary",
  approved: "success",
  rejected: "destructive",
  expired: "outline",
  revoked: "outline",
}

// Строки таблицы разделяются верхней границей (как ленты на «Обзоре»),
// поэтому border-b примитива гасится, а border-t проставляется явно.
const ROW = "hover:bg-transparent"

const completenessLabel: Record<string, string> = {
  unspecified: "adminAccess.noEvidence",
  complete: "adminAccess.evidenceComplete",
  no_baseline: "adminAccess.noBaseline",
  partial: "adminAccess.evidenceIncomplete",
  truncated: "adminAccess.evidenceTruncated",
  stale_final: "adminAccess.finalReportStale",
}

// i18n.t: функция модульная. Экран подписан на смену языка и перерисуется.
function evidenceLabel(req: AdminAccessRequest): string {
  if (!req.baseline_captured_at) return i18n.t("adminAccess.evidenceNotExpected")
  if (!req.changes_final_at) {
    if (req.status === "approved") return i18n.t("adminAccess.awaitingTheFinalReport")
    return i18n.t("adminAccess.noEvidence")
  }
  const key = completenessLabel[req.changes_completeness]
  if (key) return i18n.t(key)
  return req.changes_completeness || i18n.t("adminAccess.evidencePresent")
}


export default function AdminAccess() {
  const { t } = useTranslation()
  const [requests, setRequests] = useState<AdminAccessRequest[]>([])
  const [query, setQuery] = useState("")
  const [loading, setLoading] = useState(true)
  const [approveOpen, setApproveOpen] = useState<string | null>(null)
  const [durationValue, setDurationValue] = useState("1")
  const [durationUnit, setDurationUnit] = useState<DurationUnit>("hours")
  const [submitting, setSubmitting] = useState(false)
  const [reasonReq, setReasonReq] = useState<AdminAccessRequest | null>(null)
  const [evidenceReq, setEvidenceReq] = useState<AdminAccessRequest | null>(null)
  const [evidenceChanges, setEvidenceChanges] = useState<AdminSessionChange[]>([])
  const [evidenceLoading, setEvidenceLoading] = useState(false)
  const [showBackground, setShowBackground] = useState(false)

  const durationSeconds = Number(durationValue) * unitSeconds[durationUnit]
  const durationValid =
    Number.isInteger(Number(durationValue)) &&
    durationSeconds >= MIN_DURATION_SECONDS &&
    durationSeconds <= MAX_DURATION_SECONDS

  async function load() {
    try {
      const r = await api.get<AdminAccessRequest[]>("/admin-access-requests")
      setRequests(r.data ?? [])
    } catch {
      toast({ title: t("adminAccess.failedToLoadRequests"), variant: "destructive" })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  async function respond(id: string, decision: "approved" | "rejected", durationSeconds?: number) {
    setSubmitting(true)
    try {
      await api.post(`/admin-access-requests/${id}/respond`, {
        decision,
        duration_seconds: durationSeconds,
      })
      setApproveOpen(null)
      await load()
    } catch {
      toast({ title: t("adminAccess.failedToProcessThe"), variant: "destructive" })
    } finally {
      setSubmitting(false)
    }
  }

  async function revoke(id: string) {
    setSubmitting(true)
    try {
      await api.post(`/admin-access-requests/${id}/revoke`, {})
      await load()
    } catch {
      toast({ title: t("adminAccess.failedToRevokeThe"), variant: "destructive" })
    } finally {
      setSubmitting(false)
    }
  }



  async function openEvidence(req: AdminAccessRequest) {
    setEvidenceReq(req)
    setShowBackground(false)
    setEvidenceLoading(true)
    setEvidenceChanges([])
    try {
      const r = await api.get<AdminSessionChangesResponse>(`/admin-access-requests/${req.id}/changes`)
      setEvidenceChanges(r.data?.changes ?? [])
    } catch {
      toast({ title: t("adminAccess.failedToLoadThe"), variant: "destructive" })
    } finally {
      setEvidenceLoading(false)
    }
  }

  const pending = requests.filter((r) => r.status === "pending")
  const q = query.trim().toLowerCase()
  const visible = q
    ? requests.filter((r) =>
        (r.device_hostname ?? "").toLowerCase().includes(q) || r.device_id.toLowerCase().includes(q),
      )
    : requests

  if (loading) return <p className="text-muted-foreground text-sm">{t("adminAccess.loading")}</p>

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center gap-3">
        <h1 className="text-xl font-semibold text-foreground">{t("adminAccess.rightsRequests")}</h1>
        {pending.length > 0 && <Badge variant="secondary">{pending.length}</Badge>}
      </div>

      {/* overflow-hidden: янтарная подсветка последней pending-строки иначе вылезает
          за 16px-скругление стеклянной карты. */}
      <div className="glass overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 pt-4 pb-3">
          <div>
            <h2 className="text-[15px] font-semibold text-foreground">{t("adminAccess.accessRequests")}</h2>
            <p className="text-xs text-muted-foreground">{t("adminAccess.temporaryAdministratorRightsOn")}</p>
          </div>
          <Input
            placeholder={t("adminAccess.searchByDevice")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="max-w-[240px]"
          />
        </div>

        <Table>
          <TableHeader>
            <TableRow className={ROW}>
              <TableHead className="px-5 text-xs font-medium text-muted-foreground">{t("adminAccess.device")}</TableHead>
              <TableHead className="px-5 text-xs font-medium text-muted-foreground">{t("adminAccess.reason")}</TableHead>
              <TableHead className="px-5 text-xs font-medium text-muted-foreground">{t("adminAccess.requested")}</TableHead>
              <TableHead className="px-5 text-xs font-medium text-muted-foreground">{t("adminAccess.expires")}</TableHead>
              <TableHead className="px-5 text-xs font-medium text-muted-foreground">{t("adminAccess.status")}</TableHead>
              <TableHead className="px-5 text-xs font-medium text-muted-foreground">{t("adminAccess.evidence")}</TableHead>
              <TableHead className="px-5" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {visible.length === 0 && (
              <TableRow className={ROW}>
                <TableCell colSpan={7} className="text-center text-xs text-muted-foreground py-8">
                  {requests.length === 0 ? t("adminAccess.noRequests") : t("adminAccess.nothingFound")}
                </TableCell>
              </TableRow>
            )}
            {visible.map((req) => (
              // Ожидающие заявки подсвечены янтарным — тем же цветом, что и статус pending.
              <TableRow key={req.id} className={`${ROW} ${req.status === "pending" ? "bg-amber-500/[0.06]" : ""}`}>
                <TableCell className="px-5 py-3 text-sm font-medium text-foreground">{req.device_hostname || req.device_id.slice(0, 8)}</TableCell>
                <TableCell className="px-5 py-3 text-[13px] max-w-xs">
                  {req.reason ? (
                    <button
                      type="button"
                      onClick={() => setReasonReq(req)}
                      className="truncate block max-w-xs text-left text-soft hover:text-foreground transition-colors hover:underline underline-offset-2"
                      title={t("adminAccess.clickToSeeIt")}
                    >
                      {req.reason}
                    </button>
                  ) : <span className="text-muted-foreground">—</span>}
                </TableCell>
                <TableCell className="px-5 py-3 text-xs text-muted-foreground">{formatDistanceToNow(req.requested_at)}</TableCell>
                <TableCell className="px-5 py-3 text-xs text-muted-foreground">
                  {req.expires_at ? formatDistanceToNow(req.expires_at) : req.pending_expires_at ? formatDistanceToNow(req.pending_expires_at) : "—"}
                </TableCell>
                <TableCell className="px-5 py-3">
                  <Badge variant={statusVariant[req.status] ?? "default"}>
                    {statusLabel[req.status] ? t(statusLabel[req.status]) : req.status}
                  </Badge>
                </TableCell>
                <TableCell className="px-5 py-3">
                  <button
                    type="button"
                    onClick={() => openEvidence(req)}
                    className="text-xs text-soft hover:text-foreground hover:underline underline-offset-2"
                    title={t("adminAccess.whatChangedOnThe")}
                  >
                    {evidenceLabel(req)}
                  </button>
                </TableCell>
                <TableCell className="px-5 py-3">
                  {req.status === "pending" && (
                    <div className="flex gap-2">
                      <Dialog open={approveOpen === req.id} onOpenChange={(o) => setApproveOpen(o ? req.id : null)}>
                        <DialogTrigger asChild>
                          {/* Одобрение — единственное «продвигающее» действие строки, поэтому
                              фирменный градиент; отказ и отзыв остаются вторичными. */}
                          <Button size="sm">
                            {t("adminAccess.approve")}
                          </Button>
                        </DialogTrigger>
                        <DialogContent>
                          <DialogHeader>
                            <DialogTitle>{t("adminAccess.approveAccess")}</DialogTitle>
                          </DialogHeader>
                          <div className="space-y-4 pt-2">
                            <p className="text-[13px] text-soft">
                              <Trans i18nKey="adminAccess.deviceLine" values={{ name: req.device_hostname }} components={[<span className="font-medium text-foreground" />]} />
                            </p>
                            <div className="space-y-1.5">
                              <Label className="text-soft">{t("adminAccess.validityPeriod")}</Label>
                              <div className="flex gap-2">
                                <Input
                                  type="number"
                                  min="1"
                                  step="1"
                                  className="flex-1"
                                  value={durationValue}
                                  onChange={(e) => setDurationValue(e.target.value)}
                                />
                                <Select
                                  className="w-36"
                                  value={durationUnit}
                                  onChange={(v) => setDurationUnit(v as DurationUnit)}
                                  options={[
                                    { value: "minutes", label: t("adminAccess.minutes") },
                                    { value: "hours", label: t("adminAccess.hours") },
                                  ]}
                                />
                              </div>
                              {!durationValid && (
                                <p className="text-xs text-destructive">
                                  {t("adminAccess.durationHint")}
                                </p>
                              )}
                            </div>
                            <Button
                              className="w-full"
                              onClick={() => respond(req.id, "approved", durationSeconds)}
                              disabled={submitting || !durationValid}
                            >
                              {submitting ? t("adminAccess.sending") : t("adminAccess.confirm")}
                            </Button>
                          </div>
                        </DialogContent>
                      </Dialog>
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-destructive border-destructive/30 hover:bg-destructive/10 hover:text-destructive"
                        disabled={submitting}
                        onClick={() => respond(req.id, "rejected")}
                      >
                        {t("adminAccess.reject")}
                      </Button>
                    </div>
                  )}
                  {req.status === "approved" && (
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-destructive border-destructive/30 hover:bg-destructive/10 hover:text-destructive"
                      disabled={submitting}
                      onClick={() => revoke(req.id)}
                    >
                      {t("adminAccess.revoke")}
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>


      <Dialog open={!!evidenceReq} onOpenChange={(o) => !o && setEvidenceReq(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{t("adminAccess.changesDuringTheSession")}</DialogTitle>
          </DialogHeader>
          {evidenceReq && (
            <div className="space-y-4 pt-1">
              <p className="text-[13px] text-soft">
                <Trans i18nKey="adminAccess.deviceLine" values={{ name: evidenceReq.device_hostname || evidenceReq.device_id.slice(0, 8) }} components={[<span className="font-medium text-foreground" />]} />
                {" · "}{evidenceLabel(evidenceReq)}
                {evidenceReq.changes_truncated ? " " + t("adminAccess.listTruncated") : ""}
                {evidenceReq.changes_rebooted ? " " + t("adminAccess.wasRebooted") : ""}
              </p>
              <p className="text-xs text-muted-foreground">
                {t("adminAccess.neutralWording")}
              </p>
              <label className="flex items-center gap-2 text-xs text-soft">
                <input type="checkbox" checked={showBackground} onChange={(e) => setShowBackground(e.target.checked)} />
                {t("adminAccess.showBackground")}
              </label>
              {evidenceLoading ? (
                <p className="text-sm text-muted-foreground">{t("adminAccess.loading2")}</p>
              ) : (() => {
                const filtered = evidenceChanges.filter((c) =>
                  showBackground ? true : c.attribution === "human_likely" || c.attribution === "unknown"
                )
                if (filtered.length === 0) {
                  return (
                    <p className="text-sm text-muted-foreground py-4">
                      {!evidenceReq.baseline_captured_at
                        ? t("adminAccess.evidenceCollectionWasNot")
                        : !evidenceReq.changes_final_at
                          ? t("adminAccess.theFinalReportHas")
                          : evidenceReq.changes_completeness === "complete"
                            ? t("adminAccess.noChangesToSoftware")
                            : t("adminAccess.theEvidenceIsIncomplete")}
                    </p>
                  )
                }
                return (
                  <Table>
                    <TableHeader>
                      <TableRow className={ROW}>
                        <TableHead className="text-xs">{t("adminAccess.what")}</TableHead>
                        <TableHead className="text-xs">{t("adminAccess.change")}</TableHead>
                        <TableHead className="text-xs">{t("adminAccess.attribution")}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filtered.map((c, i) => (
                        <TableRow key={`${c.window_seq}-${c.identity_key}-${i}`} className={ROW}>
                          <TableCell className="text-sm">
                            <div className="font-medium text-foreground">{c.display_name || c.subject}</div>
                            <div className="text-xs text-muted-foreground">{c.kind}</div>
                          </TableCell>
                          <TableCell className="text-xs text-soft">
                            {[c.old_value, c.new_value].filter(Boolean).join(" → ") || "—"}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {c.attribution === "human_likely" ? t("adminAccess.likelyManual") :
                             c.attribution === "background_likely" ? t("adminAccess.likelyBackground") :
                             t("adminAccess.unclear")}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )
              })()}
            </div>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={!!reasonReq} onOpenChange={(o) => !o && setReasonReq(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("adminAccess.requestReason")}</DialogTitle>
          </DialogHeader>
          {reasonReq && (
            <div className="space-y-4 pt-1">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <p className="text-xs text-muted-foreground mb-0.5">{t("adminAccess.device")}</p>
                  <p className="text-sm font-medium text-foreground">{reasonReq.device_hostname || reasonReq.device_id.slice(0, 8)}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-0.5">{t("adminAccess.status")}</p>
                  <Badge variant={statusVariant[reasonReq.status] ?? "default"}>
                    {statusLabel[reasonReq.status] ? t(statusLabel[reasonReq.status]) : reasonReq.status}
                  </Badge>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-0.5">{t("adminAccess.requested")}</p>
                  <p className="text-[13px] text-soft">{formatDistanceToNow(reasonReq.requested_at)}</p>
                </div>
              </div>
              <div>
                <p className="text-xs text-muted-foreground mb-1.5">{t("adminAccess.reason")}</p>
                <div className="rounded-md border border-border bg-muted px-3 py-2.5 text-[13px] leading-relaxed text-soft break-words">
                  {reasonReq.reason}
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}

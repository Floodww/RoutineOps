import { useEffect, useState } from "react"
import api, { AdminAccessRequest } from "@/lib/api"
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

const statusLabel: Record<string, string> = {
  pending: "Ожидает",
  approved: "Одобрено",
  rejected: "Отклонено",
  expired: "Истекло",
  revoked: "Отозвано",
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

export default function AdminAccess() {
  const [requests, setRequests] = useState<AdminAccessRequest[]>([])
  const [query, setQuery] = useState("")
  const [loading, setLoading] = useState(true)
  const [approveOpen, setApproveOpen] = useState<string | null>(null)
  const [durationValue, setDurationValue] = useState("1")
  const [durationUnit, setDurationUnit] = useState<DurationUnit>("hours")
  const [submitting, setSubmitting] = useState(false)
  const [reasonReq, setReasonReq] = useState<AdminAccessRequest | null>(null)

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
      toast({ title: "Не удалось загрузить заявки", variant: "destructive" })
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
      toast({ title: "Не удалось обработать заявку", variant: "destructive" })
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
      toast({ title: "Не удалось отозвать права", variant: "destructive" })
    } finally {
      setSubmitting(false)
    }
  }


  const pending = requests.filter((r) => r.status === "pending")
  const q = query.trim().toLowerCase()
  const visible = q
    ? requests.filter((r) =>
        (r.device_hostname ?? "").toLowerCase().includes(q) || r.device_id.toLowerCase().includes(q),
      )
    : requests

  if (loading) return <p className="text-muted-foreground text-sm">Загрузка...</p>

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center gap-3">
        <h1 className="text-xl font-semibold text-foreground">Заявки на права</h1>
        {pending.length > 0 && <Badge variant="secondary">{pending.length}</Badge>}
      </div>

      {/* overflow-hidden: янтарная подсветка последней pending-строки иначе вылезает
          за 16px-скругление стеклянной карты. */}
      <div className="glass overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 pt-4 pb-3">
          <div>
            <h2 className="text-[15px] font-semibold text-foreground">Запросы доступа</h2>
            <p className="text-xs text-muted-foreground">Временные права администратора на устройстве</p>
          </div>
          <Input
            placeholder="Поиск по устройству..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="max-w-[240px]"
          />
        </div>

        <Table>
          <TableHeader>
            <TableRow className={ROW}>
              <TableHead className="px-5 text-xs font-medium text-muted-foreground">Устройство</TableHead>
              <TableHead className="px-5 text-xs font-medium text-muted-foreground">Причина</TableHead>
              <TableHead className="px-5 text-xs font-medium text-muted-foreground">Запрошено</TableHead>
              <TableHead className="px-5 text-xs font-medium text-muted-foreground">Истекает</TableHead>
              <TableHead className="px-5 text-xs font-medium text-muted-foreground">Статус</TableHead>
              <TableHead className="px-5" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {visible.length === 0 && (
              <TableRow className={ROW}>
                <TableCell colSpan={6} className="text-center text-xs text-muted-foreground py-8">
                  {requests.length === 0 ? "Нет заявок" : "Ничего не найдено"}
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
                      title="Нажмите, чтобы увидеть полностью"
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
                    {statusLabel[req.status] ?? req.status}
                  </Badge>
                </TableCell>
                <TableCell className="px-5 py-3">
                  {req.status === "pending" && (
                    <div className="flex gap-2">
                      <Dialog open={approveOpen === req.id} onOpenChange={(o) => setApproveOpen(o ? req.id : null)}>
                        <DialogTrigger asChild>
                          {/* Одобрение — единственное «продвигающее» действие строки, поэтому
                              фирменный градиент; отказ и отзыв остаются вторичными. */}
                          <Button size="sm">
                            Одобрить
                          </Button>
                        </DialogTrigger>
                        <DialogContent>
                          <DialogHeader>
                            <DialogTitle>Одобрить доступ</DialogTitle>
                          </DialogHeader>
                          <div className="space-y-4 pt-2">
                            <p className="text-[13px] text-soft">
                              Устройство: <span className="font-medium text-foreground">{req.device_hostname}</span>
                            </p>
                            <div className="space-y-1.5">
                              <Label className="text-soft">Срок действия</Label>
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
                                    { value: "minutes", label: "минут" },
                                    { value: "hours", label: "часов" },
                                  ]}
                                />
                              </div>
                              {!durationValid && (
                                <p className="text-xs text-destructive">
                                  От 1 минуты до 30 суток, целое число.
                                </p>
                              )}
                            </div>
                            <Button
                              className="w-full"
                              onClick={() => respond(req.id, "approved", durationSeconds)}
                              disabled={submitting || !durationValid}
                            >
                              {submitting ? "Отправка..." : "Подтвердить"}
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
                        Отклонить
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
                      Отозвать
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <Dialog open={!!reasonReq} onOpenChange={(o) => !o && setReasonReq(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Причина запроса</DialogTitle>
          </DialogHeader>
          {reasonReq && (
            <div className="space-y-4 pt-1">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <p className="text-xs text-muted-foreground mb-0.5">Устройство</p>
                  <p className="text-sm font-medium text-foreground">{reasonReq.device_hostname || reasonReq.device_id.slice(0, 8)}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-0.5">Статус</p>
                  <Badge variant={statusVariant[reasonReq.status] ?? "default"}>
                    {statusLabel[reasonReq.status] ?? reasonReq.status}
                  </Badge>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-0.5">Запрошено</p>
                  <p className="text-[13px] text-soft">{formatDistanceToNow(reasonReq.requested_at)}</p>
                </div>
              </div>
              <div>
                <p className="text-xs text-muted-foreground mb-1.5">Причина</p>
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

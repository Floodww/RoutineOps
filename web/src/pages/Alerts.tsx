import { useEffect, useState } from "react"
import { AlertTriangle, ChevronDown, ChevronRight } from "lucide-react"
import api, { Alert } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { formatDistanceToNow } from "@/lib/time"
import { toast } from "@/lib/toast"
import { useMe } from "@/lib/useMe"

const alertTypeLabel: Record<string, string> = {
  forbidden_software:             "Запрещённое ПО",
  unauthorized_install:           "Неавторизованная установка",
  unauthorized_settings_change:   "Изменение настроек",
  agent_unreachable:              "Агент недоступен",
}

const alertTypeColor: Record<string, string> = {
  forbidden_software:           "text-red-600 dark:text-red-500",
  unauthorized_install:         "text-amber-600 dark:text-amber-500",
  unauthorized_settings_change: "text-orange-600 dark:text-orange-500",
  agent_unreachable:            "text-blue-600 dark:text-blue-500",
}

// TYPE_ORDER — порядок секций. Типы вне списка (сервер хранит alert_type свободным
// TEXT, без enum) уезжают в конец по алфавиту, а не пропадают.
const TYPE_ORDER = [
  "forbidden_software",
  "unauthorized_install",
  "unauthorized_settings_change",
  "agent_unreachable",
]

type AlertGroup = { type: string; alerts: Alert[]; unacked: number }

// groupByType сохраняет порядок алертов внутри секции (сервер отдаёт их created_at DESC).
function groupByType(alerts: Alert[]): AlertGroup[] {
  const buckets = new Map<string, Alert[]>()
  for (const a of alerts) {
    const list = buckets.get(a.alert_type)
    if (list) list.push(a)
    else buckets.set(a.alert_type, [a])
  }
  const rank = (t: string) => {
    const i = TYPE_ORDER.indexOf(t)
    return i === -1 ? TYPE_ORDER.length : i
  }
  return [...buckets.entries()]
    .map(([type, list]) => ({ type, alerts: list, unacked: list.filter((a) => !a.acknowledged_at).length }))
    .sort((a, b) => rank(a.type) - rank(b.type) || a.type.localeCompare(b.type))
}

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [onlyNew, setOnlyNew] = useState(false)
  const [query, setQuery] = useState("")
  const [submitting, setSubmitting] = useState<string | null>(null)
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())
  const { isAdmin } = useMe()

  function toggleGroup(type: string) {
    setCollapsed((prev) => {
      const next = new Set(prev)
      if (next.has(type)) next.delete(type)
      else next.add(type)
      return next
    })
  }

  async function load() {
    try {
      const r = await api.get<Alert[]>("/alerts")
      setAlerts(r.data ?? [])
    } catch {
      toast({ title: "Не удалось загрузить алерты", variant: "destructive" })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  async function acknowledge(id: string, e?: React.MouseEvent) {
    e?.stopPropagation()
    setSubmitting(id)
    try {
      await api.post(`/alerts/${id}/acknowledge`, {})
      await load()
      if (selectedAlert?.id === id) setSelectedAlert(null)
    } catch {
      toast({ title: "Не удалось принять алерт", variant: "destructive" })
    } finally {
      setSubmitting(null)
    }
  }

  if (loading) return <p className="text-muted-foreground text-sm">Загрузка...</p>

  const unacked = alerts.filter((a) => !a.acknowledged_at)
  const q = query.trim().toLowerCase()
  const base = onlyNew ? unacked : alerts
  const visible = q
    ? base.filter((a) =>
        (a.device_hostname ?? "").toLowerCase().includes(q) || a.device_id.toLowerCase().includes(q),
      )
    : base
  const groups = groupByType(visible)

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center gap-3">
        <h1 className="text-xl font-semibold text-foreground">Алерты</h1>
        {unacked.length > 0 && (
          <span className="flex items-center gap-1 rounded-full bg-red-500/15 px-2 py-0.5 text-xs font-semibold text-red-600 dark:text-red-400">
            <AlertTriangle className="h-3.5 w-3.5" strokeWidth={2} />
            {unacked.length} новых
          </span>
        )}
        <button
          type="button"
          className={`ml-auto text-xs px-3 py-1.5 rounded-md border transition-colors ${onlyNew ? "bg-destructive/10 border-destructive/30 text-destructive" : "border-input text-muted-foreground hover:text-foreground"}`}
          onClick={() => setOnlyNew(!onlyNew)}
        >
          {onlyNew ? "Показать все" : "Только новые"}
        </button>
      </div>

      <Input
        placeholder="Поиск по устройству..."
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        className="max-w-sm"
      />

      {groups.length === 0 && (
        <div className="glass py-10 text-center text-sm text-muted-foreground">
          Нет алертов
        </div>
      )}

      {/* Алерты сгруппированы по типу: «агент недоступен» и «запрещённое ПО» — разные
          инциденты, и разбирают их разные люди. Секции сворачиваются. */}
      {groups.map((g) => {
        const isCollapsed = collapsed.has(g.type)
        const color = alertTypeColor[g.type] ?? "text-foreground"
        return (
          <div key={g.type} className="glass overflow-hidden">
            <button
              type="button"
              onClick={() => toggleGroup(g.type)}
              className="glass-hover flex w-full items-center gap-2.5 px-5 py-4 text-left"
            >
              {isCollapsed ? (
                <ChevronRight className="h-4 w-4 text-muted-foreground" strokeWidth={2} />
              ) : (
                <ChevronDown className="h-4 w-4 text-muted-foreground" strokeWidth={2} />
              )}
              <AlertTriangle className={`h-[17px] w-[17px] ${color}`} strokeWidth={2} />
              <span className="text-[15px] font-semibold text-foreground">
                {alertTypeLabel[g.type] ?? g.type}
              </span>
              <span className="text-xs text-muted-foreground tabular-nums">{g.alerts.length}</span>
              {g.unacked > 0 && (
                <span className="rounded-full bg-red-500/15 px-2 py-0.5 text-xs font-semibold text-red-600 dark:text-red-400">
                  {g.unacked} новых
                </span>
              )}
            </button>

            {!isCollapsed && (
              <div>
                {g.alerts.map((a) => (
                  <div
                    key={a.id}
                    className={`glass-hover flex cursor-pointer items-center gap-3 border-t border-border px-5 py-3 last:rounded-b-2xl ${!a.acknowledged_at ? "bg-red-500/[0.06]" : ""}`}
                    onClick={() => setSelectedAlert(a)}
                  >
                    <span
                      className={`h-2 w-2 flex-shrink-0 rounded-full ${a.acknowledged_at ? "bg-muted-foreground/40" : "bg-red-500"}`}
                    />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium text-foreground">
                        {a.device_hostname || <span className="font-mono text-xs text-muted-foreground">{a.device_id.slice(0, 8)}</span>}
                      </p>
                      <p className="truncate text-xs text-soft">{a.details || "—"}</p>
                    </div>
                    <div className="ml-4 flex flex-shrink-0 items-center gap-3">
                      <span className="hidden whitespace-nowrap text-xs text-muted-foreground sm:block">
                        {formatDistanceToNow(a.created_at)}
                      </span>
                      {a.acknowledged_at ? (
                        <Badge variant="secondary">Принято</Badge>
                      ) : (
                        <Badge variant="destructive">Новый</Badge>
                      )}
                      {isAdmin && !a.acknowledged_at && (
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={submitting === a.id}
                          onClick={(e) => acknowledge(a.id, e)}
                        >
                          {submitting === a.id ? "..." : "Принять"}
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )
      })}

      {/* Alert detail dialog */}
      <Dialog open={!!selectedAlert} onOpenChange={(o) => !o && setSelectedAlert(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className={`h-[17px] w-[17px] ${selectedAlert ? (alertTypeColor[selectedAlert.alert_type] ?? "text-foreground") : ""}`} strokeWidth={2} />
              {selectedAlert ? (alertTypeLabel[selectedAlert.alert_type] ?? selectedAlert.alert_type) : ""}
            </DialogTitle>
          </DialogHeader>
          {selectedAlert && (
            <div className="space-y-4 pt-1">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p className="text-xs text-muted-foreground mb-0.5">Устройство</p>
                  <p className="font-medium text-foreground">{selectedAlert.device_hostname || selectedAlert.device_id.slice(0, 8)}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-0.5">Создан</p>
                  <p className="text-soft">{formatDistanceToNow(selectedAlert.created_at)}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-0.5">Статус</p>
                  {selectedAlert.acknowledged_at ? (
                    <Badge variant="secondary">Принято</Badge>
                  ) : (
                    <Badge variant="destructive">Новый</Badge>
                  )}
                </div>
              </div>

              {selectedAlert.details && (
                <div>
                  <p className="text-xs text-muted-foreground mb-1.5">Детали</p>
                  <div className="rounded-md border border-border bg-muted px-3 py-2.5 text-sm font-mono text-soft break-all">
                    {selectedAlert.details}
                  </div>
                </div>
              )}

              {isAdmin && !selectedAlert.acknowledged_at && (
                <Button
                  className="w-full"
                  onClick={() => acknowledge(selectedAlert.id)}
                  disabled={submitting === selectedAlert.id}
                >
                  {submitting === selectedAlert.id ? "Принятие..." : "Принять алерт"}
                </Button>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}

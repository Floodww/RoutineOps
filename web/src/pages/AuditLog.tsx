import { useEffect, useState } from "react"
import api from "@/lib/api"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Select } from "@/components/ui/select"
import { Label } from "@/components/ui/label"

interface AuditEntry {
  id: string
  user_email: string
  action: string
  target_type: string
  target_id: string
  details: Record<string, unknown> | null
  created_at: string
}

const ACTION_LABELS: Record<string, string> = {
  block_device:          "Заблокировал устройство",
  unblock_device:        "Разблокировал устройство",
  approve_admin_request: "Одобрил заявку на права",
  reject_admin_request:  "Отклонил заявку на права",
  revoke_admin_request:  "Отозвал права администратора",
  create_device:         "Добавил устройство",
  reenroll_device:       "Перерегистрировал устройство",
  apply_license:         "Применил лицензию",
  deactivate_license:    "Деактивировал лицензию",
}

export default function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<AuditEntry | null>(null)
  const [from, setFrom] = useState("")
  const [to, setTo] = useState("")
  const [who, setWho] = useState("")

  useEffect(() => {
    api.get<AuditEntry[]>("/audit-log?limit=200")
      .then(r => setEntries(r.data ?? []))
      .finally(() => setLoading(false))
  }, [])

  const users = [...new Set(entries.map((e) => e.user_email))].sort()
  const fromMs = from ? new Date(`${from}T00:00:00`).getTime() : null
  const toMs = to ? new Date(`${to}T23:59:59.999`).getTime() : null
  const filtered = entries.filter((e) => {
    if (who && e.user_email !== who) return false
    const t = new Date(e.created_at).getTime()
    if (fromMs !== null && t < fromMs) return false
    if (toMs !== null && t > toMs) return false
    return true
  })

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Журнал действий</h1>
      {loading ? (
        <p className="text-sm text-muted-foreground">Загрузка...</p>
      ) : entries.length === 0 ? (
        <p className="text-sm text-muted-foreground">Нет записей</p>
      ) : (
        <>
        <div className="flex flex-wrap items-end gap-3">
          <div className="space-y-1">
            <Label className="text-xs text-muted-foreground">С</Label>
            <input
              type="date"
              value={from}
              onChange={(e) => setFrom(e.target.value)}
              className="flex h-9 rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-xs text-muted-foreground">По</Label>
            <input
              type="date"
              value={to}
              onChange={(e) => setTo(e.target.value)}
              className="flex h-9 rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            />
          </div>
          <div className="space-y-1 min-w-48">
            <Label className="text-xs text-muted-foreground">Кто</Label>
            <Select
              value={who}
              onChange={setWho}
              options={[{ value: "", label: "Все" }, ...users.map((u) => ({ value: u, label: u }))]}
            />
          </div>
          {(from || to || who) && (
            <button
              type="button"
              onClick={() => { setFrom(""); setTo(""); setWho("") }}
              className="h-9 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              Сбросить
            </button>
          )}
        </div>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Когда</TableHead>
              <TableHead>Кто</TableHead>
              <TableHead>Действие</TableHead>
              <TableHead>ID объекта</TableHead>
              <TableHead>Детали</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                  Ничего не найдено
                </TableCell>
              </TableRow>
            )}
            {filtered.map(e => {
              const summary = e.details
                ? Object.entries(e.details).map(([k, v]) => `${k}: ${v}`).join(", ")
                : null
              return (
                <TableRow key={e.id} className={e.details ? "cursor-pointer hover:bg-accent/40 group" : ""} onClick={() => e.details && setSelected(e)}>
                  <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                    {new Date(e.created_at).toLocaleString("ru-RU")}
                  </TableCell>
                  <TableCell className="text-sm">{e.user_email}</TableCell>
                  <TableCell className="text-sm">{ACTION_LABELS[e.action] ?? e.action}</TableCell>
                  <TableCell className="text-xs font-mono text-muted-foreground">
                    {e.target_id.slice(0, 8)}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground max-w-xs">
                    {summary
                      ? <span className="truncate block group-hover:text-foreground transition-colors">{summary}</span>
                      : "-"}
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
        </>
      )}

      <Dialog open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{selected ? (ACTION_LABELS[selected.action] ?? selected.action) : ""}</DialogTitle>
          </DialogHeader>
          {selected && (
            <div className="space-y-3 pt-1">
              <div className="flex gap-4 text-sm text-muted-foreground">
                <span>{new Date(selected.created_at).toLocaleString("ru-RU")}</span>
                <span>{selected.user_email}</span>
              </div>
              <div className="rounded-md border bg-muted/40 p-4">
                <table className="w-full text-sm">
                  <tbody>
                    {Object.entries(selected.details ?? {}).map(([k, v]) => (
                      <tr key={k} className="border-b border-border/50 last:border-0">
                        <td className="py-1.5 pr-4 font-medium text-muted-foreground whitespace-nowrap">{k}</td>
                        <td className="py-1.5 font-mono break-all">{String(v)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="text-xs text-muted-foreground font-mono">ID: {selected.target_id}</p>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}

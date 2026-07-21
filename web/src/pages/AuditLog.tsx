import { useEffect, useState, type ElementType, type CSSProperties } from "react"
import { Monitor, FileCode2, ShieldAlert, KeyRound, UserCog } from "lucide-react"
import api from "@/lib/api"
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
  approve_device:        "Одобрил устройство",
  reject_device:         "Отклонил устройство",
  approve_pending_bulk:  "Одобрил очередь энроллмента",
  reject_pending_bulk:   "Отклонил очередь энроллмента",
  create_bulk_token:     "Выпустил массовый токен",
  decommission_device:   "Вывел устройство из эксплуатации",
  create_api_token:      "Выпустил API-токен",
  revoke_api_token:      "Отозвал API-токен",
}

// Таксономия событий ленты — та же, что на Обзоре: security должно цепляться
// взглядом сразу, остальные категории различаются иконкой и сдержанным акцентом.
type EventCategory = "security" | "auth" | "admin" | "device" | "content"

const ACTION_CATEGORY: Record<string, EventCategory> = {
  login_failed: "security", block_device: "security", lock_device: "security",
  login: "auth", logout: "auth", change_password: "auth",
  password_reset: "auth", password_reset_requested: "auth",
  invite_user: "admin", accept_invite: "admin",
  approve_admin_request: "admin", reject_admin_request: "admin", revoke_admin_request: "admin",
  create_device: "device", delete_device: "device", reenroll_device: "device",
  unblock_device: "device", unlock_device: "device",
  create_bulk_token: "security", approve_device: "security", approve_pending_bulk: "security",
  create_api_token: "security", revoke_api_token: "security",
  reject_device: "device", reject_pending_bulk: "device", decommission_device: "device",
  run_script: "device", run_script_on_group: "device",
  create_device_group: "device", update_device_group: "device", delete_device_group: "device",
  add_device_to_group: "device", remove_device_from_group: "device",
  // всё остальное (скрипты/политики/алерты/лицензии) — content по умолчанию
}

const CATEGORY_STYLE: Record<EventCategory, { icon: ElementType; fg: string; bg: string }> = {
  // red-700 в светлой теме: red-500 на белом даёт 3.57:1 — ниже AA для text-xs.
  security: { icon: ShieldAlert, fg: "text-red-700 dark:text-red-400",         bg: "bg-red-500/10" },
  auth:     { icon: KeyRound,    fg: "text-sky-600 dark:text-sky-400",         bg: "bg-sky-500/10" },
  admin:    { icon: UserCog,     fg: "text-violet-600 dark:text-violet-400",   bg: "bg-violet-500/10" },
  device:   { icon: Monitor,     fg: "text-emerald-600 dark:text-emerald-400", bg: "bg-emerald-500/10" },
  content:  { icon: FileCode2,   fg: "text-muted-foreground",                  bg: "bg-muted" },
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
    <div className="flex flex-col gap-5">
      <h1 className="text-xl font-semibold text-foreground">Журнал действий</h1>
      {loading ? (
        <p className="text-sm text-muted-foreground">Загрузка...</p>
      ) : entries.length === 0 ? (
        <p className="text-sm text-muted-foreground">Нет записей</p>
      ) : (
        <>
        <div className="glass px-5 py-[18px] flex flex-wrap items-end gap-3">
          <div className="space-y-1">
            <Label className="text-xs text-muted-foreground">С</Label>
            <input
              type="date"
              value={from}
              onChange={(e) => setFrom(e.target.value)}
              className="flex h-9 rounded-md border border-input bg-transparent px-3 py-1 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-xs text-muted-foreground">По</Label>
            <input
              type="date"
              value={to}
              onChange={(e) => setTo(e.target.value)}
              className="flex h-9 rounded-md border border-input bg-transparent px-3 py-1 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
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

        <div className="glass">
          <div className="px-5 pt-4 pb-3">
            <h2 className="text-[15px] font-semibold text-foreground">События</h2>
            <p className="text-xs text-muted-foreground">Показано {filtered.length} из {entries.length}</p>
          </div>
          {filtered.length === 0 && (
            <p className="text-xs text-muted-foreground px-5 py-8 text-center border-t border-border">
              Ничего не найдено
            </p>
          )}
          {filtered.map((e, i) => {
            const summary = e.details
              ? Object.entries(e.details).map(([k, v]) => `${k}: ${v}`).join(", ")
              : null
            const cat = ACTION_CATEGORY[e.action] ?? "content"
            const { icon: CatIcon, fg, bg } = CATEGORY_STYLE[cat]
            return (
              <div
                key={e.id}
                className={`feed-item group flex items-start gap-3 px-5 py-2.5 border-t border-border last:rounded-b-2xl ${cat === "security" ? "bg-red-500/[0.06]" : ""} ${e.details ? "cursor-pointer glass-hover" : ""}`}
                style={{ "--i": i } as CSSProperties}
                onClick={() => e.details && setSelected(e)}
              >
                <div className={`mt-px h-[26px] w-[26px] rounded-full ${bg} flex items-center justify-center flex-shrink-0`}>
                  <CatIcon className={`h-3.5 w-3.5 ${fg}`} strokeWidth={2} />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-[13px] leading-snug text-soft">
                    <span className="font-medium text-foreground">{e.user_email}</span>
                    {" "}
                    <span className={cat === "security" ? fg : "text-muted-foreground"}>
                      {ACTION_LABELS[e.action] ?? e.action}
                    </span>
                  </p>
                  {summary && (
                    <p className="text-xs text-muted-foreground truncate group-hover:text-soft transition-colors mt-0.5">
                      {summary}
                    </p>
                  )}
                  <p className="text-[11px] text-muted-foreground mt-0.5">
                    {new Date(e.created_at).toLocaleString("ru-RU")}
                    {" · "}
                    <span className="font-mono">{e.target_id.slice(0, 8)}</span>
                  </p>
                </div>
              </div>
            )
          })}
        </div>
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
              <div className="px-5 py-[18px]">
                <table className="w-full text-sm">
                  <tbody>
                    {Object.entries(selected.details ?? {}).map(([k, v]) => (
                      <tr key={k} className="border-t border-border first:border-t-0">
                        <td className="py-1.5 pr-4 font-medium text-soft whitespace-nowrap">{k}</td>
                        <td className="py-1.5 font-mono break-all text-foreground">{String(v)}</td>
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

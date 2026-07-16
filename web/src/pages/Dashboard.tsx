import { useEffect, useRef, useState, type ElementType, type CSSProperties } from "react"
import { useNavigate } from "react-router-dom"
import { Monitor, FileCode2, Shield, Bell, ChevronRight, Activity, ShieldAlert, KeyRound, UserCog } from "lucide-react"
import api, { Device, Script, PolicyRule, Alert } from "@/lib/api"
import { formatDistanceToNow } from "@/lib/time"
import { toast } from "@/lib/toast"
import SpotlightCard from "@/components/SpotlightCard"

interface AuditEntry {
  id: string
  user_email: string
  action: string
  target_type: string
  created_at: string
}

const ONLINE_THRESHOLD_MS = 5 * 60 * 1000

const ACTION_LABELS: Record<string, string> = {
  block_device:          "заблокировал устройство",
  unblock_device:        "разблокировал устройство",
  approve_admin_request: "одобрил заявку на права",
  reject_admin_request:  "отклонил заявку на права",
  revoke_admin_request:  "отозвал права",
  create_device:         "добавил устройство",
  delete_device:         "удалил устройство",
  reenroll_device:       "перерегистрировал устройство",
  lock_device:           "заблокировал экран устройства",
  unlock_device:         "разблокировал экран устройства",
  create_script:         "создал скрипт",
  update_script:         "изменил скрипт",
  delete_script:         "удалил скрипт",
  create_policy:         "создал политику",
  delete_policy:         "удалил политику",
  run_script:            "запустил скрипт",
  run_script_on_group:   "запустил скрипт на группе",
  create_script_policy:  "создал скрипт-политику",
  delete_script_policy:  "удалил скрипт-политику",
  enable_script_policy:  "включил скрипт-политику",
  disable_script_policy: "выключил скрипт-политику",
  acknowledge_alert:     "подтвердил алерт",
  login:                 "вошёл в систему",
  logout:                "вышел из системы",
  login_failed:          "неудачная попытка входа",
  change_password:       "сменил пароль",
  password_reset_requested: "запросил сброс пароля",
  password_reset:        "сбросил пароль",
  invite_user:           "пригласил пользователя",
  accept_invite:         "принял приглашение",
  create_device_group:   "создал группу устройств",
  update_device_group:   "изменил группу устройств",
  delete_device_group:   "удалил группу устройств",
  add_device_to_group:   "добавил устройство в группу",
  remove_device_from_group: "убрал устройство из группы",
  assign_policy_to_group:   "назначил группе политику",
  unassign_policy_from_group: "снял с группы политику",
  assign_software_policy_to_group:   "назначил группе политику ПО",
  unassign_software_policy_from_group: "снял с группы политику ПО",
}

// Таксономия событий ленты: security должно цепляться взглядом сразу,
// остальные категории различаются иконкой и сдержанным цветовым акцентом.
type EventCategory = "security" | "auth" | "admin" | "device" | "content"

const ACTION_CATEGORY: Record<string, EventCategory> = {
  login_failed: "security", block_device: "security", lock_device: "security",
  login: "auth", logout: "auth", change_password: "auth",
  password_reset: "auth", password_reset_requested: "auth",
  invite_user: "admin", accept_invite: "admin",
  approve_admin_request: "admin", reject_admin_request: "admin", revoke_admin_request: "admin",
  create_device: "device", delete_device: "device", reenroll_device: "device",
  unblock_device: "device", unlock_device: "device",
  // Запуск скрипта — исполнение кода на устройстве/парке, не правка контента.
  run_script: "device", run_script_on_group: "device",
  create_device_group: "device", update_device_group: "device", delete_device_group: "device",
  add_device_to_group: "device", remove_device_from_group: "device",
  // всё остальное (скрипты/политики/алерты) — content по умолчанию
}

const CATEGORY_STYLE: Record<EventCategory, { icon: ElementType; fg: string; bg: string }> = {
  // red-700 в светлой теме: red-500 на белом даёт 3.57:1 — ниже AA для text-xs.
  security: { icon: ShieldAlert, fg: "text-red-700 dark:text-red-400",         bg: "bg-red-500/10" },
  auth:     { icon: KeyRound,    fg: "text-sky-600 dark:text-sky-400",         bg: "bg-sky-500/10" },
  admin:    { icon: UserCog,     fg: "text-violet-600 dark:text-violet-400",   bg: "bg-violet-500/10" },
  device:   { icon: Monitor,     fg: "text-emerald-600 dark:text-emerald-400", bg: "bg-emerald-500/10" },
  content:  { icon: FileCode2,   fg: "text-muted-foreground",                  bg: "bg-muted" },
}

// Count-up цифр карточек при первой загрузке. Уважает prefers-reduced-motion.
// Анимирует от последнего показанного значения, не от нуля — чтобы при
// будущем рефреше данных цифра не прыгала в 0.
function useCountUp(target: number, duration = 600): number {
  const [value, setValue] = useState(0)
  const lastRef = useRef(0)
  useEffect(() => {
    const from = lastRef.current
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches || from === target) {
      lastRef.current = target
      setValue(target)
      return
    }
    let raf = 0
    const start = performance.now()
    const tick = (t: number) => {
      const p = Math.min((t - start) / duration, 1)
      const v = Math.round(from + (target - from) * (1 - Math.pow(1 - p, 3)))
      lastRef.current = v
      setValue(v)
      if (p < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [target, duration])
  return value
}

function StatValue({ value }: { value: number }) {
  return <p className="text-2xl font-semibold tabular-nums">{useCountUp(value)}</p>
}

function osFamily(os: string): "macOS" | "Windows" | "Linux" {
  const l = os.toLowerCase()
  if (l.includes("mac") || l.includes("darwin")) return "macOS"
  if (l.includes("win")) return "Windows"
  // всё остальное (linux/ubuntu/debian/centos/прочие дистрибутивы) — Linux-парк
  return "Linux"
}

const OS_COLOR: Record<string, string> = {
  macOS:   "bg-blue-500",
  Windows: "bg-violet-500",
  Linux:   "bg-amber-500",
}

export default function Dashboard() {
  const navigate = useNavigate()
  const [devices, setDevices]   = useState<Device[]>([])
  const [scripts, setScripts]   = useState<Script[]>([])
  const [policies, setPolicies] = useState<PolicyRule[]>([])
  const [activity, setActivity] = useState<AuditEntry[]>([])
  const [alerts, setAlerts]     = useState<Alert[]>([])
  const [loading, setLoading]   = useState(true)
  // При ошибке загрузки нули — не «пустой парк», CTA показывать нечестно.
  const [loadFailed, setLoadFailed] = useState(false)

  useEffect(() => {
    Promise.all([
      api.get<Device[]>("/devices"),
      api.get<Script[]>("/scripts"),
      api.get<PolicyRule[]>("/policies"),
      api.get<AuditEntry[]>("/audit-log?limit=12"),
      api.get<Alert[]>("/alerts"),
    ]).then(([d, s, p, a, al]) => {
      setDevices(d.data ?? [])
      setScripts(s.data ?? [])
      setPolicies(p.data ?? [])
      setActivity(a.data ?? [])
      setAlerts(al.data ?? [])
    }).catch(() => {
      setLoadFailed(true)
      toast({ title: "Не удалось загрузить данные", variant: "destructive" })
    }).finally(() => setLoading(false))
  }, [])

  const now = Date.now()
  const active   = devices.filter((d) => d.status === "active").length
  const enrolled = devices.filter((d) => d.status === "enrolled").length
  const pending  = devices.filter((d) => d.status === "pending").length
  const online   = devices.filter((d) => d.last_seen_at && now - new Date(d.last_seen_at).getTime() < ONLINE_THRESHOLD_MS).length
  // API отдаёт acknowledged_at (timestamp | null), поля `acknowledged` не существует —
  // старый фильтр по нему считал ВСЕ алерты непринятыми.
  const unackedAlerts = alerts.filter((a) => !a.acknowledged_at).length

  const osCounts = devices.reduce<Record<string, number>>((acc, d) => {
    const fam = osFamily(d.os)
    acc[fam] = (acc[fam] ?? 0) + 1
    return acc
  }, {})
  const osEntries = Object.entries(osCounts).sort((a, b) => b[1] - a[1])
  // Доли part-to-whole: масштаб от общего числа устройств, не от максимума —
  // иначе самая крупная ОС всегда рисуется на 100% и полосы визуально врут.
  const totalDevices = Math.max(devices.length, 1)

  if (loading) {
    return <div className="flex items-center justify-center h-48 text-muted-foreground text-sm">Загрузка...</div>
  }

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">Обзор</h1>

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {/* Цветом метим только то, что требует внимания: непрочитанные алерты.
            Нулевые счётчики превращаем в CTA — три нуля подряд читаются как
            «заброшенный продукт», а «Добавить …» зовёт к действию. */}
        {[
          { label: "Всего устройств", value: devices.length, icon: Monitor,   sub: `${online} онлайн`, cta: "Подключить устройство", accent: "border-t-brand",     iconColor: "text-brand",            onClick: () => navigate("/devices")  },
          { label: "Скриптов",        value: scripts.length,  icon: FileCode2, sub: "в библиотеке",     cta: "Добавить скрипт",       accent: "border-t-brand",     iconColor: "text-brand",            onClick: () => navigate("/scripts")  },
          { label: "Политик",         value: policies.length, icon: Shield,    sub: "правил ПО",        cta: "Добавить политику",     accent: "border-t-brand",     iconColor: "text-brand",            onClick: () => navigate("/policies") },
          { label: "Алертов",         value: unackedAlerts,   icon: Bell,      sub: "",                 cta: "",                      accent: unackedAlerts > 0 ? "border-t-destructive" : "border-t-border", iconColor: unackedAlerts > 0 ? "text-destructive" : "text-muted-foreground", onClick: () => navigate("/alerts") },
        ].map(({ label, value, icon: Icon, sub, cta, accent, iconColor, onClick }) => (
          <SpotlightCard
            as="button"
            type="button"
            key={label}
            onClick={onClick}
            // Акцентная кромка идёт ПОСЛЕ `border-border`: className проходит через
            // tailwind-merge внутри SpotlightCard, и более поздний класс выигрывает.
            className={`rounded-lg border border-border border-t-2 ${accent} bg-card p-4 text-left hover:bg-accent/50 transition-colors`}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs text-muted-foreground">{label}</span>
              <Icon className={`h-4 w-4 ${iconColor}`} />
            </div>
            <StatValue value={value} />
            {value === 0 && cta && !loadFailed ? (
              // В светлой теме --brand (52%) даёт ~4:1 на белом — ниже AA для
              // text-xs, поэтому CTA затемнён той же тональностью (~6.8:1).
              <p className="text-xs font-medium text-[hsl(220_65%_42%)] dark:text-brand mt-1">{cta} →</p>
            ) : sub ? (
              <p className="text-xs text-muted-foreground mt-1">{sub}</p>
            ) : null}
          </SpotlightCard>
        ))}
      </div>

      {/* Two-column section */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">

        {/* Left: Devices by OS + status breakdown */}
        <div className="lg:col-span-2 space-y-4">
          <div className="rounded-lg border bg-card p-4">
            <h2 className="text-sm font-medium mb-4">Устройства по ОС</h2>
            {osEntries.length === 0 ? (
              <p className="text-xs text-muted-foreground">Нет данных</p>
            ) : (
              <div className="space-y-3">
                {osEntries.map(([os, count]) => (
                  <div key={os}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-muted-foreground">{os}</span>
                      <span className="text-xs font-medium tabular-nums">
                        {count}
                        <span className="text-muted-foreground font-normal"> · {Math.round((count / totalDevices) * 100)}%</span>
                      </span>
                    </div>
                    <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                      <div
                        className={`h-full rounded-full ${OS_COLOR[os] ?? "bg-zinc-500"} transition-all`}
                        style={{ width: `${(count / totalDevices) * 100}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Status breakdown */}
          <div className="rounded-lg border bg-card p-4">
            <h2 className="text-sm font-medium mb-3">Статусы</h2>
            <div className="space-y-2">
              {[
                { label: "Активных",           count: active,   dot: "bg-emerald-500" },
                { label: "Зарегистрированных", count: enrolled, dot: "bg-blue-500"    },
                { label: "Ожидающих",          count: pending,  dot: "bg-amber-500"   },
                { label: "Заблокированных",    count: devices.filter((d) => d.status === "blocked").length, dot: "bg-red-500" },
              ].map(({ label, count, dot }) => (
                <div key={label} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`h-2 w-2 rounded-full ${dot}`} />
                    <span className="text-xs text-muted-foreground">{label}</span>
                  </div>
                  <span className="text-xs font-medium">{count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: Activity feed */}
        <div className="lg:col-span-3 rounded-lg border bg-card">
          <div className="flex items-center justify-between px-4 py-3 border-b">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-muted-foreground" />
              <h2 className="text-sm font-medium">Активность</h2>
            </div>
            <button
              type="button"
              onClick={() => navigate("/audit-log")}
              className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              Все события <ChevronRight className="h-3 w-3" />
            </button>
          </div>
          <div className="divide-y">
            {activity.length === 0 && (
              <p className="text-xs text-muted-foreground px-4 py-6 text-center">Нет событий</p>
            )}
            {activity.map((e, i) => {
              const cat = ACTION_CATEGORY[e.action] ?? "content"
              const { icon: CatIcon, fg, bg } = CATEGORY_STYLE[cat]
              return (
                <div
                  key={e.id}
                  className={`feed-item flex items-start gap-3 px-4 py-2.5 ${cat === "security" ? "bg-red-500/[0.04]" : ""}`}
                  style={{ "--i": i } as CSSProperties}
                >
                  <div className={`mt-0.5 h-6 w-6 rounded-full ${bg} flex items-center justify-center flex-shrink-0`}>
                    <CatIcon className={`h-3.5 w-3.5 ${fg}`} />
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs leading-snug">
                      <span className="font-medium">{e.user_email}</span>
                      {" "}
                      <span className={cat === "security" ? fg : "text-muted-foreground"}>
                        {ACTION_LABELS[e.action] ?? e.action}
                      </span>
                    </p>
                    <p className="text-[11px] text-muted-foreground mt-0.5">{formatDistanceToNow(e.created_at)}</p>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Recent devices */}
      <div className="rounded-lg border bg-card">
        <div className="flex items-center justify-between px-4 py-3 border-b">
          <h2 className="text-sm font-medium">Последние устройства</h2>
          <button
            type="button"
            onClick={() => navigate("/devices")}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            Все устройства <ChevronRight className="h-3 w-3" />
          </button>
        </div>
        <div className="divide-y">
          {devices.slice(0, 5).map((d) => {
            const statusColor: Record<Device["status"], string> = {
              active:   "bg-emerald-500",
              enrolled: "bg-blue-500",
              pending:  "bg-amber-500",
              blocked:  "bg-red-500",
            }
            return (
              <button
                type="button"
                key={d.id}
                onClick={() => navigate(`/devices/${d.id}`)}
                className="w-full flex items-center justify-between px-4 py-3 hover:bg-accent/50 transition-colors text-left"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span className={`h-2 w-2 rounded-full flex-shrink-0 ${statusColor[d.status]}`} />
                  <div className="min-w-0">
                    <p className="text-sm font-medium truncate">{d.hostname}</p>
                    <p className="text-xs text-muted-foreground">{d.os}</p>
                  </div>
                </div>
                <div className="flex items-center gap-4 flex-shrink-0 ml-4">
                  <span className="text-xs text-muted-foreground hidden sm:block">
                    {d.ip_address || "—"}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {d.last_seen_at ? formatDistanceToNow(d.last_seen_at) : "—"}
                  </span>
                  <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                </div>
              </button>
            )
          })}
        </div>
      </div>
    </div>
  )
}

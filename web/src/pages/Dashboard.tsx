import { useEffect, useRef, useState, type ElementType, type CSSProperties } from "react"
import { useTranslation } from "react-i18next"
import { useNavigate } from "react-router-dom"
import { Monitor, FileCode2, Shield, Bell, ChevronRight, ShieldAlert, KeyRound, UserCog } from "lucide-react"
import api, { Device, Script, PolicyRule, Alert, DEVICE_STATUS } from "@/lib/api"
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

// Счётчик читается «Активных: 12», а бейдж на карточке — «Активен». Одна карта на оба
// падежа звучала бы криво в одном из мест, поэтому здесь только форма для счётчиков;
// цвет и порядок по-прежнему берутся из общей DEVICE_STATUS.
// Значения — КЛЮЧИ словаря: t() на уровне модуля недоступен, перевод берётся в
// компоненте (тот же приём, что в Login и Profile).
const STATUS_PLURAL: Record<string, string> = {
  active:           "dashboard.statusActive",
  enrolled:         "dashboard.statusEnrolled",
  pending:          "dashboard.statusPending",
  pending_approval: "dashboard.statusPendingApproval",
  rejected:         "dashboard.statusRejected",
  blocked:          "dashboard.statusBlocked",
  decommissioned:   "dashboard.statusDecommissioned",
}


// Таксономия событий ленты: security должно цепляться взглядом сразу,
// остальные категории различаются иконкой и сдержанным цветовым акцентом.


import { actionCategory, actionLabel, hiddenFromFeed, type EventCategory } from "@/lib/auditActions"

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

function StatValue({ value, className }: { value: number; className?: string }) {
  // 30px/300 из хендоффа: крупная тонкая цифра — главный якорь плитки.
  return <p className={`text-[30px] font-light leading-[1.1] tabular-nums mt-0.5 ${className ?? "text-foreground"}`}>{useCountUp(value)}</p>
}

function osFamily(os: string): "macOS" | "Windows" | "Linux" {
  const l = os.toLowerCase()
  if (l.includes("mac") || l.includes("darwin")) return "macOS"
  if (l.includes("win")) return "Windows"
  // всё остальное (linux/ubuntu/debian/centos/прочие дистрибутивы) — Linux-парк
  return "Linux"
}


export default function Dashboard() {
  const { t } = useTranslation()
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
      // Фильтруем ЗДЕСЬ, а не при отрисовке: иначе «Нет событий» не показывалось бы
      // на странице, где все пришедшие записи скрыты, — лента выглядела бы сломанной.
      setActivity((a.data ?? []).filter((e) => !hiddenFromFeed(e.action)))
      setAlerts(al.data ?? [])
    }).catch(() => {
      setLoadFailed(true)
      toast({ title: t("dashboard.loadFailed"), variant: "destructive" })
    }).finally(() => setLoading(false))
  }, [])

  const now = Date.now()
  // Считаем ПО ФАКТУ, а не перечислением статусов руками: раньше карточка знала четыре
  // строки, сумма молча расходилась с «Всего устройств», а строка «Ожидающих» вообще
  // была мёртвой — считала литеральный 'pending', который сервер не отдаёт
  // (ListEnrolledDevices режет его в SQL). Порядок строк — как в DEVICE_STATUS.
  const statusCounts = devices.reduce<Record<string, number>>((acc, d) => {
    acc[d.status] = (acc[d.status] ?? 0) + 1
    return acc
  }, {})
  const statusOrder = Object.keys(DEVICE_STATUS)
  const statusRows = Object.entries(statusCounts)
    .sort((a, b) => statusOrder.indexOf(a[0]) - statusOrder.indexOf(b[0]))
    .map(([status, count]) => ({
      label: STATUS_PLURAL[status] ? t(STATUS_PLURAL[status]) : DEVICE_STATUS[status as keyof typeof DEVICE_STATUS]?.label ?? status,
      dot: DEVICE_STATUS[status as keyof typeof DEVICE_STATUS]?.dot ?? "bg-muted-foreground/40",
      count,
    }))
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
    return <div className="flex items-center justify-center h-48 text-muted-foreground text-sm">{t("common.loading")}</div>
  }

  return (
    <div className="flex flex-col gap-5">
      <h1 className="text-xl font-semibold text-foreground">{t("dashboard.title")}</h1>

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {/* Цветом метим только то, что требует внимания: непрочитанные алерты
            (красно-оранжевая колонка и цифра). Нулевые счётчики превращаем в CTA —
            три нуля подряд читаются как «заброшенный продукт». */}
        {[
          { label: t("dashboard.totalDevices"), value: devices.length, icon: Monitor,   sub: t("dashboard.online", { count: online }), cta: t("dashboard.connectDevice"), onClick: () => navigate("/devices")  },
          { label: t("dashboard.scripts"),        value: scripts.length,  icon: FileCode2, sub: t("dashboard.inLibrary"),     cta: t("dashboard.addScript"),       onClick: () => navigate("/scripts")  },
          { label: t("dashboard.policies"),         value: policies.length, icon: Shield,    sub: t("dashboard.softwareRules"),        cta: t("dashboard.addPolicy"),     onClick: () => navigate("/policies") },
          { label: t("dashboard.alerts"),         value: unackedAlerts,   icon: Bell,      sub: t("dashboard.unacknowledged"), cta: "",                      onClick: () => navigate("/alerts"), alert: true },
        ].map(({ label, value, icon: Icon, sub, cta, onClick, alert }) => (
          <SpotlightCard
            as="button"
            type="button"
            key={label}
            onClick={onClick}
            className="glass glass-hover flex min-h-[104px] overflow-hidden text-left"
          >
            {/* Градиентная колонка 64px с иконкой — единственный цветной элемент
                плитки; у алертов она красно-оранжевая. */}
            <div className={`w-16 flex-shrink-0 flex items-center justify-center text-white ${alert && value > 0 ? "alert-gradient" : "brand-gradient"}`}>
              <Icon className="h-[26px] w-[26px]" strokeWidth={2} />
            </div>
            <div className="flex-1 min-w-0 flex flex-col px-4 py-3.5">
              <span className="text-[13px] text-muted-foreground truncate">{label}</span>
              <StatValue value={value} className={alert && value > 0 ? "text-[hsl(0_62%_45%)] dark:text-[hsl(0_72%_66%)]" : "text-foreground"} />
              {value === 0 && cta && !loadFailed ? (
                // В светлой теме --brand (52%) даёт ~4:1 на белом — ниже AA для
                // text-xs, поэтому CTA затемнён той же тональностью (~6.8:1).
                <p className="text-xs font-medium text-[hsl(220_65%_42%)] dark:text-brand mt-auto">{cta} →</p>
              ) : sub ? (
                <p className="text-xs text-muted-foreground mt-auto truncate">{sub}</p>
              ) : null}
            </div>
          </SpotlightCard>
        ))}
      </div>

      {/* Two-column section: 2fr / 3fr. Именно так, а не grid-cols-5 + col-span:
          при пяти равных колонках gap считается иначе и пропорция уезжает. */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-[2fr_3fr]">

        {/* Left: Devices by OS + status breakdown */}
        <div className="flex flex-col gap-5">
          <div className="glass px-5 py-[18px]">
            <h2 className="text-[15px] font-semibold text-foreground">{t("dashboard.byOS")}</h2>
            <p className="text-xs text-muted-foreground mb-4">{t("dashboard.totalOf", { count: devices.length })}</p>
            {osEntries.length === 0 ? (
              <p className="text-xs text-muted-foreground">{t("common.none")}</p>
            ) : (
              <div className="flex flex-col gap-3.5">
                {osEntries.map(([os, count]) => (
                  <div key={os}>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-[13px] text-soft">{os}</span>
                      <span className="text-[13px] text-foreground tabular-nums">
                        {count}
                        <span className="text-muted-foreground"> · {Math.round((count / totalDevices) * 100)}%</span>
                      </span>
                    </div>
                    {/* Полосы одного фирменного градиента: доля читается длиной,
                        разноцветные ОС добавляли смысл, которого нет. */}
                    <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                      <div
                        className="h-full rounded-full brand-gradient-h transition-all"
                        style={{ width: `${(count / totalDevices) * 100}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Status breakdown */}
          <div className="glass px-5 py-[18px]">
            <h2 className="text-[15px] font-semibold text-foreground">{t("dashboard.statuses")}</h2>
            <p className="text-xs text-muted-foreground mb-3.5">{t("dashboard.fleetSpread")}</p>
            <div className="flex flex-col gap-2.5">
              {statusRows.length === 0 && (
                <p className="text-xs text-muted-foreground">{t("dashboard.noDevices")}</p>
              )}
              {statusRows.map(({ label, count, dot }) => (
                <div key={label} className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <span className={`h-2 w-2 rounded-full ${dot}`} />
                    <span className="text-[13px] text-soft">{label}</span>
                  </div>
                  <span className="text-[13px] font-semibold text-foreground tabular-nums">{count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: Activity feed */}
        <div className="glass flex flex-col">
          <div className="flex items-center justify-between px-5 pt-4 pb-3">
            <div>
              <h2 className="text-[15px] font-semibold text-foreground">{t("dashboard.activity")}</h2>
              <p className="text-xs text-muted-foreground">{t("dashboard.recentEvents")}</p>
            </div>
            <button
              type="button"
              onClick={() => navigate("/audit-log")}
              className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              {t("dashboard.allEvents")} <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
          <div>
            {activity.length === 0 && (
              <p className="text-xs text-muted-foreground px-5 py-6 text-center">{t("dashboard.noEvents")}</p>
            )}
            {activity.map((e, i) => {
              const cat = actionCategory(e.action)
              const { icon: CatIcon, fg, bg } = CATEGORY_STYLE[cat]
              return (
                <div
                  key={e.id}
                  // last:rounded-b-2xl обязателен: у security-строки есть красная
                  // подложка, и без скругления она заливала бы нижние углы карты.
                  className={`feed-item flex items-start gap-3 px-5 py-2.5 border-t border-border last:rounded-b-2xl ${cat === "security" ? "bg-red-500/[0.06]" : ""}`}
                  style={{ "--i": i } as CSSProperties}
                >
                  <div className={`mt-px h-[26px] w-[26px] rounded-full ${bg} flex items-center justify-center flex-shrink-0`}>
                    <CatIcon className={`h-3.5 w-3.5 ${fg}`} />
                  </div>
                  <div className="min-w-0">
                    <p className="text-[13px] leading-snug text-soft">
                      <span className="font-medium text-foreground">{e.user_email}</span>
                      {" "}
                      <span className={cat === "security" ? fg : "text-muted-foreground"}>
                        {actionLabel(e.action)}
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
      <div className="glass">
        <div className="flex items-center justify-between px-5 pt-4 pb-3">
          <div>
            <h2 className="text-[15px] font-semibold text-foreground">{t("dashboard.recentDevices")}</h2>
            <p className="text-xs text-muted-foreground">{t("dashboard.recentlySeen")}</p>
          </div>
          <button
            type="button"
            onClick={() => navigate("/devices")}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            {t("dashboard.allDevices")} <ChevronRight className="h-3.5 w-3.5" />
          </button>
        </div>
        <div>
          {devices.length === 0 && (
            <p className="text-xs text-muted-foreground px-5 py-6 text-center">{t("dashboard.noDevices")}</p>
          )}
          {devices.slice(0, 5).map((d) => {
            // Фолбэк не декоративный: без него неизвестный статус давал className
            // "... undefined" — точка молча становилась невидимой.
            const dot = DEVICE_STATUS[d.status]?.dot ?? "bg-muted-foreground/40"
            return (
              <button
                type="button"
                key={d.id}
                onClick={() => navigate(`/devices/${d.id}`)}
                className="w-full flex items-center justify-between px-5 py-3 border-t border-border glass-hover text-left last:rounded-b-2xl"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span className={`h-2 w-2 rounded-full flex-shrink-0 ${dot}`} />
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">{d.hostname}</p>
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

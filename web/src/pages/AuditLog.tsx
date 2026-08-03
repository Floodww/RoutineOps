import { useEffect, useState, type ElementType, type CSSProperties } from "react"
import { useTranslation } from "react-i18next"
import { Monitor, FileCode2, ShieldAlert, KeyRound, UserCog } from "lucide-react"
import api, { PAGE_SIZE, totalCount } from "@/lib/api"
import Pager, { pageLabel } from "@/components/Pager"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

interface AuditEntry {
  id: string
  seq: number | null
  user_email: string
  action: string
  target_type: string
  target_id: string
  details: Record<string, unknown> | null
  created_at: string
}


// Таксономия событий ленты — та же, что на Обзоре: security должно цепляться
// взглядом сразу, остальные категории различаются иконкой и сдержанным акцентом.


import { actionCategory, actionLabelCap, eventNumber, type EventCategory } from "@/lib/auditActions"
import { formatDateTime } from "@/lib/time"

const CATEGORY_STYLE: Record<EventCategory, { icon: ElementType; fg: string; bg: string }> = {
  // red-700 в светлой теме: red-500 на белом даёт 3.57:1 — ниже AA для text-xs.
  security: { icon: ShieldAlert, fg: "text-red-700 dark:text-red-400",         bg: "bg-red-500/10" },
  auth:     { icon: KeyRound,    fg: "text-sky-600 dark:text-sky-400",         bg: "bg-sky-500/10" },
  admin:    { icon: UserCog,     fg: "text-violet-600 dark:text-violet-400",   bg: "bg-violet-500/10" },
  device:   { icon: Monitor,     fg: "text-emerald-600 dark:text-emerald-400", bg: "bg-emerald-500/10" },
  content:  { icon: FileCode2,   fg: "text-muted-foreground",                  bg: "bg-muted" },
}

// dayBound переводит дату из <input type="date"> в момент времени для сервера.
// Границу суток считаем в поясе браузера — у оператора «23 июля» это его 23 июля,
// а не UTC-сутки, которые в Москве начинаются в три часа ночи.
function dayBound(date: string, end: boolean): string {
  if (!date) return ""
  const d = new Date(`${date}T${end ? "23:59:59.999" : "00:00:00"}`)
  return isNaN(d.getTime()) ? "" : d.toISOString()
}

export default function AuditLog() {
  const { t } = useTranslation()
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<AuditEntry | null>(null)
  const [from, setFrom] = useState("")
  const [to, setTo] = useState("")
  const [who, setWho] = useState("")

  // Фильтры считает сервер. Раньше страница тянула последние 200 записей и фильтровала
  // их в браузере: за пределами этих 200 журнал для оператора не существовал, а разницу
  // между «за период ничего не было» и «период старше двухсот последних событий»
  // интерфейс не показывал никак.
  useEffect(() => {
    const params = new URLSearchParams()
    const fromISO = dayBound(from, false)
    const toISO = dayBound(to, true)
    if (fromISO) params.set("from", fromISO)
    if (toISO) params.set("to", toISO)
    if (who.trim()) params.set("who", who.trim())
    params.set("limit", String(PAGE_SIZE))
    if (offset) params.set("offset", String(offset))
    const timer = setTimeout(() => {
      api.get<AuditEntry[]>(`/audit-log?${params.toString()}`)
        .then((r) => {
          const rows = r.data ?? []
          // Записи подчистились ретенцией, пока листали — уходим на первую страницу.
          if (rows.length === 0 && offset > 0) {
            setOffset(0)
            return
          }
          setEntries(rows)
          setTotal(totalCount(r.headers, rows.length))
        })
        .finally(() => setLoading(false))
    }, who.trim() ? 250 : 0)
    return () => clearTimeout(timer)
  }, [from, to, who, offset])

  const filtering = !!(from || to || who.trim())

  return (
    <div className="flex flex-col gap-5">
      <h1 className="text-xl font-semibold text-foreground">{t("audit.title")}</h1>
      {loading ? (
        <p className="text-sm text-muted-foreground">{t("common.loading")}</p>
      ) : entries.length === 0 && !filtering ? (
        <p className="text-sm text-muted-foreground">{t("audit.empty")}</p>
      ) : (
        <>
        <div className="glass px-5 py-[18px] flex flex-wrap items-end gap-3">
          <div className="space-y-1">
            <Label className="text-xs text-muted-foreground">{t("audit.from")}</Label>
            <input
              type="date"
              value={from}
              onChange={(e) => { setFrom(e.target.value); setOffset(0) }}
              className="flex h-9 rounded-md border border-input bg-transparent px-3 py-1 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-xs text-muted-foreground">{t("audit.when")}</Label>
            <input
              type="date"
              value={to}
              onChange={(e) => { setTo(e.target.value); setOffset(0) }}
              className="flex h-9 rounded-md border border-input bg-transparent px-3 py-1 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            />
          </div>
          {/* Было выпадающим списком, собранным из загруженных записей — то есть из
              последних 200 событий. Постранично такой список показывал бы только тех,
              кто попал на текущую страницу; подстрока честнее и ищет по всему журналу. */}
          <div className="space-y-1 min-w-48">
            <Label className="text-xs text-muted-foreground">{t("audit.who")}</Label>
            <Input
              value={who}
              placeholder={t("audit.filterPlaceholder")}
              onChange={(e) => { setWho(e.target.value); setOffset(0) }}
            />
          </div>
          {filtering && (
            <button
              type="button"
              onClick={() => { setFrom(""); setTo(""); setWho(""); setOffset(0) }}
              className="h-9 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              {t("audit.reset")}
            </button>
          )}
        </div>

        <div className="glass">
          <div className="px-5 pt-4 pb-3">
            <h2 className="text-[15px] font-semibold text-foreground">{t("audit.events")}</h2>
            <p className="text-xs text-muted-foreground">{pageLabel(offset, PAGE_SIZE, total)}</p>
          </div>
          {entries.length === 0 && (
            <p className="text-xs text-muted-foreground px-5 py-8 text-center border-t border-border">
              {t("audit.nothingFound")}
            </p>
          )}
          {entries.map((e, i) => {
            const summary = e.details
              ? Object.entries(e.details).map(([k, v]) => `${k}: ${v}`).join(", ")
              : null
            const cat = actionCategory(e.action)
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
                      {actionLabelCap(e.action)}
                    </span>
                  </p>
                  {summary && (
                    <p className="text-xs text-muted-foreground truncate group-hover:text-soft transition-colors mt-0.5">
                      {summary}
                    </p>
                  )}
                  <p className="text-[11px] text-muted-foreground mt-0.5">
                    {formatDateTime(e.created_at)}
                    {" · "}
                    {/* Номер события есть у КАЖДОЙ записи. Раньше здесь стоял
                        target_id — идентификатор ОБЪЕКТА, которого у логина,
                        выхода и надзорного просмотра нет вовсе, и строка
                        обрывалась на середине. */}
                    <span className="font-mono">{eventNumber(e.seq)}</span>
                  </p>
                </div>
              </div>
            )
          })}
          <Pager offset={offset} limit={PAGE_SIZE} total={total} onChange={setOffset} />
        </div>
        </>
      )}

      <Dialog open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{selected ? actionLabelCap(selected.action) : ""}</DialogTitle>
          </DialogHeader>
          {selected && (
            <div className="space-y-3 pt-1">
              <div className="flex gap-4 text-sm text-muted-foreground">
                <span>{formatDateTime(selected.created_at)}</span>
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
              <p className="text-xs text-muted-foreground font-mono">{t("audit.event", { n: eventNumber(selected.seq) })}</p>
              {selected.target_id && (
                <p className="text-xs text-muted-foreground font-mono">{t("audit.object", { id: selected.target_id })}</p>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}

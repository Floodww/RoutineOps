import { useEffect, useState } from "react"
import { useNavigate } from "react-router-dom"
import { Trash2, ChevronLeft } from "lucide-react"
import api, { PolicyRule, SoftwarePolicyCompliance } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import ConfirmDialog from "@/components/ConfirmDialog"
import { toast } from "@/lib/toast"
import { formatDistanceToNow } from "@/lib/time"

const PLATFORMS = ["macOS", "Windows", "Linux"] as const

// PassFail — счётчики соответствия правилу. Пока агрегация не приехала, показываем «…»,
// а не нули: ноль нарушителей и «ещё не посчитали» — разные вещи.
function PassFail({ c }: { c?: SoftwarePolicyCompliance }) {
  if (!c) return <span className="text-muted-foreground text-xs">…</span>
  if (!c.checked) {
    return (
      <span className="text-muted-foreground text-xs" title="Правило-разрешение: агент его не проверяет">
        —
      </span>
    )
  }
  return (
    <span className="flex items-center gap-2 text-sm tabular-nums">
      <span className="text-emerald-600 dark:text-emerald-400" title="Устройств соответствует правилу">
        {c.pass}
      </span>
      <span className="text-muted-foreground/40">/</span>
      <span className={c.fail > 0 ? "text-red-600 dark:text-red-400 font-semibold" : "text-muted-foreground"} title="Устройств нарушает правило">
        {c.fail}
      </span>
    </span>
  )
}

export default function Policies() {
  const navigate = useNavigate()
  const [rules, setRules] = useState<PolicyRule[]>([])
  const [compliance, setCompliance] = useState<Record<string, SoftwarePolicyCompliance>>({})
  const [query, setQuery] = useState("")
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState({ software_name: "", rule_type: "allowed" as "allowed" | "forbidden", device_id: "" })
  const [platforms, setPlatforms] = useState({ macOS: true, Windows: true, Linux: true })
  const [submitting, setSubmitting] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState<PolicyRule | null>(null)

  async function load() {
    try {
      const r = await api.get<PolicyRule[]>("/policies")
      setRules(r.data ?? [])
    } catch {
      toast({ title: "Не удалось загрузить политики", variant: "destructive" })
    } finally {
      setLoading(false)
    }
    // Счётчики отдельным запросом: агрегация ходит по всему парку и инвентарю, список
    // правил не должен её ждать. Ошибка не критична — колонки останутся с «…».
    try {
      const c = await api.get<SoftwarePolicyCompliance[]>("/policies/compliance")
      setCompliance(Object.fromEntries((c.data ?? []).map((x) => [x.rule_id, x])))
    } catch {
      // молча: соответствие — справочная информация, не блокирует страницу
    }
  }

  useEffect(() => { load() }, [])

  async function addRule() {
    setSubmitting(true)
    try {
      const body: Record<string, unknown> = { software_name: form.software_name, rule_type: form.rule_type }
      if (form.device_id) body.device_id = form.device_id
      body.platforms = (Object.keys(platforms) as (keyof typeof platforms)[]).filter((p) => platforms[p])
      await api.post("/policies", body)
      setForm({ software_name: "", rule_type: "allowed", device_id: "" })
      setPlatforms({ macOS: true, Windows: true, Linux: true })
      setCreating(false)
      await load()
    } finally {
      setSubmitting(false)
    }
  }

  async function deleteRule(id: string) {
    try {
      await api.delete(`/policies/${id}`)
      setRules((prev) => prev.filter((r) => r.id !== id))
      setConfirmDelete(null)
      toast({ title: "Политика удалена", variant: "success" })
    } catch {
      toast({ title: "Не удалось удалить политику", variant: "destructive" })
    }
  }

  function togglePlatform(p: typeof PLATFORMS[number]) {
    setPlatforms((prev) => ({ ...prev, [p]: !prev[p] }))
  }

  if (creating) {
    return (
      <div className="flex flex-col gap-5 max-w-2xl">
        <button
          type="button"
          onClick={() => setCreating(false)}
          className="flex items-center gap-1.5 self-start text-sm text-muted-foreground hover:text-foreground transition-colors"
        >
          <ChevronLeft className="h-4 w-4" strokeWidth={2} />
          Назад к политикам
        </button>

        <h1 className="text-xl font-semibold text-foreground">Новая политика</h1>

        <div className="glass flex flex-col gap-6 px-5 py-[18px]">
          {/* Condition editor – Fleet-style */}
          <div>
            <Label className="text-sm font-medium text-soft mb-2 block">Условие</Label>
            <div className="rounded-md border border-input bg-transparent overflow-hidden font-mono text-sm focus-within:ring-1 focus-within:ring-ring">
              <div className="flex items-start gap-3 px-4 py-3">
                <span className="text-xs text-muted-foreground select-none mt-px">1</span>
                <input
                  id="policy-condition"
                  aria-label="Имя программы"
                  className="flex-1 bg-transparent outline-none text-foreground placeholder:text-muted-foreground"
                  placeholder="chrome"
                  value={form.software_name}
                  onChange={(e) => setForm({ ...form, software_name: e.target.value })}
                />
              </div>
            </div>
            {/* Раньше placeholder показывал синтаксис `software_name = "chrome"` — его
                вводили буквально, правило молча не матчилось ни с чем. */}
            <p className="text-xs text-muted-foreground mt-1.5">
              Подстрока имени программы без учёта регистра: «chrome» поймает и Google Chrome, и Chromium.
            </p>
          </div>

          {/* Rule type toggle */}
          <div>
            <Label className="text-sm font-medium text-soft mb-2 block">Тип правила</Label>
            <div className="flex gap-2">
              {(["allowed", "forbidden"] as const).map((t) => (
                <button
                  type="button"
                  key={t}
                  onClick={() => setForm({ ...form, rule_type: t })}
                  className={
                    "px-3 py-1.5 rounded-md text-sm border transition-colors " +
                    (form.rule_type === t
                      ? t === "allowed"
                        ? "bg-emerald-600/20 border-emerald-600/50 text-emerald-600 dark:text-emerald-400"
                        : "bg-red-600/20 border-red-600/50 text-red-500 dark:text-red-400"
                      : "border-border text-muted-foreground hover:text-foreground")
                  }
                >
                  {t === "allowed" ? "Разрешено" : "Запрещено"}
                </button>
              ))}
            </div>
          </div>

          {/* Compatible with */}
          <div>
            <Label className="text-sm font-medium text-soft mb-2.5 block">Совместимо с</Label>
            <div className="flex items-center gap-5">
              {PLATFORMS.map((p) => {
                const on = platforms[p]
                return (
                  <button
                    type="button"
                    key={p}
                    onClick={() => togglePlatform(p)}
                    className="flex items-center gap-1.5 text-sm transition-colors"
                  >
                    <span className={on ? "text-emerald-600 dark:text-emerald-400" : "text-muted-foreground"}>
                      {on ? "✓" : "—"}
                    </span>
                    <span className={on ? "text-foreground" : "text-muted-foreground"}>{p}</span>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Optional device scope */}
          <div>
            <Label className="text-sm font-medium text-soft mb-2 block">Устройство <span className="text-muted-foreground font-normal">(необязательно)</span></Label>
            <Input
              placeholder="UUID устройства — пусто = глобальное"
              value={form.device_id}
              onChange={(e) => setForm({ ...form, device_id: e.target.value })}
              className="max-w-sm"
            />
          </div>

          {/* Actions */}
          <div className="flex items-center gap-4 pt-1">
            <Button
              onClick={addRule}
              disabled={submitting || !form.software_name || !Object.values(platforms).some(Boolean)}
            >
              {submitting ? "Сохранение..." : "Сохранить"}
            </Button>
            <button
              type="button"
              onClick={() => setCreating(false)}
              className="text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              Отмена
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-foreground">Политики</h1>
        <Button size="sm" onClick={() => setCreating(true)}>
          + Новая политика
        </Button>
      </div>

      <div className="glass flex flex-wrap items-center gap-3 px-5 py-4">
        <Input
          placeholder="Поиск по программе..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="max-w-sm"
        />
      </div>

      {loading ? (
        <p className="text-muted-foreground text-sm">Загрузка...</p>
      ) : (
        <div className="glass overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="border-t-0 hover:bg-transparent">
                <TableHead className="text-xs">Программа</TableHead>
                <TableHead className="text-xs">Тип</TableHead>
                <TableHead className="text-xs" title="Устройств соответствует / нарушает">Pass / Fail</TableHead>
                <TableHead className="text-xs" title="Устройств в области действия правила">Охват</TableHead>
                <TableHead className="text-xs">Устройство</TableHead>
                <TableHead className="text-xs">Обновлено</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {(() => {
                const q = query.trim().toLowerCase()
                const filtered = q ? rules.filter((r) => r.software_name.toLowerCase().includes(q)) : rules
                if (filtered.length === 0) {
                  return (
                    <TableRow className="hover:bg-transparent">
                      <TableCell colSpan={7} className="py-8 text-center text-sm text-muted-foreground">
                        {rules.length === 0 ? "Нет политик" : "Ничего не найдено"}
                      </TableCell>
                    </TableRow>
                  )
                }
                return filtered.map((r) => (
                <TableRow
                  key={r.id}
                  onClick={() => navigate(`/policies/${r.id}`)}
                  className="cursor-pointer glass-hover"
                >
                  <TableCell className="px-4 py-3 font-medium font-mono text-sm text-foreground">
                    {r.software_name}
                    {r.platforms && r.platforms.length > 0 && r.platforms.length < 3 && (
                      <div className="text-[10px] text-muted-foreground font-sans mt-0.5">{r.platforms.join(", ")}</div>
                    )}
                  </TableCell>
                  <TableCell className="px-4 py-3">
                    <Badge variant={r.rule_type === "allowed" ? "success" : "destructive"}>
                      {r.rule_type === "allowed" ? "Разрешено" : "Запрещено"}
                    </Badge>
                  </TableCell>
                  <TableCell className="px-4 py-3">
                    <PassFail c={compliance[r.id]} />
                  </TableCell>
                  <TableCell className="px-4 py-3 text-muted-foreground text-xs tabular-nums">
                    {compliance[r.id] ? compliance[r.id].in_scope : "…"}
                  </TableCell>
                  <TableCell className="px-4 py-3 text-muted-foreground text-xs font-mono">
                    {/* group_id раньше игнорировался — групповое правило выглядело как глобальное */}
                    {r.device_id ? r.device_id.slice(0, 8) : r.group_id ? "Группа" : "Глобальное"}
                  </TableCell>
                  <TableCell className="px-4 py-3 text-xs text-muted-foreground">
                    {formatDistanceToNow(r.updated_at)}
                  </TableCell>
                  <TableCell className="px-4 py-3">
                    <button
                      type="button"
                      onClick={(e) => { e.stopPropagation(); setConfirmDelete(r) }}
                      className="text-muted-foreground hover:text-destructive transition-colors"
                    >
                      <Trash2 className="h-4 w-4" strokeWidth={2} />
                    </button>
                  </TableCell>
                </TableRow>
                ))
              })()}
            </TableBody>
          </Table>
        </div>
      )}

      <ConfirmDialog
        open={!!confirmDelete}
        onOpenChange={(o) => !o && setConfirmDelete(null)}
        title="Удалить политику?"
        description={confirmDelete ? `Правило для «${confirmDelete.software_name}» будет удалено.` : ""}
        confirmLabel="Удалить"
        destructive
        onConfirm={() => { if (confirmDelete) deleteRule(confirmDelete.id) }}
      />
    </div>
  )
}

import { useEffect, useState } from "react"
import { useNavigate, useParams } from "react-router-dom"
import { ChevronLeft, ChevronRight } from "lucide-react"
import api, { PolicyRule, PolicyDeviceCompliance, DeviceGroup } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import { toast } from "@/lib/toast"
import { formatDistanceToNow } from "@/lib/time"

// Разрез софт-правила по устройствам: кто в области действия, кто pass, кто fail
// и что именно совпало в инвентаре. Для allowed-правил вердикта нет (агент их не
// проверяет) — колонка показывает справку «установлено/нет».
export default function PolicyDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [rule, setRule] = useState<PolicyRule | null>(null)
  const [rows, setRows] = useState<PolicyDeviceCompliance[]>([])
  const [groups, setGroups] = useState<DeviceGroup[]>([])
  const [loading, setLoading] = useState(true)
  // Ошибка загрузки ≠ «политика не найдена»: не приписываем удаление при упавшем API.
  const [loadFailed, setLoadFailed] = useState(false)

  useEffect(() => {
    if (!id) return
    // Флаг отмены: при back/forward ответ старого id не должен перезаписать новый.
    let stale = false
    Promise.all([
      // Отдельного GET /policies/{id} нет — правило достаём из общего списка.
      api.get<PolicyRule[]>("/policies"),
      api.get<PolicyDeviceCompliance[]>(`/policies/${id}/compliance`),
    ]).then(([r, c]) => {
      if (stale) return
      setRule((r.data ?? []).find((x) => x.id === id) ?? null)
      setRows(c.data ?? [])
    }).catch(() => {
      if (stale) return
      setLoadFailed(true)
      toast({ title: "Не удалось загрузить политику", variant: "destructive" })
    }).finally(() => { if (!stale) setLoading(false) })
    // Группы нужны только для имени в подзаголовке — best-effort, не валит страницу.
    api.get<DeviceGroup[]>("/device-groups")
      .then((g) => { if (!stale) setGroups(g.data ?? []) })
      .catch(() => {})
    return () => { stale = true }
  }, [id])

  if (loading) {
    return <div className="flex items-center justify-center h-48 text-muted-foreground text-sm">Загрузка...</div>
  }

  const back = (
    <button
      type="button"
      onClick={() => navigate("/policies")}
      className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground mb-6 transition-colors"
    >
      <ChevronLeft className="h-4 w-4" />
      Назад к политикам
    </button>
  )

  if (!rule) {
    return (
      <div>
        {back}
        <p className="text-sm text-muted-foreground">
          {loadFailed ? "Не удалось загрузить политику — попробуй обновить страницу." : "Политика не найдена — возможно, она была удалена."}
        </p>
      </div>
    )
  }

  const forbidden = rule.rule_type === "forbidden"
  const fail = rows.filter((r) => r.installed).length
  const pass = rows.length - fail

  const scope = rule.device_id
    ? `Устройство ${rule.device_id.slice(0, 8)}`
    : rule.group_id
      ? `Группа «${groups.find((g) => g.id === rule.group_id)?.name ?? rule.group_id.slice(0, 8)}»`
      : "Глобальное — весь парк"

  return (
    <div>
      {back}

      <div className="flex items-center gap-3 mb-1 flex-wrap">
        <h1 className="text-2xl font-semibold font-mono">{rule.software_name}</h1>
        <Badge variant={forbidden ? "destructive" : "success"}>
          {forbidden ? "Запрещено" : "Разрешено"}
        </Badge>
      </div>
      <p className="text-sm text-muted-foreground mb-6">
        {scope}
        {rule.platforms && rule.platforms.length > 0 && rule.platforms.length < 3 && (
          <> · {rule.platforms.join(", ")}</>
        )}
        {" · обновлено "}{formatDistanceToNow(rule.updated_at)}
      </p>

      {/* Сводка. Для allowed-правил pass/fail не считаются — агент проверяет только forbidden. */}
      {forbidden ? (
        <div className="flex items-center gap-6 mb-4 text-sm">
          <span className="text-muted-foreground">В охвате: <span className="text-foreground font-medium tabular-nums">{rows.length}</span></span>
          <span className="text-emerald-600 dark:text-emerald-400">Pass: <span className="font-medium tabular-nums">{pass}</span></span>
          <span className={fail > 0 ? "text-red-600 dark:text-red-400 font-medium" : "text-muted-foreground"}>
            Fail: <span className="tabular-nums">{fail}</span>
          </span>
        </div>
      ) : (
        <p className="text-xs text-muted-foreground mb-4">
          Правило-разрешение: агент его не проверяет. Ниже — справка, где это ПО установлено.
        </p>
      )}

      {rows.length === 0 ? (
        <div className="rounded-lg border bg-card p-6 text-center text-sm text-muted-foreground">
          Правило не действует ни на одно устройство.
          {rule.group_id && " Проверь, что в группе есть устройства."}
          {rule.platforms && rule.platforms.length > 0 && rule.platforms.length < 3 && " Возможно, в парке нет устройств выбранных платформ."}
        </div>
      ) : (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Устройство</TableHead>
                <TableHead>ОС</TableHead>
                <TableHead>Найдено в инвентаре</TableHead>
                <TableHead>{forbidden ? "Вердикт" : "Установлено"}</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r) => (
                <TableRow
                  key={r.device_id}
                  onClick={() => navigate(`/devices/${r.device_id}`)}
                  className="cursor-pointer"
                >
                  <TableCell className="font-medium text-sm">{r.hostname}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{r.os || "—"}</TableCell>
                  <TableCell className="text-xs font-mono">
                    {r.installed
                      ? <>{r.matched_software}{r.matched_version && <span className="text-muted-foreground"> {r.matched_version}</span>}</>
                      : <span className="text-muted-foreground font-sans">—</span>}
                  </TableCell>
                  <TableCell>
                    {forbidden ? (
                      <Badge variant={r.installed ? "destructive" : "success"}>
                        {r.installed ? "Fail" : "Pass"}
                      </Badge>
                    ) : (
                      <span className="text-xs text-muted-foreground">{r.installed ? "Да" : "Нет"}</span>
                    )}
                  </TableCell>
                  <TableCell className="w-8">
                    <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  )
}

import { useEffect, useState } from "react"
import { useNavigate } from "react-router-dom"
import { Copy, Check } from "lucide-react"
import api, { Device, DeviceGroup, DEVICE_STATUS, BulkEnrollmentTokenResponse } from "@/lib/api"
import { GroupBadges } from "@/components/GroupBadge"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Select } from "@/components/ui/select"
import ConfirmDialog from "@/components/ConfirmDialog"
import { formatDistanceToNow } from "@/lib/time"
import { toast } from "@/lib/toast"

type DialogStep = "form" | "token"

// Пустая строка не может быть значением Select (он показывает placeholder на любом
// falsy) — тот же приём, что в Devices.tsx: сентинел, который перед POST схлопывается в "".
const NO_GROUP = "none"

const DEFAULT_TTL_HOURS = 168 // совпадает с bulkTokenDefaultTTLHours на сервере

function apiBase() {
  return window.location.origin
}

// Команда установки для массового токена. Отличие от Devices.tsx: устройство ещё не
// существует — оно создастся само при первом энроллменте, поэтому Device ID тут нет.
function enrollCommand(os: string, token: string, caSHA256: string): string {
  const base = apiBase()
  const serverAddr = `${window.location.hostname}:50051`
  if (os === "windows") {
    return `msiexec /i RoutineOps-agent.msi /qn ENROLL_URL="${base}/api/v1/enroll" ` +
      `ENROLL_TOKEN="${token}" CA_URL="${base}/ca.crt" ` +
      `CA_SHA256="${caSHA256}" SERVER_ADDR="${serverAddr}"`
  }
  if (os === "darwin") {
    return `sudo installer -pkg RoutineOps-agent.pkg -target /\n` +
      `sudo /usr/local/bin/RoutineOps-agent enroll -install-service ` +
      `-enroll-url ${base}/api/v1/enroll -token ${token} ` +
      `-ca-url ${base}/ca.crt -ca-sha256 ${caSHA256} ` +
      `-server ${serverAddr} -server-name routineops-server`
  }
  return `sudo RoutineOps-agent enroll -install-service ` +
    `-enroll-url ${base}/api/v1/enroll -token ${token} ` +
    `-ca-url ${base}/ca.crt -ca-sha256 ${caSHA256} -server ${serverAddr}`
}

// Тело запроса на выпуск токена. Вынесено из компонента и экспортировано ради теста:
// 🔴 max_uses на сервере — указатель, ОТСУТСТВИЕ ключа означает «безлимит», а явный 0
// отбивается 400-й. Пустое поле формы поэтому обязано ключ УБРАТЬ, а не слать нулём.
// Ровно так же require_approval: nil на сервере = true, но мы всегда шлём явный bool,
// чтобы снятая галочка не превращалась молча во включённую очередь.
export function bulkTokenBody(opts: {
  groupID: string
  maxUses: string
  ttlHours: string
  requireApproval: boolean
}): Record<string, unknown> {
  const body: Record<string, unknown> = {
    group_id: opts.groupID === NO_GROUP ? "" : opts.groupID,
    require_approval: opts.requireApproval,
    ttl_hours: Math.trunc(Number(opts.ttlHours)) || DEFAULT_TTL_HOURS,
  }
  // Math.trunc, а не отказ на дробном: поле number принимает «2.5», а Go-шный *int
  // на дробном JSON-числе падает в 400 «invalid json» — сообщение, по которому админ
  // никогда не догадается, что дело в точке.
  const uses = Math.trunc(Number(opts.maxUses))
  if (opts.maxUses.trim() !== "" && Number.isFinite(uses) && uses > 0) body.max_uses = uses
  return body
}

export default function EnrollmentQueue() {
  const navigate = useNavigate()
  const [devices, setDevices] = useState<Device[]>([])
  const [groups, setGroups] = useState<DeviceGroup[]>([])
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)

  const [dialogOpen, setDialogOpen] = useState(false)
  const [step, setStep] = useState<DialogStep>("form")
  const [groupID, setGroupID] = useState(NO_GROUP)
  const [maxUses, setMaxUses] = useState("")
  const [ttlHours, setTTLHours] = useState(String(DEFAULT_TTL_HOURS))
  const [requireApproval, setRequireApproval] = useState(true)
  const [issuing, setIssuing] = useState(false)
  const [result, setResult] = useState<BulkEnrollmentTokenResponse | null>(null)
  const [cmdOS, setCmdOS] = useState("windows")
  const [copied, setCopied] = useState(false)

  const [confirmReject, setConfirmReject] = useState<Device | null>(null)
  const [confirmRejectAll, setConfirmRejectAll] = useState(false)
  const [confirmApproveAll, setConfirmApproveAll] = useState(false)
  const [loadFailed, setLoadFailed] = useState(false)

  // Отдельной ручки под очередь на сервере нет: GET /devices отдаёт весь парк
  // (фильтруется только литеральный 'pending'), поэтому режем на клиенте.
  async function load() {
    try {
      const r = await api.get<Device[]>("/devices")
      setDevices(r.data ?? [])
      setLoadFailed(false)
    } catch {
      // 🔴 Не глотаем: на экране безопасности пустая таблица читается как «всё чисто».
      // Отказ загрузки обязан выглядеть отказом, а не пустой очередью.
      setLoadFailed(true)
      toast({ title: "Не удалось загрузить устройства", variant: "destructive" })
    } finally {
      setLoading(false)
    }
  }

  // Машины приезжают асинхронно: раскатка партии растянута на десятки минут, а админ
  // держит вкладку открытой. Без поллинга очередь показывала бы «пусто» всё это время,
  // и об этом в UI не было бы ни слова. Интервал — как в Devices.tsx.
  useEffect(() => {
    load()
    const t = setInterval(load, 30_000)
    return () => clearInterval(t)
  }, [])

  // Группы — отдельным запросом: страница обязана работать и без них (список групп
  // нужен только для дропдауна в форме токена), поэтому не валим load() целиком.
  useEffect(() => {
    api.get<DeviceGroup[]>("/device-groups")
      .then((r) => setGroups(r.data ?? []))
      .catch(() => setGroups([]))
  }, [])

  const queue = devices.filter((d) => d.status === "pending_approval")
  const rejected = devices.filter((d) => d.status === "rejected")

  async function decide(device: Device, action: "approve" | "reject") {
    setSubmitting(true)
    try {
      await api.post(`/devices/${device.id}/${action}`)
      await load()
      toast({
        title: action === "approve" ? `${device.hostname} одобрено` : `${device.hostname} отклонено`,
        variant: action === "approve" ? "success" : "default",
      })
    } catch {
      // авто-тост интерсептора. Перечитываем: 409 «device not in approval queue» и
      // означает, что строка устарела (второй админ уже решил) — без рефетча она
      // висела бы в очереди вечно и давала бы тот же 409 на каждый клик.
      load()
    } finally {
      setSubmitting(false)
    }
  }

  async function decideAll(action: "approve" | "reject") {
    setSubmitting(true)
    try {
      const r = await api.post<{ approved?: number; rejected?: number }>(`/enrollment-queue/${action}`, {})
      const n = action === "approve" ? r.data.approved : r.data.rejected
      await load()
      toast({
        title: action === "approve" ? `Одобрено устройств: ${n ?? 0}` : `Отклонено устройств: ${n ?? 0}`,
        variant: action === "approve" ? "success" : "default",
      })
    } catch {
      // авто-тост интерсептора
    } finally {
      setSubmitting(false)
    }
  }

  function resetDialog() {
    setStep("form")
    setResult(null)
    setGroupID(NO_GROUP)
    setMaxUses("")
    setTTLHours(String(DEFAULT_TTL_HOURS))
    setRequireApproval(true)
    setCmdOS("windows")
    setCopied(false)
  }

  async function issueToken() {
    setIssuing(true)
    try {
      const body = bulkTokenBody({ groupID, maxUses, ttlHours, requireApproval })
      const r = await api.post<BulkEnrollmentTokenResponse>("/enrollment-tokens/bulk", body)
      setResult(r.data)
      setStep("token")
    } catch {
      // авто-тост интерсептора
    } finally {
      setIssuing(false)
    }
  }

  async function copyCommand() {
    if (!result) return
    const text = enrollCommand(cmdOS, result.enrollment_token, result.ca_sha256)
    try {
      await navigator.clipboard.writeText(text)
    } catch {
      const el = document.createElement("textarea")
      el.value = text
      el.style.cssText = "position:fixed;opacity:0"
      document.body.appendChild(el)
      el.select()
      document.execCommand("copy")
      document.body.removeChild(el)
    }
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  if (loading) return <div className="flex items-center justify-center h-48 text-muted-foreground text-sm">Загрузка...</div>

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-foreground">Энроллмент</h1>
        {/* Сбрасываем ТОЛЬКО когда закрыли форму: на шаге «токен» Esc или клик мимо
            стёрли бы единственную копию токена — на сервере он лежит хэшем, перечитать
            нечем, отозвать тоже нечем. Случайное закрытие теперь просто прячет диалог,
            «Выпустить токен» возвращает к той же команде. Стирает только «Готово». */}
        <Dialog open={dialogOpen} onOpenChange={(o) => { setDialogOpen(o); if (!o && step === "form") resetDialog() }}>
          <DialogTrigger asChild>
            <Button size="sm">Выпустить токен</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{step === "form" ? "Массовый токен энроллмента" : "Токен выпущен"}</DialogTitle>
            </DialogHeader>

            {step === "form" && (
              <div className="space-y-4 pt-2">
                <p className="text-sm text-muted-foreground">
                  Один токен на партию машин. Устройство создаётся само при первом подключении —
                  заводить его заранее не нужно.
                </p>
                <div className="space-y-1.5">
                  <Label>Группа</Label>
                  <Select
                    value={groupID}
                    onChange={setGroupID}
                    options={[
                      { value: NO_GROUP, label: "Без группы" },
                      ...groups.map((g) => ({ value: g.id, label: g.name })),
                    ]}
                  />
                  <p className="text-xs text-muted-foreground">
                    Всё, что подключится по этому токену, попадёт в группу — назначать её
                    каждой машине руками не нужно.
                  </p>
                </div>
                <div className="space-y-1.5">
                  <Label>Лимит использований</Label>
                  <Input
                    type="number"
                    min={1}
                    placeholder="без лимита"
                    value={maxUses}
                    onChange={(e) => setMaxUses(e.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>Срок жизни, часов</Label>
                  <Input
                    type="number"
                    min={1}
                    value={ttlHours}
                    onChange={(e) => setTTLHours(e.target.value)}
                  />
                </div>
                <label className="flex items-start gap-2 text-sm">
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={requireApproval}
                    onChange={(e) => setRequireApproval(e.target.checked)}
                  />
                  <span>
                    Требовать одобрения
                    <span className="block text-xs text-muted-foreground">
                      Устройства встанут в очередь: подключатся и отдадут инвентарь, но скрипты
                      выполнять не будут, пока их не одобрят. Снимать галочку стоит, только если
                      токен уезжает в закрытый контур.
                    </span>
                  </span>
                </label>
                <Button className="w-full" onClick={issueToken} disabled={issuing}>
                  {issuing ? "Выпуск..." : "Выпустить"}
                </Button>
              </div>
            )}

            {step === "token" && result && (
              <div className="space-y-4 pt-2">
                <p className="text-sm text-muted-foreground">
                  {result.require_approval
                    ? "Машины по этому токену встанут в очередь одобрения."
                    : "Машины по этому токену подключатся сразу, без одобрения."}
                  {" "}Действует до {new Date(result.expires_at).toLocaleString("ru-RU")}.
                </p>
                <div className="space-y-1.5">
                  <Label>ОС</Label>
                  <Select
                    value={cmdOS}
                    onChange={setCmdOS}
                    options={[
                      { value: "windows", label: "Windows" },
                      { value: "darwin",  label: "macOS"   },
                      { value: "linux",   label: "Linux"   },
                    ]}
                  />
                </div>
                <div className="relative">
                  <pre className="rounded-md border border-border bg-muted px-3 py-3 text-xs font-mono text-soft break-all whitespace-pre-wrap pr-10">
                    {enrollCommand(cmdOS, result.enrollment_token, result.ca_sha256)}
                  </pre>
                  <button
                    type="button"
                    onClick={copyCommand}
                    aria-label={copied ? "Команда скопирована" : "Скопировать команду"}
                    className="absolute right-2 top-2 rounded p-1 text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {copied ? <Check className="h-4 w-4 text-emerald-600 dark:text-emerald-500" /> : <Copy className="h-4 w-4" />}
                  </button>
                </div>
                <div className="text-xs text-muted-foreground space-y-0.5">
                  <p>Token: <span className="font-mono">{result.enrollment_token}</span></p>
                  {result.ca_sha256
                    ? <p>CA SHA-256: <span className="font-mono break-all">{result.ca_sha256}</span></p>
                    : <p className="text-amber-600 dark:text-amber-500">Сервер поднят без CA — пин сертификата недоступен.</p>}
                </div>
                {/* Токен показывается ОДИН раз: на сервере он лежит хэшем, переоткрыть нечем. */}
                <p className="text-xs text-muted-foreground">
                  Сохраните команду сейчас — повторно токен посмотреть будет нельзя.
                </p>
                <Button className="w-full" variant="outline" onClick={() => { setDialogOpen(false); resetDialog() }}>
                  Готово
                </Button>
              </div>
            )}
          </DialogContent>
        </Dialog>
      </div>

      <div className="glass overflow-hidden">
        <div className="flex items-center justify-between gap-3 px-5 pt-4 pb-3">
          <div>
            <h2 className="text-[15px] font-semibold text-foreground">
              Очередь одобрения{queue.length > 0 && <span className="text-muted-foreground"> — {queue.length}</span>}
            </h2>
            <p className="text-xs text-muted-foreground">Ждут решения администратора</p>
          </div>
          {queue.length > 0 && (
            <div className="flex flex-shrink-0 gap-2">
              {/* Одобрение — выдача доступа к парку, и оно бьёт по СЕРВЕРНОМУ набору
                  pending_approval, а не по строкам на экране: пока админ читал список,
                  могли приехать ещё машины. Подтверждение обязательно — раньше его имела
                  только менее опасная кнопка «Отклонить все». */}
              <Button size="sm" variant="outline" disabled={submitting} onClick={() => setConfirmApproveAll(true)}>
                Одобрить все
              </Button>
              <Button size="sm" variant="destructive" disabled={submitting} onClick={() => setConfirmRejectAll(true)}>
                Отклонить все
              </Button>
            </div>
          )}
        </div>
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="text-xs">Имя</TableHead>
              <TableHead className="text-xs">ОС</TableHead>
              {/* Серийник — единственное в этой таблице, что админ может сверить с
                  реальной машиной: hostname и ОС агент сообщает о себе сам, и назваться
                  «BUH-WS-01» может кто угодно. */}
              <TableHead className="text-xs">Серийный номер</TableHead>
              <TableHead className="text-xs">IP</TableHead>
              <TableHead className="text-xs">Группы</TableHead>
              <TableHead className="text-xs">Подключилось</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {queue.length === 0 && (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={7} className="text-center py-8 text-sm">
                  {loadFailed ? (
                    <span className="text-destructive">
                      Не удалось загрузить список — очередь может быть НЕ пуста.{" "}
                      <button type="button" className="underline" onClick={() => load()}>Повторить</button>
                    </span>
                  ) : (
                    <span className="text-muted-foreground">
                      Очередь пуста — новые устройства появятся здесь, как только подключатся
                      по массовому токену. Список обновляется сам.
                    </span>
                  )}
                </TableCell>
              </TableRow>
            )}
            {/* Янтарная подложка строки — тот же смысловой цвет, что и статус
                pending: очередь должна цепляться взглядом на фоне остального. */}
            {queue.map((d) => (
              <TableRow key={d.id} className="bg-amber-500/[0.06] hover:bg-amber-500/10">
                <TableCell className="px-4 py-3">
                  <button
                    type="button"
                    className="text-sm font-medium text-foreground hover:underline text-left"
                    onClick={() => navigate(`/devices/${d.id}`)}
                  >
                    {d.hostname}
                  </button>
                </TableCell>
                <TableCell className="px-4 py-3 text-xs text-muted-foreground">{d.os} {d.os_version}</TableCell>
                <TableCell className="px-4 py-3 text-muted-foreground font-mono text-xs">{d.serial_number || "—"}</TableCell>
                <TableCell className="px-4 py-3 text-muted-foreground font-mono text-xs">{d.ip_address}</TableCell>
                <TableCell className="px-4 py-3"><GroupBadges groups={d.groups} /></TableCell>
                <TableCell className="px-4 py-3 text-muted-foreground text-xs">
                  {d.last_seen_at ? formatDistanceToNow(d.last_seen_at) : "—"}
                </TableCell>
                <TableCell className="px-4 py-3 text-right whitespace-nowrap">
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={submitting}
                    className="text-emerald-600 border-emerald-500/40 hover:bg-emerald-500/10 dark:text-emerald-400 mr-2"
                    onClick={() => decide(d, "approve")}
                  >
                    Одобрить
                  </Button>
                  <Button size="sm" variant="destructive" disabled={submitting} onClick={() => setConfirmReject(d)}>
                    Отклонить
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {/* Отклонённые показываем отдельно и всегда: статус терминальный, и если машина
          попала сюда по ошибке, админ должен это видеть, а не искать её в общем списке. */}
      {rejected.length > 0 && (
        <div className="glass overflow-hidden">
          <div className="px-5 pt-4 pb-3">
            <h2 className="text-[15px] font-semibold text-foreground">Отклонённые — {rejected.length}</h2>
            <p className="text-xs text-muted-foreground">Статус терминальный</p>
          </div>
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="text-xs">Имя</TableHead>
                <TableHead className="text-xs">ОС</TableHead>
                <TableHead className="text-xs">IP</TableHead>
                <TableHead className="text-xs text-right">Статус</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rejected.map((d) => (
                <TableRow key={d.id} className="glass-hover">
                  <TableCell className="px-4 py-3">
                    <button
                      type="button"
                      className="text-sm font-medium text-foreground hover:underline text-left"
                      onClick={() => navigate(`/devices/${d.id}`)}
                    >
                      {d.hostname}
                    </button>
                  </TableCell>
                  <TableCell className="px-4 py-3 text-xs text-muted-foreground">{d.os} {d.os_version}</TableCell>
                  <TableCell className="px-4 py-3 text-muted-foreground font-mono text-xs">{d.ip_address}</TableCell>
                  <TableCell className="px-4 py-3 text-right">
                    <Badge variant={DEVICE_STATUS.rejected.variant}>{DEVICE_STATUS.rejected.label}</Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <ConfirmDialog
        open={!!confirmReject}
        onOpenChange={(o) => !o && setConfirmReject(null)}
        title="Отклонить устройство?"
        description={confirmReject
          ? `«${confirmReject.hostname}» потеряет доступ: статус терминальный, обратно через одобрение не вернуть — машину придётся энролить заново.`
          : ""}
        confirmLabel="Отклонить"
        destructive
        onConfirm={() => { if (confirmReject) decide(confirmReject, "reject") }}
      />

      <ConfirmDialog
        open={confirmApproveAll}
        onOpenChange={setConfirmApproveAll}
        title="Одобрить все устройства в очереди?"
        description={`Сейчас в очереди: ${queue.length}. Одобрение снимает ограничение и даёт машинам полный доступ, включая выполнение скриптов. Действие применится ко всем, кто стоит в очереди на момент подтверждения, — включая тех, кто мог подключиться, пока вы читали список.`}
        confirmLabel="Одобрить все"
        onConfirm={() => decideAll("approve")}
      />

      <ConfirmDialog
        open={confirmRejectAll}
        onOpenChange={setConfirmRejectAll}
        title="Отклонить все устройства в очереди?"
        description={`Будет отклонено устройств: ${queue.length}. Статус терминальный — вернуть их можно только повторным энроллментом.`}
        confirmLabel="Отклонить все"
        destructive
        onConfirm={() => decideAll("reject")}
      />
    </div>
  )
}

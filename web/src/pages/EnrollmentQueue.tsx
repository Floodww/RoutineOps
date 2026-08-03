import i18n from "@/i18n/config"
import { useTranslation } from "react-i18next"
import { useEffect, useState } from "react"
import { useNavigate } from "react-router-dom"
import { Copy, Check } from "lucide-react"
import api, { Device, DeviceGroup, DEVICE_STATUS, BulkEnrollmentTokenResponse, BulkEnrollmentToken } from "@/lib/api"
import { GroupBadges } from "@/components/GroupBadge"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Select } from "@/components/ui/select"
import ConfirmDialog from "@/components/ConfirmDialog"
import { formatDistanceToNow, formatDateTime } from "@/lib/time"
import { toast } from "@/lib/toast"
import { getIntuneMigrationScript, getJamfMigrationScript } from "@/lib/migrationScripts"

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

function isDead(t: BulkEnrollmentToken): boolean {
  return new Date(t.expires_at).getTime() <= Date.now()
}

// Заведены, но так и не подключились. Два источника: устройство создали руками и агент
// ещё не приехал, либо энролл по массовому токену оборвался между созданием строки и
// подписью CSR — такая машина остаётся 'pending' навсегда и не видна нигде, кроме
// общего списка парка, где она неотличима от нормально ждущей. Старые сверху: чем
// дольше висит, тем вероятнее, что это осадок, а не машина в пути.
// 🔴 last_seen_at обязателен в условии, и ради него функция вынесена под тест: реенролл
// тоже ставит 'pending', и БОЕВОЕ устройство со всей историей попало бы в этот список
// под кнопку «Удалить» — да ещё и помеченным просроченным, потому что created_at у него
// давний. «Ни разу не выходило на связь» — это именно last_seen_at IS NULL.
export function pendingNotConnected(devices: Device[]): Device[] {
  return devices
    .filter((d) => d.status === "pending" && !d.last_seen_at)
    .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
}

export default function EnrollmentQueue() {
  const { t } = useTranslation()
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
  const [scriptType, setScriptType] = useState<"cmd" | "intune" | "jamf">("cmd")
  const [copied, setCopied] = useState(false)

  const [confirmReject, setConfirmReject] = useState<Device | null>(null)
  const [confirmRejectAll, setConfirmRejectAll] = useState(false)
  const [confirmApproveAll, setConfirmApproveAll] = useState(false)
  const [loadFailed, setLoadFailed] = useState(false)

  const [tokens, setTokens] = useState<BulkEnrollmentToken[]>([])
  const [confirmRevoke, setConfirmRevoke] = useState<BulkEnrollmentToken | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<Device | null>(null)

  // Отдельной ручки под очередь на сервере нет: GET /devices отдаёт весь парк
  // (фильтруется только литеральный 'pending'), поэтому режем на клиенте.
  //
  // Комментарий выше ВЕРЕН, и это стоит держать в голове: 'pending' и
  // 'pending_approval' — разные состояния. Первое = энроллмент не завершён (серта нет),
  // такую строку в парке показывать нечего; второе = очередь одобрения, она приходит
  // в GET /devices штатно. Пустая очередь при непустой таблице devices почти всегда
  // значит, что строки заведены со статусом 'pending' в обход энроллмента, а не что
  // сломан список. Держится тестами internal/server/storage/enrollment_queue_visibility_test.go.
  async function load() {
    try {
      const r = await api.get<Device[]>("/devices")
      setDevices(r.data ?? [])
      setLoadFailed(false)
    } catch {
      // 🔴 Не глотаем: на экране безопасности пустая таблица читается как «всё чисто».
      // Отказ загрузки обязан выглядеть отказом, а не пустой очередью.
      setLoadFailed(true)
      toast({ title: t("enrollment.failedToLoadDevices"), variant: "destructive" })
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

  function loadTokens() {
    api.get<BulkEnrollmentToken[]>("/enrollment-tokens/bulk")
      .then((r) => setTokens(r.data ?? []))
      .catch(() => setTokens([]))
  }
  useEffect(loadTokens, [])

  const queue = devices.filter((d) => d.status === "pending_approval")
  const rejected = devices.filter((d) => d.status === "rejected")
  const notConnected = pendingNotConnected(devices)
  // Отзыв на сервере = мгновенное истечение, поэтому «отозван» и «истёк сам» на экране
  // одно и то же состояние: не действует. Кто отозвал — в аудите.
  const liveTokens = tokens.filter((t) => !isDead(t))

  async function decide(device: Device, action: "approve" | "reject") {
    setSubmitting(true)
    try {
      await api.post(`/devices/${device.id}/${action}`)
      await load()
      toast({
        title: action === "approve" ? t("enrollment.deviceApproved", { name: device.hostname }) : t("enrollment.deviceRejected", { name: device.hostname }),
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
        title: action === "approve" ? t("enrollment.approvedCount", { count: n ?? 0 }) : t("enrollment.rejectedCount", { count: n ?? 0 }),
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
    setScriptType("cmd")
    setCopied(false)
  }

  async function issueToken() {
    setIssuing(true)
    try {
      const body = bulkTokenBody({ groupID, maxUses, ttlHours, requireApproval })
      const r = await api.post<BulkEnrollmentTokenResponse>("/enrollment-tokens/bulk", body)
      setResult(r.data)
      setStep("token")
      loadTokens()
    } catch {
      // авто-тост интерсептора
    } finally {
      setIssuing(false)
    }
  }

  async function deletePending(d: Device) {
    setSubmitting(true)
    try {
      await api.delete(`/devices/${d.id}`)
      toast({ title: t("enrollment.deviceDeleted", { name: d.hostname }) })
    } catch {
      // авто-тост интерсептора
    } finally {
      setSubmitting(false)
      load()
    }
  }

  // Параметр называется tok, а не t: t() из useTranslation закрылась бы им.
  async function revokeToken(tok: BulkEnrollmentToken) {
    try {
      await api.delete(`/enrollment-tokens/${tok.id}`)
      toast({ title: t("enrollment.tokenRevoked"), variant: "success" })
    } catch {
      // авто-тост интерсептора. 409 = токен уже мёртв, перечитываем список.
    } finally {
      loadTokens()
    }
  }

  function getTextToCopy() {
    if (!result) return ""
    if (scriptType === "intune") {
      return getIntuneMigrationScript(apiBase(), `${window.location.hostname}:50051`, result.enrollment_token, result.ca_sha256)
    }
    if (scriptType === "jamf") {
      return getJamfMigrationScript(apiBase(), `${window.location.hostname}:50051`, result.enrollment_token, result.ca_sha256)
    }
    return enrollCommand(cmdOS, result.enrollment_token, result.ca_sha256)
  }

  async function copyCommand() {
    const text = getTextToCopy()
    if (!text) return
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

  if (loading) return <div className="flex items-center justify-center h-48 text-muted-foreground text-sm">{t("enrollment.loading")}</div>

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-foreground">{t("enrollment.enrollment")}</h1>
        {/* Сбрасываем ТОЛЬКО когда закрыли форму: на шаге «токен» Esc или клик мимо
            стёрли бы единственную копию токена — на сервере он лежит хэшем, перечитать
            нечем. Случайное закрытие теперь просто прячет диалог, «Выпустить токен»
            возвращает к той же команде. Стирает только «Готово». Потерянный таким
            образом токен теперь хотя бы гасится: он виден в списке ниже. */}
        <Dialog open={dialogOpen} onOpenChange={(o) => { setDialogOpen(o); if (!o && step === "form") resetDialog() }}>
          <DialogTrigger asChild>
            <Button size="sm">{t("enrollment.issueAToken")}</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{step === "form" ? t("enrollment.bulkEnrollmentToken") : t("enrollment.tokenIssued")}</DialogTitle>
            </DialogHeader>

            {step === "form" && (
              <div className="space-y-4 pt-2">
                <p className="text-sm text-muted-foreground">
                  {t("enrollment.bulkHint")}
                </p>
                <div className="space-y-1.5">
                  <Label>{t("enrollment.group")}</Label>
                  <Select
                    value={groupID}
                    onChange={setGroupID}
                    options={[
                      { value: NO_GROUP, label: t("enrollment.noGroup") },
                      ...groups.map((g) => ({ value: g.id, label: g.name })),
                    ]}
                  />
                  <p className="text-xs text-muted-foreground">
                    {t("enrollment.groupHint")}
                  </p>
                </div>
                <div className="space-y-1.5">
                  <Label>{t("enrollment.usageLimit")}</Label>
                  <Input
                    type="number"
                    min={1}
                    placeholder={t("enrollment.noLimit")}
                    value={maxUses}
                    onChange={(e) => setMaxUses(e.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>{t("enrollment.lifetimeHours")}</Label>
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
                    {t("enrollment.requireApproval")}
                    <span className="block text-xs text-muted-foreground">
                      {t("enrollment.approvalHint")}
                    </span>
                  </span>
                </label>
                <Button className="w-full" onClick={issueToken} disabled={issuing}>
                  {issuing ? t("enrollment.issuing") : t("enrollment.issue")}
                </Button>
              </div>
            )}

            {step === "token" && result && (
              <div className="space-y-4 pt-2">
                <p className="text-sm text-muted-foreground">
                  {result.require_approval
                    ? t("enrollment.machinesUsingThisToken2")
                    : t("enrollment.machinesUsingThisToken")}
                  {" "}{t("enrollment.validUntilDate", { date: formatDateTime(result.expires_at) })}
                </p>
                <div className="flex gap-2 mb-2">
                  <Button size="sm" variant={scriptType === "cmd" ? "default" : "outline"} onClick={() => setScriptType("cmd")}>{t("enrollment.installationCommand")}</Button>
                  <Button size="sm" variant={scriptType === "intune" ? "default" : "outline"} onClick={() => setScriptType("intune")}>Intune (Windows)</Button>
                  <Button size="sm" variant={scriptType === "jamf" ? "default" : "outline"} onClick={() => setScriptType("jamf")}>Jamf / WSO (macOS)</Button>
                </div>
                {scriptType === "cmd" && (
                  <div className="space-y-1.5">
                    <Label>{t("enrollment.os")}</Label>
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
                )}
                {scriptType === "intune" && (
                  <p className="text-xs text-muted-foreground">
                    {t("enrollment.intuneHint")}
                  </p>
                )}
                {scriptType === "jamf" && (
                  <p className="text-xs text-muted-foreground">
                    {t("enrollment.jamfHint")}
                  </p>
                )}
                <div className="relative">
                  <pre className="rounded-md border border-border bg-muted px-3 py-3 text-xs font-mono text-soft break-all whitespace-pre-wrap pr-10">
                    {getTextToCopy()}
                  </pre>
                  <button
                    type="button"
                    onClick={copyCommand}
                    aria-label={copied ? t("enrollment.commandCopied") : t("enrollment.copyTheCommand")}
                    className="absolute right-2 top-2 rounded p-1 text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {copied ? <Check className="h-4 w-4 text-emerald-600 dark:text-emerald-500" /> : <Copy className="h-4 w-4" />}
                  </button>
                </div>
                <div className="text-xs text-muted-foreground space-y-0.5">
                  <p>Token: <span className="font-mono">{result.enrollment_token}</span></p>
                  {result.ca_sha256
                    ? <p>CA SHA-256: <span className="font-mono break-all">{result.ca_sha256}</span></p>
                    : <p className="text-amber-600 dark:text-amber-500">{t("enrollment.theServerRunsWithout")}</p>}
                </div>
                {/* Токен показывается ОДИН раз: на сервере он лежит хэшем, переоткрыть нечем. */}
                <p className="text-xs text-muted-foreground">
                  {t("enrollment.saveNow")}
                </p>
                <Button className="w-full" variant="outline" onClick={() => { setDialogOpen(false); resetDialog() }}>
                  {t("common.done")}
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
              {t("enrollment.approvalQueue")}{queue.length > 0 && <span className="text-muted-foreground"> — {queue.length}</span>}
            </h2>
            <p className="text-xs text-muted-foreground">{t("enrollment.awaitingAnAdministratorS")}</p>
          </div>
          {queue.length > 0 && (
            <div className="flex flex-shrink-0 gap-2">
              {/* Одобрение — выдача доступа к парку, и оно бьёт по СЕРВЕРНОМУ набору
                  pending_approval, а не по строкам на экране: пока админ читал список,
                  могли приехать ещё машины. Подтверждение обязательно — раньше его имела
                  только менее опасная кнопка «Отклонить все». */}
              <Button size="sm" variant="outline" disabled={submitting} onClick={() => setConfirmApproveAll(true)}>
                {t("enrollment.approveAll")}
              </Button>
              <Button size="sm" variant="destructive" disabled={submitting} onClick={() => setConfirmRejectAll(true)}>
                {t("enrollment.rejectAll")}
              </Button>
            </div>
          )}
        </div>
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="text-xs">{t("enrollment.name")}</TableHead>
              <TableHead className="text-xs">{t("enrollment.os")}</TableHead>
              {/* Серийник — единственное в этой таблице, что админ может сверить с
                  реальной машиной: hostname и ОС агент сообщает о себе сам, и назваться
                  «BUH-WS-01» может кто угодно. */}
              <TableHead className="text-xs">{t("enrollment.serialNumber")}</TableHead>
              <TableHead className="text-xs">IP</TableHead>
              <TableHead className="text-xs">{t("enrollment.groups")}</TableHead>
              <TableHead className="text-xs">{t("enrollment.connected")}</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {queue.length === 0 && (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={7} className="text-center py-8 text-sm">
                  {loadFailed ? (
                    <span className="text-destructive">
                      {t("enrollment.listFailed")}{" "}
                      <button type="button" className="underline" onClick={() => load()}>{t("enrollment.retry")}</button>
                    </span>
                  ) : (
                    <span className="text-muted-foreground">
                      {t("enrollment.queueEmpty")}
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
                    {t("enrollment.approve")}
                  </Button>
                  <Button size="sm" variant="destructive" disabled={submitting} onClick={() => setConfirmReject(d)}>
                    {t("enrollment.reject")}
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
            <h2 className="text-[15px] font-semibold text-foreground">{t("enrollment.rejectedHeading", { count: rejected.length })}</h2>
            <p className="text-xs text-muted-foreground">{t("enrollment.theStatusIsTerminal")}</p>
          </div>
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="text-xs">{t("enrollment.name")}</TableHead>
                <TableHead className="text-xs">{t("enrollment.os")}</TableHead>
                <TableHead className="text-xs">IP</TableHead>
                <TableHead className="text-xs text-right">{t("enrollment.status")}</TableHead>
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
                    <Badge variant={DEVICE_STATUS.rejected.variant}>{i18n.t(DEVICE_STATUS.rejected.label)}</Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Заведённые, но не подключившиеся. Показываем только когда есть: в отличие от
          токенов, пустота тут — норма, а не отсутствие информации. */}
      {notConnected.length > 0 && (
        <div className="glass overflow-hidden">
          <div className="px-5 pt-4 pb-3">
            <h2 className="text-[15px] font-semibold text-foreground">{t("enrollment.notConnectedHeading", { count: notConnected.length })}</h2>
            <p className="text-xs text-muted-foreground">
              {t("enrollment.notConnectedHint")}
            </p>
          </div>
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="text-xs">{t("enrollment.name")}</TableHead>
                <TableHead className="text-xs">{t("enrollment.os")}</TableHead>
                <TableHead className="text-xs">{t("enrollment.created")}</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {notConnected.map((d) => {
                const stale = Date.now() - new Date(d.created_at).getTime() > 24 * 3600_000
                return (
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
                    <TableCell className="px-4 py-3 text-xs">
                      <span className={stale ? "text-amber-600 dark:text-amber-400" : "text-muted-foreground"}>
                        {formatDistanceToNow(d.created_at)}
                      </span>
                    </TableCell>
                    <TableCell className="px-4 py-3 text-right">
                      <Button size="sm" variant="outline" disabled={submitting} onClick={() => setConfirmDelete(d)}>
                        {t("enrollment.delete")}
                      </Button>
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>
      )}

      <ConfirmDialog
        open={!!confirmDelete}
        onOpenChange={(o) => !o && setConfirmDelete(null)}
        title={t("enrollment.deleteTheRecord")}
        description={confirmDelete
          ? t("enrollment.deleteWarn", { name: confirmDelete.hostname })
          : ""}
        confirmLabel={t("enrollment.delete")}
        destructive
        onConfirm={() => { if (confirmDelete) deletePending(confirmDelete) }}
      />

      {/* Выпущенные массовые токены. Показываем ВСЕГДА, даже когда список пуст: живой
          токен — это стоячее право заводить машины в парке, и оператор должен видеть,
          сколько таких прав сейчас выдано, не листая аудит. */}
      <div className="glass overflow-hidden">
        <div className="px-5 pt-4 pb-3">
          <h2 className="text-[15px] font-semibold text-foreground">
            {t("enrollment.bulkTokens")}{liveTokens.length > 0 && <span className="text-muted-foreground"> — {t("enrollment.liveTokens", { count: liveTokens.length })}</span>}
          </h2>
          <p className="text-xs text-muted-foreground">
            {t("enrollment.tokenStorageHint")}
          </p>
        </div>
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="text-xs">{t("enrollment.group")}</TableHead>
              <TableHead className="text-xs">{t("enrollment.uses")}</TableHead>
              <TableHead className="text-xs">{t("enrollment.approvalQueue")}</TableHead>
              <TableHead className="text-xs">{t("enrollment.issued")}</TableHead>
              <TableHead className="text-xs">{t("enrollment.validUntil")}</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {tokens.length === 0 && (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={6} className="text-center py-8 text-sm text-muted-foreground">
                  {t("enrollment.noTokens")}
                </TableCell>
              </TableRow>
            )}
            {/* Переменная называется tok: t() из useTranslation закрылась бы ей. */}
            {tokens.map((tok) => {
              const dead = isDead(tok)
              return (
                <TableRow key={tok.id} className={dead ? "opacity-55 hover:bg-transparent" : "glass-hover"}>
                  <TableCell className="px-4 py-3 text-sm">{tok.group_name || <span className="text-muted-foreground">{t("enrollment.noGroup2")}</span>}</TableCell>
                  <TableCell className="px-4 py-3 text-sm font-mono">
                    {tok.uses}{tok.max_uses ? ` / ${tok.max_uses}` : <span className="text-muted-foreground"> / ∞</span>}
                  </TableCell>
                  <TableCell className="px-4 py-3">
                    {/* Токен без очереди одобрения заводит машины сразу в строй — это
                        более опасная конфигурация, и она обязана быть видна в списке. */}
                    {tok.require_approval
                      ? <span className="text-xs text-muted-foreground">{t("enrollment.on")}</span>
                      : <Badge variant="destructive">{t("enrollment.off")}</Badge>}
                  </TableCell>
                  <TableCell className="px-4 py-3 text-xs text-muted-foreground">{formatDistanceToNow(tok.created_at)}</TableCell>
                  <TableCell className="px-4 py-3 text-xs">
                    {dead
                      ? <span className="text-muted-foreground">{t("enrollment.notInEffect")}</span>
                      : <span className="text-foreground">{formatDistanceToNow(tok.expires_at)}</span>}
                  </TableCell>
                  <TableCell className="px-4 py-3 text-right">
                    {!dead && (
                      <Button size="sm" variant="destructive" onClick={() => setConfirmRevoke(tok)}>
                        {t("enrollment.revoke")}
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      </div>

      <ConfirmDialog
        open={!!confirmRevoke}
        onOpenChange={(o) => !o && setConfirmRevoke(null)}
        title={t("enrollment.revokeTheToken")}
        description={confirmRevoke
          ? t("enrollment.revokeWarn") +
            (confirmRevoke.uses > 0 ? " " + t("enrollment.revokeUses", { count: confirmRevoke.uses }) : "")
          : ""}
        confirmLabel={t("enrollment.revoke")}
        destructive
        onConfirm={() => { if (confirmRevoke) revokeToken(confirmRevoke) }}
      />

      <ConfirmDialog
        open={!!confirmReject}
        onOpenChange={(o) => !o && setConfirmReject(null)}
        title={t("enrollment.rejectTheDevice")}
        description={confirmReject
          ? t("enrollment.rejectWarn", { name: confirmReject.hostname })
          : ""}
        confirmLabel={t("enrollment.reject")}
        destructive
        onConfirm={() => { if (confirmReject) decide(confirmReject, "reject") }}
      />

      <ConfirmDialog
        open={confirmApproveAll}
        onOpenChange={setConfirmApproveAll}
        title={t("enrollment.approveEveryDeviceIn")}
        description={t("enrollment.approveAllWarn", { count: queue.length })}
        confirmLabel={t("enrollment.approveAll")}
        onConfirm={() => decideAll("approve")}
      />

      <ConfirmDialog
        open={confirmRejectAll}
        onOpenChange={setConfirmRejectAll}
        title={t("enrollment.rejectEveryDeviceIn")}
        description={t("enrollment.rejectAllWarn", { count: queue.length })}
        confirmLabel={t("enrollment.rejectAll")}
        destructive
        onConfirm={() => decideAll("reject")}
      />
    </div>
  )
}

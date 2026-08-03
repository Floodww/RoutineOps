import i18n from "@/i18n/config"
import { useEffect, useState } from "react"
import { useTranslation, Trans } from "react-i18next"
import { useParams, useNavigate } from "react-router-dom"
import { ChevronLeft, Copy, Check, Terminal, ShieldCheck, Cpu, HardDrive, MemoryStick, ChevronDown, Trash2 } from "lucide-react"
import api, { errMessage, Device, Software, Task, Script, DeviceDetailResponse, ReenrollResponse, deviceRunsScript, agentPlatform, DEVICE_STATUS, REBOOT_DELAYS, EscrowRecord, EscrowReveal, ESCROW_SECRET_TYPE, UNINSTALL_OUTCOME, Vulnerability } from "@/lib/api"
import { GroupBadge } from "@/components/GroupBadge"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Select } from "@/components/ui/select"
import OwnerCard from "@/components/OwnerCard"
import { ScreenSessionPanel } from "@/components/ScreenSessionPanel"
import { Dialog, DialogTrigger, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator } from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import ConfirmDialog from "@/components/ConfirmDialog"
import { toast } from "@/lib/toast"
import { formatDistanceToNow, formatDateTime } from "@/lib/time"
import { useMe } from "@/lib/useMe"
import { useTenants } from "@/lib/useTenants"

type TaskForm = { script: string; platform: string; priority: string }
type TaskMode = "library" | "manual"


const statusBadge = (status: Device["status"]) => {
  // i18n.t, а не useTranslation: функция модульная, хука здесь нет. Экран сам
  // подписан на смену языка, поэтому подпись перерисуется вместе с ним.
  const known = DEVICE_STATUS[status]
  return <Badge variant={known?.variant ?? "outline"}>{known ? i18n.t(known.label) : status}</Badge>
}

// lockDivergence — расхождение ЖЕЛАЕМОГО лока (lock_status) с ФАКТИЧЕСКИМ, о котором
// доложил агент (lock_actual_state). Показываем только состояния, где машина НЕ закрыта
// или закрыта наполовину: именно они опасны молчанием — панель рисует «заблокировано»,
// а устройством пользуются. Совпадение desired/actual и пустой actual — не рисуем.
// Значения — КЛЮЧИ словаря: t() на уровне модуля недоступен.
const LOCK_ACTUAL_ALERTS: Record<string, { label: string; hint: string }> = {
  lock_failed: {
    label: "deviceDetail.lockNotApplied",
    hint: "deviceDetail.theAgentCouldNot",
  },
  filevault_revoked: {
    label: "deviceDetail.filevaultRebootRequired",
    hint: "deviceDetail.theSecureTokenIs",
  },
  filevault_revoke_failed: {
    label: "deviceDetail.filevaultRevokeDidNot",
    hint: "deviceDetail.aDestructiveOperationMay",
  },
}

const lockDivergence = (device: Device) => LOCK_ACTUAL_ALERTS[device.lock_actual_state ?? ""] ?? null

// decommissionArmed — кнопку сноса разрешаем только после того, как оператор ввёл имя
// устройства руками. Операция необратима и стирает агента с ЖИВОЙ машины, а пункт меню
// стоит в двух строках от «Заблокировать экран» — одного клика для неё мало.
// Регистр и пробелы прощаем: имя копируют из заголовка, промах по Caps не должен злить.
export function decommissionArmed(hostname: string, typed: string): boolean {
  const want = hostname.trim().toLowerCase()
  return want !== "" && typed.trim().toLowerCase() === want
}

// Значения — КЛЮЧИ словаря: t() на уровне модуля недоступен.
const taskStatusLabel: Record<string, string> = {
  pending:   "deviceDetail.pending",
  acked:     "deviceDetail.accepted",
  completed: "deviceDetail.done",
  failed:    "deviceDetail.error",
}

const taskStatusVariant: Record<string, "default" | "secondary" | "success" | "destructive" | "outline"> = {
  pending:   "secondary",
  acked:     "outline",
  completed: "success",
  failed:    "destructive",
}

const PLATFORM_OPTIONS = [
  { value: "linux",   label: "Linux"   },
  { value: "darwin",  label: "macOS"   },
  { value: "windows", label: "Windows" },
]

const PRIORITY_OPTIONS = [
  { value: "low",    label: "deviceDetail.low"    },
  { value: "normal", label: "deviceDetail.normal" },
  { value: "high",   label: "deviceDetail.high"   },
]

export default function DeviceDetail() {
  const { t } = useTranslation()
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { isAdmin, isProvider } = useMe()
  const { tenants: allTenants } = useTenants()
  const [device, setDevice] = useState<Device | null>(null)
  const [software, setSoftware] = useState<Software[]>([])
  // Что сносим — держим всю запись: в подтверждении нужны имя, версия и метод, иначе
  // оператор соглашается на «удалить ПО» вслепую, а одноимённых записей бывает две.
  const [toUninstall, setToUninstall] = useState<Software | null>(null)
  const [uninstalling, setUninstalling] = useState(false)
  const [tasks, setTasks] = useState<Task[]>([])
  const [loading, setLoading] = useState(true)
  const [blocking, setBlocking] = useState(false)
  const [taskForm, setTaskForm] = useState<TaskForm>({ script: "", platform: "linux", priority: "normal" })
  const [taskOpen, setTaskOpen] = useState(false)
  const [taskMode, setTaskMode] = useState<TaskMode>("library")
  const [submitting, setSubmitting] = useState(false)
  const [scripts, setScripts] = useState<Script[]>([])
  const [selectedScriptId, setSelectedScriptId] = useState<string>("")
  const [logTask, setLogTask] = useState<Task | null>(null)
  const [confirmBlock, setConfirmBlock] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [reenrollOpen, setReenrollOpen] = useState(false)
  const [reenrolling, setReenrolling] = useState(false)
  const [reenrollResult, setReenrollResult] = useState<ReenrollResponse | null>(null)
  const [copied, setCopied] = useState(false)
  const [lockOpen, setLockOpen] = useState(false)
  const [lockReason, setLockReason] = useState("")
  const [locking, setLocking] = useState(false)
  const [lockPassword, setLockPassword] = useState<string | null>(null)
  const [lockCopied, setLockCopied] = useState(false)
  const [decomOpen, setDecomOpen] = useState(false)
  const [decomReason, setDecomReason] = useState("")
  const [decomTyped, setDecomTyped] = useState("")
  const [decommissioning, setDecommissioning] = useState(false)
  const [moveOpen, setMoveOpen] = useState(false)
  const [moveTo, setMoveTo] = useState("")
  const [moving, setMoving] = useState(false)
  const [rebootOpen, setRebootOpen] = useState(false)
  const [rebootReason, setRebootReason] = useState("")
  const [rebootDelay, setRebootDelay] = useState(REBOOT_DELAYS[0].value)
  const [rebooting, setRebooting] = useState(false)
  const [escrow, setEscrow] = useState<EscrowRecord[]>([])
  const [revealing, setRevealing] = useState(false)
  const [revealed, setRevealed] = useState<EscrowReveal | null>(null)
  const [vulns, setVulns] = useState<Vulnerability[]>([])

  useEffect(() => {
    async function load() {
      try {
        const [d, t, v] = await Promise.all([
          api.get<DeviceDetailResponse>(`/devices/${id}`),
          api.get<Task[]>(`/devices/${id}/tasks`),
          api.get<Vulnerability[]>(`/devices/${id}/vulnerabilities`).catch(() => ({ data: [] as Vulnerability[] })),
        ])
        setDevice(d.data.device)
        setSoftware(d.data.software ?? [])
        setTasks(t.data ?? [])
        setVulns(v.data ?? [])
      } catch {
        toast({ title: t("deviceDetail.failedToLoadThe"), variant: "destructive" })
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [id])

  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const [d, t] = await Promise.all([
          api.get<DeviceDetailResponse>(`/devices/${id}`),
          api.get<Task[]>(`/devices/${id}/tasks`),
        ])
        setDevice(d.data.device)
        setSoftware(d.data.software ?? [])
        setTasks(t.data ?? [])
      } catch { /* фоновый поллинг */ }
    }, 10000)
    return () => clearInterval(interval)
  }, [id])

  useEffect(() => {
    api.get<Script[]>("/scripts").then((r) => setScripts(r.data ?? [])).catch(() => {})
  }, [])

  // Эскроу — enterprise-ручка: в свободной редакции её нет (404), у viewer'а нет прав
  // (403). В обоих случаях раздел просто не показываем, ошибку не шумим.
  useEffect(() => {
    api.get<EscrowRecord[]>(`/devices/${id}/escrow`)
      .then((r) => setEscrow(r.data ?? []))
      .catch(() => setEscrow([]))
  }, [id])

  const runnableScripts = device ? scripts.filter((s) => deviceRunsScript(device.os, s.platform)) : []
  const selectedScript = runnableScripts.find((s) => s.id === selectedScriptId) ?? null
  const scriptOptions = runnableScripts.map((s) => ({ value: s.id, label: `${s.name} (${s.platform})` }))

  function openTaskDialog(mode: TaskMode) {
    setTaskMode(mode)
    setSelectedScriptId("")
    setTaskForm({ script: "", platform: "linux", priority: "normal" })
    setTaskOpen(true)
  }

  async function sendLock() {
    if (!device) return
    setLocking(true)
    try {
      const r = await api.post<{ task_id: string; password: string }>(`/devices/${id}/lock`, { reason: lockReason })
      setLockPassword(r.data.password)
      setDevice({ ...device, lock_status: "locked" })
    } catch {
      toast({ title: t("deviceDetail.failedToSendThe2"), variant: "destructive" })
    } finally {
      setLocking(false)
    }
  }

  async function sendUnlock() {
    if (!device) return
    try {
      await api.post(`/devices/${id}/unlock`, {})
      setDevice({ ...device, lock_status: "unlocked" })
      toast({ title: t("deviceDetail.theUnlockCommandWas"), variant: "success" })
    } catch {
      toast({ title: t("deviceDetail.failedToSendThe"), variant: "destructive" })
    }
  }

  // Перенос в другой тенант — действие надзора над инсталляцией. Членство в группах
  // при этом снимается сервером: группы принадлежат покинутому тенанту, и устройство,
  // оставшееся в них, попало бы под чужие политики.
  async function moveTenant() {
    if (!moveTo) return
    setMoving(true)
    try {
      await api.post(`/devices/${id}/tenant`, { tenant_id: moveTo })
      setMoveOpen(false)
      toast({
        title: t("deviceDetail.deviceMoved"),
        description: t("deviceDetail.groupsWereClearedAssign"),
        variant: "success",
      })
      navigate("/devices")
    } catch (e) {
      toast({ title: t("deviceDetail.failedToMove"), description: errMessage(e), variant: "destructive" })
    } finally {
      setMoving(false)
    }
  }

  // Снос агента. Статус устройства НЕ трогаем: сервер тоже его не меняет, терминальный
  // decommissioned ставит gateway по подтверждению агента (handler.go:1131). Поэтому
  // никакого оптимистичного setDevice — только обновляем список задач, чтобы оператор
  // видел прогресс, и говорим прямо, что команда ждёт выхода машины на связь.
  async function sendDecommission() {
    if (!device) return
    setDecommissioning(true)
    try {
      await api.post(`/devices/${id}/decommission`, { reason: decomReason })
      setDecomOpen(false)
      toast({
        title: t("deviceDetail.theRemovalTaskWas"),
        description: t("deviceDetail.theAgentRemovesItself"),
        variant: "success",
      })
      const fresh = await api.get<Task[]>(`/devices/${id}/tasks`)
      setTasks(fresh.data ?? [])
    } catch (e) {
      const status = (e as { response?: { status?: number } }).response?.status
      toast({
        title: status === 409
          ? t("deviceDetail.theDeviceIsAlready")
          : t("deviceDetail.failedToQueueThe3"),
        variant: "destructive",
      })
    } finally {
      setDecommissioning(false)
    }
  }

  // Перезагрузка. Успех означает «ЗАПЛАНИРОВАНА» — агент отчитывается сразу, как
  // планировщик ОС принял команду, а не после того, как машина поднялась. Повторный
  // клик по той же машине попадает в ту же задачу (сервер не выдаёт новый task_id),
  // поэтому дополнительной защиты от двойного клика здесь не нужно.
  // Удаление ПО. Повторный клик безопасен: сервер возвращает ТУ ЖЕ задачу, пока
  // предыдущая не доставлена.
  async function sendUninstall() {
    if (!toUninstall) return
    setUninstalling(true)
    try {
      await api.post(`/devices/${id}/software/uninstall`, {
        software_name: toUninstall.name,
        uninstall_id: toUninstall.uninstall_id ?? "",
      })
      setToUninstall(null)
      toast({
        title: t("deviceDetail.theUninstallTaskWas"),
        description: t("deviceDetail.theAgentTakesA"),
        variant: "success",
      })
      const fresh = await api.get<Task[]>(`/devices/${id}/tasks`)
      setTasks(fresh.data ?? [])
    } catch (e) {
      const r = (e as { response?: { status?: number; data?: unknown } }).response
      const text = typeof r?.data === "string" ? r.data.trim() : ""
      toast({
        // 402 — лицензия, 404 — свободная редакция (ручки физически нет), 409 —
        // осмысленный отказ с причиной от сервера. Их важно различать: «попробуйте
        // ещё раз» подходит ровно ни к одному из них.
        title: r?.status === 404
          ? t("deviceDetail.softwareRemovalIsAvailable")
          : r?.status === 402
            ? t("deviceDetail.theLicenseDoesNot")
            : r?.status === 409 && text
              ? text
              : t("deviceDetail.failedToQueueThe2"),
        variant: "destructive",
      })
    } finally {
      setUninstalling(false)
    }
  }

  async function sendReboot() {
    if (!device) return
    setRebooting(true)
    try {
      await api.post(`/devices/${id}/reboot`, { reason: rebootReason, delay_seconds: rebootDelay })
      setRebootOpen(false)
      toast({
        title: t("deviceDetail.rebootScheduled"),
        description: t("deviceDetail.theCommandIsExecuted"),
        variant: "success",
      })
      const fresh = await api.get<Task[]>(`/devices/${id}/tasks`)
      setTasks(fresh.data ?? [])
    } catch (e) {
      const status = (e as { response?: { status?: number } }).response?.status
      toast({
        title: status === 409
          ? t("deviceDetail.theDeviceIsNot")
          : t("deviceDetail.failedToQueueThe"),
        variant: "destructive",
      })
    } finally {
      setRebooting(false)
    }
  }

  // Выгрузка заэскроенного секрета. Сервер отдаёт ШИФРТЕКСТ — расшифровать его он не
  // умеет и не должен; открывает оператор офлайн, утилитой routineops-unseal с шерами
  // приватного ключа. Поэтому здесь только сохранение файла и подсказка с командой.
  async function revealEscrow(secretType: string) {
    setRevealing(true)
    try {
      const r = await api.post<EscrowReveal>(`/devices/${id}/escrow/reveal`, { secret_type: secretType })
      setRevealed(r.data)
      const raw = Uint8Array.from(atob(r.data.ciphertext_b64), (c) => c.charCodeAt(0))
      const url = URL.createObjectURL(new Blob([raw], { type: "application/octet-stream" }))
      const a = document.createElement("a")
      a.href = url
      a.download = `escrow-${secretType}-${r.data.id}.age`
      a.click()
      URL.revokeObjectURL(url)
      const list = await api.get<EscrowRecord[]>(`/devices/${id}/escrow`)
      setEscrow(list.data ?? [])
    } catch {
      // авто-тост интерсептора (403 без гранта, 409 чужой recipient, 404 нет строки)
    } finally {
      setRevealing(false)
    }
  }

  async function toggleBlock() {
    if (!device) return
    setBlocking(true)
    try {
      const next = device.status === "active" ? "blocked" : "active"
      await api.put(`/devices/${id}/status`, { status: next })
      setDevice({ ...device, status: next })
      toast({ title: next === "blocked" ? t("deviceDetail.deviceLocked") : t("deviceDetail.deviceUnlocked"), variant: "success" })
    } finally {
      setBlocking(false)
    }
  }

  async function submitTask() {
    setSubmitting(true)
    try {
      if (taskMode === "library") {
        if (!selectedScript) return
        await api.post(`/devices/${id}/tasks`, {
          script_content: selectedScript.content,
          platform: agentPlatform(selectedScript.platform),
          priority: "normal",
        })
      } else {
        await api.post(`/devices/${id}/tasks`, {
          script_content: taskForm.script,
          platform: taskForm.platform,
          priority: taskForm.priority,
        })
      }
      setTaskOpen(false)
      setSelectedScriptId("")
      setTaskForm({ script: "", platform: "linux", priority: "normal" })
      const fresh = await api.get<Task[]>(`/devices/${id}/tasks`)
      setTasks(fresh.data ?? [])
      toast({ title: t("deviceDetail.theTaskWasSent"), variant: "success" })
    } finally {
      setSubmitting(false)
    }
  }

  async function removeDevice() {
    setDeleting(true)
    try {
      await api.delete(`/devices/${id}`)
      toast({ title: t("deviceDetail.deviceDeleted"), variant: "success" })
      navigate("/devices")
    } catch (e) {
      const status = (e as { response?: { status?: number } }).response?.status
      toast({
        title: status === 409
          ? t("deviceDetail.cannotDeleteRecoveryKeys")
          : t("deviceDetail.failedToDeleteThe"),
        variant: "destructive",
      })
    } finally {
      setDeleting(false)
    }
  }

  async function reenroll() {
    setReenrolling(true)
    try {
      const r = await api.post<ReenrollResponse>(`/devices/${id}/reenroll`, {})
      setReenrollResult(r.data)
    } catch {
      toast({ title: t("deviceDetail.failedToCreateA"), variant: "destructive" })
      setReenrollOpen(false)
    } finally {
      setReenrolling(false)
    }
  }

  function reenrollCommand() {
    if (!reenrollResult) return ""
    const enrollURL = `${window.location.origin}/api/v1/enroll`
    return `agent enroll -enroll-url ${enrollURL} -token ${reenrollResult.enrollment_token}`
  }

  async function copyCommand() {
    await navigator.clipboard.writeText(reenrollCommand())
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  if (loading) return <p className="text-muted-foreground text-sm">{t("deviceDetail.loading")}</p>
  if (!device) return <p className="text-destructive text-sm">{t("deviceDetail.deviceNotFound")}</p>

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={() => navigate("/devices")}
          className="text-muted-foreground hover:text-foreground transition-colors"
        >
          <ChevronLeft className="h-5 w-5" strokeWidth={2} />
        </button>
        <h1 className="text-xl font-semibold text-foreground">{device.hostname}</h1>
        {statusBadge(device.status)}
        {device.lock_status === "locked" && <Badge variant="destructive">{t("deviceDetail.theScreenIsLocked")}</Badge>}
        {/* Фактическое состояние лока расходится с желаемым — оператору это ВАЖНЕЕ
            бейджа «заблокировано» рядом: машина в этот момент рабочая либо закрыта
            наполовину. Пусто/unlocked-совпадение ничего не рисуем — шум. */}
        {lockDivergence(device) && (
          <Badge variant="outline" className="border-amber-500 text-amber-600 dark:text-amber-400"
                 title={t(lockDivergence(device)!.hint)}>
            ⚠ {t(lockDivergence(device)!.label)}
          </Badge>
        )}
        {/* Очередь отчётов мертва: устройство на связи, но всё, что оно должно
            рассказывать, теряется по дороге. Рисуем рядом со статусом именно потому,
            что остальные признаки на этой карточке в такой момент недостоверны —
            включая бейдж лока выше. */}
        {device.outbox_unavailable && (
          <Badge variant="outline" className="border-violet-500 text-violet-600 dark:text-violet-400"
                 title={t("deviceDetail.blindTitle") +
                   (device.degraded_detail ? ".\n" + t("deviceDetail.blindReason", { detail: device.degraded_detail }) : "") +
                   (device.degraded_since ? "\n" + t("deviceDetail.blindSince", { since: formatDateTime(device.degraded_since) }) : "")}>
            {t("deviceDetail.agentBlind")}
          </Badge>
        )}
        {device.groups?.map((g) => <GroupBadge key={g.id} group={g} />)}
        <div className="ml-auto flex gap-2">
          {/* Действия: перерегистрация и блокировка — только it_admin */}
          {isAdmin && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                {t("deviceDetail.actions")} <ChevronDown className="ml-1 h-3.5 w-3.5 opacity-60" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem disabled={reenrolling} onSelect={() => { setReenrollOpen(true); if (!reenrollResult) reenroll() }}>
                {t("deviceDetail.reenroll")}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              {device.lock_status === "locked" ? (
                <DropdownMenuItem onSelect={sendUnlock}>
                  {t("deviceDetail.unlockScreen")}
                </DropdownMenuItem>
              ) : (
                <DropdownMenuItem
                  onSelect={() => { setLockPassword(null); setLockReason(""); setLockOpen(true) }}
                  disabled={device.status !== "active"}
                >
                  {t("deviceDetail.lockTheScreen")}
                </DropdownMenuItem>
              )}
              <DropdownMenuSeparator />
              {/* Разблокировка = PUT status=active, а сервер такой переход из очереди
                  одобрения и терминальных состояний отбивает 409-й (handler.go:629).
                  Раньше пункт для них был ВКЛЮЧЁН и звал «Разблокировать доступ» —
                  клик приводил к сырому английскому тексту ошибки в тосте.
                  Разрешаем только там, где блокировка реально применима. */}
              <DropdownMenuItem
                destructive
                disabled={blocking || (device.status !== "active" && device.status !== "blocked")}
                onSelect={() => device.status === "active" ? setConfirmBlock(true) : toggleBlock()}
              >
                {device.status === "active" ? t("deviceDetail.blockAccess2") : t("deviceDetail.unblockAccess")}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              {/* Перезагрузка только для active: остальные состояния сервер отбивает 409
                  (Connect их не примет, задача висела бы pending). */}
              <DropdownMenuItem
                disabled={rebooting || device.status !== "active"}
                onSelect={() => { setRebootReason(""); setRebootDelay(REBOOT_DELAYS[0].value); setRebootOpen(true) }}
              >
                {t("deviceDetail.reboot")}
              </DropdownMenuItem>
              {/* Перенос между тенантами — только надзор над инсталляцией и только
                  когда тенантов больше одного: иначе пункт меню обещает выбор,
                  которого нет. */}
              {isProvider && allTenants.length > 1 && (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    disabled={moving}
                    onSelect={() => { setMoveTo(""); setMoveOpen(true) }}
                  >
                    {t("deviceDetail.moveTenant")}
                  </DropdownMenuItem>
                </>
              )}
              <DropdownMenuSeparator />
              {/* Гасим только уже списанные — сервер на них отвечает 409 (handler.go:1155).
                  Оффлайн-машину списывать РАЗРЕШАЕМ: задача штатно ждёт выхода на связь. */}
              <DropdownMenuItem
                destructive
                disabled={decommissioning || device.status === "decommissioned"}
                onSelect={() => { setDecomReason(""); setDecomTyped(""); setDecomOpen(true) }}
              >
                {t("deviceDetail.decommission")}
              </DropdownMenuItem>
              {/* Только для decommissioned: delete на живом устройстве воскрешает его
                  скелетом (агент апсертит строку heartbeat'ом в gateway) и сиротеет.
                  Сначала «Вывести из эксплуатации» снимает агента, потом чистим запись.
                  Never-connected удаляют в EnrollmentQueue — там свой гард по last_seen. */}
              {device.status === "decommissioned" && (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem destructive disabled={deleting} onSelect={() => setConfirmDelete(true)}>
                    {t("deviceDetail.deleteFromInventory")}
                  </DropdownMenuItem>
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
          )}

          {/* Диалог перерегистрации (открывается из dropdown) */}
          <Dialog open={reenrollOpen} onOpenChange={(o) => { setReenrollOpen(o); if (!o) { setReenrollResult(null); setCopied(false) } }}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>{t("deviceDetail.deviceReEnrollment")}</DialogTitle>
              </DialogHeader>
              {reenrollResult ? (
                <div className="space-y-4 pt-2">
                  <p className="text-sm text-muted-foreground">{t("deviceDetail.runItOnThe")}</p>
                  <div className="relative">
                    <pre className="rounded-md border border-border bg-muted px-3 py-3 text-xs font-mono break-all whitespace-pre-wrap pr-10 text-soft">
                      {reenrollCommand()}
                    </pre>
                    <button
                      type="button"
                      onClick={copyCommand}
                      className="absolute right-2 top-2 rounded p-1 text-muted-foreground hover:text-foreground transition-colors"
                    >
                      {copied ? <Check className="h-4 w-4 text-emerald-600 dark:text-emerald-500" /> : <Copy className="h-4 w-4" />}
                    </button>
                  </div>
                  <p className="text-xs text-muted-foreground font-mono">{reenrollResult.enrollment_token}</p>
                  <Button className="w-full" variant="outline" onClick={() => setReenrollOpen(false)}>
                    {t("deviceDetail.done")}
                  </Button>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground pt-2">{t("deviceDetail.generatingAToken")}</p>
              )}
            </DialogContent>
          </Dialog>

          {/* Единый диалог задачи: библиотека / вручную */}
          <Dialog open={taskOpen} onOpenChange={(o) => { setTaskOpen(o); if (!o) { setSelectedScriptId(""); setTaskForm({ script: "", platform: "linux", priority: "normal" }) } }}>
            {isAdmin && (
            <DialogTrigger asChild>
              <Button size="sm" onClick={() => openTaskDialog("library")}>{t("deviceDetail.newTask")}</Button>
            </DialogTrigger>
            )}
            <DialogContent>
              <DialogHeader>
                <DialogTitle>{t("deviceDetail.newTaskFor", { name: device.hostname })}</DialogTitle>
              </DialogHeader>
              <div className="space-y-4 pt-2">
                {/* Переключатель режима */}
                <div className="flex rounded-md border border-border p-0.5 gap-0.5">
                  {(["library", "manual"] as TaskMode[]).map((mode) => (
                    <button
                      type="button"
                      key={mode}
                      onClick={() => setTaskMode(mode)}
                      className={[
                        "flex-1 rounded px-3 py-1.5 text-sm font-medium transition-colors",
                        taskMode === mode
                          ? "brand-gradient text-white dark:text-[hsl(224_14%_10%)]"
                          : "text-muted-foreground hover:text-foreground",
                      ].join(" ")}
                    >
                      {mode === "library" ? t("deviceDetail.fromTheLibrary") : t("deviceDetail.writeByHand")}
                    </button>
                  ))}
                </div>

                {taskMode === "library" ? (
                  <>
                    <div className="space-y-1.5">
                      <Label>{t("deviceDetail.scriptFor", { os: device.os })}</Label>
                      {runnableScripts.length === 0 ? (
                        <p className="text-sm text-muted-foreground">
                          {t("deviceDetail.noScriptsForOS")}
                        </p>
                      ) : (
                        <Select
                          value={selectedScriptId}
                          onChange={setSelectedScriptId}
                          placeholder={t("deviceDetail.chooseAScript")}
                          options={[{ value: "", label: t("deviceDetail.chooseAScript"), disabled: true }, ...scriptOptions]}
                        />
                      )}
                    </div>
                    {selectedScript && (
                      <pre className="rounded-md border border-border bg-muted px-3 py-2 text-xs font-mono whitespace-pre-wrap break-all max-h-48 overflow-auto text-soft">
                        {selectedScript.content}
                      </pre>
                    )}
                    <Button
                      className="w-full"
                      onClick={submitTask}
                      disabled={submitting || !selectedScript}
                    >
                      {submitting ? t("deviceDetail.running") : t("deviceDetail.run")}
                    </Button>
                  </>
                ) : (
                  <>
                    <div className="space-y-1.5">
                      <Label htmlFor="task-script">{t("deviceDetail.script")}</Label>
                      <textarea
                        id="task-script"
                        className="flex min-h-[120px] w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring font-mono"
                        placeholder="#!/bin/bash&#10;echo hello"
                        value={taskForm.script}
                        onChange={(e) => setTaskForm({ ...taskForm, script: e.target.value })}
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="space-y-1.5">
                        <Label>{t("deviceDetail.platform2")}</Label>
                        <Select
                          value={taskForm.platform}
                          onChange={(v) => setTaskForm({ ...taskForm, platform: v })}
                          options={PLATFORM_OPTIONS}
                        />
                      </div>
                      <div className="space-y-1.5">
                        <Label>{t("deviceDetail.priority2")}</Label>
                        <Select
                          value={taskForm.priority}
                          onChange={(v) => setTaskForm({ ...taskForm, priority: v })}
                          options={PRIORITY_OPTIONS.map((o) => ({ ...o, label: t(o.label) }))}
                        />
                      </div>
                    </div>
                    <Button
                      className="w-full"
                      onClick={submitTask}
                      disabled={submitting || !taskForm.script}
                    >
                      {submitting ? t("deviceDetail.sending") : t("deviceDetail.create")}
                    </Button>
                  </>
                )}
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {[
          { label: t("deviceDetail.os"),              value: `${device.os} ${device.os_version}` },
          { label: "IP",              value: device.ip_address || "—"            },
          { label: t("deviceDetail.lastSeen"),   value: device.last_seen_at ? formatDistanceToNow(device.last_seen_at) : "—" },
          { label: t("deviceDetail.enrolled"),value: formatDistanceToNow(device.created_at) },
        ].map(({ label, value }) => (
          <div key={label} className="glass px-5 py-[18px]">
            <p className="text-xs text-muted-foreground">{label}</p>
            <p className="text-sm font-medium text-foreground mt-1 truncate">{value}</p>
          </div>
        ))}
      </div>

      <OwnerCard
        device={device}
        isAdmin={isAdmin}
        onChanged={async () => {
          const d = await api.get<DeviceDetailResponse>(`/devices/${id}`)
          setDevice(d.data.device)
        }}
      />

      <div className="glass px-5 py-[18px]">
        <h2 className="text-[15px] font-semibold text-foreground flex items-center gap-2 mb-4">
          <ShieldCheck className="h-[17px] w-[17px] text-muted-foreground" strokeWidth={2} />
          {t("deviceDetail.diagnostics")}
        </h2>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="space-y-3">
            <div>
              <p className="text-xs text-soft mb-0.5">{t("deviceDetail.consoleUser")}</p>
              <p className="text-sm text-foreground">{device.console_user || "—"}</p>
            </div>
            <div>
              <p className="text-xs text-soft mb-0.5">Device ID (cert CN)</p>
              <p className="text-sm font-mono text-foreground">{device.cert_cn || "—"}</p>
            </div>
            <div>
              <p className="text-xs text-soft mb-0.5">{t("deviceDetail.enrollment")}</p>
              <p className="text-sm text-foreground">{device.enrolled_at ? formatDistanceToNow(device.enrolled_at) : "—"}</p>
            </div>
            <div>
              <p className="text-xs text-soft mb-0.5">{t("deviceDetail.macAddress")}</p>
              <p className="text-sm font-mono text-foreground">{device.mac_address || "—"}</p>
            </div>
            <div>
              <p className="text-xs text-soft mb-0.5">{t("deviceDetail.serialNumberSn")}</p>
              <p className="text-sm font-mono text-foreground">{device.serial_number || "—"}</p>
            </div>
            <div>
              <p className="text-xs text-soft mb-0.5">{t("deviceDetail.agentVersion")}</p>
              <p className="text-sm font-mono text-foreground">{device.agent_version || "—"}</p>
            </div>
            <div>
              <p className="text-xs text-soft mb-0.5">{t("deviceDetail.internalIp")}</p>
              <p className="text-sm font-mono text-foreground">{device.ip_address || "—"}</p>
            </div>
            <div>
              <p className="text-xs text-soft mb-0.5">{t("deviceDetail.externalIp")}</p>
              <p className="text-sm font-mono text-foreground">{device.public_ip || "—"}</p>
            </div>
          </div>
          <div className="space-y-3">
            {device.cpu && (
              <div className="flex items-start gap-2">
                <Cpu className="h-3.5 w-3.5 text-muted-foreground mt-0.5 shrink-0" strokeWidth={2} />
                <div>
                  <p className="text-xs text-soft">CPU</p>
                  <p className="text-sm text-foreground">{device.cpu}</p>
                </div>
              </div>
            )}
            {device.ram_mb > 0 && (
              <div className="flex items-start gap-2">
                <MemoryStick className="h-3.5 w-3.5 text-muted-foreground mt-0.5 shrink-0" strokeWidth={2} />
                <div>
                  <p className="text-xs text-soft">RAM</p>
                  <p className="text-sm text-foreground">{t("deviceDetail.gigabytes", { value: (device.ram_mb / 1024).toFixed(1) })}</p>
                </div>
              </div>
            )}
            {device.disk && (
              <div className="flex items-start gap-2">
                <HardDrive className="h-3.5 w-3.5 text-muted-foreground mt-0.5 shrink-0" strokeWidth={2} />
                <div>
                  <p className="text-xs text-soft">{t("deviceDetail.diskC")}</p>
                  <p className="text-sm text-foreground">{device.disk}</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="glass">
        <div className="px-5 pt-4 pb-3">
          <h2 className="text-[15px] font-semibold text-foreground flex items-center gap-2">
            <Terminal className="h-[17px] w-[17px] text-muted-foreground" strokeWidth={2} />
            {t("deviceDetail.tasks")}
          </h2>
        </div>
        <div>
          {tasks.length === 0 && (
            <p className="border-t border-border px-5 py-6 text-center text-xs text-muted-foreground">
              {t("deviceDetail.noTasks")}
            </p>
          )}
          {/* Переменная называется task: t() из useTranslation закрылась бы ей. */}
          {tasks.map((task) => {
            const hasLog = !!(task.output || task.error_log || task.script_content)
            return (
              <div
                key={task.id}
                className={[
                  "flex items-center justify-between gap-4 border-t border-border px-5 py-3 last:rounded-b-2xl",
                  hasLog ? "cursor-pointer glass-hover" : "",
                ].join(" ")}
                onClick={() => hasLog && setLogTask(task)}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <Badge variant={taskStatusVariant[task.status]}>
                    {taskStatusLabel[task.status] ? i18n.t(taskStatusLabel[task.status]) : task.status}
                  </Badge>
                  {/* Исход удаления вместо платформы: у uninstall-задачи «linux/normal»
                      не говорит ничего, а исход — единственное, что оператору нужно.
                      Незнакомое значение показываем как есть: сервер хранит домен
                      открытым, и новый исход агента должен быть виден, а не пропасть. */}
                  {task.uninstall_outcome ? (
                    <>
                      <Badge
                        variant="outline"
                        title={UNINSTALL_OUTCOME[task.uninstall_outcome] ? i18n.t(UNINSTALL_OUTCOME[task.uninstall_outcome].hint) : undefined}
                        className={task.uninstall_outcome === "removed"
                          ? "border-emerald-500 text-emerald-600 dark:text-emerald-400"
                          : "border-amber-500 text-amber-600 dark:text-amber-400"}
                      >
                        {UNINSTALL_OUTCOME[task.uninstall_outcome] ? i18n.t(UNINSTALL_OUTCOME[task.uninstall_outcome].label) : task.uninstall_outcome}
                      </Badge>
                      <span className="text-[13px] text-soft truncate">
                        {task.uninstall?.software_name}
                      </span>
                    </>
                  ) : (
                    <>
                      <span className="text-[13px] text-soft truncate">{task.platform}</span>
                      <span className="text-xs text-muted-foreground">{task.priority}</span>
                    </>
                  )}
                </div>
                <div className="flex items-center gap-4 flex-shrink-0">
                  <span className="text-xs text-muted-foreground">{formatDistanceToNow(task.created_at)}</span>
                  {hasLog && <span className="text-xs text-brand">{t("deviceDetail.log")}</span>}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {escrow.length > 0 && (
        <div className="glass">
          <div className="px-5 pt-4 pb-3">
            <h2 className="text-[15px] font-semibold text-foreground">{t("deviceDetail.recoveryKeysEscrow")}</h2>
            <p className="text-xs text-muted-foreground mt-1">
              {t("deviceDetail.escrowHint1")}
              <Trans i18nKey="deviceDetail.escrowHint2" components={[<span className="font-mono" />]} />
            </p>
          </div>
          <div>
            {escrow.map((e) => (
              <div key={e.id} className="flex items-center justify-between gap-4 border-t border-border px-5 py-3 last:rounded-b-2xl">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-foreground truncate">
                      {ESCROW_SECRET_TYPE[e.secret_type] ? i18n.t(ESCROW_SECRET_TYPE[e.secret_type]) : e.secret_type}
                    </span>
                    {e.latest && <Badge variant="outline">{t("deviceDetail.current")}</Badge>}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {t("deviceDetail.escrowedAt", { when: formatDistanceToNow(e.escrowed_at) })}
                    {e.agent_version && " · " + t("deviceDetail.escrowAgent", { version: e.agent_version })}
                    {e.revealed_at && " · " + t("deviceDetail.escrowRevealed", { who: e.revealed_by || "—", when: formatDistanceToNow(e.revealed_at) })}
                  </div>
                </div>
                {/* Выгружаем только актуальную строку: устаревший ключ откроется, но
                    машину им уже не разблокировать — PRK ротируется при перевыпуске. */}
                {e.latest && (
                  <Button size="sm" variant="outline" disabled={revealing} onClick={() => revealEscrow(e.secret_type)}>
                    {revealing ? "..." : t("deviceDetail.reveal")}
                  </Button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Экран устройства (ADR-8, только Enterprise). Секция сама прячется, если
          ручек нет: в open-core их не существует вовсе. */}
      <ScreenSessionPanel deviceId={id!} />

      {vulns.length > 0 && (
        <div className="glass">
          <div className="px-5 pt-4 pb-3">
            <h2 className="text-[15px] font-semibold text-foreground">{t("deviceDetail.vulnerabilitiesCve")}</h2>
          </div>
          <div>
            {vulns.map((v) => (
              <div
                key={`${v.cve_id}|${v.software_name}`}
                className="flex items-center justify-between gap-4 border-t border-border px-5 py-3 last:rounded-b-2xl"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-foreground truncate">{v.cve_id}</span>
                    <span className="text-xs font-medium bg-destructive/10 text-destructive px-1.5 py-0.5 rounded-md">
                      CVSS {v.cvss_score ?? "N/A"}
                    </span>
                  </div>
                  <div className="text-xs text-muted-foreground truncate mt-0.5">
                    {v.software_name}
                  </div>
                  <div className="text-sm text-muted-foreground mt-1 line-clamp-2">
                    {v.description}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {software.length > 0 && (
        <div className="glass">
          <div className="px-5 pt-4 pb-3">
            <h2 className="text-[15px] font-semibold text-foreground">{t("deviceDetail.software")}</h2>
          </div>
          <div>
            {software.map((s) => (
              // Ключ составной: одно и то же имя приезжает дважды — установка на
              // машину и установка в профиль пользователя это разные записи.
              <div
                key={`${s.name}|${s.scope ?? ""}|${s.uninstall_id ?? ""}`}
                className="flex items-center justify-between gap-4 border-t border-border px-5 py-3 last:rounded-b-2xl"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-foreground truncate">{s.name}</span>
                    {s.scope === "user" && (
                      <span
                        className="flex-shrink-0 rounded-md bg-amber-500/10 px-1.5 py-0.5 text-[11px] font-medium text-amber-600 dark:text-amber-500"
                        title={t("deviceDetail.installedIntoAUser")}
                      >
                        {t("deviceDetail.inUserProfile")}
                      </span>
                    )}
                  </div>
                  {(s.vendor || s.arch) && (
                    <div className="text-xs text-muted-foreground truncate">
                      {[s.vendor, s.arch].filter(Boolean).join(" · ")}
                    </div>
                  )}
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  <span className="text-xs text-muted-foreground">{s.version}</span>
                  {/* Кнопку рисуем только там, где метод снятия ЕСТЬ. Пустой метод — не
                      «попробуем и посмотрим»: коллектор агента оставляет его пустым
                      ровно там, где снять нечем (per-user под Windows, защищённое SIP).
                      Кнопка на такой записи гарантированно вернула бы NOT_REMOVABLE. */}
                  {isAdmin && s.uninstall_method && (
                    <Button
                      variant="ghost"
                      size="sm"
                      aria-label={t("deviceDetail.removeAria", { name: s.name })}
                      title={t("deviceDetail.removeFromTheDevice")}
                      onClick={() => setToUninstall(s)}
                      className="text-muted-foreground hover:text-destructive"
                    >
                      <Trash2 className="h-4 w-4" strokeWidth={2} />
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Подтверждение удаления ПО. Показываем весь селектор, а не одно имя: одноимённых
          записей на машине бывает две (разные версии, разные вендоры), и оператор должен
          видеть, какую именно он сносит. */}
      <Dialog open={toUninstall !== null} onOpenChange={(o) => { if (!o) setToUninstall(null) }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("deviceDetail.removeTheProgramFrom")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 pt-2">
            <div className="rounded-lg border border-border px-3 py-2 text-sm">
              <div className="font-medium text-foreground">{toUninstall?.name}</div>
              <div className="text-xs text-muted-foreground">
                {[toUninstall?.version, toUninstall?.vendor, toUninstall?.uninstall_method]
                  .filter(Boolean).join(" · ")}
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              {t("deviceDetail.uninstallHint")}
            </p>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setToUninstall(null)} disabled={uninstalling}>
                {t("deviceDetail.cancel")}
              </Button>
              <Button variant="destructive" onClick={sendUninstall} disabled={uninstalling}>
                {uninstalling ? t("deviceDetail.sending") : t("deviceDetail.delete")}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Task log dialog */}
      <Dialog open={!!logTask} onOpenChange={(o) => !o && setLogTask(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Terminal className="h-4 w-4 text-muted-foreground" strokeWidth={2} />
              {t("deviceDetail.taskLog")}
              {logTask && (
                <Badge variant={taskStatusVariant[logTask.status]} className="ml-1">
                  {taskStatusLabel[logTask.status] ? t(taskStatusLabel[logTask.status]) : logTask.status}
                </Badge>
              )}
            </DialogTitle>
          </DialogHeader>
          {logTask && (
            <div className="space-y-4 pt-1">
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <span>{t("deviceDetail.platform")} <span className="text-foreground">{logTask.platform}</span></span>
                <span>{t("deviceDetail.priority")} <span className="text-foreground">{logTask.priority}</span></span>
                <span>{t("deviceDetail.created")} <span className="text-foreground">{formatDistanceToNow(logTask.created_at)}</span></span>
              </div>

              {logTask.script_content && (
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground">{t("deviceDetail.script")}</p>
                  <pre className="rounded-md border border-border bg-muted px-3 py-2.5 text-xs font-mono whitespace-pre-wrap break-all max-h-40 overflow-auto text-soft">
                    {logTask.script_content}
                  </pre>
                </div>
              )}

              {logTask.output && (
                <div className="space-y-1">
                  <p className="text-xs font-medium text-emerald-600 dark:text-emerald-400">{t("deviceDetail.output")}</p>
                  <pre className="rounded-md border border-emerald-500/20 bg-emerald-500/5 px-3 py-2.5 text-xs font-mono whitespace-pre-wrap break-all max-h-64 overflow-auto text-foreground">
                    {logTask.output}
                  </pre>
                </div>
              )}

              {logTask.error_log && (
                <div className="space-y-1">
                  <p className="text-xs font-medium text-destructive">{t("deviceDetail.errors")}</p>
                  <pre className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2.5 text-xs font-mono whitespace-pre-wrap break-all max-h-64 overflow-auto text-destructive">
                    {logTask.error_log}
                  </pre>
                </div>
              )}

              {!logTask.output && !logTask.error_log && (
                <p className="text-sm text-muted-foreground">
                  {logTask.status === "pending" || logTask.status === "acked"
                    ? t("deviceDetail.theTaskIsStill")
                    : t("deviceDetail.noOutput")}
                </p>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={confirmBlock}
        onOpenChange={setConfirmBlock}
        title={t("deviceDetail.blockAccess")}
        description={t("deviceDetail.blockWarn", { name: device.hostname })}
        confirmLabel={t("deviceDetail.lock")}
        destructive
        onConfirm={toggleBlock}
      />

      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title={t("deviceDetail.deleteTheDevice")}
        description={t("deviceDetail.deleteWarn", { name: device.hostname })}
        confirmLabel={t("deviceDetail.delete")}
        destructive
        onConfirm={removeDevice}
      />

      {/* Диалог блокировки экрана */}
      <Dialog open={lockOpen} onOpenChange={(o) => { setLockOpen(o); if (!o) { setLockPassword(null); setLockReason("") } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("deviceDetail.lockTheScreen")}</DialogTitle>
          </DialogHeader>
          {lockPassword ? (
            <div className="space-y-4 pt-2">
              <p className="text-sm text-muted-foreground">{t("deviceDetail.theCommandWasSent")}</p>
              <div className="relative">
                <pre className="rounded-md border border-border bg-muted px-3 py-3 text-sm font-mono pr-10 text-foreground">{lockPassword}</pre>
                <button
                  type="button"
                  onClick={async () => {
                    await navigator.clipboard.writeText(lockPassword).catch(() => {})
                    setLockCopied(true)
                    setTimeout(() => setLockCopied(false), 2000)
                  }}
                  className="absolute right-2 top-2 rounded p-1 text-muted-foreground hover:text-foreground transition-colors"
                >
                  {lockCopied ? <Check className="h-4 w-4 text-emerald-600 dark:text-emerald-500" /> : <Copy className="h-4 w-4" />}
                </button>
              </div>
              <Button className="w-full" variant="outline" onClick={() => setLockOpen(false)}>{t("deviceDetail.close")}</Button>
            </div>
          ) : (
            <div className="space-y-4 pt-2">
              <p className="text-sm text-muted-foreground">
                {t("deviceDetail.lockHint")}
              </p>
              <div className="space-y-1.5">
                <Label htmlFor="lock-reason">{t("deviceDetail.reasonOptional")}</Label>
                <input
                  id="lock-reason"
                  className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  placeholder={t("deviceDetail.securityIncidentLostLaptop")}
                  value={lockReason}
                  onChange={(e) => setLockReason(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && sendLock()}
                />
              </div>
              <Button className="w-full" onClick={sendLock} disabled={locking}>
                {locking ? t("deviceDetail.sending") : t("deviceDetail.lockTheScreen")}
              </Button>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Диалог вывода из эксплуатации. Отдельный, а не ConfirmDialog: нужны причина
          для аудита и ввод имени руками — операция необратима. */}
      <Dialog open={moveOpen} onOpenChange={setMoveOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("deviceDetail.moveTitle", { name: device.hostname })}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="move-tenant">{t("deviceDetail.tenant")}</Label>
              <select
                id="move-tenant"
                value={moveTo}
                onChange={(e) => setMoveTo(e.target.value)}
                className="w-full h-9 rounded-md border bg-background px-3 text-sm"
              >
                <option value="">{t("deviceDetail.choose")}</option>
                {allTenants
                  .filter((t) => t.id !== device.tenant_id)
                  .map((tn) => <option key={tn.id} value={tn.id}>{tn.name}</option>)}
              </select>
            </div>
            <p className="text-xs text-muted-foreground">
              {t("deviceDetail.moveHint")}
            </p>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setMoveOpen(false)} disabled={moving}>
                {t("deviceDetail.cancel")}
              </Button>
              <Button onClick={moveTenant} disabled={moving || moveTo === ""}>
                {moving ? t("deviceDetail.moving") : t("deviceDetail.move")}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={decomOpen} onOpenChange={(o) => { setDecomOpen(o); if (!o) { setDecomReason(""); setDecomTyped("") } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("deviceDetail.decommission")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 pt-2">
            <p className="text-sm text-soft">
              {t("deviceDetail.decommissionHint", { name: device.hostname })}
            </p>
            <p className="text-sm text-soft">
              {t("deviceDetail.decommissionDelivery")}
            </p>
            <div className="space-y-1.5">
              <Label htmlFor="decom-reason">{t("deviceDetail.reasonOptional")}</Label>
              <Input
                id="decom-reason"
                placeholder={t("deviceDetail.hardwareWriteOffEmployee")}
                value={decomReason}
                onChange={(e) => setDecomReason(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="decom-confirm">
                <Trans i18nKey="deviceDetail.typeToConfirm" values={{ name: device.hostname }} components={[<span className="font-mono text-foreground" />]} />
              </Label>
              <Input
                id="decom-confirm"
                className="font-mono"
                autoComplete="off"
                value={decomTyped}
                onChange={(e) => setDecomTyped(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && decommissionArmed(device.hostname, decomTyped)) sendDecommission()
                }}
              />
            </div>
            <Button
              className="w-full"
              variant="destructive"
              onClick={sendDecommission}
              disabled={decommissioning || !decommissionArmed(device.hostname, decomTyped)}
            >
              {decommissioning ? t("deviceDetail.sending") : t("deviceDetail.decommission")}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Что делать с выгруженным файлом — показываем сразу после скачивания:
          команду с нужными аргументами оператор в инциденте вспоминать не должен. */}
      <Dialog open={!!revealed} onOpenChange={(o) => !o && setRevealed(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("deviceDetail.keyRevealed")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">
              {t("deviceDetail.revealSaved")}
            </p>
            <pre className="text-xs font-mono bg-muted/40 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap break-all">
{`routineops-unseal unseal \\
  -blob escrow-${revealed?.secret_type}-${revealed?.id}.age \\
  -expect-device ${revealed?.device_id} \\
  -expect-type ${revealed?.secret_type} \\
  -share share1.txt -share share2.txt`}
            </pre>
            <p className="text-xs text-muted-foreground">
              {t("deviceDetail.revealAudited")}
            </p>
          </div>
        </DialogContent>
      </Dialog>

      {/* Перезагрузка */}
      <Dialog open={rebootOpen} onOpenChange={setRebootOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("deviceDetail.rebootTitle", { name: device.hostname })}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              {t("deviceDetail.rebootDelayHint")}
              {/* device.os — сырая строка от агента, не ScriptPlatform: сверяем подстрокой. */}
              {!/win/i.test(device.os) && (
                <> {t("deviceDetail.rebootNoWarningHint")}</>
              )}
            </p>
            <div className="space-y-1.5">
              <Label>{t("deviceDetail.when")}</Label>
              <Select
                value={String(rebootDelay)}
                onChange={(v) => setRebootDelay(Number(v))}
                options={REBOOT_DELAYS.map((d) => ({ value: String(d.value), label: i18n.t(d.label) }))}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="reboot-reason">{t("deviceDetail.reasonOptional")}</Label>
              <Input
                id="reboot-reason"
                placeholder={t("deviceDetail.installingSecurityUpdates")}
                value={rebootReason}
                onChange={(e) => setRebootReason(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                {t("deviceDetail.windowsNoticeHint")}
              </p>
            </div>
            <Button className="w-full" onClick={sendReboot} disabled={rebooting}>
              {rebooting ? t("deviceDetail.sending") : t("deviceDetail.scheduleAReboot")}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}

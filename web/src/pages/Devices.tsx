import { useEffect, useRef, useState } from "react"
import { useNavigate } from "react-router-dom"
import { Copy, Check, ChevronRight } from "lucide-react"
import api, { Device, CreateDeviceResponse, DeviceGroup, DEVICE_STATUS, PAGE_SIZE, totalCount } from "@/lib/api"
import Pager from "@/components/Pager"
import { GroupBadges, groupAccent } from "@/components/GroupBadge"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Select } from "@/components/ui/select"
import { formatDistanceToNow } from "@/lib/time"
import { useMe } from "@/lib/useMe"

type DialogStep = "form" | "token"

function apiBase() {
  return window.location.origin
}

function isOnline(device: Device): boolean {
  if (!device.last_seen_at) return false
  return Date.now() - new Date(device.last_seen_at).getTime() < 2 * 60 * 1000
}

function OnlineBadge({ device }: { device: Device }) {
  const online = isOnline(device)
  return (
    <span className="flex items-center gap-1.5">
      <span className={`h-2 w-2 rounded-full flex-shrink-0 ${online ? "bg-emerald-500" : "bg-muted-foreground/40"}`} />
      <span className={`text-[13px] ${online ? "text-emerald-600 dark:text-emerald-400" : "text-muted-foreground"}`}>
        {online ? "Онлайн" : "Офлайн"}
      </span>
    </span>
  )
}

const stripSeparators = (s: string) => s.replace(/[:\-. ]/g, "")

// matchHint объясняет, ПОЧЕМУ устройство попало в выдачу, когда совпал атрибут,
// которого нет в таблице (серийник, MAC, внешний IP). Иначе поиск по хвосту
// серийника выглядит как случайная строка.
function matchHint(d: Device, query: string): string | null {
  const q = query.trim().toLowerCase()
  if (!q) return null

  const visible = `${d.hostname} ${d.ip_address ?? ""}`.toLowerCase()
  if (visible.includes(q)) return null

  const sq = stripSeparators(q)
  const hits = (value?: string) => {
    const v = (value ?? "").toLowerCase()
    if (!v) return false
    return v.includes(q) || (sq !== "" && stripSeparators(v).includes(sq))
  }

  if (hits(d.serial_number)) return `S/N ${d.serial_number}`
  if (hits(d.mac_address)) return `MAC ${d.mac_address}`
  if (hits(d.public_ip)) return `Внешний IP ${d.public_ip}`
  return null
}

function osIcon(os: string) {
  const defaultIcon = <img src="/linux.png" alt="Linux" className="w-3.5 h-3.5 inline-block mr-1 align-text-bottom" />
  if (!os) return defaultIcon
  const l = os.toLowerCase()
  if (l.includes("win")) return <img src="/windows.png" alt="Windows" className="w-3.5 h-3.5 inline-block mr-1 align-text-bottom" />
  if (l.includes("mac") || l.includes("darwin")) return <img src="/apple.png" alt="macOS" className="w-3.5 h-3.5 inline-block mr-1 align-text-bottom" />
  return defaultIcon
}

// ALL_GROUPS — значение Select'а «все устройства». Пустая строка не годится: наш Select
// показывает placeholder вместо выбранной опции, когда value пустое.
const ALL_GROUPS = "all"

export default function Devices() {
  const [devices, setDevices] = useState<Device[]>([])
  const [groups, setGroups] = useState<DeviceGroup[]>([])
  const [groupId, setGroupId] = useState(ALL_GROUPS)
  // Сервер отдаёт только заэнроленные устройства (pending скрыты). Только что созданное
  // держим отдельно, иначе серверный рефетч по поиску стирал бы его с экрана.
  const [justCreated, setJustCreated] = useState<Device[]>([])
  const [loading, setLoading] = useState(true)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [step, setStep] = useState<DialogStep>("form")
  const [os, setOs] = useState("linux")
  const [creating, setCreating] = useState(false)
  const [result, setResult] = useState<CreateDeviceResponse | null>(null)
  const [copied, setCopied] = useState(false)
  const [arch, setArch] = useState("amd64")
  const [query, setQuery] = useState("")
  const [offset, setOffset] = useState(0)
  const [total, setTotal] = useState(0)
  const navigate = useNavigate()
  const { isAdmin } = useMe()
  // Счётчик запросов: медленный ответ по старому запросу не должен затирать свежий.
  const reqSeq = useRef(0)

  // Поиск, фильтр по группе и страница — серверные: поиск лезет в атрибуты, которых нет
  // в таблице (MAC, серийник, CPU), членство в группе живёт в отдельной таблице, а парк
  // целиком в браузер больше не едет.
  useEffect(() => {
    const q = query.trim()
    const params = new URLSearchParams()
    if (q) params.set("q", q)
    if (groupId !== ALL_GROUPS) params.set("group_id", groupId)
    params.set("limit", String(PAGE_SIZE))
    if (offset) params.set("offset", String(offset))
    const seq = ++reqSeq.current
    const timer = setTimeout(() => {
      api
        .get<Device[]>(`/devices?${params.toString()}`)
        .then((r) => {
          if (seq !== reqSeq.current) return
          const rows = r.data ?? []
          // Страница пуста, а мы не на первой — устройства удалили, пока листали.
          // Возвращаемся в начало: total на пустой странице приходит нулём (счётчик
          // едет окном вместе со строками), и пагинатор нарисовал бы «0 записей».
          if (rows.length === 0 && offset > 0) {
            setOffset(0)
            return
          }
          setDevices(rows)
          setTotal(totalCount(r.headers, rows.length))
        })
        .finally(() => {
          if (seq === reqSeq.current) setLoading(false)
        })
    }, q ? 250 : 0)
    return () => clearTimeout(timer)
  }, [query, groupId, offset])

  // Группы нужны только для выпадашки фильтра — тянем один раз. Ошибку глотаем: без
  // списка групп страница устройств остаётся полностью рабочей.
  useEffect(() => {
    api.get<DeviceGroup[]>("/device-groups")
      .then((r) => setGroups(r.data ?? []))
      .catch(() => setGroups([]))
  }, [])

  // обновляем онлайн-индикатор каждые 30 секунд без перезапроса API
  useEffect(() => {
    const t = setInterval(() => setDevices((d) => [...d]), 30_000)
    return () => clearInterval(t)
  }, [])

  function resetDialog() {
    setStep("form")
    setOs("linux")
    setResult(null)
    setCopied(false)
    setCreating(false)
  }

  async function createDevice() {
    setCreating(true)
    try {
      // hostname всё равно перезапишется реальным именем машины при энролле —
      // шлём читаемый плейсхолдер, чтобы pending-строка не была пустой
      const placeholder = `new-${os}-${Math.random().toString(36).slice(2, 6)}`
      const r = await api.post<CreateDeviceResponse>("/devices", { hostname: placeholder, os })
      setResult(r.data)
      setJustCreated((prev) => [r.data.device, ...prev])
      setStep("token")
    } finally {
      setCreating(false)
    }
  }

  function enrollCommand() {
    if (!result) return ""
    const base = apiBase()
    const serverAddr = `${window.location.hostname}:50051`
    if (result.device.os === "windows") {
      return `msiexec /i RoutineOps-agent.msi /qn ENROLL_URL="${base}/api/v1/enroll" ` +
        `ENROLL_TOKEN="${result.enrollment_token}" CA_URL="${base}/ca.crt" ` +
        `CA_SHA256="${result.ca_sha256}" SERVER_ADDR="${serverAddr}"`
    }
    if (result.device.os === "darwin") {
      // .pkg только раскладывает бинарь — энролл отдельной командой (root), как в docs/install.md.
      return `sudo installer -pkg RoutineOps-agent.pkg -target /\n` +
        `sudo /usr/local/bin/RoutineOps-agent enroll -install-service ` +
        `-enroll-url ${base}/api/v1/enroll -token ${result.enrollment_token} ` +
        `-ca-url ${base}/ca.crt -ca-sha256 ${result.ca_sha256} ` +
        `-server ${serverAddr} -server-name routineops-server`
    }
    return `agent enroll -enroll-url ${base}/api/v1/enroll -token ${result.enrollment_token}`
  }

  async function copyCommand() {
    const text = enrollCommand()
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

  const searching = query.trim() !== ""
  const filtering = searching || groupId !== ALL_GROUPS
  // Пока устройство не заэнролилось, сервер его не вернёт — показываем сами.
  // При активном поиске ИЛИ фильтре по группе выдачей владеет сервер: примешивать
  // локальные строки нельзя (свежесозданное устройство ни в одной группе не состоит).
  // Со второй страницы тоже не примешиваем — иначе одна и та же pending-строка
  // висела бы сверху на каждой странице.
  const pendingRows = filtering || offset > 0 ? [] : justCreated.filter((p) => !devices.some((d) => d.id === p.id))
  const rows = [...pendingRows, ...devices]

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-foreground">Устройства</h1>
        {isAdmin && (
        <Dialog open={dialogOpen} onOpenChange={(o) => { setDialogOpen(o); if (!o) resetDialog() }}>
          <DialogTrigger asChild>
            <Button size="sm">Добавить устройство</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{step === "form" ? "Добавить устройство" : "Устройство создано"}</DialogTitle>
            </DialogHeader>

            {step === "form" && (
              <div className="space-y-4 pt-2">
                <div className="space-y-1.5">
                  <Label>ОС</Label>
                  <Select
                    value={os}
                    onChange={setOs}
                    options={[
                      { value: "linux",   label: "Linux"   },
                      { value: "darwin",  label: "macOS"   },
                      { value: "windows", label: "Windows" },
                    ]}
                  />
                </div>
                <Button className="w-full" onClick={createDevice} disabled={creating}>
                  {creating ? "Создание..." : "Создать"}
                </Button>
              </div>
            )}

            {step === "token" && result && (
              <div className="space-y-4 pt-2">
                <p className="text-sm text-muted-foreground">
                  Запустите на целевой машине. Токен действует 24ч.
                </p>
                <div className="relative">
                  <pre className="rounded-md border border-border bg-muted px-3 py-3 text-xs font-mono text-soft break-all whitespace-pre-wrap pr-10">
                    {enrollCommand()}
                  </pre>
                  <button
                    type="button"
                    onClick={copyCommand}
                    className="absolute right-2 top-2 rounded p-1 text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {copied ? <Check className="h-4 w-4 text-emerald-600 dark:text-emerald-500" /> : <Copy className="h-4 w-4" />}
                  </button>
                </div>
                <div className="text-xs text-muted-foreground space-y-0.5">
                  <p>Device ID: <span className="font-mono">{result.device.id}</span></p>
                  <p>Token: <span className="font-mono">{result.enrollment_token}</span></p>
                </div>
                {result.device.os === "windows" ? (
                  <a href={`${apiBase()}/downloads/RoutineOps-agent.msi`} download className="block">
                    <Button variant="outline" className="w-full">Скачать MSI (Windows)</Button>
                  </a>
                ) : result.device.os === "darwin" ? (
                  <a href={`${apiBase()}/downloads/RoutineOps-agent.pkg`} download className="block">
                    <Button variant="outline" className="w-full">Скачать PKG (macOS)</Button>
                  </a>
                ) : (
                  <div className="flex gap-2 items-center">
                    <select
                      className="flex h-9 rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                      value={arch}
                      onChange={(e) => setArch(e.target.value)}
                    >
                      <option value="amd64">amd64</option>
                      <option value="arm64">arm64</option>
                    </select>
                    <a
                      href={`${apiBase()}/api/v1/installer?os=${result.device.os}&arch=${arch}&token=${result.enrollment_token}`}
                      download
                      className="flex-1"
                    >
                      <Button variant="outline" className="w-full">Скачать установщик (.sh)</Button>
                    </a>
                  </div>
                )}
                <Button className="w-full" variant="outline" onClick={() => { setDialogOpen(false); resetDialog() }}>
                  Готово
                </Button>
              </div>
            )}
          </DialogContent>
        </Dialog>
        )}
      </div>

      {/* Фильтры живут в отдельной стеклянной панели, а не внутри карты таблицы:
          карте таблицы нужен overflow-hidden (иначе ховер последней строки вылезает
          за скругление), а он обрезал бы выпадашку Select'а. */}
      <div className="glass flex flex-wrap items-center gap-3 px-5 py-4">
        <Input
          placeholder="Поиск: имя, IP, MAC, серийник, ОС, CPU..."
          value={query}
          onChange={(e) => { setQuery(e.target.value); setOffset(0) }}
          className="max-w-sm"
        />
        <Select
          value={groupId}
          onChange={(v) => { setGroupId(v); setOffset(0) }}
          className="w-56"
          options={[
            { value: ALL_GROUPS, label: "Все устройства" },
            ...groups.map((g) => ({ value: g.id, label: g.name })),
          ]}
        />
      </div>

      <div className="glass overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="border-t-0 hover:bg-transparent">
              <TableHead className="text-xs">Устройство</TableHead>
              <TableHead className="text-xs">Группа</TableHead>
              <TableHead className="text-xs">IP</TableHead>
              <TableHead className="text-xs">Статус</TableHead>
              <TableHead className="text-xs">Агент</TableHead>
              <TableHead className="text-xs">Последний раз</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 && (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={6} className="py-8 text-center text-sm text-muted-foreground">
                  {filtering ? "Ничего не найдено" : "Нет устройств"}
                </TableCell>
              </TableRow>
            )}
            {rows.map((d) => {
              const hint = matchHint(d, query)
              const accent = groupAccent(d.groups)
              return (
              <TableRow
                key={d.id}
                className="cursor-pointer border-l-2 glass-hover"
                // Рамка цветом группы. Без группы — прозрачная того же размера, иначе
                // строки «прыгали» бы по горизонтали при появлении цвета.
                style={{ borderLeftColor: accent ?? "transparent" }}
                onClick={() => navigate(`/devices/${d.id}`)}
              >
                <TableCell className="px-4 py-3">
                  <div className="flex flex-col gap-0.5">
                    <span className="text-sm font-medium text-foreground">{d.hostname}</span>
                    <span className="text-xs text-muted-foreground">
                      {osIcon(d.os)} {d.os}{d.os_version ? ` ${d.os_version}` : ""}
                    </span>
                    {hint && (
                      <span className="text-xs text-muted-foreground/80 font-mono">{hint}</span>
                    )}
                  </div>
                </TableCell>
                <TableCell className="px-4 py-3">
                  <GroupBadges groups={d.groups} />
                </TableCell>
                <TableCell className="px-4 py-3 text-muted-foreground text-xs">{d.ip_address || "—"}</TableCell>
                <TableCell className="px-4 py-3">
                  {/* Онлайн-бейдж — это свежесть last_seen_at, а НЕ статус устройства.
                      Пока их не различали, отклонённая или ждущая одобрения машина,
                      которая исправно шлёт хартбит, выглядела обычной зелёной строкой.
                      Статус показываем только когда он не «активен» — иначе колонка
                      превращается в шум на здоровом парке. */}
                  <div className="flex items-center gap-2">
                    <OnlineBadge device={d} />
                    {d.status !== "active" && (
                      <Badge variant={DEVICE_STATUS[d.status]?.variant ?? "outline"}>
                        {DEVICE_STATUS[d.status]?.label ?? d.status}
                      </Badge>
                    )}
                  </div>
                </TableCell>
                <TableCell className="px-4 py-3 text-muted-foreground text-xs font-mono">
                  {d.agent_version || "—"}
                </TableCell>
                <TableCell className="px-4 py-3 text-muted-foreground text-xs">
                  <span className="flex items-center justify-between gap-3">
                    {d.last_seen_at ? formatDistanceToNow(d.last_seen_at) : "—"}
                    <ChevronRight className="h-3.5 w-3.5 flex-shrink-0" strokeWidth={2} />
                  </span>
                </TableCell>
              </TableRow>
              )
            })}
          </TableBody>
        </Table>
        <Pager offset={offset} limit={PAGE_SIZE} total={total} onChange={setOffset} />
      </div>
    </div>
  )
}

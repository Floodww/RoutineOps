import { useEffect, useMemo, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { Network } from "lucide-react"
import api, { Device, DEVICE_STATUS, PAGE_SIZE, totalCount, errMessage, errStatus } from "@/lib/api"
import Pager from "@/components/Pager"
import { GroupBadges } from "@/components/GroupBadge"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import { formatDistanceToNow } from "@/lib/time"
import { useTenants } from "@/lib/useTenants"

function isOnline(device: Device): boolean {
  if (!device.last_seen_at) return false
  return Date.now() - new Date(device.last_seen_at).getTime() < 2 * 60 * 1000
}

function OnlineBadge({ device }: { device: Device }) {
  const { t } = useTranslation()
  const online = isOnline(device)
  return (
    <span className="flex items-center gap-1.5">
      <span className={`h-2 w-2 rounded-full flex-shrink-0 ${online ? "bg-emerald-500" : "bg-muted-foreground/40"}`} />
      <span className={`text-[13px] ${online ? "text-emerald-600 dark:text-emerald-400" : "text-muted-foreground"}`}>
        {online ? t("acrossTenants.online") : t("acrossTenants.offline")}
      </span>
    </span>
  )
}

function osIcon(os: string) {
  const defaultIcon = <img src="/linux.png" alt="Linux" className="w-3.5 h-3.5 inline-block mr-1 align-text-bottom" />
  if (!os) return defaultIcon
  const l = os.toLowerCase()
  if (l.includes("win")) return <img src="/windows.png" alt="Windows" className="w-3.5 h-3.5 inline-block mr-1 align-text-bottom" />
  if (l.includes("mac") || l.includes("darwin")) return <img src="/apple.png" alt="macOS" className="w-3.5 h-3.5 inline-block mr-1 align-text-bottom" />
  return defaultIcon
}

// Обзор парка по всем тенантам. Только provider_admin; карточка устройства
// (GET /devices/:id) тенант-скоупнута — клик сюда её не открывает, иначе чужой
// тенант дал бы 404. Управление — в «Устройства» в своём скоупе.
export default function AcrossTenants() {
  const { t } = useTranslation()
  const [devices, setDevices] = useState<Device[]>([])
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState("")
  const [offset, setOffset] = useState(0)
  const [total, setTotal] = useState(0)
  const [loadError, setLoadError] = useState<string | null>(null)
  const { tenants } = useTenants()
  const reqSeq = useRef(0)

  const tenantName = useMemo(() => {
    const m = new Map<string, string>()
    for (const t of tenants) m.set(t.id, t.name)
    return m
  }, [tenants])

  useEffect(() => {
    const q = query.trim()
    const params = new URLSearchParams()
    if (q) params.set("q", q)
    params.set("limit", String(PAGE_SIZE))
    if (offset) params.set("offset", String(offset))
    const seq = ++reqSeq.current
    setLoadError(null)
    const timer = setTimeout(() => {
      api
        .get<Device[]>(`/devices/across-tenants?${params.toString()}`)
        .then((r) => {
          if (seq !== reqSeq.current) return
          const rows = r.data ?? []
          if (rows.length === 0 && offset > 0) {
            setOffset(0)
            return
          }
          setDevices(rows)
          setTotal(totalCount(r.headers, rows.length))
          setLoadError(null)
        })
        .catch((e) => {
          if (seq !== reqSeq.current) return
          const status = errStatus(e)
          if (status === 403) {
            setLoadError(t("acrossTenants.noAccessTheProvider"))
          } else if (status === 404 || status === 501) {
            setLoadError(t("acrossTenants.thisEndpointIsNot"))
          } else {
            setLoadError(errMessage(e))
          }
          setDevices([])
          setTotal(0)
        })
        .finally(() => {
          if (seq === reqSeq.current) setLoading(false)
        })
    }, q ? 250 : 0)
    return () => clearTimeout(timer)
  }, [query, offset])

  useEffect(() => {
    const t = setInterval(() => setDevices((d) => [...d]), 30_000)
    return () => clearInterval(t)
  }, [])

  const searching = query.trim() !== ""
  const emptyLabel = loadError ? "—" : searching ? t("acrossTenants.nothingFound") : t("acrossTenants.noDevices")

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h1 className="text-xl font-semibold text-foreground flex items-center gap-2">
          <Network className="h-5 w-5" />
          {t("acrossTenants.title")}
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          {t("acrossTenants.intro")}
        </p>
      </div>

      <div className="glass flex flex-wrap items-center gap-3 px-5 py-4">
        <Input
          placeholder={t("acrossTenants.searchNameIpMac")}
          value={query}
          onChange={(e) => { setQuery(e.target.value); setOffset(0) }}
          className="max-w-sm"
        />
      </div>

      {loadError && (
        <p className="text-sm text-destructive px-1">{loadError}</p>
      )}

      <div className="glass overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-48 text-muted-foreground text-sm">{t("acrossTenants.loading")}</div>
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow className="border-t-0 hover:bg-transparent">
                  <TableHead className="text-xs">{t("acrossTenants.device")}</TableHead>
                  <TableHead className="text-xs">{t("acrossTenants.tenant")}</TableHead>
                  <TableHead className="text-xs">{t("acrossTenants.group")}</TableHead>
                  <TableHead className="text-xs">IP</TableHead>
                  <TableHead className="text-xs">{t("acrossTenants.status")}</TableHead>
                  <TableHead className="text-xs">{t("acrossTenants.agent")}</TableHead>
                  <TableHead className="text-xs">{t("acrossTenants.lastSeen")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {devices.length === 0 && (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={7} className="py-8 text-center text-sm text-muted-foreground">
                      {emptyLabel}
                    </TableCell>
                  </TableRow>
                )}
                {devices.map((d) => (
                  <TableRow key={d.id} className="cursor-default border-l-2 border-l-transparent">
                    <TableCell className="px-4 py-3">
                      <div className="flex flex-col gap-0.5">
                        <span className="text-sm font-medium text-foreground">{d.hostname}</span>
                        <span className="text-xs text-muted-foreground">
                          {osIcon(d.os)} {d.os}{d.os_version ? ` ${d.os_version}` : ""}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="px-4 py-3">
                      <span className="text-sm text-foreground">
                        {d.tenant_id ? (tenantName.get(d.tenant_id) ?? d.tenant_id.slice(0, 8)) : "—"}
                      </span>
                    </TableCell>
                    <TableCell className="px-4 py-3">
                      <GroupBadges groups={d.groups} />
                    </TableCell>
                    <TableCell className="px-4 py-3 text-muted-foreground text-xs">{d.ip_address || "—"}</TableCell>
                    <TableCell className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <OnlineBadge device={d} />
                        {d.status !== "active" && (
                          <Badge variant={DEVICE_STATUS[d.status]?.variant ?? "outline"}>
                            {DEVICE_STATUS[d.status]?.label ?? d.status}
                          </Badge>
                        )}
                        {d.outbox_unavailable && (
                          <Badge
                            variant="outline"
                            className="border-violet-500 text-violet-600 dark:text-violet-400"
                            title={d.degraded_detail || t("acrossTenants.theAgentReportQueue")}
                          >
                            {t("devices.blind")}
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="px-4 py-3 text-muted-foreground text-xs font-mono">
                      {d.agent_version || "—"}
                    </TableCell>
                    <TableCell className="px-4 py-3 text-muted-foreground text-xs">
                      {d.last_seen_at ? formatDistanceToNow(d.last_seen_at) : "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {!loadError && (
              <Pager offset={offset} limit={PAGE_SIZE} total={total} onChange={setOffset} />
            )}
          </>
        )}
      </div>
    </div>
  )
}

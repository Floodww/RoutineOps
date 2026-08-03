import { useState, useEffect, useMemo } from "react"
import { useTranslation, Trans } from "react-i18next"
import api, { errMessage, errStatus } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Badge } from "@/components/ui/badge"
import { toast } from "@/lib/toast"
import { Plus, Pencil, Trash2, Send } from "lucide-react"
import ConfirmDialog from "@/components/ConfirmDialog"
import { ACTION_LABELS, ACTION_CATEGORY, actionLabel } from "@/lib/auditActions"

type SinkType = "webhook" | "syslog" | "cef"

type Integration = {
  id: string
  type: SinkType
  url: string
  has_secret: boolean
  event_filter: string[]
  enabled: boolean
  last_delivery_at: string | null
  last_status: "" | "ok" | "error"
  last_error: string
  error_count: number
  delivered_count: number
}

type IntegrationInput = {
  type: SinkType
  url: string
  secret: string
  clear_secret: boolean
  event_filter: string[]
  enabled: boolean
}

const EMPTY_INPUT: IntegrationInput = {
  type: "webhook",
  url: "",
  secret: "",
  clear_secret: false,
  event_filter: [],
  enabled: true,
}

// Подсказка по адресу зависит от типа: у webhook и syslog разные схемы, и попытка
// ввести https:// для syslog отбивается сервером — лучше сказать заранее.
const URL_HINT: Record<SinkType, string> = {
  webhook: "https://siem.example.com/hooks/routineops",
  syslog: "udp://192.0.2.10:514",
  cef: "udp://192.0.2.10:514",
}

// Значения — КЛЮЧИ словаря: t() на уровне модуля недоступен.
const TYPE_LABEL: Record<SinkType, string> = {
  webhook: "siem.webhookJsonOverHttp",
  syslog: "siem.syslogRfc5424Text",
  cef: "siem.cefOverSyslog",
}

export default function SIEM() {
  const { t } = useTranslation()
  const [items, setItems] = useState<Integration[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState("")

  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingID, setEditingID] = useState<string | null>(null)
  const [form, setForm] = useState<IntegrationInput>(EMPTY_INPUT)
  const [saving, setSaving] = useState(false)
  const [filterQuery, setFilterQuery] = useState("")

  const [confirmDelete, setConfirmDelete] = useState<Integration | null>(null)
  const [testing, setTesting] = useState<string | null>(null)

  // Список известных действий журнала — берём из того же словаря, которым
  // подписывается сам журнал: расходиться им нельзя.
  const knownActions = useMemo(() => {
    const q = filterQuery.trim().toLowerCase()
    return Object.keys(ACTION_LABELS)
      .filter((a) => !q || a.toLowerCase().includes(q) || actionLabel(a).toLowerCase().includes(q))
      .sort((a, b) => (ACTION_CATEGORY[a] ?? "content").localeCompare(ACTION_CATEGORY[b] ?? "content") || a.localeCompare(b))
  }, [filterQuery])

  async function load() {
    setLoading(true)
    try {
      const res = await api.get<Integration[]>("/siem")
      setItems(res.data ?? [])
      setLoadError("")
    } catch (e) {
      const st = errStatus(e)
      if (st === 404 || st === 501) {
        setLoadError(t("siem.siemExportIsAvailable"))
      } else if (st === 401 || st === 403) {
        setLoadError(t("siem.noAccessAnAdministrator"))
      } else {
        setLoadError(st ? t("siem.listFailedHTTP", { status: st }) : t("siem.listFailed"))
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  function openCreate() {
    setEditingID(null)
    setForm(EMPTY_INPUT)
    setFilterQuery("")
    setDialogOpen(true)
  }

  function openEdit(i: Integration) {
    setEditingID(i.id)
    setForm({
      type: i.type,
      url: i.url,
      secret: "", // "" = не менять
      clear_secret: false,
      event_filter: i.event_filter ?? [],
      enabled: i.enabled,
    })
    setFilterQuery("")
    setDialogOpen(true)
  }

  function toggleAction(action: string) {
    setForm((f) => ({
      ...f,
      event_filter: f.event_filter.includes(action)
        ? f.event_filter.filter((a) => a !== action)
        : [...f.event_filter, action],
    }))
  }

  async function handleSave() {
    if (!form.url) {
      toast({ title: t("siem.enterTheReceiverAddress"), variant: "destructive" })
      return
    }
    setSaving(true)
    try {
      if (editingID) {
        await api.put(`/siem/${editingID}`, form)
        toast({ title: t("siem.integrationUpdated"), variant: "success" })
      } else {
        await api.post("/siem", form)
        toast({
          title: t("siem.integrationCreated"),
          description: t("siem.pressCheckToConfirm"),
          variant: "success",
        })
      }
      setDialogOpen(false)
      load()
    } catch (err) {
      toast({ title: t("siem.saveFailed"), description: errMessage(err), variant: "destructive" })
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete(i: Integration) {
    try {
      await api.delete(`/siem/${i.id}`)
      toast({ title: t("siem.integrationDeleted"), variant: "success" })
      load()
    } catch {
      toast({ title: t("siem.deleteFailed"), variant: "destructive" })
    } finally {
      setConfirmDelete(null)
    }
  }

  async function runTest(i: Integration) {
    setTesting(i.id)
    try {
      const res = await api.post<{ ok: boolean; error?: string }>(`/siem/${i.id}/test`, {})
      if (res.data.ok) {
        toast({ title: t("siem.testEventDelivered"), variant: "success" })
      } else {
        toast({ title: t("siem.eventWasNotDelivered"), description: res.data.error ?? "", variant: "destructive" })
      }
      // Статус и счётчики обновились на сервере — перечитываем.
      load()
    } catch (err) {
      toast({ title: t("siem.checkDidNotRun"), description: errMessage(err), variant: "destructive" })
    } finally {
      setTesting(null)
    }
  }

  const isEdit = !!editingID

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">{t("siem.siemExport")}</h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            {t("siem.intro")}
          </p>
        </div>
        <Dialog open={dialogOpen} onOpenChange={(open) => { if (!open) setDialogOpen(false) }}>
          <DialogTrigger asChild>
            <Button size="sm" onClick={openCreate}>
              <Plus className="h-4 w-4 mr-1.5" /> {t("siem.addReceiver")}
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle>{isEdit ? t("siem.editReceiver") : t("siem.addReceiver")}</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 pt-2">
              <div className="space-y-1.5">
                <Label>{t("siem.receiverType")}</Label>
                <div className="flex flex-col gap-1.5">
                  {/* Переменная называется kind, а не t: t() из useTranslation
                      закрылась бы параметром и подпись осталась бы ключом. */}
                  {(Object.keys(TYPE_LABEL) as SinkType[]).map((kind) => (
                    <label key={kind} className="flex items-center gap-2 text-sm cursor-pointer">
                      <input
                        type="radio"
                        name="siem-type"
                        checked={form.type === kind}
                        onChange={() => setForm((f) => ({ ...f, type: kind }))}
                      />
                      {t(TYPE_LABEL[kind])}
                    </label>
                  ))}
                </div>
              </div>

              <div className="space-y-1.5">
                <Label>{t("siem.address")} <span className="text-destructive">*</span></Label>
                <Input
                  placeholder={URL_HINT[form.type]}
                  value={form.url}
                  onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
                />
                <p className="text-xs text-muted-foreground">
                  {form.type === "webhook"
                    ? t("siem.httpOrHttpsOver")
                    : t("siem.udpOrTcpThe")}
                </p>
              </div>

              {form.type === "webhook" && (
                <div className="space-y-1.5">
                  <Label>
                    {t("siem.signingSecret")}
                    {isEdit && <span className="text-xs text-muted-foreground ml-1">{t("siem.emptyLeaveUnchanged")}</span>}
                  </Label>
                  <Input
                    type="password"
                    placeholder={isEdit ? "••••••••" : ""}
                    value={form.secret}
                    onChange={(e) => setForm((f) => ({ ...f, secret: e.target.value, clear_secret: false }))}
                  />
                  <p className="text-xs text-muted-foreground">
                    <Trans i18nKey="siem.signatureHint" components={[<code />]} />
                  </p>
                  {isEdit && (
                    <label className="flex items-center gap-2 text-xs cursor-pointer text-muted-foreground">
                      <input
                        type="checkbox"
                        checked={form.clear_secret}
                        disabled={form.secret !== ""}
                        onChange={(e) => setForm((f) => ({ ...f, clear_secret: e.target.checked }))}
                      />
                      {t("siem.clearSignature")}
                    </label>
                  )}
                </div>
              )}

              <div className="space-y-1.5">
                <Label>
                  {t("siem.eventFilter")}
                  <span className="text-xs text-muted-foreground ml-1">
                    {form.event_filter.length === 0 ? t("siem.nothingSelectedAllEvents") : t("siem.selectedCount", { count: form.event_filter.length })}
                  </span>
                </Label>
                <Input
                  placeholder={t("siem.searchByAction")}
                  value={filterQuery}
                  onChange={(e) => setFilterQuery(e.target.value)}
                />
                <div className="max-h-40 overflow-y-auto rounded-md border border-input p-2 space-y-0.5">
                  {knownActions.map((a) => (
                    <label key={a} className="flex items-center gap-2 text-xs cursor-pointer">
                      <input
                        type="checkbox"
                        checked={form.event_filter.includes(a)}
                        onChange={() => toggleAction(a)}
                      />
                      <span className="font-mono text-[11px] text-muted-foreground w-52 shrink-0 truncate">{a}</span>
                      <span className="truncate">{actionLabel(a)}</span>
                    </label>
                  ))}
                  {knownActions.length === 0 && (
                    <p className="text-xs text-muted-foreground py-2 text-center">{t("siem.nothingFound")}</p>
                  )}
                </div>
                {form.event_filter.length > 0 && (
                  <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => setForm((f) => ({ ...f, event_filter: [] }))}>
                    {t("siem.resetFilter")}
                  </Button>
                )}
              </div>

              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input
                  type="checkbox"
                  checked={form.enabled}
                  onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
                />
                {t("siem.enabled")}
              </label>

              <Button className="w-full" onClick={handleSave} disabled={saving}>
                {saving ? t("siem.saving") : isEdit ? t("siem.save") : t("siem.create")}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="glass overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="text-xs">{t("siem.type")}</TableHead>
              <TableHead className="text-xs">{t("siem.address")}</TableHead>
              <TableHead className="text-xs">{t("siem.events")}</TableHead>
              <TableHead className="text-xs">{t("siem.lastDelivery")}</TableHead>
              <TableHead className="text-xs">{t("siem.errors")}</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading && (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={6} className="text-center py-8 text-sm text-muted-foreground">{t("siem.loading")}</TableCell>
              </TableRow>
            )}
            {!loading && loadError !== "" && (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={6} className="text-center py-8 text-sm text-destructive">{loadError}</TableCell>
              </TableRow>
            )}
            {!loading && loadError === "" && items.length === 0 && (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={6} className="text-center py-8 text-sm text-muted-foreground">
                  {t("siem.empty")}
                </TableCell>
              </TableRow>
            )}
            {items.map((i) => (
              <TableRow key={i.id}>
                <TableCell className="text-sm">
                  <div className="flex items-center gap-1.5">
                    <span className="font-medium">{i.type}</span>
                    {i.has_secret && <Badge variant="outline" className="text-[10px]">{t("siem.signed")}</Badge>}
                    {!i.enabled && <Badge variant="outline" className="text-[10px]">{t("siem.disabled")}</Badge>}
                  </div>
                </TableCell>
                <TableCell className="text-xs font-mono text-muted-foreground max-w-[260px] truncate">{i.url}</TableCell>
                <TableCell className="text-xs">
                  {i.event_filter.length === 0
                    ? <span className="text-muted-foreground">{t("siem.all")}</span>
                    : t("siem.filterCount", { count: i.event_filter.length })}
                </TableCell>
                <TableCell className="text-xs">
                  {i.last_delivery_at ? (
                    <div className="flex flex-col gap-0.5">
                      <span className={i.last_status === "error" ? "text-destructive" : "text-emerald-600"}>
                        {i.last_status === "error" ? t("siem.error") : t("siem.delivered")} · {new Date(i.last_delivery_at).toLocaleString("ru-RU")}
                      </span>
                      {i.last_status === "error" && i.last_error && (
                        <span className="text-[11px] text-muted-foreground max-w-[280px] truncate" title={i.last_error}>
                          {i.last_error}
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className="text-muted-foreground">{t("siem.noEventsYet")}</span>
                  )}
                </TableCell>
                <TableCell className="text-xs">
                  <span className={i.error_count > 0 ? "text-destructive font-medium" : "text-muted-foreground"}>
                    {i.error_count}
                  </span>
                  <span className="text-muted-foreground"> / {i.delivered_count + i.error_count}</span>
                </TableCell>
                <TableCell className="text-right">
                  <div className="flex justify-end gap-1">
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 px-2 text-xs"
                      disabled={testing === i.id}
                      onClick={() => runTest(i)}
                    >
                      <Send className="h-3.5 w-3.5 mr-1" />
                      {testing === i.id ? t("siem.sending") : t("siem.check")}
                    </Button>
                    <Button size="sm" variant="ghost" className="h-7 w-7 p-0" onClick={() => openEdit(i)}>
                      <Pencil className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 w-7 p-0 text-destructive hover:text-destructive"
                      onClick={() => setConfirmDelete(i)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <ConfirmDialog
        open={!!confirmDelete}
        onOpenChange={(open) => { if (!open) setConfirmDelete(null) }}
        title={t("siem.deleteTheReceiver")}
        description={t("siem.deleteWarn", { url: confirmDelete?.url ?? "" })}
        confirmLabel={t("siem.delete")}
        destructive
        onConfirm={() => confirmDelete && handleDelete(confirmDelete)}
      />
    </div>
  )
}

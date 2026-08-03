import i18n from "@/i18n/config"
import { useState, useEffect } from "react"
import { useTranslation } from "react-i18next"
import api, { errMessage, errStatus } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Badge } from "@/components/ui/badge"
import { toast } from "@/lib/toast"
import { Plus, Pencil, Trash2, FileDown, PlugZap, Copy } from "lucide-react"
import ConfirmDialog from "@/components/ConfirmDialog"

type Provider = {
  id: string
  name: string
  idp_metadata_url: string
  idp_metadata_xml?: string
  has_idp_metadata_xml: boolean
  sp_entity_id: string
  sp_acs_url: string
  sp_metadata_url: string
  sp_certificate: string
  login_url: string
  enabled: boolean
}

type ProviderInput = {
  name: string
  idp_metadata_url: string
  idp_metadata_xml: string
  sp_entity_id: string
  enabled: boolean
}

type SPMetadata = {
  entity_id: string
  acs_url: string
  metadata_url: string
  certificate: string
  metadata_xml: string
}

type TestResult = {
  ok: boolean
  error?: string
  idp_entity_id?: string
  sso_url?: string
  signing_certs: number
  source?: string
}

const EMPTY_INPUT: ProviderInput = {
  name: "",
  idp_metadata_url: "",
  idp_metadata_xml: "",
  sp_entity_id: "",
  enabled: true,
}

// copy — буфер обмена с откатом на скрытую textarea: clipboard API недоступен вне
// защищённого контекста, а стенды поднимают по http.
async function copy(text: string, what: string) {
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    const ta = document.createElement("textarea")
    ta.value = text
    document.body.appendChild(ta)
    ta.select()
    document.execCommand("copy")
    document.body.removeChild(ta)
  }
  toast({ title: i18n.t("saml.copied", { what }), variant: "success" })
}

export default function SAML() {
  const { t } = useTranslation()
  const [providers, setProviders] = useState<Provider[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState("")

  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingID, setEditingID] = useState<string | null>(null)
  const [form, setForm] = useState<ProviderInput>(EMPTY_INPUT)
  const [saving, setSaving] = useState(false)

  const [confirmDelete, setConfirmDelete] = useState<Provider | null>(null)

  // Карточка «наша сторона»: то, что админ переносит в IdP.
  const [spMeta, setSpMeta] = useState<{ provider: Provider; meta: SPMetadata } | null>(null)
  const [testing, setTesting] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<{ provider: Provider; res: TestResult } | null>(null)

  async function load() {
    setLoading(true)
    try {
      const res = await api.get<Provider[]>("/saml/providers")
      setProviders(res.data ?? [])
      setLoadError("")
    } catch (e) {
      // Различаем причины так же, как на странице OIDC: «доступно только в
      // Enterprise» на протухшей сессии — это ложный след, который уже стоил
      // разбирательства на проде 30.07.
      const st = errStatus(e)
      if (st === 404 || st === 501) {
        setLoadError(t("saml.samlSsoIsAvailable"))
      } else if (st === 401 || st === 403) {
        setLoadError(t("saml.noAccessAnAdministrator"))
      } else {
        setLoadError(st ? t("saml.listFailedHTTP", { status: st }) : t("saml.listFailed"))
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  function openCreate() {
    setEditingID(null)
    setForm(EMPTY_INPUT)
    setDialogOpen(true)
  }

  async function openEdit(p: Provider) {
    // Карточку читаем отдельным запросом: в списке XML метаданных намеренно нет
    // (десятки килобайт на строку), а редактировать его надо.
    try {
      const res = await api.get<Provider>(`/saml/providers/${p.id}`)
      setEditingID(p.id)
      setForm({
        name: res.data.name,
        idp_metadata_url: res.data.idp_metadata_url ?? "",
        idp_metadata_xml: res.data.idp_metadata_xml ?? "",
        sp_entity_id: res.data.sp_entity_id ?? "",
        enabled: res.data.enabled,
      })
      setDialogOpen(true)
    } catch (err) {
      toast({ title: t("saml.failedToOpenThe"), description: errMessage(err), variant: "destructive" })
    }
  }

  async function handleSave() {
    if (!form.name) {
      toast({ title: t("saml.enterAName"), variant: "destructive" })
      return
    }
    if (!form.idp_metadata_url && !form.idp_metadata_xml) {
      toast({ title: t("saml.anIdpMetadataUrl"), variant: "destructive" })
      return
    }
    setSaving(true)
    try {
      if (editingID) {
        await api.put(`/saml/providers/${editingID}`, form)
        toast({ title: t("saml.providerUpdated"), variant: "success" })
      } else {
        await api.post("/saml/providers", form)
        toast({
          title: t("saml.providerCreated"),
          description: t("saml.nextSpMetadataIt"),
          variant: "success",
        })
      }
      setDialogOpen(false)
      load()
    } catch (err) {
      toast({ title: t("saml.saveFailed"), description: errMessage(err), variant: "destructive" })
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete(p: Provider) {
    try {
      await api.delete(`/saml/providers/${p.id}`)
      toast({ title: t("saml.providerDeleted", { name: p.name }), variant: "success" })
      load()
    } catch {
      toast({ title: t("saml.deleteFailed"), variant: "destructive" })
    } finally {
      setConfirmDelete(null)
    }
  }

  async function openSPMetadata(p: Provider) {
    try {
      const res = await api.get<SPMetadata>(`/saml/providers/${p.id}/sp-metadata`)
      setSpMeta({ provider: p, meta: res.data })
    } catch (err) {
      toast({ title: t("saml.failedToFetchSp"), description: errMessage(err), variant: "destructive" })
    }
  }

  async function runTest(p: Provider) {
    setTesting(p.id)
    try {
      const res = await api.post<TestResult>(`/saml/providers/${p.id}/test`, {})
      setTestResult({ provider: p, res: res.data })
    } catch (err) {
      toast({ title: t("saml.checkDidNotRun"), description: errMessage(err), variant: "destructive" })
    } finally {
      setTesting(null)
    }
  }

  function downloadSPMetadata(p: Provider, xml: string) {
    const url = URL.createObjectURL(new Blob([xml], { type: "application/samlmetadata+xml" }))
    const a = document.createElement("a")
    a.href = url
    a.download = `routineops-sp-${p.name.replace(/[^\w.-]+/g, "_")}.xml`
    a.click()
    URL.revokeObjectURL(url)
  }

  const isEdit = !!editingID

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">SSO / SAML</h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            {t("saml.intro")}
          </p>
        </div>
        <Dialog open={dialogOpen} onOpenChange={(open) => { if (!open) setDialogOpen(false) }}>
          <DialogTrigger asChild>
            <Button size="sm" onClick={openCreate}>
              <Plus className="h-4 w-4 mr-1.5" /> {t("saml.addProvider")}
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle>{isEdit ? t("saml.editProvider") : t("saml.addProvider")}</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 pt-2">
              <div className="space-y-1.5">
                <Label>{t("saml.name")} <span className="text-destructive">*</span></Label>
                <Input
                  placeholder="Keycloak"
                  value={form.name}
                  onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                />
              </div>
              <div className="space-y-1.5">
                <Label>{t("saml.idpMetadataUrl")}</Label>
                <Input
                  placeholder="https://idp.example.com/realms/main/protocol/saml/descriptor"
                  value={form.idp_metadata_url}
                  onChange={(e) => setForm((f) => ({ ...f, idp_metadata_url: e.target.value }))}
                />
                <p className="text-xs text-muted-foreground">
                  {t("saml.metadataHint")}
                </p>
              </div>
              <div className="space-y-1.5">
                <Label>{t("saml.orIdpMetadataAs")}</Label>
                <textarea
                  className="w-full min-h-[110px] rounded-md border border-input bg-transparent px-3 py-2 text-xs font-mono outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  placeholder="<EntityDescriptor …>"
                  value={form.idp_metadata_xml}
                  onChange={(e) => setForm((f) => ({ ...f, idp_metadata_xml: e.target.value }))}
                />
                <p className="text-xs text-muted-foreground">
                  {t("saml.xmlHint")}
                </p>
              </div>
              <div className="space-y-1.5">
                <Label>{t("saml.ourEntityId")} <span className="text-xs text-muted-foreground">{t("saml.optional")}</span></Label>
                <Input
                  placeholder={t("saml.theSpMetadataUrl")}
                  value={form.sp_entity_id}
                  onChange={(e) => setForm((f) => ({ ...f, sp_entity_id: e.target.value }))}
                />
              </div>
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={form.enabled}
                  onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
                />
                {t("saml.enabled")}
              </label>
              <Button className="w-full" onClick={handleSave} disabled={saving}>
                {saving ? t("saml.saving") : isEdit ? t("saml.save") : t("saml.create")}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="glass overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="text-xs">{t("saml.name")}</TableHead>
              <TableHead className="text-xs">{t("saml.idpMetadata")}</TableHead>
              <TableHead className="text-xs">{t("saml.status")}</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading && (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={4} className="text-center py-8 text-sm text-muted-foreground">
                  {t("common.loading")}
                </TableCell>
              </TableRow>
            )}
            {!loading && loadError !== "" && (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={4} className="text-center py-8 text-sm text-destructive">
                  {loadError}
                </TableCell>
              </TableRow>
            )}
            {!loading && loadError === "" && providers.length === 0 && (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={4} className="text-center py-8 text-sm text-muted-foreground">
                  {t("saml.empty")}
                </TableCell>
              </TableRow>
            )}
            {providers.map((p) => (
              <TableRow key={p.id}>
                <TableCell className="font-medium text-sm">{p.name}</TableCell>
                <TableCell className="text-xs text-muted-foreground font-mono max-w-[340px] truncate">
                  {p.has_idp_metadata_xml ? t("saml.xmlUploadedManually") : p.idp_metadata_url}
                </TableCell>
                <TableCell>
                  {p.enabled
                    ? <Badge variant="default" className="text-xs bg-emerald-600 text-white hover:bg-emerald-700">{t("saml.enabled")}</Badge>
                    : <Badge variant="outline" className="text-xs">{t("saml.disabled")}</Badge>}
                </TableCell>
                <TableCell className="text-right">
                  <div className="flex justify-end gap-1">
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 px-2 text-xs"
                      title={t("saml.checkIdpAvailability")}
                      disabled={testing === p.id}
                      onClick={() => runTest(p)}
                    >
                      <PlugZap className="h-3.5 w-3.5 mr-1" />
                      {testing === p.id ? t("saml.checking") : t("saml.check")}
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 px-2 text-xs"
                      title={t("saml.ourSideSMetadata")}
                      onClick={() => openSPMetadata(p)}
                    >
                      <FileDown className="h-3.5 w-3.5 mr-1" /> {t("saml.spMetadata")}
                    </Button>
                    <Button size="sm" variant="ghost" className="h-7 w-7 p-0" onClick={() => openEdit(p)}>
                      <Pencil className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 w-7 p-0 text-destructive hover:text-destructive"
                      onClick={() => setConfirmDelete(p)}
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

      {/* Наша сторона. Без этой карточки настройка невозможна в принципе: IdP надо
          сообщить entity ID, ACS и сертификат, а взять их админу неоткуда. */}
      <Dialog open={!!spMeta} onOpenChange={(open) => { if (!open) setSpMeta(null) }}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{t("saml.spMetaTitle", { name: spMeta?.provider.name ?? "" })}</DialogTitle>
          </DialogHeader>
          {spMeta && (
            <div className="space-y-3 pt-2 text-sm">
              <p className="text-xs text-muted-foreground">
                {t("saml.spMetaHint")}
              </p>
              {([
                ["Entity ID", spMeta.meta.entity_id],
                ["Assertion Consumer Service (ACS)", spMeta.meta.acs_url],
                [t("saml.spMetadataUrl"), spMeta.meta.metadata_url],
                [t("saml.signInLink"), spMeta.provider.login_url],
              ] as const).map(([label, value]) => (
                <div key={label} className="space-y-1">
                  <Label className="text-xs">{label}</Label>
                  <div className="flex gap-2">
                    <Input readOnly value={value} className="font-mono text-xs" />
                    <Button size="sm" variant="outline" className="h-9 px-2" onClick={() => copy(value, label)}>
                      <Copy className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              ))}
              <div className="space-y-1">
                <Label className="text-xs">{t("saml.spSigningCertificate")}</Label>
                <textarea
                  readOnly
                  className="w-full min-h-[120px] rounded-md border border-input bg-transparent px-3 py-2 text-[11px] font-mono outline-none"
                  value={spMeta.meta.certificate}
                />
              </div>
              <div className="flex gap-2">
                <Button size="sm" onClick={() => downloadSPMetadata(spMeta.provider, spMeta.meta.metadata_xml)}>
                  <FileDown className="h-4 w-4 mr-1.5" /> {t("saml.downloadXml")}
                </Button>
                <Button size="sm" variant="outline" onClick={() => copy(spMeta.meta.metadata_xml, t("saml.metadataXml"))}>
                  <Copy className="h-4 w-4 mr-1.5" /> {t("saml.copyXml")}
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Результат проверки. Показываем подробно: смысл кнопки в том, чтобы назвать
          причину, а не сказать «не получилось». */}
      <Dialog open={!!testResult} onOpenChange={(open) => { if (!open) setTestResult(null) }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t("saml.testTitle", { name: testResult?.provider.name ?? "" })}</DialogTitle>
          </DialogHeader>
          {testResult && (
            <div className="space-y-3 pt-2 text-sm">
              {testResult.res.ok ? (
                <Badge className="bg-emerald-600 text-white hover:bg-emerald-700">{t("saml.idpMetadataReceived")}</Badge>
              ) : (
                <Badge variant="destructive">{t("saml.setupIncomplete")}</Badge>
              )}
              {testResult.res.error && (
                <p className="text-xs text-destructive break-words">{testResult.res.error}</p>
              )}
              <dl className="text-xs space-y-1.5">
                <div className="flex gap-2">
                  <dt className="text-muted-foreground w-32 shrink-0">{t("saml.source")}</dt>
                  <dd className="font-mono">{testResult.res.source === "xml" ? t("saml.pastedXml") : t("saml.metadataUrl")}</dd>
                </div>
                {testResult.res.idp_entity_id && (
                  <div className="flex gap-2">
                    <dt className="text-muted-foreground w-32 shrink-0">Entity ID IdP</dt>
                    <dd className="font-mono break-all">{testResult.res.idp_entity_id}</dd>
                  </div>
                )}
                {testResult.res.sso_url && (
                  <div className="flex gap-2">
                    <dt className="text-muted-foreground w-32 shrink-0">{t("saml.ssoUrl")}</dt>
                    <dd className="font-mono break-all">{testResult.res.sso_url}</dd>
                  </div>
                )}
                <div className="flex gap-2">
                  <dt className="text-muted-foreground w-32 shrink-0">{t("saml.signingCertificates")}</dt>
                  <dd className="font-mono">{testResult.res.signing_certs}</dd>
                </div>
              </dl>
            </div>
          )}
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={!!confirmDelete}
        onOpenChange={(open) => { if (!open) setConfirmDelete(null) }}
        title={t("saml.deleteTheProvider")}
        description={t("saml.deleteWarn", { name: confirmDelete?.name ?? "" })}
        confirmLabel={t("saml.delete")}
        destructive
        onConfirm={() => confirmDelete && handleDelete(confirmDelete)}
      />
    </div>
  )
}

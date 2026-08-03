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
import { Plus, Pencil, Trash2 } from "lucide-react"
import ConfirmDialog from "@/components/ConfirmDialog"

type Provider = {
  id: string
  name: string
  client_id: string
  issuer_url: string
  redirect_uri: string
  enabled: boolean
  has_secret: boolean
}

type ProviderInput = {
  name: string
  client_id: string
  client_secret: string
  issuer_url: string
  redirect_uri: string
  enabled: boolean
}

const EMPTY_INPUT: ProviderInput = {
  name: "",
  client_id: "",
  client_secret: "",
  issuer_url: "",
  redirect_uri: "",
  enabled: true,
}

export default function OIDC() {
  const { t } = useTranslation()
  const [providers, setProviders] = useState<Provider[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState("")

  // Диалог создания/редактирования
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingID, setEditingID] = useState<string | null>(null)
  const [form, setForm] = useState<ProviderInput>(EMPTY_INPUT)
  const [saving, setSaving] = useState(false)

  // Подтверждение удаления
  const [confirmDelete, setConfirmDelete] = useState<Provider | null>(null)

  async function load() {
    setLoading(true)
    try {
      const res = await api.get<Provider[]>("/oidc/providers")
      setProviders(res.data ?? [])
      setLoadError("")
    } catch (e) {
      // Раньше ЛЮБАЯ ошибка объявлялась «доступно только в Enterprise-сборке».
      // На проде 30.07 это сбило с толку: сессия протухла после смены пароля,
      // страница получила 401 и сообщила, что сборка не та. Различаем явно.
      const st = errStatus(e)
      if (st === 404 || st === 501) {
        setLoadError(t("oidc.ssoOidcIsAvailable"))
      } else if (st === 401 || st === 403) {
        setLoadError(t("oidc.noAccessAnAdministrator"))
      } else {
        setLoadError(st ? t("oidc.listFailedHTTP", { status: st }) : t("oidc.listFailed"))
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

  function openEdit(p: Provider) {
    setEditingID(p.id)
    setForm({
      name: p.name,
      client_id: p.client_id,
      client_secret: "", // не перезаполняем — "" = не менять
      issuer_url: p.issuer_url,
      redirect_uri: p.redirect_uri,
      enabled: p.enabled,
    })
    setDialogOpen(true)
  }

  async function handleSave() {
    if (!form.name || !form.client_id || !form.issuer_url || !form.redirect_uri) {
      toast({ title: t("oidc.fillInAllRequired"), variant: "destructive" })
      return
    }
    if (!editingID && !form.client_secret) {
      toast({ title: t("oidc.clientSecretIsRequired"), variant: "destructive" })
      return
    }
    setSaving(true)
    try {
      if (editingID) {
        await api.put(`/oidc/providers/${editingID}`, form)
        toast({ title: t("oidc.providerUpdated"), variant: "success" })
      } else {
        await api.post("/oidc/providers", form)
        toast({ title: t("oidc.providerCreated"), variant: "success" })
      }
      setDialogOpen(false)
      load()
    } catch (err) {
      // Причина отказа приходит текстом (например, требование https у issuer_url) —
      // без неё админ видит «ошибка» и не знает, что именно поправить.
      toast({ title: t("oidc.saveFailed"), description: errMessage(err), variant: "destructive" })
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete(p: Provider) {
    try {
      await api.delete(`/oidc/providers/${p.id}`)
      toast({ title: t("oidc.providerDeleted", { name: p.name }), variant: "success" })
      load()
    } catch {
      toast({ title: t("oidc.deleteFailed"), variant: "destructive" })
    } finally {
      setConfirmDelete(null)
    }
  }

  const isEdit = !!editingID

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">SSO / OIDC</h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            {t("oidc.intro")}
          </p>
        </div>
        <Dialog open={dialogOpen} onOpenChange={open => {
          // При ручном закрытии — только если не на шаге «токен»
          if (!open) { setDialogOpen(false) }
        }}>
          <DialogTrigger asChild>
            <Button size="sm" onClick={openCreate}>
              <Plus className="h-4 w-4 mr-1.5" /> {t("oidc.addProvider")}
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>{isEdit ? t("oidc.editProvider") : t("oidc.addProvider")}</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 pt-2">
              <div className="space-y-1.5">
                <Label>{t("oidc.name")} <span className="text-destructive">*</span></Label>
                <Input placeholder="Google" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
              </div>
              <div className="space-y-1.5">
                <Label>Issuer URL <span className="text-destructive">*</span></Label>
                <Input placeholder="https://accounts.google.com" value={form.issuer_url} onChange={e => setForm(f => ({ ...f, issuer_url: e.target.value }))} />
                <p className="text-xs text-muted-foreground">{t("oidc.urlFromWellKnown")}</p>
              </div>
              <div className="space-y-1.5">
                <Label>Client ID <span className="text-destructive">*</span></Label>
                <Input value={form.client_id} onChange={e => setForm(f => ({ ...f, client_id: e.target.value }))} />
              </div>
              <div className="space-y-1.5">
                <Label>
                  Client Secret {!isEdit && <span className="text-destructive">*</span>}
                  {isEdit && <span className="text-xs text-muted-foreground ml-1">{t("oidc.emptyLeaveUnchanged")}</span>}
                </Label>
                <Input
                  type="password"
                  placeholder={isEdit ? "••••••••" : ""}
                  value={form.client_secret}
                  onChange={e => setForm(f => ({ ...f, client_secret: e.target.value }))}
                />
              </div>
              <div className="space-y-1.5">
                <Label>Redirect URI <span className="text-destructive">*</span></Label>
                <Input
                  placeholder={`${window.location.origin}/api/v1/auth/oidc/<id>/callback`}
                  value={form.redirect_uri}
                  onChange={e => setForm(f => ({ ...f, redirect_uri: e.target.value }))}
                />
                <p className="text-xs text-muted-foreground">
                  {t("oidc.registerURI")}
                </p>
              </div>
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={form.enabled}
                  onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))}
                />
                {t("oidc.enabled")}
              </label>
              <Button className="w-full" onClick={handleSave} disabled={saving}>
                {saving ? t("oidc.saving") : isEdit ? t("oidc.save") : t("oidc.create")}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="glass overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="text-xs">{t("oidc.name")}</TableHead>
              <TableHead className="text-xs">Issuer</TableHead>
              <TableHead className="text-xs">Client ID</TableHead>
              <TableHead className="text-xs">{t("oidc.status")}</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading && (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={5} className="text-center py-8 text-sm text-muted-foreground">
                  {t("common.loading")}
                </TableCell>
              </TableRow>
            )}
            {!loading && loadError !== "" && (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={5} className="text-center py-8 text-sm text-destructive">
                  {loadError}
                </TableCell>
              </TableRow>
            )}
            {!loading && loadError === "" && providers.length === 0 && (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={5} className="text-center py-8 text-sm text-muted-foreground">
                  {t("oidc.empty")}
                </TableCell>
              </TableRow>
            )}
            {providers.map(p => (
              <TableRow key={p.id}>
                <TableCell className="font-medium text-sm">{p.name}</TableCell>
                <TableCell className="text-xs text-muted-foreground font-mono">{p.issuer_url}</TableCell>
                <TableCell className="text-xs font-mono">{p.client_id}</TableCell>
                <TableCell>
                  {p.enabled
                    ? <Badge variant="default" className="text-xs bg-emerald-600 text-white hover:bg-emerald-700">{t("oidc.enabled")}</Badge>
                    : <Badge variant="outline" className="text-xs">{t("oidc.disabled")}</Badge>}
                </TableCell>
                <TableCell className="text-right">
                  <div className="flex justify-end gap-1">
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

      <ConfirmDialog
        open={!!confirmDelete}
        onOpenChange={(open) => { if (!open) setConfirmDelete(null) }}
        title={t("oidc.deleteTheProvider")}
        description={t("oidc.deleteWarn", { name: confirmDelete?.name ?? "" })}
        confirmLabel={t("oidc.delete")}
        destructive
        onConfirm={() => confirmDelete && handleDelete(confirmDelete)}
      />
    </div>
  )
}

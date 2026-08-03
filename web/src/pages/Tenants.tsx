import { useEffect, useState, FormEvent } from "react"
import { useTranslation, Trans } from "react-i18next"
import api, { errMessage } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Building2, Pencil, Plus, Trash2, UserPlus } from "lucide-react"
import { toast } from "@/lib/toast"
import { clearTenantsCache } from "@/lib/useTenants"
import { formatDateTime } from "@/lib/time"

// Тенант по умолчанию: id фиксирован миграцией 045.
const DEFAULT_TENANT_ID = "00000000-0000-4000-8000-000000000001"

interface Tenant {
  id: string
  name: string
  created_at: string
}

export default function Tenants() {
  const { t } = useTranslation()
  const [tenants, setTenants] = useState<Tenant[]>([])
  const [loading, setLoading] = useState(true)
  const [createOpen, setCreateOpen] = useState(false)
  const [name, setName] = useState("")
  const [saving, setSaving] = useState(false)
  const [rename, setRename] = useState<Tenant | null>(null)
  const [renameName, setRenameName] = useState("")
  const [toDelete, setToDelete] = useState<Tenant | null>(null)
  const [inviteTo, setInviteTo] = useState<Tenant | null>(null)
  const [inviteEmail, setInviteEmail] = useState("")
  const [inviteRole, setInviteRole] = useState("it_admin")
  const [inviteURL, setInviteURL] = useState("")

  function load() {
    setLoading(true)
    api.get<{ tenants: Tenant[] }>("/tenants")
      .then((r) => setTenants(r.data.tenants ?? []))
      .catch(() => toast({ title: t("tenants.loadFailed"), variant: "destructive" }))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  async function handleCreate(e: FormEvent) {
    e.preventDefault()
    setSaving(true)
    try {
      await api.post("/tenants", { name })
      clearTenantsCache()
      toast({ title: t("tenants.created"), variant: "success" })
      setCreateOpen(false)
      setName("")
      load()
    } catch {
      toast({ title: t("tenants.createFailed"), variant: "destructive" })
    } finally {
      setSaving(false)
    }
  }

  async function handleRename(e: FormEvent) {
    e.preventDefault()
    if (!rename) return
    setSaving(true)
    try {
      await api.patch(`/tenants/${rename.id}`, { name: renameName })
      clearTenantsCache()
      toast({ title: t("tenants.renamed"), variant: "success" })
      setRename(null)
      load()
    } catch {
      toast({ title: t("tenants.renameFailed"), variant: "destructive" })
    } finally {
      setSaving(false)
    }
  }

  async function handleInvite(e: FormEvent) {
    e.preventDefault()
    if (!inviteTo) return
    setSaving(true)
    setInviteURL("")
    try {
      const r = await api.post<{ email_sent: string; invite_url?: string }>(
        `/tenants/${inviteTo.id}/invites`, { email: inviteEmail, role: inviteRole })
      if (r.data.email_sent === "true") {
        toast({ title: t("tenants.inviteSent", { email: inviteEmail }), variant: "success" })
        setInviteTo(null)
        setInviteEmail("")
      } else {
        // Почта выключена или не ушла — отдаём ссылку, иначе пригласить некем.
        setInviteURL(r.data.invite_url ?? "")
        toast({ title: t("tenants.mailNotSent"), variant: "destructive" })
      }
    } catch (e) {
      toast({ title: t("tenants.inviteFailed"), description: errMessage(e), variant: "destructive" })
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete() {
    if (!toDelete) return
    setSaving(true)
    try {
      await api.delete(`/tenants/${toDelete.id}`)
      clearTenantsCache()
      toast({ title: t("tenants.deleted"), variant: "success" })
      setToDelete(null)
      load()
    } catch (e) {
      toast({ title: t("tenants.deleteFailed"), description: errMessage(e), variant: "destructive" })
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="p-6 max-w-4xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold flex items-center gap-2">
            <Building2 className="h-5 w-5" />
            {t("tenants.title")}
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            {t("tenants.intro")}
          </p>
        </div>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="h-4 w-4 mr-1" />
          {t("common.create")}
        </Button>
      </div>

      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="px-5">{t("tenants.name")}</TableHead>
            <TableHead className="px-5">{t("tenants.created_at")}</TableHead>
            <TableHead className="px-5 w-px" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {loading && (
            <TableRow className="hover:bg-transparent">
              <TableCell colSpan={3} className="text-center text-xs text-muted-foreground py-8">{t("common.loading")}</TableCell>
            </TableRow>
          )}
          {!loading && tenants.length === 0 && (
            <TableRow className="hover:bg-transparent">
              <TableCell colSpan={3} className="text-center text-xs text-muted-foreground py-8">
                {t("tenants.empty")}
              </TableCell>
            </TableRow>
          )}
          {tenants.map((tn) => (
            <TableRow key={tn.id}>
              <TableCell className="px-5 font-medium">{tn.name}</TableCell>
              <TableCell className="px-5 text-muted-foreground text-sm">
                {formatDateTime(tn.created_at)}
              </TableCell>
              <TableCell className="px-5">
                <div className="flex items-center gap-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => { setInviteTo(tn); setInviteEmail(""); setInviteRole("it_admin"); setInviteURL("") }}
                    title={t("tenants.inviteAdmin")}
                  >
                    <UserPlus className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => { setRename(tn); setRenameName(tn.name) }}
                    title={t("tenants.rename")}
                  >
                    <Pencil className="h-4 w-4" />
                  </Button>
                  {/* Тенант по умолчанию неудаляем: в нём бутстрап-админ, без него
                      в систему некому войти. Переименовать его при этом можно. */}
                  {tn.id !== DEFAULT_TENANT_ID && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setToDelete(tn)}
                      title={t("common.delete")}
                      className="text-destructive hover:text-destructive"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <Dialog open={inviteTo !== null} onOpenChange={(o) => !o && setInviteTo(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("tenants.inviteTitle", { name: inviteTo?.name ?? "" })}</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleInvite} className="space-y-4">
            <div>
              <Label htmlFor="inv-email">E-mail</Label>
              <Input id="inv-email" type="email" value={inviteEmail}
                     onChange={(e) => setInviteEmail(e.target.value)} required autoFocus />
            </div>
            <div>
              <Label htmlFor="inv-role">{t("tenants.role")}</Label>
              <select id="inv-role" value={inviteRole} onChange={(e) => setInviteRole(e.target.value)}
                      className="w-full h-9 rounded-md border bg-background px-3 text-sm">
                <option value="it_admin">{t("tenants.roleAdmin")}</option>
                <option value="viewer">{t("tenants.roleViewer")}</option>
              </select>
            </div>
            {inviteURL !== "" && (
              <div className="text-xs break-all rounded-md bg-muted p-2">
                {t("tenants.manualLink")}<br />{inviteURL}
              </div>
            )}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => setInviteTo(null)}>{t("common.close")}</Button>
              <Button type="submit" disabled={saving}>{saving ? t("tenants.sending") : t("tenants.inviteBtn")}</Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={toDelete !== null} onOpenChange={(o) => !o && setToDelete(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("tenants.deleteQ", { name: toDelete?.name ?? "" })}</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 text-sm">
            {/* Trans, а не t(): «перейдут в Default» обязано остаться выделенным
                внутри фразы, а в английском этот кусок стоит на другом месте. */}
            <p>
              <Trans i18nKey="tenants.deleteWarn" components={[<b />]} />
            </p>
            <p className="text-muted-foreground">
              {t("tenants.auditNote")}
            </p>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={() => setToDelete(null)} disabled={saving}>
              {t("common.cancel")}
            </Button>
            <Button variant="destructive" onClick={handleDelete} disabled={saving}>
              {saving ? t("tenants.deleting") : t("tenants.deleteConfirm")}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("tenants.newTenant")}</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleCreate} className="space-y-4">
            <div>
              <Label htmlFor="tenant-name">{t("tenants.name")}</Label>
              <Input
                id="tenant-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                autoFocus
              />
            </div>
            <Button type="submit" disabled={saving || !name.trim()}>
              {saving ? t("tenants.creating") : t("common.create")}
            </Button>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={!!rename} onOpenChange={(o) => !o && setRename(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("tenants.rename")}</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleRename} className="space-y-4">
            <div>
              <Label htmlFor="rename-name">{t("tenants.name")}</Label>
              <Input
                id="rename-name"
                value={renameName}
                onChange={(e) => setRenameName(e.target.value)}
                required
                autoFocus
              />
            </div>
            <Button type="submit" disabled={saving || !renameName.trim()}>
              {saving ? t("tenants.saving") : t("common.save")}
            </Button>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}

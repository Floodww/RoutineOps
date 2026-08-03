import { useEffect, useState, FormEvent } from "react"
import { useTranslation, Trans } from "react-i18next"
import { FolderTree, RefreshCw, Plug } from "lucide-react"
import api, { DirectoryConfig, DirectorySyncResult, DirectoryPerson, errMessage, errStatus } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select } from "@/components/ui/select"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import { toast } from "@/lib/toast"

const EMPTY: DirectoryConfig = {
  enabled: false, url: "", bind_dn: "", base_dn: "", user_filter: "", sync_interval_min: 0, has_password: false,
  start_tls: false, has_ca_cert: false, login_enabled: false,
}

// {t("directory.title")} — enterprise-фича. В open-core ручки /directory/* отвечают 501 → страница
// показывает «недоступно в этой редакции» (тот же приём, что License при 404). Ручной
// bind-пароль write-only: has_password говорит, задан ли он, а само поле пустое = не менять.
export default function Directory() {
  const { t } = useTranslation()
  const [form, setForm] = useState<DirectoryConfig>(EMPTY)
  const [bindPassword, setBindPassword] = useState("")
  // PEM тоже write-only: сервер отдаёт лишь has_ca_cert, поле всегда пустое при загрузке.
  const [caCertPem, setCaCertPem] = useState("")
  const [persons, setPersons] = useState<DirectoryPerson[]>([])
  const [unavailable, setUnavailable] = useState(false)
  const [loadError, setLoadError] = useState(false)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [syncing, setSyncing] = useState(false)

  async function loadPersons() {
    try {
      const p = await api.get<DirectoryPerson[]>("/directory/persons")
      setPersons(p.data ?? [])
    } catch { /* список — вторично, конфиг важнее */ }
  }

  // load самодостаточна (не зовёт другие компонент-функции), иначе exhaustive-deps
  // потребует её в deps эффекта. Персоны — вторичны: их сбой не прячет форму конфига.
  async function load() {
    try {
      const r = await api.get<DirectoryConfig>("/directory/config")
      setForm(r.data)
    } catch (e) {
      if (errStatus(e) === 501) setUnavailable(true)
      else setLoadError(true)
      setLoading(false)
      return
    }
    try {
      const p = await api.get<DirectoryPerson[]>("/directory/persons")
      setPersons(p.data ?? [])
    } catch { /* список вторичен */ }
    setLoading(false)
  }
  useEffect(() => { load() }, [])

  async function save(e: FormEvent) {
    e.preventDefault()
    setSaving(true)
    try {
      await api.put("/directory/config", { ...form, bind_password: bindPassword, ca_cert_pem: caCertPem })
      setBindPassword("")
      const r = await api.get<DirectoryConfig>("/directory/config")
      setForm(r.data)
      toast({ title: t("directory.directoryConfigurationSaved") })
    } catch (err) {
      toast({ title: t("directory.failedToSave"), description: errMessage(err), variant: "destructive" })
    } finally {
      setSaving(false)
    }
  }

  async function test() {
    setTesting(true)
    try {
      const r = await api.post<{ status: string; error?: string }>("/directory/test")
      if (r.data.status === "ok") toast({ title: t("directory.connectionSucceeded") })
      else toast({ title: t("directory.connectionFailed"), description: r.data.error, variant: "destructive" })
    } catch (err) {
      toast({ title: t("directory.theCheckFailed"), description: errMessage(err), variant: "destructive" })
    } finally {
      setTesting(false)
    }
  }

  async function sync() {
    setSyncing(true)
    try {
      const r = await api.post<DirectorySyncResult>("/directory/sync")
      toast({ title: t("directory.synchronizationFinished"), description: t("directory.syncResult", { synced: r.data.synced, disabled: r.data.disabled }) })
      await loadPersons()
    } catch (err) {
      toast({ title: t("directory.synchronizationFailed"), description: errMessage(err), variant: "destructive" })
    } finally {
      setSyncing(false)
    }
  }

  if (loading) return <div className="p-6 text-sm text-muted-foreground">{t("directory.loading")}</div>

  if (unavailable) {
    return (
      <div className="glass px-5 py-[18px] max-w-2xl">
        <h1 className="text-[15px] font-semibold text-foreground flex items-center gap-2">
          <FolderTree className="h-[17px] w-[17px] text-muted-foreground" strokeWidth={2} />
          {t("directory.unavailable")}
        </h1>
        <p className="text-sm text-muted-foreground mt-2">
          {t("directory.enterpriseOnly")}
          {t("directory.manualOwnerHint")}
        </p>
      </div>
    )
  }
  if (loadError) return <div className="p-6 text-sm text-destructive">{t("directory.failedToLoadDirectory")}</div>

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-xl font-semibold text-foreground flex items-center gap-2">
          <FolderTree className="h-5 w-5 text-muted-foreground" strokeWidth={2} />
          {t("directory.title")}
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          {t("directory.intro")}
        </p>
      </div>

      <form onSubmit={save} className="glass px-5 py-[18px] space-y-4">
        <div className="flex items-center justify-between">
          <Label>{t("directory.synchronization")}</Label>
          <Select
            value={form.enabled ? "1" : ""}
            onChange={(v) => setForm({ ...form, enabled: v === "1" })}
            options={[{ value: "1", label: t("directory.on") }, { value: "", label: t("directory.off") }]}
            className="max-w-[180px]"
          />
        </div>
        <div>
          <Label htmlFor="url">{t("directory.serverUrl")}</Label>
          <Input id="url" value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })}
            placeholder="ldaps://dc.corp.local:636" />
        </div>
        <div className="flex items-center justify-between">
          <div>
            <Label>StartTLS</Label>
            <p className="text-xs text-soft mt-1">
              <Trans i18nKey="directory.startTLSHint" components={[<code />, <code />]} />
            </p>
          </div>
          <Select
            value={form.start_tls ? "1" : ""}
            onChange={(v) => setForm({ ...form, start_tls: v === "1" })}
            options={[{ value: "1", label: t("directory.enabled") }, { value: "", label: t("directory.disabled") }]}
            className="max-w-[180px]"
          />
        </div>
        <div>
          <Label htmlFor="ca_cert">{t("directory.directoryRootCertificatePem")}</Label>
          <textarea
            id="ca_cert"
            value={caCertPem}
            onChange={(e) => setCaCertPem(e.target.value)}
            rows={4}
            spellCheck={false}
            className="w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm font-mono"
            placeholder={form.has_ca_cert
              ? t("directory.setLeaveEmptyTo")
              : t("directory.beginCertificateNNeeded")}
          />
          <p className="text-xs text-soft mt-1">
            {t("directory.caHint")}
          </p>
        </div>
        <div>
          <Label htmlFor="bind_dn">{t("directory.bindDnServiceAccount")}</Label>
          <Input id="bind_dn" value={form.bind_dn} onChange={(e) => setForm({ ...form, bind_dn: e.target.value })}
            placeholder="CN=svc-mdm,OU=Service,DC=corp,DC=local" />
        </div>
        <div>
          <Label htmlFor="bind_password">{t("directory.bindPassword")}</Label>
          <Input id="bind_password" type="password" value={bindPassword} onChange={(e) => setBindPassword(e.target.value)}
            placeholder={form.has_password ? t("directory.setLeaveEmptyTo") : t("directory.serviceAccountPassword")} />
        </div>
        <div>
          <Label htmlFor="base_dn">{t("directory.baseDnWhereTo")}</Label>
          <Input id="base_dn" value={form.base_dn} onChange={(e) => setForm({ ...form, base_dn: e.target.value })}
            placeholder="OU=Users,DC=corp,DC=local" />
        </div>
        <div>
          <Label htmlFor="user_filter">{t("directory.userFilter")}</Label>
          <Input id="user_filter" value={form.user_filter} onChange={(e) => setForm({ ...form, user_filter: e.target.value })}
            placeholder={t("directory.objectclassUserObjectcategoryPer")} />
        </div>
        <div>
          <Label htmlFor="interval">{t("directory.syncIntervalMin0")}</Label>
          <Input id="interval" type="number" min={0} value={form.sync_interval_min}
            onChange={(e) => setForm({ ...form, sync_interval_min: Number(e.target.value) || 0 })} className="max-w-[180px]" />
        </div>
        <div className="flex items-center justify-between border-t border-border pt-4">
          <div className="pr-4">
            <Label>{t("directory.signInWithThe")}</Label>
            <p className="text-xs text-soft mt-1">
              <Trans i18nKey="directory.loginHint" components={[<b />, <code />, <code />]} />
            </p>
          </div>
          <Select
            value={form.login_enabled ? "1" : ""}
            onChange={(v) => setForm({ ...form, login_enabled: v === "1" })}
            options={[{ value: "1", label: t("directory.allowed") }, { value: "", label: t("directory.denied") }]}
            className="max-w-[180px] shrink-0"
          />
        </div>
        <div className="flex items-center gap-2 pt-1">
          <Button type="submit" disabled={saving}>{saving ? t("directory.saving") : t("directory.save")}</Button>
          <Button type="button" variant="outline" disabled={testing} onClick={test}>
            <Plug className="h-4 w-4 mr-1.5" strokeWidth={2} />
            {testing ? t("directory.checking") : t("directory.testTheConnection")}
          </Button>
          <Button type="button" variant="outline" disabled={syncing || !form.enabled} onClick={sync}>
            <RefreshCw className={`h-4 w-4 mr-1.5 ${syncing ? "animate-spin" : ""}`} strokeWidth={2} />
            {syncing ? t("directory.synchronizing") : t("directory.synchronize")}
          </Button>
        </div>
      </form>

      <div className="glass px-5 py-[18px]">
        <h2 className="text-[15px] font-semibold text-foreground mb-4">{t("directory.persons", { count: persons.length })}</h2>
        {persons.length === 0 ? (
          <p className="text-sm text-soft">{t("directory.emptyRunASynchronization")}</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("directory.name")}</TableHead>
                <TableHead>{t("directory.login")}</TableHead>
                <TableHead>E-mail</TableHead>
                <TableHead>{t("directory.status")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {persons.map((p) => (
                <TableRow key={p.id}>
                  <TableCell className="text-foreground">{p.display_name || "—"}</TableCell>
                  <TableCell className="font-mono text-xs">{p.sam_account || "—"}</TableCell>
                  <TableCell>{p.email || "—"}</TableCell>
                  <TableCell>
                    {p.disabled ? <Badge variant="outline">{t("directory.disabled2")}</Badge> : <Badge variant="default">{t("directory.active")}</Badge>}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
    </div>
  )
}

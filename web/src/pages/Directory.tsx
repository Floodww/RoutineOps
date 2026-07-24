import { useEffect, useState, FormEvent } from "react"
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
}

// Каталог (LDAP) — enterprise-фича. В open-core ручки /directory/* отвечают 501 → страница
// показывает «недоступно в этой редакции» (тот же приём, что License при 404). Ручной
// bind-пароль write-only: has_password говорит, задан ли он, а само поле пустое = не менять.
export default function Directory() {
  const [form, setForm] = useState<DirectoryConfig>(EMPTY)
  const [bindPassword, setBindPassword] = useState("")
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
      await api.put("/directory/config", { ...form, bind_password: bindPassword })
      setBindPassword("")
      const r = await api.get<DirectoryConfig>("/directory/config")
      setForm(r.data)
      toast({ title: "Конфиг каталога сохранён" })
    } catch (err) {
      toast({ title: "Не удалось сохранить", description: errMessage(err), variant: "destructive" })
    } finally {
      setSaving(false)
    }
  }

  async function test() {
    setTesting(true)
    try {
      const r = await api.post<{ status: string; error?: string }>("/directory/test")
      if (r.data.status === "ok") toast({ title: "Подключение успешно" })
      else toast({ title: "Подключение не удалось", description: r.data.error, variant: "destructive" })
    } catch (err) {
      toast({ title: "Проверка не удалась", description: errMessage(err), variant: "destructive" })
    } finally {
      setTesting(false)
    }
  }

  async function sync() {
    setSyncing(true)
    try {
      const r = await api.post<DirectorySyncResult>("/directory/sync")
      toast({ title: "Синхронизация завершена", description: `персон: ${r.data.synced}, отключено: ${r.data.disabled}, привязано: ${r.data.matched}` })
      await loadPersons()
    } catch (err) {
      toast({ title: "Синхронизация не удалась", description: errMessage(err), variant: "destructive" })
    } finally {
      setSyncing(false)
    }
  }

  if (loading) return <div className="p-6 text-sm text-muted-foreground">Загрузка…</div>

  if (unavailable) {
    return (
      <div className="glass px-5 py-[18px] max-w-2xl">
        <h1 className="text-[15px] font-semibold text-foreground flex items-center gap-2">
          <FolderTree className="h-[17px] w-[17px] text-muted-foreground" strokeWidth={2} />
          Каталог недоступен в этой редакции
        </h1>
        <p className="text-sm text-muted-foreground mt-2">
          Синхронизация с LDAP/Active Directory и авто-привязка владельцев — функция enterprise-редакции.
          Ручную привязку владельца можно задать в карточке устройства.
        </p>
      </div>
    )
  }
  if (loadError) return <div className="p-6 text-sm text-destructive">Не удалось загрузить настройки каталога.</div>

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-xl font-semibold text-foreground flex items-center gap-2">
          <FolderTree className="h-5 w-5 text-muted-foreground" strokeWidth={2} />
          Каталог (LDAP)
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Синк персон из Active Directory/LDAP и авто-привязка владельца устройства по консольному пользователю.
        </p>
      </div>

      <form onSubmit={save} className="glass px-5 py-[18px] space-y-4">
        <div className="flex items-center justify-between">
          <Label>Синхронизация</Label>
          <Select
            value={form.enabled ? "1" : ""}
            onChange={(v) => setForm({ ...form, enabled: v === "1" })}
            options={[{ value: "1", label: "Включена" }, { value: "", label: "Выключена" }]}
            className="max-w-[180px]"
          />
        </div>
        <div>
          <Label htmlFor="url">URL сервера</Label>
          <Input id="url" value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })}
            placeholder="ldaps://dc.corp.local:636" />
        </div>
        <div>
          <Label htmlFor="bind_dn">Bind DN (сервис-аккаунт)</Label>
          <Input id="bind_dn" value={form.bind_dn} onChange={(e) => setForm({ ...form, bind_dn: e.target.value })}
            placeholder="CN=svc-mdm,OU=Service,DC=corp,DC=local" />
        </div>
        <div>
          <Label htmlFor="bind_password">Bind-пароль</Label>
          <Input id="bind_password" type="password" value={bindPassword} onChange={(e) => setBindPassword(e.target.value)}
            placeholder={form.has_password ? "•••••••• (задан, оставьте пустым — не менять)" : "пароль сервис-аккаунта"} />
        </div>
        <div>
          <Label htmlFor="base_dn">Base DN (где искать персон)</Label>
          <Input id="base_dn" value={form.base_dn} onChange={(e) => setForm({ ...form, base_dn: e.target.value })}
            placeholder="OU=Users,DC=corp,DC=local" />
        </div>
        <div>
          <Label htmlFor="user_filter">Фильтр пользователей</Label>
          <Input id="user_filter" value={form.user_filter} onChange={(e) => setForm({ ...form, user_filter: e.target.value })}
            placeholder="(&(objectClass=user)(objectCategory=person)) — по умолчанию" />
        </div>
        <div>
          <Label htmlFor="interval">Интервал синка (мин, 0 = только вручную)</Label>
          <Input id="interval" type="number" min={0} value={form.sync_interval_min}
            onChange={(e) => setForm({ ...form, sync_interval_min: Number(e.target.value) || 0 })} className="max-w-[180px]" />
        </div>
        <div className="flex items-center gap-2 pt-1">
          <Button type="submit" disabled={saving}>{saving ? "Сохранение…" : "Сохранить"}</Button>
          <Button type="button" variant="outline" disabled={testing} onClick={test}>
            <Plug className="h-4 w-4 mr-1.5" strokeWidth={2} />
            {testing ? "Проверка…" : "Проверить подключение"}
          </Button>
          <Button type="button" variant="outline" disabled={syncing || !form.enabled} onClick={sync}>
            <RefreshCw className={`h-4 w-4 mr-1.5 ${syncing ? "animate-spin" : ""}`} strokeWidth={2} />
            {syncing ? "Синхронизация…" : "Синхронизировать"}
          </Button>
        </div>
      </form>

      <div className="glass px-5 py-[18px]">
        <h2 className="text-[15px] font-semibold text-foreground mb-4">Персоны каталога ({persons.length})</h2>
        {persons.length === 0 ? (
          <p className="text-sm text-soft">Пусто — запустите синхронизацию.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Имя</TableHead>
                <TableHead>Логин</TableHead>
                <TableHead>E-mail</TableHead>
                <TableHead>Статус</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {persons.map((p) => (
                <TableRow key={p.id}>
                  <TableCell className="text-foreground">{p.display_name || "—"}</TableCell>
                  <TableCell className="font-mono text-xs">{p.sam_account || "—"}</TableCell>
                  <TableCell>{p.email || "—"}</TableCell>
                  <TableCell>
                    {p.disabled ? <Badge variant="outline">отключён</Badge> : <Badge variant="default">активен</Badge>}
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

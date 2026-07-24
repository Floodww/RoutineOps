import { useEffect, useState } from "react"
import { Copy, Check } from "lucide-react"
import api from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Select } from "@/components/ui/select"
import ConfirmDialog from "@/components/ConfirmDialog"
import { formatDistanceToNow } from "@/lib/time"
import { toast } from "@/lib/toast"

type APIToken = {
  id: string
  name: string
  role: string
  created_at: string
  expires_at: string | null
  last_used_at: string | null
}
// Плейнтекст токена приходит ТОЛЬКО в ответе на создание — в БД лежит хэш, список его
// не отдаёт, переоткрыть нечем (см. createAPITokenResponse на сервере).
type CreatedAPIToken = APIToken & { token: string }

type DialogStep = "form" | "token"

const MAX_TTL_DAYS = 3650 // = maxAPITokenTTLDays на сервере

export default function APITokens() {
  const [tokens, setTokens] = useState<APIToken[]>([])
  const [loading, setLoading] = useState(true)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [step, setStep] = useState<DialogStep>("form")
  const [name, setName] = useState("")
  const [role, setRole] = useState("viewer")
  const [expiresDays, setExpiresDays] = useState("") // "" = бессрочно
  const [creating, setCreating] = useState(false)
  const [result, setResult] = useState<CreatedAPIToken | null>(null)
  const [copied, setCopied] = useState(false)
  const [confirmRevoke, setConfirmRevoke] = useState<APIToken | null>(null)

  async function load() {
    try {
      const r = await api.get<APIToken[]>("/api-tokens")
      setTokens(r.data ?? [])
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { load() }, [])

  function resetDialog() {
    setStep("form"); setName(""); setRole("viewer"); setExpiresDays(""); setResult(null); setCopied(false)
  }

  async function createToken() {
    const trimmed = name.trim()
    if (!trimmed) { toast({ title: "Введите имя токена", variant: "destructive" }); return }
    // Пусто = бессрочно (0). Валидируем здесь, чтобы не гонять заведомо битый запрос:
    // сервер всё равно режет, но ранний тост понятнее 400-й.
    const days = expiresDays.trim() === "" ? 0 : Number(expiresDays)
    if (!Number.isInteger(days) || days < 0 || days > MAX_TTL_DAYS) {
      toast({ title: `Срок — целое от 0 до ${MAX_TTL_DAYS} дней (0 = бессрочно)`, variant: "destructive" }); return
    }
    setCreating(true)
    try {
      const r = await api.post<CreatedAPIToken>("/api-tokens", { name: trimmed, role, expires_in_days: days })
      setResult(r.data)
      setStep("token")
      load()
    } catch {
      // авто-тост интерсептора
    } finally {
      setCreating(false)
    }
  }

  async function copyToken() {
    if (!result) return
    try {
      await navigator.clipboard.writeText(result.token)
    } catch {
      const ta = document.createElement("textarea")
      ta.value = result.token; document.body.appendChild(ta); ta.select()
      document.execCommand("copy"); document.body.removeChild(ta)
    }
    setCopied(true); setTimeout(() => setCopied(false), 2000)
  }

  async function revokeToken(t: APIToken) {
    try {
      await api.delete(`/api-tokens/${t.id}`)
      toast({ title: "Токен отозван", variant: "success" })
    } catch {
      // 404 = токен уже мёртв — просто перечитываем список
    } finally {
      setConfirmRevoke(null)
      load()
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-foreground">API-токены</h1>
          <p className="text-sm text-muted-foreground">
            Доступ к API автоматизацией (CI, скрипты). Ручки, что выпускают или повышают права,
            токеном недоступны — только человеком под паролем.
          </p>
        </div>
        {/* Сброс формы ТОЛЬКО при закрытии на шаге form: на шаге token закрытие мимо/Esc
            стёрло бы единственную копию токена. Токен всё равно виден в списке ниже (как факт),
            но плейнтекст — нет. */}
        <Dialog open={dialogOpen} onOpenChange={(o) => { setDialogOpen(o); if (!o && step === "form") resetDialog() }}>
          <DialogTrigger asChild>
            <Button size="sm">Выпустить токен</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{step === "form" ? "Новый API-токен" : "Токен выпущен"}</DialogTitle>
            </DialogHeader>

            {step === "form" && (
              <div className="space-y-4 pt-2">
                <div className="space-y-1.5">
                  <Label>Имя</Label>
                  <Input value={name} maxLength={128} placeholder="напр. ci-deploy"
                    onChange={(e) => setName(e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label>Роль</Label>
                  <Select value={role} onChange={setRole} options={[
                    { value: "viewer", label: "viewer — только чтение" },
                    { value: "it_admin", label: "it_admin — полный доступ" },
                  ]} />
                </div>
                <div className="space-y-1.5">
                  <Label>Срок жизни, дней</Label>
                  <Input type="number" min={0} max={MAX_TTL_DAYS} placeholder="бессрочно"
                    value={expiresDays} onChange={(e) => setExpiresDays(e.target.value)} />
                  <p className="text-xs text-muted-foreground">Пусто или 0 — бессрочный токен.</p>
                </div>
                <Button className="w-full" onClick={createToken} disabled={creating}>
                  {creating ? "Выпуск..." : "Выпустить"}
                </Button>
              </div>
            )}

            {step === "token" && result && (
              <div className="space-y-4 pt-2">
                <p className="text-sm text-muted-foreground">
                  Роль {result.role}.{" "}
                  {result.expires_at
                    ? `Действует до ${new Date(result.expires_at).toLocaleString("ru-RU")}.`
                    : "Бессрочный."}
                </p>
                <div className="relative">
                  <pre className="rounded-md border border-border bg-muted px-3 py-3 text-xs font-mono text-soft break-all whitespace-pre-wrap pr-10">{result.token}</pre>
                  <button type="button" onClick={copyToken}
                    aria-label={copied ? "Токен скопирован" : "Скопировать токен"}
                    className="absolute right-2 top-2 rounded p-1 text-muted-foreground hover:text-foreground transition-colors">
                    {copied ? <Check className="h-4 w-4 text-emerald-600 dark:text-emerald-500" /> : <Copy className="h-4 w-4" />}
                  </button>
                </div>
                <p className="text-xs text-muted-foreground">
                  Сохраните токен сейчас — на сервере он лежит хэшем, повторно посмотреть будет нельзя.
                </p>
                <div className="rounded-md border border-border bg-muted/50 px-3 py-2 text-xs text-muted-foreground">
                  <span className="font-medium text-foreground">Использование: </span>
                  заголовок <code className="font-mono">Authorization: Bearer &lt;токен&gt;</code>
                </div>
                <Button className="w-full" variant="outline" onClick={() => { setDialogOpen(false); resetDialog() }}>
                  Готово
                </Button>
              </div>
            )}
          </DialogContent>
        </Dialog>
      </div>

      <div className="glass overflow-hidden">
        {loading ? (
          <p className="px-5 py-8 text-sm text-muted-foreground">Загрузка…</p>
        ) : tokens.length === 0 ? (
          <p className="px-5 py-8 text-sm text-muted-foreground">Токенов пока нет. Выпустите первый.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Имя</TableHead>
                <TableHead>Роль</TableHead>
                <TableHead>Создан</TableHead>
                <TableHead>Истекает</TableHead>
                <TableHead>Использован</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {tokens.map((t) => (
                <TableRow key={t.id}>
                  <TableCell className="font-medium text-foreground">{t.name}</TableCell>
                  <TableCell><Badge variant={t.role === "it_admin" ? "default" : "outline"}>{t.role}</Badge></TableCell>
                  <TableCell className="text-muted-foreground">{formatDistanceToNow(t.created_at)}</TableCell>
                  <TableCell className="text-muted-foreground">{t.expires_at ? formatDistanceToNow(t.expires_at) : "бессрочно"}</TableCell>
                  <TableCell className="text-muted-foreground">{t.last_used_at ? formatDistanceToNow(t.last_used_at) : "—"}</TableCell>
                  <TableCell className="text-right">
                    <Button size="sm" variant="destructive" onClick={() => setConfirmRevoke(t)}>Отозвать</Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      <ConfirmDialog
        open={!!confirmRevoke}
        onOpenChange={(o) => !o && setConfirmRevoke(null)}
        title="Отозвать токен?"
        description={confirmRevoke
          ? `Токен «${confirmRevoke.name}» перестанет работать немедленно — автоматизация, использующая его, потеряет доступ. Отмена невозможна.`
          : ""}
        confirmLabel="Отозвать"
        destructive
        onConfirm={() => { if (confirmRevoke) revokeToken(confirmRevoke) }}
      />
    </div>
  )
}

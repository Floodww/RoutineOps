import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
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
  // scope — СУЖЕНИЕ доступа. "" = обычный токен, "scim" = только /scim/v2/*.
  scope: string
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
  const { t } = useTranslation()
  const [tokens, setTokens] = useState<APIToken[]>([])
  const [loading, setLoading] = useState(true)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [step, setStep] = useState<DialogStep>("form")
  const [name, setName] = useState("")
  const [role, setRole] = useState("viewer")
  const [scope, setScope] = useState("")
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
    setStep("form"); setName(""); setRole("viewer"); setScope(""); setExpiresDays(""); setResult(null); setCopied(false)
  }

  async function createToken() {
    const trimmed = name.trim()
    if (!trimmed) { toast({ title: t("tokens.nameRequired"), variant: "destructive" }); return }
    // Пусто = бессрочно (0). Валидируем здесь, чтобы не гонять заведомо битый запрос:
    // сервер всё равно режет, но ранний тост понятнее 400-й.
    const days = expiresDays.trim() === "" ? 0 : Number(expiresDays)
    if (!Number.isInteger(days) || days < 0 || days > MAX_TTL_DAYS) {
      toast({ title: t("tokens.ttlRange", { max: MAX_TTL_DAYS }), variant: "destructive" }); return
    }
    setCreating(true)
    try {
      const r = await api.post<CreatedAPIToken>("/api-tokens", { name: trimmed, role, scope, expires_in_days: days })
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

  async function revokeToken(tok: APIToken) {
    try {
      await api.delete(`/api-tokens/${tok.id}`)
      toast({ title: t("tokens.revoked"), variant: "success" })
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
          <h1 className="text-xl font-semibold text-foreground">{t("tokens.title")}</h1>
          <p className="text-sm text-muted-foreground">
            {t("tokens.intro")}
          </p>
        </div>
        {/* Сброс формы ТОЛЬКО при закрытии на шаге form: на шаге token закрытие мимо/Esc
            стёрло бы единственную копию токена. Токен всё равно виден в списке ниже (как факт),
            но плейнтекст — нет. */}
        <Dialog open={dialogOpen} onOpenChange={(o) => { setDialogOpen(o); if (!o && step === "form") resetDialog() }}>
          <DialogTrigger asChild>
            <Button size="sm">{t("tokens.issue")}</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{step === "form" ? t("tokens.newToken") : t("tokens.issued")}</DialogTitle>
            </DialogHeader>

            {step === "form" && (
              <div className="space-y-4 pt-2">
                <div className="space-y-1.5">
                  <Label>{t("tokens.name")}</Label>
                  <Input value={name} maxLength={128} placeholder={t("tokens.namePlaceholder")}
                    onChange={(e) => setName(e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label>{t("tokens.role")}</Label>
                  <Select
                    value={role}
                    onChange={setRole}
                    options={[
                      // SCIM-токен заводит и удаляет пользователей — роль ниже it_admin
                      // для него бессмысленна, и сервер такой токен не выпустит.
                      { value: "viewer", label: t("tokens.roleViewerOpt"), disabled: scope === "scim" },
                      { value: "it_admin", label: t("tokens.roleAdminOpt") },
                    ]}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>{t("tokens.scope")}</Label>
                  <Select
                    value={scope}
                    onChange={(v) => { setScope(v); if (v === "scim") setRole("it_admin") }}
                    options={[
                      { value: "", label: t("tokens.scopeAny") },
                      { value: "scim", label: t("tokens.scopeSCIM") },
                    ]}
                  />
                  <p className="text-xs text-muted-foreground">
                    {scope === "scim"
                      ? t("tokens.scopeSCIMHint")
                      : t("tokens.scopeAnyHint")}
                  </p>
                </div>
                <div className="space-y-1.5">
                  <Label>{t("tokens.ttlDays")}</Label>
                  <Input type="number" min={0} max={MAX_TTL_DAYS} placeholder={t("tokens.forever")}
                    value={expiresDays} onChange={(e) => setExpiresDays(e.target.value)} />
                  <p className="text-xs text-muted-foreground">{t("tokens.ttlHint")}</p>
                </div>
                <Button className="w-full" onClick={createToken} disabled={creating}>
                  {creating ? t("tokens.issuing") : t("tokens.issueShort")}
                </Button>
              </div>
            )}

            {step === "token" && result && (
              <div className="space-y-4 pt-2">
                <p className="text-sm text-muted-foreground">
                  {result.scope
                    ? t("tokens.issuedRoleScope", { role: result.role, scope: result.scope })
                    : t("tokens.issuedRole", { role: result.role })}{" "}
                  {result.expires_at
                    ? t("tokens.expiresAt", { date: new Date(result.expires_at).toLocaleString() })
                    : t("tokens.neverExpires")}
                </p>
                <div className="relative">
                  <pre className="rounded-md border border-border bg-muted px-3 py-3 text-xs font-mono text-soft break-all whitespace-pre-wrap pr-10">{result.token}</pre>
                  <button type="button" onClick={copyToken}
                    aria-label={copied ? t("tokens.copied") : t("tokens.copy")}
                    className="absolute right-2 top-2 rounded p-1 text-muted-foreground hover:text-foreground transition-colors">
                    {copied ? <Check className="h-4 w-4 text-emerald-600 dark:text-emerald-500" /> : <Copy className="h-4 w-4" />}
                  </button>
                </div>
                <p className="text-xs text-muted-foreground">
                  {t("tokens.saveNow")}
                </p>
                <div className="rounded-md border border-border bg-muted/50 px-3 py-2 text-xs text-muted-foreground">
                  <span className="font-medium text-foreground">{t("tokens.usage")}</span>
                  {t("tokens.usageHeader")} <code className="font-mono">Authorization: Bearer &lt;{t("tokens.tokenWord")}&gt;</code>
                </div>
                <Button className="w-full" variant="outline" onClick={() => { setDialogOpen(false); resetDialog() }}>
                  {t("tokens.done")}
                </Button>
              </div>
            )}
          </DialogContent>
        </Dialog>
      </div>

      <div className="glass overflow-hidden">
        {loading ? (
          <p className="px-5 py-8 text-sm text-muted-foreground">{t("common.loading")}</p>
        ) : tokens.length === 0 ? (
          <p className="px-5 py-8 text-sm text-muted-foreground">{t("tokens.empty")}</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("tokens.name")}</TableHead>
                <TableHead>{t("tokens.role")}</TableHead>
                <TableHead>{t("tokens.scope")}</TableHead>
                <TableHead>{t("tokens.created")}</TableHead>
                <TableHead>{t("tokens.expires")}</TableHead>
                <TableHead>{t("tokens.used")}</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {tokens.map((tok) => (
                <TableRow key={tok.id}>
                  <TableCell className="font-medium text-foreground">{tok.name}</TableCell>
                  <TableCell><Badge variant={tok.role === "it_admin" ? "default" : "outline"}>{tok.role}</Badge></TableCell>
                  <TableCell>
                    {tok.scope
                      ? <Badge variant="outline" className="text-xs">{tok.scope}</Badge>
                      : <span className="text-muted-foreground text-xs">{t("tokens.unlimited")}</span>}
                  </TableCell>
                  <TableCell className="text-muted-foreground">{formatDistanceToNow(tok.created_at)}</TableCell>
                  <TableCell className="text-muted-foreground">{tok.expires_at ? formatDistanceToNow(tok.expires_at) : t("tokens.forever")}</TableCell>
                  <TableCell className="text-muted-foreground">{tok.last_used_at ? formatDistanceToNow(tok.last_used_at) : "—"}</TableCell>
                  <TableCell className="text-right">
                    <Button size="sm" variant="destructive" onClick={() => setConfirmRevoke(tok)}>{t("tokens.revoke")}</Button>
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
        title={t("tokens.revokeQ")}
        description={confirmRevoke ? t("tokens.revokeWarn", { name: confirmRevoke.name }) : ""}
        confirmLabel={t("tokens.revoke")}
        destructive
        onConfirm={() => { if (confirmRevoke) revokeToken(confirmRevoke) }}
      />
    </div>
  )
}

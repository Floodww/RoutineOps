import { useState, useEffect, FormEvent } from "react"
import { useTranslation, Trans } from "react-i18next"
import api from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Select } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { UserPlus, Trash2 } from "lucide-react"
import { toast } from "@/lib/toast"
import { useMe } from "@/lib/useMe"
import { formatDate } from "@/lib/time"

interface User {
  id: string
  name: string
  email: string
  role: string
  created_at: string
}

const roleLabels: Record<string, string> = {
  // Значения — КЛЮЧИ словаря (t() на уровне модуля недоступен).
  it_admin: "users.roleAdminFull",
  viewer: "users.roleViewer",
}

export default function Users() {
  const { t } = useTranslation()
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState("")
  const [inviteOpen, setInviteOpen] = useState(false)
  const [inviteEmail, setInviteEmail] = useState("")
  const [inviteRole, setInviteRole] = useState("it_admin")
  const [inviteLoading, setInviteLoading] = useState(false)
  // Ссылка-приглашение, если письмо не ушло (SMTP выключен или отправка не удалась):
  // бэкенд возвращает invite_url, чтобы оператор передал её вручную.
  const [inviteLink, setInviteLink] = useState<string | null>(null)
  const { me } = useMe()
  // Кого удаляем — держим весь объект, а не id: в подтверждении нужен email, иначе
  // оператор соглашается на «удалить пользователя» вслепую.
  const [toDelete, setToDelete] = useState<User | null>(null)
  const [deleting, setDeleting] = useState(false)

  useEffect(() => {
    api.get<User[]>("/users")
      .then((r) => setUsers(r.data))
      .catch(() => toast({ title: t("users.loadFailed"), variant: "destructive" }))
      .finally(() => setLoading(false))
  }, [])

  async function handleInvite(e: FormEvent) {
    e.preventDefault()
    setInviteLoading(true)
    setInviteLink(null)
    try {
      const r = await api.post<{ email_sent?: string; invite_url?: string }>(
        "/users/invite", { email: inviteEmail, role: inviteRole })
      if (r.data.email_sent === "true") {
        toast({ title: t("users.inviteSent", { email: inviteEmail }), variant: "success" })
        setInviteOpen(false)
        setInviteEmail("")
        return
      }
      // Письмо не ушло (SMTP выключен/сбой) — показываем ссылку для ручной передачи,
      // диалог НЕ закрываем, иначе ссылка потеряется.
      if (r.data.invite_url) {
        setInviteLink(r.data.invite_url)
        toast({ title: t("users.mailNotSent"), variant: "destructive" })
      } else {
        toast({ title: t("users.inviteNoLink"), variant: "destructive" })
      }
    } catch {
      toast({ title: t("users.inviteFailed"), variant: "destructive" })
    } finally {
      setInviteLoading(false)
    }
  }

  async function handleDelete() {
    if (!toDelete) return
    setDeleting(true)
    try {
      await api.delete(`/users/${toDelete.id}`)
      setUsers((prev) => prev.filter((u) => u.id !== toDelete.id))
      toast({ title: t("users.deleted", { email: toDelete.email }), variant: "success" })
      setToDelete(null)
    } catch (e) {
      // 409 — отказ по смыслу (последний администратор, попытка удалить себя), и
      // причину сервер называет текстом. Показываем её, а не «не удалось»: иначе
      // осмысленный отказ выглядит сбоем и оператор идёт жать ещё раз.
      const detail = (e as { response?: { status?: number; data?: unknown } })?.response
      const text = typeof detail?.data === "string" ? detail.data.trim() : ""
      toast({
        title: detail?.status === 409 && text ? text : t("users.deleteFailed"),
        variant: "destructive",
      })
    } finally {
      setDeleting(false)
    }
  }

  const isAdmin = me?.role === "it_admin"

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold text-foreground">{t("users.title")}</h1>
        <Button onClick={() => setInviteOpen(true)}>
          <UserPlus className="h-4 w-4 mr-2" strokeWidth={2} />
          {t("users.inviteShort")}
        </Button>
      </div>

      <div className="glass">
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 pt-4 pb-3">
          <div>
            <h2 className="text-[15px] font-semibold text-foreground">{t("users.accounts")}</h2>
            <p className="text-xs text-muted-foreground">{t("users.panelAccess")}</p>
          </div>
          <Input
            placeholder={t("users.searchEmail")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="max-w-[240px]"
          />
        </div>

        {/* Строки таблицы разделяются верхней границей (как ленты на «Обзоре»),
            поэтому border-b примитива гасится, а border-t проставляется явно. */}
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="px-5 text-xs font-medium text-muted-foreground">{t("users.name")}</TableHead>
              <TableHead className="px-5 text-xs font-medium text-muted-foreground">Email</TableHead>
              <TableHead className="px-5 text-xs font-medium text-muted-foreground">{t("users.role")}</TableHead>
              <TableHead className="px-5 text-xs font-medium text-muted-foreground">{t("users.added")}</TableHead>
              {isAdmin && <TableHead className="px-5 w-px" />}
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow className="hover:bg-transparent"><TableCell colSpan={isAdmin ? 5 : 4} className="text-center text-xs text-muted-foreground py-8">{t("common.loading")}</TableCell></TableRow>
            ) : users.length === 0 ? (
              <TableRow className="hover:bg-transparent"><TableCell colSpan={isAdmin ? 5 : 4} className="text-center text-xs text-muted-foreground py-8">{t("users.empty")}</TableCell></TableRow>
            ) : (() => {
              const q = query.trim().toLowerCase()
              const filtered = q ? users.filter((u) => u.email.toLowerCase().includes(q)) : users
              if (filtered.length === 0) {
                return <TableRow className="hover:bg-transparent"><TableCell colSpan={isAdmin ? 5 : 4} className="text-center text-xs text-muted-foreground py-8">{t("users.nothingFound")}</TableCell></TableRow>
              }
              return filtered.map((u) => (
              <TableRow key={u.id} className="hover:bg-transparent">
                <TableCell className="px-5 py-3 text-sm font-medium text-foreground">{u.name}</TableCell>
                <TableCell className="px-5 py-3 text-[13px] text-soft">{u.email}</TableCell>
                <TableCell className="px-5 py-3">
                  <Badge variant={u.role === "it_admin" ? "default" : "outline"}>
                    {roleLabels[u.role] ? t(roleLabels[u.role]) : u.role}
                  </Badge>
                </TableCell>
                <TableCell className="px-5 py-3 text-xs text-muted-foreground tabular-nums">
                  {formatDate(u.created_at)}
                </TableCell>
                {/* Себе кнопку не рисуем: сервер такое удаление отвергает, и показывать
                    действие, которое заведомо откажет, — обман. */}
                {isAdmin && (
                  <TableCell className="px-5 py-3 text-right">
                    {u.id !== me?.id && (
                      <Button
                        variant="ghost"
                        size="sm"
                        aria-label={t("users.deleteAria", { email: u.email })}
                        title={t("users.deleteAccount")}
                        onClick={() => setToDelete(u)}
                        className="text-muted-foreground hover:text-destructive"
                      >
                        <Trash2 className="h-4 w-4" strokeWidth={2} />
                      </Button>
                    )}
                  </TableCell>
                )}
              </TableRow>
              ))
            })()}
          </TableBody>
        </Table>
      </div>

      {/* Подтверждение простое, без ввода имени руками: удаление аккаунта обратимо
          приглашением, в отличие от сноса агента с живой машины. Но email в тексте
          обязателен — по строке «удалить пользователя?» соглашаются не глядя. */}
      <Dialog open={toDelete !== null} onOpenChange={(o) => { if (!o) setToDelete(null) }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("users.deleteAccountQ")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 pt-2">
            {/* Trans, а не t(): email внутри фразы обязан остаться выделенным, а в
                английском он стоит на другом месте — склеивать строку из кусков
                значило бы зашить в код русский порядок слов. */}
            <p className="text-sm text-soft">
              <Trans
                i18nKey="users.deleteWarn"
                values={{ email: toDelete?.email }}
                components={[<span className="font-medium text-foreground" />]}
              />
            </p>
            <p className="text-xs text-muted-foreground">{t("users.deleteKeeps")}</p>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setToDelete(null)} disabled={deleting}>
                {t("common.cancel")}
              </Button>
              <Button variant="destructive" onClick={handleDelete} disabled={deleting}>
                {deleting ? t("users.deleting") : t("common.delete")}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={inviteOpen} onOpenChange={(o) => { setInviteOpen(o); if (!o) { setInviteLink(null); setInviteEmail("") } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("users.invite")}</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleInvite} className="space-y-4 pt-2">
            <div className="space-y-1.5">
              <Label className="text-soft">Email</Label>
              <Input
                type="email"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                placeholder="colleague@company.com"
                required
                autoFocus
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-soft">{t("users.role")}</Label>
              <Select
                value={inviteRole}
                onChange={setInviteRole}
                options={[
                  { value: "it_admin", label: t("users.roleAdminFull") },
                  { value: "viewer", label: t("users.roleViewer") },
                ]}
              />
            </div>
            {inviteLink && (
              <div className="space-y-1.5">
                <Label className="text-soft">{t("users.inviteLink")}</Label>
                <Input readOnly value={inviteLink} onFocus={(e) => e.currentTarget.select()} />
                <p className="text-xs text-muted-foreground">
                  {t("users.smtpOff")}
                </p>
              </div>
            )}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => setInviteOpen(false)}>
                {inviteLink ? t("common.close") : t("common.cancel")}
              </Button>
              <Button type="submit" disabled={inviteLoading}>
                {inviteLoading ? t("users.sending") : t("users.sendInvite")}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}

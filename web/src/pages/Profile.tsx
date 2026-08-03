import { useState, FormEvent } from "react"
import { useTranslation } from "react-i18next"
import { useNavigate } from "react-router-dom"
import api, { errMessage } from "@/lib/api"
import { useMe } from "@/lib/useMe"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { toast } from "@/lib/toast"

// Значения — КЛЮЧИ словаря, а не готовый текст: t() на уровне модуля недоступен,
// перевод берётся уже в компоненте.
const roleLabels: Record<string, string> = {
  it_admin: "profile.roleAdminFull",
  viewer: "profile.roleViewer",
}

export default function Profile() {
  const { t } = useTranslation()
  const { me } = useMe()
  const navigate = useNavigate()
  const [current, setCurrent] = useState("")
  const [next, setNext] = useState("")
  const [confirmP, setConfirmP] = useState("")
  const [loading, setLoading] = useState(false)
  const [mfaLoading, setMfaLoading] = useState(false)

  async function disableMFA() {
    // Сервер требует свежий код второго фактора: снятие MFA весит столько же,
    // сколько её выдача, и одной угнанной сессии для этого быть не должно.
    const code = prompt(t("profile.disablePrompt"))
    if (!code) return
    setMfaLoading(true)
    try {
      await api.delete("/auth/mfa", { data: { code } })
      toast({ title: t("profile.mfaDisabled"), variant: "success" })
      window.location.reload()
    } catch (e) {
      toast({ title: t("profile.disableFailed"), description: errMessage(e), variant: "destructive" })
    } finally {
      setMfaLoading(false)
    }
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (next !== confirmP) {
      toast({ title: t("profile.mismatch"), variant: "destructive" })
      return
    }
    setLoading(true)
    try {
      await api.post("/me/password", { current_password: current, new_password: next })
      toast({ title: t("profile.changed"), variant: "success" })
      setCurrent("")
      setNext("")
      setConfirmP("")
    } catch (e) {
      toast({ title: t("profile.changeFailed"), description: errMessage(e), variant: "destructive" })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col gap-5 max-w-lg">
      <h1 className="text-xl font-semibold text-foreground">{t("profile.title")}</h1>

      <div className="glass px-5 py-[18px]">
        <h2 className="text-[15px] font-semibold text-foreground">{t("profile.account")}</h2>
        <p className="text-xs text-muted-foreground mb-3.5">{t("profile.accountHint")}</p>
        <div className="flex flex-col gap-2.5 text-[13px]">
          <div className="flex items-center justify-between gap-4">
            <span className="text-soft">{t("profile.name")}</span>
            <span className="text-foreground truncate">{me?.name ?? "—"}</span>
          </div>
          <div className="flex items-center justify-between gap-4">
            <span className="text-soft">Email</span>
            <span className="text-foreground truncate">{me?.email ?? "—"}</span>
          </div>
          <div className="flex items-center justify-between gap-4">
            <span className="text-soft">{t("profile.role")}</span>
            {me && <Badge variant={me.role === "it_admin" ? "default" : "secondary"}>{roleLabels[me.role] ? t(roleLabels[me.role]) : me.role}</Badge>}
          </div>
        </div>
      </div>

      <div className="glass px-5 py-[18px]">
        <h2 className="text-[15px] font-semibold text-foreground">{t("profile.mfa")}</h2>
        <p className="text-xs text-muted-foreground mb-3.5">{t("profile.mfaHint")}</p>
        <div className="flex items-center justify-between">
          <span className="text-[13px] text-foreground">
            {t("profile.status")}: {me?.mfa_enabled ? <Badge className="ml-2 bg-green-600 text-white hover:bg-green-700">{t("profile.mfaOn")}</Badge> : <Badge variant="secondary" className="ml-2">{t("profile.mfaOff")}</Badge>}
          </span>
          {me?.mfa_enabled ? (
            <Button variant="destructive" size="sm" onClick={disableMFA} disabled={mfaLoading}>{t("profile.disable")}</Button>
          ) : (
            <Button size="sm" onClick={() => navigate("/mfa-setup")}>{t("profile.enable")}</Button>
          )}
        </div>
      </div>

      <form onSubmit={handleSubmit} className="glass px-5 py-[18px] flex flex-col gap-4">
        <div>
          <h2 className="text-[15px] font-semibold text-foreground">{t("profile.changePassword")}</h2>
          <p className="text-xs text-muted-foreground">{t("profile.changePasswordHint")}</p>
        </div>
        <div className="space-y-1.5">
          <Label className="text-soft">{t("profile.currentPassword")}</Label>
          <Input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} required autoComplete="current-password" />
        </div>
        <div className="space-y-1.5">
          <Label className="text-soft">{t("profile.newPassword")}</Label>
          <Input type="password" value={next} onChange={(e) => setNext(e.target.value)} required autoComplete="new-password" />
        </div>
        <div className="space-y-1.5">
          <Label className="text-soft">{t("profile.repeatPassword")}</Label>
          <Input type="password" value={confirmP} onChange={(e) => setConfirmP(e.target.value)} required autoComplete="new-password" />
        </div>
        <Button type="submit" disabled={loading} className="self-start">{loading ? t("profile.saving") : t("profile.submitChange")}</Button>
      </form>
    </div>
  )
}

import { useState, useEffect, FormEvent } from "react"
import { useNavigate, Link, useSearchParams } from "react-router-dom"
import { useTranslation } from "react-i18next"
import { login, loginMFA } from "@/lib/auth"
import api from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { RoutineOpsLogo } from "@/components/RoutineOpsLogo"
import SpotlightCard from "@/components/SpotlightCard"

type OIDCProvider = { id: string; name: string; enabled: boolean }

// Значения — КЛЮЧИ словаря, а не готовый текст: сообщение выбирается по коду от
// сервера, а переводится уже в компоненте (t() недоступен на уровне модуля).
const SSO_ERROR_MSG: Record<string, string> = {
  not_registered: "login.ssoNotRegistered",
  auth_failed: "login.ssoAuthFailed",
}

export default function Login() {
  const { t } = useTranslation()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [mfaCode, setMfaCode] = useState("")
  const [mfaStep, setMfaStep] = useState(false)
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const [providers, setProviders] = useState<OIDCProvider[]>([])
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()

  // Показываем ошибку от OIDC callback (sso_error=...)
  useEffect(() => {
    const ssoErr = searchParams.get("sso_error")
    if (ssoErr) setError(t(SSO_ERROR_MSG[ssoErr] ?? "login.ssoGeneric"))
  }, [searchParams])

  // Загружаем список включённых OIDC-провайдеров (только для enterprise).
  useEffect(() => {
    api.get<OIDCProvider[]>("/oidc/providers")
      .then(res => setProviders((res.data ?? []).filter(p => p.enabled)))
      .catch(() => { /* open-core: 501 — не показываем SSO-кнопки */ })
  }, [])

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError("")
    setLoading(true)
    try {
      if (mfaStep) {
        await loginMFA(mfaCode)
        navigate("/dashboard")
      } else {
        const res = await login(email, password)
        if (res.mfaSetupRequired) {
          navigate("/mfa-setup")
        } else if (res.mfaRequired) {
          setMfaStep(true)
        } else {
          navigate("/dashboard")
        }
      }
    } catch {
      if (mfaStep) {
        setError(t("login.badMfaCode"))
      } else {
        setError(t("login.badCredentials"))
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    // Без bg-background: карта стоит прямо на фоне body с радиальными бликами.
    <div className="min-h-screen flex items-center justify-center p-4">
      <SpotlightCard as={Card} className="w-full max-w-sm">
        <CardHeader className="px-5 pt-6 pb-2">
          <CardTitle className="flex items-center justify-center gap-2.5 py-2 text-foreground">
            <RoutineOpsLogo size={32} />
            <span className="text-lg font-semibold tracking-tight">RoutineOps</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="px-5 pb-6">
          {/* SSO-кнопки — только при настроенных провайдерах (enterprise) */}
          {providers.length > 0 && (
            <div className="mb-4 space-y-2">
              {providers.map(p => (
                <a
                  key={p.id}
                  href={`/api/v1/auth/oidc/${p.id}/begin`}
                  className="flex w-full items-center justify-center gap-2 rounded-md border border-border bg-muted px-4 py-2 text-sm font-medium text-foreground hover:bg-accent transition-colors"
                >
                  <svg className="h-4 w-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                  </svg>
                  {t("login.viaProvider", { name: p.name })}
                </a>
              ))}
              <div className="relative my-3">
                <div className="absolute inset-0 flex items-center">
                  <span className="w-full border-t border-border" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-card px-2 text-muted-foreground">{t("login.or")}</span>
                </div>
              </div>
            </div>
          )}
          <form onSubmit={handleSubmit} className="space-y-4">
            {!mfaStep ? (
              <>
                <div className="space-y-1.5">
                  <Label htmlFor="email" className="text-soft">Email</Label>
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    autoFocus={providers.length === 0}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="password" className="text-soft">{t("login.password")}</Label>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>
              </>
            ) : (
              <div className="space-y-1.5">
                <Label htmlFor="mfaCode" className="text-soft">{t("login.mfaCodeLabel")}</Label>
                <Input
                  id="mfaCode"
                  type="text"
                  placeholder="000000"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  required
                  autoFocus
                  autoComplete="one-time-code"
                />
              </div>
            )}
            {/* --destructive в тёмной теме (45% светлоты) на стекле почти не читается —
                берём тот же красный, что у алерт-цифры на дашборде. */}
            {error && <p className="text-sm text-destructive dark:text-[hsl(0_72%_66%)]">{error}</p>}
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? t("login.submitting") : mfaStep ? t("login.confirm") : t("login.submit")}
            </Button>
            {!mfaStep && (
              <Link to="/forgot-password" className="block text-center text-sm text-muted-foreground hover:text-foreground transition-colors">
                {t("login.forgot")}
              </Link>
            )}
          </form>
        </CardContent>
      </SpotlightCard>
    </div>
  )
}

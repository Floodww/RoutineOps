import { useState, useEffect, FormEvent } from "react"
import { useTranslation } from "react-i18next"
import { useNavigate } from "react-router-dom"
import api from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { RoutineOpsLogo } from "@/components/RoutineOpsLogo"
import SpotlightCard from "@/components/SpotlightCard"
import QRCode from "react-qr-code"

export default function MFASetup() {
  const { t } = useTranslation()
  const [uri, setUri] = useState("")
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([])
  const [code, setCode] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    api.post("/auth/mfa/enroll")
      .then(res => {
        setUri(res.data.uri)
        setRecoveryCodes(res.data.recovery_codes)
      })
      .catch(() => setError(t("auth.mfaInitFailed")))
  }, [])

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError("")
    setLoading(true)
    try {
      await api.post("/auth/mfa/verify", { code })
      // После успешной верификации mfaVerifyEnroll ставит mfa_token="", 
      // выдаёт финальный JWT-токен (через куку) и авторизует. 
      // Нам надо только обновить флаг в sessionStorage, чтобы PrivateRoute пустил.
      sessionStorage.setItem("session", "1")
      navigate("/dashboard")
    } catch {
      setError(t("auth.mfaBadCode"))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <SpotlightCard as={Card} className="w-full max-w-md">
        <CardHeader className="px-5 pt-6 pb-2">
          <CardTitle className="flex items-center justify-center gap-2.5 py-2 text-foreground">
            <RoutineOpsLogo size={32} />
            <span className="text-lg font-semibold tracking-tight">{t("auth.mfaSetup")}</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="px-5 pb-6">
          {!uri ? (
            <p className="text-center text-muted-foreground">{error || t("common.loading")}</p>
          ) : (
            <div className="space-y-6">
              <p className="text-sm text-center text-muted-foreground">
                {t("auth.scanQR")}
              </p>
              <div className="flex justify-center bg-white p-4 rounded-md">
                <QRCode value={uri} size={150} />
              </div>
              <div className="space-y-2">
                <p className="text-sm font-medium">{t("auth.recoveryCodes")}</p>
                <p className="text-xs text-muted-foreground">
                  {t("auth.saveCodes")}
                </p>
                <div className="bg-muted p-3 rounded-md grid grid-cols-2 gap-2 text-xs font-mono text-center">
                  {recoveryCodes.map(c => <span key={c}>{c}</span>)}
                </div>
              </div>
              <form onSubmit={handleSubmit} className="space-y-4">
                <Input
                  type="text"
                  placeholder={t("auth.codeFromApp")}
                  value={code}
                  onChange={e => setCode(e.target.value)}
                  required
                  autoFocus
                />
                {error && <p className="text-sm text-destructive">{error}</p>}
                <Button type="submit" className="w-full" disabled={loading}>
                  {t("auth.confirmAndEnter")}
                </Button>
              </form>
            </div>
          )}
        </CardContent>
      </SpotlightCard>
    </div>
  )
}

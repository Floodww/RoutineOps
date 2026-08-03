import { useState, FormEvent } from "react"
import { useTranslation } from "react-i18next"
import { Link } from "react-router-dom"
import axios from "axios"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { RoutineOpsLogo } from "@/components/RoutineOpsLogo"
import SpotlightCard from "@/components/SpotlightCard"

export default function ForgotPassword() {
  const { t } = useTranslation()
  const [email, setEmail] = useState("")
  const [sent, setSent] = useState(false)
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setLoading(true)
    try {
      await axios.post("/api/v1/auth/forgot-password", { email })
    } finally {
      setLoading(false)
      setSent(true)
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
          <p className="text-center text-xs text-muted-foreground">{t("auth.forgotTitle")}</p>
        </CardHeader>
        <CardContent className="px-5 pb-6">
          {sent ? (
            <div className="space-y-4">
              <p className="text-sm text-soft">
                {t("auth.resetSent")}
              </p>
              <Link to="/login" className="block text-sm text-brand hover:underline">
                {t("auth.backToLogin")}
              </Link>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="email" className="text-soft">Email</Label>
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  autoFocus
                />
              </div>
              <Button type="submit" className="w-full" disabled={loading}>
                {loading ? t("auth.sending") : t("auth.sendLink")}
              </Button>
              <Link to="/login" className="block text-center text-sm text-muted-foreground hover:text-foreground transition-colors">
                {t("auth.backToLogin")}
              </Link>
            </form>
          )}
        </CardContent>
      </SpotlightCard>
    </div>
  )
}

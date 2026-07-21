import { useState, FormEvent } from "react"
import { useNavigate, useSearchParams, Link } from "react-router-dom"
import axios from "axios"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { RoutineOpsLogo } from "@/components/RoutineOpsLogo"
import SpotlightCard from "@/components/SpotlightCard"

export default function ResetPassword() {
  const [searchParams] = useSearchParams()
  const token = searchParams.get("token") ?? ""
  const navigate = useNavigate()

  const [password, setPassword] = useState("")
  const [confirm, setConfirm] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError("")
    if (password !== confirm) {
      setError("Пароли не совпадают")
      return
    }
    if (password.length < 8) {
      setError("Минимум 8 символов")
      return
    }
    setLoading(true)
    try {
      await axios.post("/api/v1/auth/reset-password", { token, password })
      navigate("/login")
    } catch {
      setError("Ссылка недействительна или истекла")
    } finally {
      setLoading(false)
    }
  }

  if (!token) {
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
            {/* --destructive в тёмной теме (45% светлоты) на стекле почти не читается —
                берём тот же красный, что у алерт-цифры на дашборде. */}
            <p className="text-sm text-destructive dark:text-[hsl(0_72%_66%)]">Неверная ссылка.</p>
            <Link to="/login" className="mt-2 block text-sm text-brand hover:underline">На страницу входа</Link>
          </CardContent>
        </SpotlightCard>
      </div>
    )
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
          <p className="text-center text-xs text-muted-foreground">Новый пароль</p>
        </CardHeader>
        <CardContent className="px-5 pb-6">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="password" className="text-soft">Новый пароль</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoFocus
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="confirm" className="text-soft">Подтвердите пароль</Label>
              <Input
                id="confirm"
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                required
              />
            </div>
            {/* --destructive в тёмной теме (45% светлоты) на стекле почти не читается —
                берём тот же красный, что у алерт-цифры на дашборде. */}
            {error && <p className="text-sm text-destructive dark:text-[hsl(0_72%_66%)]">{error}</p>}
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? "Сохранение..." : "Сохранить пароль"}
            </Button>
          </form>
        </CardContent>
      </SpotlightCard>
    </div>
  )
}

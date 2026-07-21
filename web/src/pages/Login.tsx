import { useState, FormEvent } from "react"
import { useNavigate, Link } from "react-router-dom"
import { login } from "@/lib/auth"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { RoutineOpsLogo } from "@/components/RoutineOpsLogo"
import SpotlightCard from "@/components/SpotlightCard"

export default function Login() {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError("")
    setLoading(true)
    try {
      await login(email, password)
      navigate("/dashboard")
    } catch {
      setError("Неверный email или пароль")
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
            <div className="space-y-1.5">
              <Label htmlFor="password" className="text-soft">Пароль</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            {/* --destructive в тёмной теме (45% светлоты) на стекле почти не читается —
                берём тот же красный, что у алерт-цифры на дашборде. */}
            {error && <p className="text-sm text-destructive dark:text-[hsl(0_72%_66%)]">{error}</p>}
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? "Вход..." : "Войти"}
            </Button>
            <Link to="/forgot-password" className="block text-center text-sm text-muted-foreground hover:text-foreground transition-colors">
              Забыли пароль?
            </Link>
          </form>
        </CardContent>
      </SpotlightCard>
    </div>
  )
}

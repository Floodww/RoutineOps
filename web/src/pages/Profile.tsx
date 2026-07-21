import { useState, FormEvent } from "react"
import api, { errMessage } from "@/lib/api"
import { useMe } from "@/lib/useMe"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { toast } from "@/lib/toast"

const roleLabels: Record<string, string> = {
  it_admin: "IT-администратор",
  viewer: "Наблюдатель",
}

export default function Profile() {
  const { me } = useMe()
  const [current, setCurrent] = useState("")
  const [next, setNext] = useState("")
  const [confirm, setConfirm] = useState("")
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (next !== confirm) {
      toast({ title: "Новые пароли не совпадают", variant: "destructive" })
      return
    }
    setLoading(true)
    try {
      await api.post("/me/password", { current_password: current, new_password: next })
      toast({ title: "Пароль изменён", variant: "success" })
      setCurrent("")
      setNext("")
      setConfirm("")
    } catch (e) {
      toast({ title: "Не удалось сменить пароль", description: errMessage(e), variant: "destructive" })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col gap-5 max-w-lg">
      <h1 className="text-xl font-semibold text-foreground">Профиль</h1>

      <div className="glass px-5 py-[18px]">
        <h2 className="text-[15px] font-semibold text-foreground">Учётная запись</h2>
        <p className="text-xs text-muted-foreground mb-3.5">Данные пользователя</p>
        <div className="flex flex-col gap-2.5 text-[13px]">
          <div className="flex items-center justify-between gap-4">
            <span className="text-soft">Имя</span>
            <span className="text-foreground truncate">{me?.name ?? "—"}</span>
          </div>
          <div className="flex items-center justify-between gap-4">
            <span className="text-soft">Email</span>
            <span className="text-foreground truncate">{me?.email ?? "—"}</span>
          </div>
          <div className="flex items-center justify-between gap-4">
            <span className="text-soft">Роль</span>
            {me && <Badge variant={me.role === "it_admin" ? "default" : "secondary"}>{roleLabels[me.role] ?? me.role}</Badge>}
          </div>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="glass px-5 py-[18px] flex flex-col gap-4">
        <div>
          <h2 className="text-[15px] font-semibold text-foreground">Смена пароля</h2>
          <p className="text-xs text-muted-foreground">Введите текущий и новый пароль</p>
        </div>
        <div className="space-y-1.5">
          <Label className="text-soft">Текущий пароль</Label>
          <Input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} required autoComplete="current-password" />
        </div>
        <div className="space-y-1.5">
          <Label className="text-soft">Новый пароль</Label>
          <Input type="password" value={next} onChange={(e) => setNext(e.target.value)} required autoComplete="new-password" />
        </div>
        <div className="space-y-1.5">
          <Label className="text-soft">Повторите новый пароль</Label>
          <Input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required autoComplete="new-password" />
        </div>
        <Button type="submit" disabled={loading} className="self-start">{loading ? "Сохранение..." : "Сменить пароль"}</Button>
      </form>
    </div>
  )
}

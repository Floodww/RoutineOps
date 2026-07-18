import { useEffect, useState } from "react"
import { Outlet, NavLink, useNavigate, useLocation } from "react-router-dom"
import { LayoutDashboard, Monitor, Bell, Shield, LogOut, KeyRound, FileCode2, ListChecks, Send, History, Sun, Moon, Users, Boxes, UserCircle, BadgeCheck } from "lucide-react"
import { logout } from "@/lib/auth"
import { RoutineOpsLogo } from "@/components/RoutineOpsLogo"
import { useMe } from "@/lib/useMe"
import { useTheme } from "@/lib/theme"
import { cn } from "@/lib/utils"
import api from "@/lib/api"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { toast } from "@/lib/toast"

export default function Layout() {
  const navigate = useNavigate()
  const location = useLocation()
  const { theme, toggleTheme } = useTheme()
  const { isAdmin, me } = useMe()
  const [pendingCount, setPendingCount] = useState(0)
  const [tgOpen, setTgOpen] = useState(false)
  const [tgLinked, setTgLinked] = useState(false)
  const [tgToken, setTgToken] = useState<string | null>(null)
  const [tgLoading, setTgLoading] = useState(false)
  // Имя бота приходит с сервера (getMe): у каждого деплоя свой бот от @BotFather.
  const [tgBotUsername, setTgBotUsername] = useState("")

  useEffect(() => {
    api.get<{ id: string }[]>("/admin-access-requests?status=pending")
      .then((r) => setPendingCount(r.data?.length ?? 0))
      .catch(() => { })
    api.get<{ linked: boolean }>("/profile/telegram")
      .then((r) => setTgLinked(r.data.linked))
      .catch(() => { })
  }, [])

  async function openTelegramDialog() {
    setTgOpen(true)
    try {
      const r = await api.get<{ linked: boolean; link_token: string | null; bot_username: string }>("/profile/telegram")
      setTgLinked(r.data.linked)
      setTgToken(r.data.link_token)
      setTgBotUsername(r.data.bot_username ?? "")
    } catch {
      toast({ title: "Не удалось загрузить статус Telegram", variant: "destructive" })
    }
  }

  async function generateToken() {
    setTgLoading(true)
    try {
      const r = await api.post<{ token: string }>("/profile/telegram-link", {})
      setTgToken(r.data.token)
    } catch {
      toast({ title: "Не удалось сгенерировать токен", variant: "destructive" })
    } finally {
      setTgLoading(false)
    }
  }

  async function handleLogout() {
    await logout()
    navigate("/login")
  }

  // adminOnly скрывает пункт для роли viewer (бэкенд всё равно 403'ит мутации — это UX).
  // Иконки монохромные: активный пункт метится фирменным синим (см. .nav-item-active).
  const navItems = [
    { to: "/", label: "Обзор", icon: LayoutDashboard, badge: 0, adminOnly: false },
    { to: "/devices", label: "Устройства", icon: Monitor, badge: 0, adminOnly: false },
    { to: "/alerts", label: "Алерты", icon: Bell, badge: 0, adminOnly: false },
    { to: "/admin-access", label: "Заявки на права", icon: KeyRound, badge: pendingCount, adminOnly: true },
    { to: "/policies", label: "Политики", icon: Shield, badge: 0, adminOnly: true },
    { to: "/scripts", label: "Скрипты", icon: FileCode2, badge: 0, adminOnly: true },
    { to: "/script-policies", label: "Политики скриптов", icon: ListChecks, badge: 0, adminOnly: true },
    { to: "/groups", label: "Группы", icon: Boxes, badge: 0, adminOnly: true },
    { to: "/audit-log", label: "Журнал", icon: History, badge: 0, adminOnly: false },
    { to: "/users", label: "Пользователи", icon: Users, badge: 0, adminOnly: true },
    { to: "/license", label: "Лицензия", icon: BadgeCheck, badge: 0, adminOnly: true },
    { to: "/profile", label: "Профиль", icon: UserCircle, badge: 0, adminOnly: false },
  ].filter((i) => !i.adminOnly || isAdmin)

  return (
    <div className="flex h-screen bg-background">
      <aside className="w-56 flex flex-col sidebar-glass z-10">
        <div className="h-14 flex items-center px-4 border-b border-[var(--sidebar-border)]">
          <NavLink to="/" className="flex items-center gap-2 hover:opacity-80 transition-opacity">
            <RoutineOpsLogo size={24} />
            <span className="text-sm font-semibold tracking-tight">RoutineOps</span>
          </NavLink>
        </div>

        <nav className="flex-1 px-2 py-3 space-y-0.5">
          {navItems.map(({ to, label, icon: Icon, badge }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                cn("nav-item", isActive ? "nav-item-active" : "text-muted-foreground")
              }
            >
              {({ isActive }) => (
                <>
                  <Icon className={cn(
                    "h-4 w-4 flex-shrink-0 transition-colors duration-200",
                    isActive ? "text-brand" : "text-muted-foreground"
                  )} />
                  <span className="flex-1 truncate">{label}</span>
                  {badge > 0 && (
                    <span className="ml-auto bg-destructive text-destructive-foreground text-xs font-semibold rounded-full px-1.5 py-0.5 min-w-[1.25rem] text-center leading-none">
                      {badge}
                    </span>
                  )}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="p-2 border-t border-[var(--sidebar-border)] space-y-0.5">
          {me && (
            <div className="px-3 py-1.5 text-xs text-muted-foreground truncate" title={me.email}>
              {me.email} · {me.role === "it_admin" ? "Админ" : "Наблюдатель"}
            </div>
          )}
          <button
            type="button"
            onClick={toggleTheme}
            className="nav-item text-muted-foreground w-full"
          >
            {theme === "dark"
              ? <Sun className="h-4 w-4" />
              : <Moon className="h-4 w-4" />}
            {theme === "dark" ? "Светлая тема" : "Тёмная тема"}
          </button>
          <button
            type="button"
            onClick={openTelegramDialog}
            className="nav-item text-muted-foreground w-full"
          >
            <Send className="h-4 w-4" />
            {tgLinked ? "Telegram ✓" : "Подключить Telegram"}
          </button>
          <button
            type="button"
            onClick={handleLogout}
            className="nav-item text-muted-foreground hover:!text-destructive w-full"
          >
            <LogOut className="h-4 w-4" />
            Выход
          </button>
        </div>
      </aside>

      <Dialog open={tgOpen} onOpenChange={setTgOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Telegram уведомления</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 pt-1">
            {tgLinked ? (
              <p className="text-sm text-green-700 dark:text-green-400">Telegram подключён. Вы получаете уведомления.</p>
            ) : (
              <p className="text-sm text-muted-foreground">
                Подключите Telegram, чтобы получать уведомления об алертах и заявках на права.
              </p>
            )}
            {tgToken ? (
              <div className="space-y-2">
                <p className="text-sm">
                  {tgBotUsername ? (
                    <>
                      Отправьте боту{" "}
                      <a
                        href={`https://t.me/${tgBotUsername}`}
                        target="_blank"
                        rel="noreferrer"
                        className="font-medium underline"
                      >
                        @{tgBotUsername}
                      </a>{" "}
                      команду:
                    </>
                  ) : (
                    <>Отправьте Telegram-боту вашей организации команду:</>
                  )}
                </p>
                <code className="block bg-muted px-3 py-2 rounded-lg text-sm select-all break-all font-mono">
                  /start {tgToken}
                </code>
                <p className="text-xs text-muted-foreground">Токен одноразовый. Если не сработал — сгенерируйте новый.</p>
              </div>
            ) : null}
            <Button variant="outline" className="w-full" onClick={generateToken} disabled={tgLoading}>
              {tgLoading ? "Генерация..." : tgToken ? "Сгенерировать новый токен" : "Получить токен"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <main key={location.pathname} className="flex-1 overflow-auto p-6 animate-page-in">
        <Outlet />
      </main>
    </div>
  )
}

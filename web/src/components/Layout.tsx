import { useEffect, useState } from "react"
import { Outlet, NavLink, useNavigate, useLocation } from "react-router-dom"
import { useTranslation } from "react-i18next"
import { Contact, LayoutDashboard, Monitor, Bell, Shield, ShieldCheck, LogOut, LogIn, KeyRound, KeySquare, FileCode2, ListChecks, Send, History, Sun, Moon, Users, Boxes, UserCircle, BadgeCheck, FolderTree, Building2, Network, ScanFace, Fingerprint, Radio, Rocket, MonitorPlay, ChevronsUpDown, Check } from "lucide-react"
import { logout } from "@/lib/auth"
import { RoutineOpsLogo } from "@/components/RoutineOpsLogo"
import { useMe } from "@/lib/useMe"
import { useMyTenants } from "@/lib/useMyTenants"
import { useTheme } from "@/lib/theme"
import { cn } from "@/lib/utils"
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem } from "@/components/ui/dropdown-menu"

// Роли в подписи переключателя: сырые it_admin/viewer в интерфейсе не показываем.
// Значения — КЛЮЧИ словаря: t() на уровне модуля недоступен.
const ROLE_LABELS: Record<string, string> = {
  it_admin: "layout.roleAdmin",
  viewer: "layout.roleViewer",
}
import api from "@/lib/api"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { toast } from "@/lib/toast"

// SEVERITY_CHOICES — порог доставки уведомлений, от самого шумного к самому тихому.
// Порядок обратный шкале важности намеренно: пользователь читает слева направо и
// выбирает, НАСКОЛЬКО ЕГО БЕСПОКОИТЬ, а не насколько серьёзен инцидент.
const SEVERITY_CHOICES = [
  { value: "low", tKey: "layout.tgSeverityLow" },
  { value: "medium", tKey: "layout.tgSeverityMedium" },
  { value: "high", tKey: "layout.tgSeverityHigh" },
  { value: "critical", tKey: "layout.tgSeverityCritical" },
]

export default function Layout() {
  const navigate = useNavigate()
  const location = useLocation()
  const { theme, toggleTheme } = useTheme()
  const { isAdmin, isProvider, me } = useMe()
  const { tenants: myTenants, switchTenant } = useMyTenants()
  const [switching, setSwitching] = useState(false)
  const [pendingCount, setPendingCount] = useState(0)
  const [queueCount, setQueueCount] = useState(0)
  const [alertCount, setAlertCount] = useState(0)
  const [tgOpen, setTgOpen] = useState(false)
  const [tgLinked, setTgLinked] = useState(false)
  const [tgToken, setTgToken] = useState<string | null>(null)
  const [tgLoading, setTgLoading] = useState(false)
  // Имя бота приходит с сервера (getMe): у каждого деплоя свой бот от @BotFather.
  const [tgBotUsername, setTgBotUsername] = useState("")
  // Порог доставки уведомлений (users.notify_min_severity, миграция 041).
  const [tgMinSeverity, setTgMinSeverity] = useState("low")
  const [tgSevSaving, setTgSevSaving] = useState(false)
  const { t, i18n } = useTranslation()

  const toggleLanguage = () => {
    const nextLang = i18n.language === "ru" ? "en" : "ru"
    i18n.changeLanguage(nextLang)
  }

  useEffect(() => {
    api.get<{ linked: boolean }>("/profile/telegram")
      .then((r) => setTgLinked(r.data.linked))
      .catch(() => { })
  }, [])

  // Счётчики бейджей — отдельным эффектом, потому что у них другой жизненный цикл:
  // (1) энроллмент и заявки на права admin-only, а без гейта viewer тянул бы ВЕСЬ
  //     список устройств ради бейджа, который ему даже не рисуется; алерты видны и
  //     viewer'у, поэтому считаются до гейта;
  // (2) isAdmin приезжает асинхронно из /me, поэтому он в зависимостях — иначе бейджи
  //     навсегда остались бы нулевыми при первом входе;
  // (3) ключ по pathname: считалось один раз за сессию, и после одобрения всей очереди
  //     сайдбар продолжал показывать старое число, споря с пустой таблицей рядом.
  // Отдельной ручки-счётчика на сервере нет — считаем по общему списку.
  // ponytail: клиентский подсчёт, серверный счётчик — когда списки получат пагинацию
  useEffect(() => {
    api.get<{ acknowledged_at: string | null }[]>("/alerts")
      .then((r) => setAlertCount((r.data ?? []).filter((a) => !a.acknowledged_at).length))
      .catch(() => { })
    if (!isAdmin) return
    api.get<{ id: string }[]>("/admin-access-requests?status=pending")
      .then((r) => setPendingCount(r.data?.length ?? 0))
      .catch(() => { })
    api.get<{ status: string }[]>("/devices")
      .then((r) => setQueueCount((r.data ?? []).filter((d) => d.status === "pending_approval").length))
      .catch(() => { })
  }, [isAdmin, location.pathname])

  async function openTelegramDialog() {
    setTgOpen(true)
    try {
      const r = await api.get<{
        linked: boolean
        link_token: string | null
        bot_username: string
        min_severity: string
      }>("/profile/telegram")
      setTgLinked(r.data.linked)
      setTgToken(r.data.link_token)
      setTgBotUsername(r.data.bot_username ?? "")
      // Пустое значение с сервера означает строку, не прошедшую миграцию 041, —
      // трактуем как «всё как раньше», симметрично DEFAULT 'low' в схеме.
      setTgMinSeverity(r.data.min_severity || "low")
    } catch {
      toast({ title: t("layout.telegramFailed"), variant: "destructive" })
    }
  }

  // saveMinSeverity сохраняет порог сразу по клику: отдельная кнопка «Сохранить» для
  // одного переключателя из четырёх значений — лишний шаг, на котором настройку
  // забывают применить. Локальное состояние обновляется ТОЛЬКО после успеха, иначе
  // при отказе сервера кнопка осталась бы подсвеченной, а порог — прежним.
  async function saveMinSeverity(value: string) {
    if (value === tgMinSeverity) return
    setTgSevSaving(true)
    try {
      await api.post("/profile/notify-min-severity", { min_severity: value })
      setTgMinSeverity(value)
    } catch {
      toast({ title: t("layout.thresholdFailed"), variant: "destructive" })
    } finally {
      setTgSevSaving(false)
    }
  }

  async function generateToken() {
    setTgLoading(true)
    try {
      const r = await api.post<{ token: string }>("/profile/telegram-link", {})
      setTgToken(r.data.token)
    } catch {
      toast({ title: t("layout.tgTokenGenFail"), variant: "destructive" })
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
  // Группы — плоские подписи, а не сворачиваемые секции: пунктов мало, прятать нечего,
  // а свёрнутая группа спрятала бы счётчики энроллмента и заявок на права.
  const navSections = [
    {
      title: null,
      items: [
        { to: "/", label: t("nav.dashboard"), icon: LayoutDashboard, badge: 0, adminOnly: false },
        { to: "/compliance", label: t("nav.compliance"), icon: ShieldCheck, badge: 0, adminOnly: false },
        { to: "/alerts", label: t("nav.alerts"), icon: Bell, badge: alertCount, adminOnly: false },
        { to: "/audit-log", label: t("nav.audit"), icon: History, badge: 0, adminOnly: false },
      ],
    },
    {
      title: t("nav.hosts"),
      items: [
        { to: "/devices", label: t("nav.devices"), icon: Monitor, badge: 0, adminOnly: false },
        { to: "/across-tenants", label: t("nav.acrossTenants"), icon: Network, badge: 0, providerOnly: true },
        { to: "/enrollment", label: t("nav.enrollment"), icon: LogIn, badge: queueCount, adminOnly: true },
        { to: "/groups", label: t("nav.groups"), icon: Boxes, badge: 0, adminOnly: true },
        { to: "/owners", label: t("nav.owners"), icon: Contact, badge: 0, adminOnly: true },
        { to: "/rollout", label: t("nav.rollout"), icon: Rocket, badge: 0, adminOnly: false },
      ],
    },
    {
      title: t("nav.management"),
      items: [
        { to: "/scripts", label: t("nav.scripts"), icon: FileCode2, badge: 0, adminOnly: true },
        { to: "/script-policies", label: t("nav.scriptPolicies"), icon: ListChecks, badge: 0, adminOnly: true },
        { to: "/policies", label: t("nav.policies"), icon: Shield, badge: 0, adminOnly: true },
        { to: "/admin-access", label: t("nav.adminAccess"), icon: KeyRound, badge: pendingCount, adminOnly: true },
      ],
    },
    {
      title: t("nav.settings"),
      items: [
        { to: "/profile", label: t("nav.profile"), icon: UserCircle, badge: 0, adminOnly: false },
        { to: "/users", label: t("nav.users"), icon: Users, badge: 0, adminOnly: true },
        { to: "/license", label: t("nav.license"), icon: BadgeCheck, badge: 0, adminOnly: true },
        { to: "/api-tokens", label: t("nav.apiTokens"), icon: KeySquare, badge: 0, adminOnly: true },
        { to: "/directory", label: t("nav.directory"), icon: FolderTree, badge: 0, adminOnly: true },
        { to: "/sso", label: t("nav.sso"), icon: ScanFace, badge: 0, adminOnly: true },
        { to: "/saml", label: t("nav.saml"), icon: Fingerprint, badge: 0, adminOnly: true },
        { to: "/siem", label: t("nav.siem"), icon: Radio, badge: 0, adminOnly: true },
        { to: "/screen-access", label: t("nav.screenAccess"), icon: MonitorPlay, badge: 0, adminOnly: true },
        { to: "/tenants", label: t("nav.tenants"), icon: Building2, badge: 0, providerOnly: true },
      ],
    },
  ]
    .map((s) => ({
      ...s,
      items: s.items.filter((i) => {
        if ((i as { providerOnly?: boolean }).providerOnly) return isProvider
        if (i.adminOnly) return isAdmin
        return true
      }),
    }))
    // У viewer «Управление» пустеет целиком — заголовок без пунктов не рисуем.
    .filter((s) => s.items.length > 0)

  return (
    <div className="flex h-screen">
      <aside className="w-[236px] flex-shrink-0 flex flex-col sidebar-glass z-10">
        {/* Плашка логотипа: тёмно-синяя, как круг на знаке. Почта живёт здесь
            (а не внизу списка) — так шапка сайдбара отвечает «кто вошёл». */}
        <div className="h-[72px] flex items-center gap-2.5 px-5 border-b border-[var(--sidebar-border)] bg-[var(--logo-plate)]">
          <NavLink to="/" className="flex items-center gap-2.5 min-w-0 hover:opacity-80 transition-opacity">
            <RoutineOpsLogo size={30} />
            <div className="min-w-0">
              <div className="text-[15px] font-semibold text-foreground leading-tight">RoutineOps</div>
              {me && (
                <div className="text-[11px] text-[var(--logo-plate-fg)] truncate" title={me.email}>
                  {me.email}
                </div>
              )}
            </div>
          </NavLink>
        </div>

        {/* Переключатель тенанта (ADR-7 §11.4). Показывается только при
            мульти-членстве: при одном тенанте выбирать не из чего, а Free вообще не
            должен видеть эту сущность (контракт §10.2).

            Раньше здесь стоял голый <select> с подписью-капслоком — он выпадал из
            языка остального интерфейса и читался как настройка формы, а не как
            «где я сейчас нахожусь». Теперь это строка под шапкой: активный тенант
            виден всегда, роль в нём — рядом, выпадающий список в том же стиле, что
            и меню действий на страницах. */}
        {myTenants.length > 1 && (
          <div className="px-2.5 pt-2.5">
            <DropdownMenu>
              <DropdownMenuTrigger asChild disabled={switching}>
                <button
                  className="w-full flex items-center gap-2.5 rounded-md px-2.5 py-2 text-left transition-colors hover:bg-[var(--sidebar-accent)] disabled:opacity-60"
                  title={t("layout.tenant")}
                >
                  <Building2 className="h-4 w-4 shrink-0 text-muted-foreground" />
                  <div className="min-w-0 flex-1">
                    <div className="text-[13px] font-medium truncate">
                      {myTenants.find((m) => m.active)?.tenant_name ?? "—"}
                    </div>
                    <div className="text-[11px] text-muted-foreground truncate">
                      {switching
                        ? t("layout.switching")
                        : (() => {
                            const role = myTenants.find((m) => m.active)?.role ?? ""
                            return ROLE_LABELS[role] ? t(ROLE_LABELS[role]) : role
                          })()}
                    </div>
                  </div>
                  <ChevronsUpDown className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" className="w-[--radix-dropdown-menu-trigger-width] min-w-56">
                {myTenants.map((m) => (
                  <DropdownMenuItem
                    key={m.tenant_id}
                    disabled={m.active || switching}
                    onSelect={() => {
                      if (m.active) return
                      setSwitching(true)
                      switchTenant(m.tenant_id).catch(() => setSwitching(false))
                    }}
                  >
                    <Check className={cn("h-4 w-4 shrink-0", !m.active && "opacity-0")} />
                    <div className="min-w-0 flex-1">
                      <div className="truncate">{m.tenant_name}</div>
                      <div className="text-[11px] text-muted-foreground truncate">
                        {ROLE_LABELS[m.role] ?? m.role}
                      </div>
                    </div>
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        )}

        <nav className="flex-1 overflow-y-auto px-2.5 py-3.5 flex flex-col gap-0.5">
          {navSections.map((section, si) => (
          <div key={section.title ?? `plain-${si}`} className={cn("flex flex-col gap-0.5", si > 0 && "mt-3")}>
            {section.title && (
              <div className="px-3 pb-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/70">
                {section.title}
              </div>
            )}
            {section.items.map(({ to, label, icon: Icon, badge }) => (
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
                    "h-[17px] w-[17px] flex-shrink-0 transition-colors duration-200",
                    isActive ? "text-brand" : "text-muted-foreground"
                  )} />
                  <span className="flex-1 truncate">{label}</span>
                  {badge > 0 && (
                    // Цифры на градиенте — тёмные по той же причине, что и подпись
                    // primary-кнопки: белые дали бы 2.6:1 на самом мелком тексте оболочки.
                    <span className="ml-auto brand-gradient text-white dark:text-[hsl(224_14%_10%)] text-xs font-semibold rounded-full px-1.5 h-[22px] min-w-[22px] flex items-center justify-center leading-none">
                      {badge}
                    </span>
                  )}
                </>
              )}
            </NavLink>
            ))}
          </div>
          ))}
        </nav>

        <div className="p-2.5 border-t border-[var(--sidebar-border)] flex flex-col gap-0.5">
          {me && (
            <div className="px-3 pb-1 text-[11px] text-muted-foreground truncate">
              {me.role === "it_admin" ? t("layout.roleAdmin") : t("layout.roleViewer")}
            </div>
          )}
          <button
            type="button"
            onClick={toggleTheme}
            className="nav-item text-muted-foreground w-full"
          >
            {theme === "dark"
              ? <Sun className="h-[17px] w-[17px]" />
              : <Moon className="h-[17px] w-[17px]" />}
            {theme === "dark" ? t("layout.themeLight") : t("layout.themeDark")}
          </button>
          <button
            type="button"
            onClick={toggleLanguage}
            className="nav-item text-muted-foreground w-full"
          >
            <span className="font-semibold px-[2px]">{i18n.language.toUpperCase()}</span>
            {i18n.language === "ru" ? t("layout.langEn") : t("layout.langRu")}
          </button>
          <button
            type="button"
            onClick={openTelegramDialog}
            className="nav-item text-muted-foreground w-full"
          >
            <Send className="h-[17px] w-[17px]" />
            {tgLinked ? t("layout.tgConnected") : t("layout.tgConnect")}
          </button>
          <button
            type="button"
            onClick={handleLogout}
            className="nav-item text-muted-foreground hover:!text-destructive w-full"
          >
            <LogOut className="h-[17px] w-[17px]" />
            {t("layout.logout")}
          </button>
        </div>
      </aside>

      <Dialog open={tgOpen} onOpenChange={setTgOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("layout.tgDialogTitle")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 pt-1">
            {tgLinked ? (
              <p className="text-sm text-green-700 dark:text-green-400">{t("layout.tgDialogConnected")}</p>
            ) : (
              <p className="text-sm text-muted-foreground">
                {t("layout.tgDialogDesc")}
              </p>
            )}
            {tgToken ? (
              <div className="space-y-2">
                <p className="text-sm">
                  {tgBotUsername ? (
                    <>
                      {t("layout.tgSendToBot")}{" "}
                      <a
                        href={`https://t.me/${tgBotUsername}`}
                        target="_blank"
                        rel="noreferrer"
                        className="font-medium underline"
                      >
                        @{tgBotUsername}
                      </a>{" "}
                      {t("layout.tgCommand")}
                    </>
                  ) : (
                    <>{t("layout.tgSendToBotOrg")}</>
                  )}
                </p>
                <code className="block rounded-md border border-border bg-muted px-3 py-2.5 text-sm select-all break-all font-mono">
                  /start {tgToken}
                </code>
                <p className="text-xs text-muted-foreground">{t("layout.tgDialogNote")}</p>
              </div>
            ) : null}
            <Button variant="outline" className="w-full" onClick={generateToken} disabled={tgLoading}>
              {tgLoading ? t("layout.tgBtnGenerating") : tgToken ? t("layout.tgBtnNewToken") : t("layout.tgBtnGetToken")}
            </Button>

            {/* Порог доставки (миграция 041). Показывается всегда, а не только при
                tgLinked: настроить его до привязки — нормальный порядок действий, и
                прятать настройку за состоянием, которое пользователь как раз сейчас
                меняет, значило бы заставить его открыть диалог второй раз. */}
            <div className="space-y-2 border-t border-border pt-4">
              <p className="text-sm font-medium text-foreground">{t("layout.tgSeverityLabel")}</p>
              <div className="flex gap-1.5">
                {SEVERITY_CHOICES.map((c) => (
                  <button
                    key={c.value}
                    type="button"
                    onClick={() => saveMinSeverity(c.value)}
                    disabled={tgSevSaving}
                    className={`flex-1 rounded-md border px-2 py-1.5 text-xs font-medium transition-colors disabled:opacity-50 ${
                      tgMinSeverity === c.value
                        ? "border-primary bg-primary/10 text-foreground"
                        : "border-border text-muted-foreground hover:bg-muted"
                    }`}
                  >
                    {t(c.tKey)}
                  </button>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">
                {t("layout.tgSeverityNote")}
              </p>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Верхней градиентной панели нет намеренно (хендофф): первый элемент
          контента — H1 страницы. Колонка ограничена 1180px, чтобы карты не
          растягивались в ленты на широких мониторах. */}
      <main key={location.pathname} className="flex-1 overflow-auto p-6 animate-page-in">
        <div className="max-w-[1180px]">
          <Outlet />
        </div>
      </main>
    </div>
  )
}

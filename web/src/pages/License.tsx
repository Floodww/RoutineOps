import { useEffect, useState, FormEvent } from "react"
import api, { LicenseStatus, errStatus } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import ConfirmDialog from "@/components/ConfirmDialog"
import { toast } from "@/lib/toast"

// Порог «скоро истечёт»: за месяц до конца срока продление ещё успевает пройти
// по обычному закупочному циклу, поэтому предупреждаем заранее, а не в последний день.
const EXPIRY_WARN_DAYS = 30

function daysUntil(iso: string): number {
  return Math.ceil((new Date(iso).getTime() - Date.now()) / 86_400_000)
}

// hasExpiry: encoding/json ИГНОРИРУЕТ omitempty на time.Time (это структура), поэтому
// сервер всегда присылает expires_at — у лицензии без срока там нулевое время
// "0001-01-01T00:00:00Z". Проверка на непустую строку такое не отсеет и отрисовала бы
// «Действует до 01.01.0001», поэтому смотрим на год.
function hasExpiry(iso?: string): iso is string {
  return !!iso && new Date(iso).getUTCFullYear() > 1
}

// featuresLabel: пустой список фич в лицензии означает «вся редакция целиком»
// (семантика Claims.Has на сервере), а не «ничего не разрешено» — показать здесь
// прочерк значило бы соврать ровно наоборот.
function featuresLabel(features?: string[]): string {
  return features?.length ? features.join(", ") : "вся редакция"
}

export default function License() {
  const [status, setStatus] = useState<LicenseStatus | null>(null)
  // Три исхода загрузки, а не два. status === null означает «неизвестно», и его нельзя
  // рендерить как «не задана»: на enterprise-сервере с живой лицензией любой 500/502
  // (например рестарт контейнера по update.sh) нарисовал бы админу уверенное
  // «лицензия не установлена, редакция Free». unavailable — штатное состояние
  // open-core (роута нет → 404), loadError — настоящий сбой.
  const [unavailable, setUnavailable] = useState(false)
  const [loadError, setLoadError] = useState(false)
  const [loading, setLoading] = useState(true)
  const [blob, setBlob] = useState("")
  const [password, setPassword] = useState("")
  const [submitting, setSubmitting] = useState(false)
  const [confirmDeactivate, setConfirmDeactivate] = useState(false)
  // persistWarning живёт в state, а не только в тосте: «применено, но не сохранено»
  // означает, что рестарт вернёт сервер к прежнему состоянию — такое нельзя показать
  // на три секунды и убрать. Висит баннером до следующего успешного действия.
  const [persistWarning, setPersistWarning] = useState("")

  async function load() {
    setLoadError(false)
    try {
      const r = await api.get<LicenseStatus>("/license")
      setStatus(r.data)
    } catch (e) {
      if (errStatus(e) === 404) setUnavailable(true)
      else {
        setLoadError(true)
        toast({ title: "Не удалось загрузить статус лицензии", variant: "destructive" })
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  // submit шлёт и применение, и деактивацию (пустой blob = сброс до Free на сервере).
  // catch пустой намеренно: интерцептор уже показал текст сервера («лицензия отклонена:
  // ...»), а он информативнее любого нашего заголовка. Без catch отказ POST (штатный
  // путь — опечатка в ключе) уходил бы наверх необработанным rejection'ом.
  async function submit(license: string, activationPassword: string) {
    setSubmitting(true)
    try {
      const r = await api.post<LicenseStatus>("/license", {
        license,
        activation_password: activationPassword,
      })
      setStatus(r.data)
      setLoadError(false)
      setPersistWarning(r.data.persist_warning ?? "")
      setBlob("")
      setPassword("")
      // Успех HTTP ≠ успех по существу. Два случая, когда 200 означает проблему:
      // ключ не лёг на диск (рестарт всё откатит) и лицензия принята, но не в сроке
      // (подпись верна, а фичи не включились). Зелёный тост в этих случаях врал бы.
      if (r.data.persist_warning) {
        toast({
          title: license ? "Применена, но не сохранена на диск" : "Отключена, но не удалена с диска",
          description: r.data.persist_warning,
          variant: "destructive",
        })
      } else if (license && !r.data.valid) {
        toast({
          title: "Лицензия принята, но не в сроке",
          description: "Подпись верна, однако период действия ещё не начался или уже закончился — enterprise-функции не включены.",
          variant: "destructive",
        })
      } else {
        toast({
          title: license ? "Лицензия применена" : "Лицензия деактивирована",
          description: license ? "Изменения действуют сразу, без рестарта." : "Сервер работает в редакции Free.",
          variant: "success",
        })
      }
    } catch {
      /* авто-тост интерцептора */
    } finally {
      setSubmitting(false)
    }
  }

  function handleApply(e: FormEvent) {
    e.preventDefault()
    submit(blob.trim(), password)
  }

  if (loading) return <p className="text-muted-foreground text-sm">Загрузка...</p>

  if (unavailable) {
    return (
      <div className="space-y-4 max-w-2xl">
        <h1 className="text-xl font-semibold">Лицензия</h1>
        <div className="rounded-lg border p-4 space-y-2">
          <div className="flex items-center gap-2">
            <Badge variant="secondary">Free</Badge>
            <span className="text-sm font-medium">Лицензирование недоступно в этой редакции</span>
          </div>
          <p className="text-sm text-muted-foreground">
            Эта сборка — open-core RoutineOps: весь операционный MDM работает без лицензии и
            без ограничений. Лицензионный ключ нужен только редакции Enterprise (SSO, FileVault,
            расширенный compliance, мульти-тенантность).
          </p>
        </div>
      </div>
    )
  }

  const left = hasExpiry(status?.expires_at) ? daysUntil(status.expires_at) : null
  // «Истекла» и «ещё не действует» — разные состояния с одинаковым configured && !valid.
  // Второе бывает при отставших часах VM (см. ErrNotYet), и сказать про такую лицензию
  // «срок закончился» — послать админа искать не ту проблему.
  const notValid = !!status?.configured && !status.valid
  const notYet = notValid && left !== null && left > 0
  const expired = notValid && !notYet
  // Отсрочка: valid при уже прошедшей дате — работает ROUTINEOPS_LICENSE_GRACE.
  const inGrace = !!status?.valid && left !== null && left <= 0
  const expiringSoon = !!status?.valid && left !== null && left > 0 && left <= EXPIRY_WARN_DAYS

  return (
    <div className="space-y-6 max-w-2xl">
      <h1 className="text-xl font-semibold">Лицензия</h1>

      {persistWarning && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/5 p-4 text-sm text-destructive">
          {persistWarning}
        </div>
      )}

      {loadError ? (
        <div className="rounded-lg border p-4 space-y-3 text-sm">
          <p className="font-medium">Не удалось получить статус лицензии</p>
          <p className="text-muted-foreground">
            Состояние неизвестно — сервер не ответил. Это не значит, что лицензии нет.
          </p>
          <Button variant="outline" size="sm" onClick={load}>
            Повторить
          </Button>
        </div>
      ) : (
        <div className="rounded-lg border p-4 space-y-2 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground">Статус:</span>
            {!status?.configured && <Badge variant="secondary">Не задана</Badge>}
            {status?.valid && <Badge variant="success">Активна</Badge>}
            {notYet && <Badge variant="secondary">Ещё не действует</Badge>}
            {expired && <Badge variant="destructive">Истекла</Badge>}
          </div>

          {!status?.configured && (
            <p className="text-muted-foreground">
              Лицензия не установлена — сервер работает в редакции Free.
            </p>
          )}

          {expired && (
            <p className="text-destructive">
              Срок действия закончился, enterprise-функции отключены. Данные не затронуты:
              после применения новой лицензии всё вернётся.
            </p>
          )}

          {notYet && (
            <p className="text-muted-foreground">
              Период действия ещё не начался, поэтому enterprise-функции пока выключены.
              Если дата уже должна была наступить — проверьте часы сервера.
            </p>
          )}

          {inGrace && (
            <p className="text-yellow-700 dark:text-yellow-500">
              Срок истёк, функции пока работают на отсрочке — продлите лицензию.
            </p>
          )}

          {status?.configured && (
            <>
              <div>
                <span className="text-muted-foreground">Кому выдана: </span>
                {status.licensee || "—"}
              </div>
              <div>
                <span className="text-muted-foreground">Редакция: </span>
                {status.edition || "—"}
              </div>
              <div>
                <span className="text-muted-foreground">Функции: </span>
                {featuresLabel(status.features)}
              </div>
              {status.seats ? (
                <div>
                  <span className="text-muted-foreground">Устройств по договору: </span>
                  {status.seats}
                </div>
              ) : null}
              {hasExpiry(status.expires_at) && (
                <div className={expiringSoon ? "text-yellow-700 dark:text-yellow-500" : ""}>
                  <span className="text-muted-foreground">Действует до: </span>
                  {new Date(status.expires_at).toLocaleDateString("ru-RU")}
                  {/* Срок словами, а не только жёлтым цветом: цвет как единственный
                      носитель смысла — это WCAG 1.4.1. */}
                  {left !== null && left > 0 && ` — осталось ${left} дн.`}
                </div>
              )}
            </>
          )}
        </div>
      )}

      <form onSubmit={handleApply} className="space-y-4">
        <h2 className="text-sm font-medium">
          {status?.configured ? "Заменить лицензию" : "Применить лицензию"}
        </h2>
        <div className="space-y-1.5">
          <Label htmlFor="license-blob">Лицензионный ключ</Label>
          <textarea
            id="license-blob"
            className="flex min-h-32 w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm font-mono shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring resize-y"
            placeholder="eyJwYXlsb2FkIjoi... — одна строка base64, как её выдал routineops-license"
            value={blob}
            onChange={(e) => setBlob(e.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="license-password">Пароль активации</Label>
          <Input
            id="license-password"
            type="password"
            autoComplete="off"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <p className="text-xs text-muted-foreground">
          Применяется сразу, без перезапуска сервера. Отклонённый ключ не сбрасывает текущую лицензию.
        </p>
        <div className="flex gap-2">
          <Button type="submit" disabled={submitting || !blob.trim() || !password}>
            {submitting ? "Применение..." : "Применить"}
          </Button>
          {status?.configured && (
            <Button
              type="button"
              variant="outline"
              className="text-destructive border-destructive/30 hover:bg-destructive/10"
              disabled={submitting}
              onClick={() => setConfirmDeactivate(true)}
            >
              Деактивировать
            </Button>
          )}
        </div>
      </form>

      <ConfirmDialog
        open={confirmDeactivate}
        onOpenChange={setConfirmDeactivate}
        title="Деактивировать лицензию?"
        description="Сервер сразу перейдёт в редакцию Free: enterprise-функции отключатся, ключ будет удалён с диска. Данные не удаляются, лицензию можно применить снова."
        confirmLabel="Деактивировать"
        destructive
        onConfirm={() => submit("", "")}
      />
    </div>
  )
}

import { useEffect, useState, FormEvent } from "react"
import { useTranslation } from "react-i18next"
import api, { LicenseStatus, errStatus } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import ConfirmDialog from "@/components/ConfirmDialog"
import { toast } from "@/lib/toast"
import { formatDate } from "@/lib/time"

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
function featuresLabel(features: string[] | undefined, t: (key: string) => string): string {
  return features?.length ? features.join(", ") : t("license.wholeEdition")
}

export default function License() {
  const { t } = useTranslation()
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
        toast({ title: t("license.loadFailed"), variant: "destructive" })
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
          title: license ? t("license.appliedNotPersisted") : t("license.disabledNotRemoved"),
          description: r.data.persist_warning,
          variant: "destructive",
        })
      } else if (license && !r.data.valid) {
        toast({
          title: t("license.acceptedNotInTerm"),
          description: t("license.acceptedNotInTermHint"),
          variant: "destructive",
        })
      } else {
        toast({
          title: license ? t("license.applied") : t("license.deactivated"),
          description: license ? t("license.immediate") : t("license.nowFree"),
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

  if (loading) return <p className="text-muted-foreground text-sm">{t("common.loading")}</p>

  if (unavailable) {
    return (
      <div className="flex flex-col gap-5 max-w-2xl">
        <h1 className="text-xl font-semibold text-foreground">{t("license.title")}</h1>
        <div className="glass px-5 py-[18px] space-y-2">
          <div className="flex items-center gap-2">
            <Badge variant="secondary">Free</Badge>
            <span className="text-[15px] font-semibold text-foreground">{t("license.unavailable")}</span>
          </div>
          <p className="text-sm text-muted-foreground">
            {t("license.openCoreNote")}
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
    <div className="flex flex-col gap-5 max-w-2xl">
      <h1 className="text-xl font-semibold text-foreground">{t("license.title")}</h1>

      {persistWarning && (
        <div className="glass bg-red-500/[0.08] px-5 py-[18px] text-sm text-destructive dark:text-[hsl(0_72%_66%)]">
          {persistWarning}
        </div>
      )}

      {loadError ? (
        <div className="glass px-5 py-[18px] space-y-3 text-sm">
          <p className="text-[15px] font-semibold text-foreground">{t("license.statusFailed")}</p>
          <p className="text-muted-foreground">
            {t("license.unknownState")}
          </p>
          <Button variant="outline" size="sm" onClick={load}>
            {t("license.retry")}
          </Button>
        </div>
      ) : (
        <div className="glass px-5 py-[18px] space-y-2 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-soft">{t("license.status")}</span>
            {!status?.configured && <Badge variant="secondary">{t("license.notSet")}</Badge>}
            {status?.valid && <Badge variant="success">{t("license.active")}</Badge>}
            {notYet && <Badge variant="secondary">{t("license.notYet")}</Badge>}
            {expired && <Badge variant="destructive">{t("license.expired")}</Badge>}
          </div>

          {!status?.configured && (
            <p className="text-muted-foreground">
              {t("license.notInstalled")}
            </p>
          )}

          {expired && (
            <p className="text-destructive dark:text-[hsl(0_72%_66%)]">
              {t("license.expiredNote")}
            </p>
          )}

          {notYet && (
            <p className="text-muted-foreground">
              {t("license.notYetNote")}
            </p>
          )}

          {inGrace && (
            /* В светлой теме #f59e0b на стекле даёт ~2.2:1 — берём затемнённый
               той же тональности, в тёмной остаётся статусный amber. */
            <p className="text-[#b45309] dark:text-[#f59e0b]">
              {t("license.graceNote")}
            </p>
          )}

          {status?.configured && (
            <>
              <div className="text-foreground">
                <span className="text-soft">{t("license.licensee")}</span>
                {status.licensee || "—"}
              </div>
              <div className="text-foreground">
                <span className="text-soft">{t("license.edition")}</span>
                {status.edition || "—"}
              </div>
              <div className="text-foreground">
                <span className="text-soft">{t("license.features")}</span>
                {featuresLabel(status.features, t)}
              </div>
              {status.seats ? (
                <div className="text-foreground">
                  <span className="text-soft">{t("license.seats")}</span>
                  {status.seats}
                </div>
              ) : null}
              {hasExpiry(status.expires_at) && (
                <div className={expiringSoon ? "text-[#b45309] dark:text-[#f59e0b]" : "text-foreground"}>
                  <span className={expiringSoon ? "" : "text-soft"}>{t("license.until")}</span>
                  {formatDate(status.expires_at)}
                  {/* Срок словами, а не только жёлтым цветом: цвет как единственный
                      носитель смысла — это WCAG 1.4.1. */}
                  {left !== null && left > 0 && t("license.daysLeft", { count: left })}
                </div>
              )}
            </>
          )}
        </div>
      )}

      <form onSubmit={handleApply} className="glass px-5 py-[18px] space-y-4">
        <h2 className="text-[15px] font-semibold text-foreground">
          {status?.configured ? t("license.replace") : t("license.apply")}
        </h2>
        <div className="space-y-1.5">
          <Label htmlFor="license-blob" className="text-soft">{t("license.key")}</Label>
          <textarea
            id="license-blob"
            className="flex min-h-32 w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm font-mono shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring resize-y"
            placeholder={t("license.keyPlaceholder")}
            value={blob}
            onChange={(e) => setBlob(e.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="license-password" className="text-soft">{t("license.activationPassword")}</Label>
          <Input
            id="license-password"
            type="password"
            autoComplete="off"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <p className="text-xs text-muted-foreground">
          {t("license.applyNote")}
        </p>
        <div className="flex gap-2">
          <Button type="submit" disabled={submitting || !blob.trim() || !password}>
            {submitting ? t("license.applying") : t("license.applyShort")}
          </Button>
          {status?.configured && (
            <Button
              type="button"
              variant="outline"
              className="text-destructive border-destructive/30 hover:bg-destructive/10"
              disabled={submitting}
              onClick={() => setConfirmDeactivate(true)}
            >{t("license.deactivate")}</Button>
          )}
        </div>
      </form>

      <ConfirmDialog
        open={confirmDeactivate}
        onOpenChange={setConfirmDeactivate}
        title={t("license.deactivateQ")}
        description={t("license.deactivateWarn")}
        confirmLabel={t("license.deactivate")}
        destructive
        onConfirm={() => submit("", "")}
      />
    </div>
  )
}

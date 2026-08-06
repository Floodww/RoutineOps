import { useCallback, useEffect, useState } from "react"
import { useTranslation } from "react-i18next"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import api, { errMessage, errStatus, type ScreenAccessPolicy, type ScreenRecordingGrant } from "@/lib/api"
import { formatBytes } from "@/lib/format"
import { toast } from "@/lib/toast"

// Настройки наблюдения за экраном (docs/remote-desktop-contract.md, §4 и §5).
//
// Обе настройки на этой странице до сих пор существовали только в схеме базы:
// `tenants.screen_access_mode` не переключался ничем, кроме psql, а
// `users.can_view_session_recording` не имел в продукте НИ ОДНОГО места записи — то есть
// записи сеансов велись, занимали диск, чистились ретеншеном, и открыть их не мог никто.
//
// Страница админская целиком (AdminRoute + it_admin/requireHuman на сервере): и режим, и
// грант — решения о наблюдении за сотрудниками, а не пользовательские предпочтения.

const MODES = [
  { value: "unattended", label: "screenAccess.mode.unattended", hint: "screenAccess.mode.unattendedHint" },
  { value: "consent_required", label: "screenAccess.mode.consent", hint: "screenAccess.mode.consentHint" },
] as const

export default function ScreenAccess() {
  const { t } = useTranslation()
  const [policy, setPolicy] = useState<ScreenAccessPolicy | null>(null)
  const [grants, setGrants] = useState<ScreenRecordingGrant[]>([])
  // available=false — ручек нет вовсе (редакция Free). Показываем отсутствием, а не
  // кнопками, которые всегда отвечают ошибкой.
  const [available, setAvailable] = useState(true)
  const [busy, setBusy] = useState("")

  const load = useCallback(async () => {
    try {
      const [p, g] = await Promise.all([
        api.get<ScreenAccessPolicy>("/screen-access-mode"),
        api.get<ScreenRecordingGrant[]>("/screen-recording-grants"),
      ])
      setPolicy(p.data)
      setGrants(g.data ?? [])
      setAvailable(true)
    } catch (e) {
      if (errStatus(e) === 404) {
        setAvailable(false)
        return
      }
      toast({ title: errMessage(e), variant: "destructive" })
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const setMode = async (mode: string) => {
    if (!policy || policy.mode === mode) return
    setBusy("mode")
    try {
      await api.patch("/screen-access-mode", { mode })
      toast({ title: t("screenAccess.modeSaved"), variant: "success" })
      await load()
    } catch (e) {
      toast({ title: errMessage(e), variant: "destructive" })
    } finally {
      setBusy("")
    }
  }

  const setGrant = async (g: ScreenRecordingGrant) => {
    setBusy(g.user_id)
    try {
      await api.put(`/screen-recording-grants/${g.user_id}`, {
        can_view_session_recording: !g.can_view_session_recording,
      })
      await load()
    } catch (e) {
      toast({ title: errMessage(e), variant: "destructive" })
    } finally {
      setBusy("")
    }
  }

  if (!available) {
    return <p className="text-sm text-muted-foreground">{t("screenAccess.enterpriseOnly")}</p>
  }

  const quotaPct = policy && policy.recording_quota > 0
    ? Math.min(100, Math.round((policy.recording_used / policy.recording_quota) * 100))
    : 0

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">{t("screenAccess.title")}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t("screenAccess.subtitle")}</p>
      </div>

      <section className="glass p-5">
        <h2 className="text-[15px] font-semibold text-foreground">{t("screenAccess.modeTitle")}</h2>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          {MODES.map((m) => {
            const active = policy?.mode === m.value
            return (
              <button
                key={m.value}
                type="button"
                disabled={busy === "mode"}
                onClick={() => void setMode(m.value)}
                aria-pressed={active}
                className={
                  "rounded-xl border p-4 text-left transition-colors " +
                  (active
                    ? "border-primary bg-primary/5"
                    : "border-border hover:border-primary/40 hover:bg-muted/40")
                }
              >
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-foreground">{t(m.label)}</span>
                  {active && <Badge variant="outline">{t("screenAccess.current")}</Badge>}
                </div>
                <p className="mt-1 text-xs text-muted-foreground">{t(m.hint)}</p>
              </button>
            )
          })}
        </div>
        {/* Плашка безусловна в обоих режимах и флага отключения не имеет (§4). Сказать
            это здесь важнее, чем в документации: администратор выбирает режим именно
            здесь и может решить, что unattended означает «сотрудник не узнает». */}
        <p className="mt-3 text-xs text-muted-foreground">{t("screenAccess.noticeAlways")}</p>
      </section>

      <section className="glass p-5">
        <h2 className="text-[15px] font-semibold text-foreground">{t("screenAccess.quotaTitle")}</h2>
        {policy && (
          <>
            <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-muted">
              <div
                className={"h-full rounded-full " + (quotaPct >= 90 ? "bg-destructive" : "bg-primary")}
                style={{ width: `${quotaPct}%` }}
              />
            </div>
            <p className="mt-2 text-xs text-muted-foreground">
              {t("screenAccess.quotaUsed", {
                used: formatBytes(policy.recording_used),
                total: formatBytes(policy.recording_quota),
                pct: quotaPct,
              })}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              {t("screenAccess.retention", { days: policy.recording_retention })}
            </p>
          </>
        )}
      </section>

      <section className="glass p-5">
        <h2 className="text-[15px] font-semibold text-foreground">{t("screenAccess.grantsTitle")}</h2>
        <p className="mt-1 text-xs text-muted-foreground">{t("screenAccess.grantsHint")}</p>
        <Table className="mt-3">
          <TableHeader>
            <TableRow>
              <TableHead>{t("screenAccess.admin")}</TableHead>
              <TableHead>{t("screenAccess.grant")}</TableHead>
              <TableHead className="w-px" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {grants.map((g) => (
              <TableRow key={g.user_id}>
                <TableCell className="text-sm text-foreground">{g.email}</TableCell>
                <TableCell>
                  {g.can_view_session_recording ? (
                    <Badge variant="outline">{t("screenAccess.granted")}</Badge>
                  ) : (
                    <span className="text-xs text-muted-foreground">{t("screenAccess.notGranted")}</span>
                  )}
                </TableCell>
                <TableCell>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy === g.user_id}
                    onClick={() => void setGrant(g)}
                  >
                    {g.can_view_session_recording ? t("screenAccess.revoke") : t("screenAccess.give")}
                  </Button>
                </TableCell>
              </TableRow>
            ))}
            {grants.length === 0 && (
              <TableRow>
                <TableCell colSpan={3} className="text-sm text-muted-foreground">
                  {t("screenAccess.noAdmins")}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </section>
    </div>
  )
}

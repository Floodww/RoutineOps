import { useCallback, useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import api, { errMessage, errStatus, SCREEN_END_REASON, type ScreenSession } from "@/lib/api"
import { drawPart, parseRecords } from "@/lib/screenframe"
import { formatDistanceToNow } from "@/lib/time"

// Вкладка «Экран» карточки устройства (docs/remote-desktop-contract.md, Ф1).
//
// Ф1 — ТОЛЬКО просмотр: ни клавиатуры, ни мыши, ни передачи файлов. Это не урезание
// требования, а порядок: управление тянет за собой UIAccess на Windows и второе
// TCC-разрешение на macOS, а просмотр с полным аудитом и записью уже закрывает основной
// сценарий поддержки.
//
// Транспорт — long-poll, а не WebSocket (§3.3). WS упирается в три мины разом: серверный
// WriteTimeout переживает Hijack, nginx без proxy_http_version 1.1 рвёт апгрейд, CSP
// connect-src надо проверять на wss живьём. Лечатся они вместе с введением управления.

interface Props {
  deviceId: string
}

// Пауза long-poll. Держится ниже серверного потолка (25 с), чтобы ответ не обрубался
// таймаутом записи.
const WAIT_MS = 20000

export function ScreenSessionPanel({ deviceId }: Props) {
  const { t } = useTranslation()
  const [sessions, setSessions] = useState<ScreenSession[]>([])
  // available=false — ручек нет вовсе (open-core). Секция в этом случае не рисуется:
  // «фича не в этой редакции» лучше показать отсутствием, чем кнопкой, которая всегда
  // отвечает ошибкой.
  const [available, setAvailable] = useState(true)
  const [reason, setReason] = useState("")
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState("")
  const [live, setLive] = useState<ScreenSession | null>(null)
  const [status, setStatus] = useState("")

  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const stopRef = useRef(false)

  const loadJournal = useCallback(async () => {
    try {
      const r = await api.get<ScreenSession[]>(`/devices/${deviceId}/screen-sessions`)
      setSessions(r.data ?? [])
      setAvailable(true)
    } catch (e) {
      if (errStatus(e) === 404) setAvailable(false)
    }
  }, [deviceId])

  useEffect(() => {
    void loadJournal()
  }, [loadJournal])

  // Петля просмотра. Живёт ровно столько, сколько открыт сеанс: закрытая вкладка не
  // продлевает liveness, и сервер закроет сеанс сам (§9.9) — поэтому останавливать её
  // при размонтировании обязательно, иначе запись продолжится при отсутствующем зрителе.
  const runViewer = useCallback(
    async (sessionId: string) => {
      stopRef.current = false
      let since = 0
      let sized = false

      while (!stopRef.current) {
        let res
        try {
          res = await api.get<ArrayBuffer>(`/screen-sessions/${sessionId}/live`, {
            params: { since, wait: WAIT_MS },
            responseType: "arraybuffer",
            timeout: WAIT_MS + 15000,
          })
        } catch (e) {
          if (errStatus(e) === 410) {
            setStatus(t("screenSession.ended"))
            break
          }
          setError(errMessage(e))
          break
        }

        const w = Number(res.headers["x-screen-width"] || 0)
        const h = Number(res.headers["x-screen-height"] || 0)
        const canvas = canvasRef.current
        if (canvas && w > 0 && h > 0 && (!sized || canvas.width !== w || canvas.height !== h)) {
          canvas.width = w
          canvas.height = h
          sized = true
        }
        since = Number(res.headers["x-screen-seq"] || since)

        const body = new Uint8Array(res.data as ArrayBuffer)
        if (body.byteLength > 0 && canvas) {
          const ctx = canvas.getContext("2d")
          if (ctx) {
            try {
              for (const rec of parseRecords(body)) {
                await drawPart(ctx, rec.part)
              }
            } catch (e) {
              // Битый поток — конец сеанса, а не «пропустим кадр»: тайлы дельтовые, и
              // дальше на холст ляжет каша из двух разных моментов.
              console.error("screen: frame stream is not parseable", e)
              setError(t("screenSession.brokenStream"))
              break
            }
          }
        }

        if (res.headers["x-screen-closed"]) {
          const code = String(res.headers["x-screen-end-reason"] || "")
          setStatus(code && SCREEN_END_REASON[code] ? t(SCREEN_END_REASON[code]) : t("screenSession.ended"))
          break
        }
      }
      setLive(null)
      void loadJournal()
    },
    [loadJournal, t],
  )

  useEffect(() => {
    return () => {
      stopRef.current = true
    }
  }, [])

  const start = async () => {
    setError("")
    const text = reason.trim()
    if (!text) {
      setError(t("screenSession.reasonRequired"))
      return
    }
    setStarting(true)
    try {
      const r = await api.post<ScreenSession>(`/devices/${deviceId}/screen-sessions`, { reason: text })
      setLive(r.data)
      setStatus(t("screenSession.waitingAgent"))
      setReason("")
      void runViewer(r.data.id)
    } catch (e) {
      // Отказы 409 — не сбои, а ответы: устройство не на связи либо агент этой редакции
      // удалённого стола не содержит. Оператор обязан прочитать причину, а не «ошибку».
      const body = (e as { response?: { data?: { error?: string } } })?.response?.data
      if (body?.error === "device_offline") setError(t("screenSession.deviceOffline"))
      else if (body?.error === "agent_unsupported") setError(t("screenSession.agentUnsupported"))
      else setError(errMessage(e))
    } finally {
      setStarting(false)
    }
  }

  const stop = async () => {
    if (!live) return
    stopRef.current = true
    try {
      await api.post(`/screen-sessions/${live.id}/stop`)
    } catch {
      // Сеанс мог закрыться сам (сотрудник, потолок длительности) — это не ошибка.
    }
    setLive(null)
    void loadJournal()
  }

  if (!available) return null

  return (
    <div className="glass">
      <div className="px-5 pt-4 pb-3">
        <h2 className="text-[15px] font-semibold text-foreground">{t("screenSession.title")}</h2>
        <p className="text-xs text-muted-foreground mt-1">{t("screenSession.hint")}</p>
      </div>

      <div className="border-t border-border px-5 py-4">
        {live ? (
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <Badge variant="outline">{t("screenSession.watching")}</Badge>
                <span className="text-xs text-muted-foreground">{status}</span>
              </div>
              <Button size="sm" variant="outline" onClick={stop}>
                {t("screenSession.stop")}
              </Button>
            </div>
            <canvas
              ref={canvasRef}
              className="w-full rounded-xl border border-border bg-black"
              aria-label={t("screenSession.canvasLabel")}
            />
            <p className="text-xs text-muted-foreground">{t("screenSession.recordingNotice")}</p>
          </div>
        ) : (
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <input
              className="flex-1 rounded-lg border border-border bg-transparent px-3 py-2 text-sm"
              placeholder={t("screenSession.reasonPlaceholder")}
              value={reason}
              maxLength={500}
              onChange={(e) => setReason(e.target.value)}
            />
            <Button size="sm" disabled={starting} onClick={start}>
              {starting ? "…" : t("screenSession.connect")}
            </Button>
          </div>
        )}
        {error && <p className="mt-2 text-xs text-destructive">{error}</p>}
      </div>

      {sessions.length > 0 && (
        <div>
          {sessions.map((s) => (
            <div key={s.id} className="flex items-center justify-between gap-4 border-t border-border px-5 py-3 last:rounded-b-2xl">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="truncate text-sm font-medium text-foreground">{s.reason}</span>
                  {s.mode === "consent_required" && <Badge variant="outline">{t("screenSession.consentMode")}</Badge>}
                  {s.status !== "ended" && <Badge variant="outline">{t("screenSession.live")}</Badge>}
                </div>
                <div className="text-xs text-muted-foreground">
                  {t("screenSession.byOperator", { who: s.operator_email })}
                  {" · "}
                  {formatDistanceToNow(s.created_at)}
                  {s.end_reason && " · " + (SCREEN_END_REASON[s.end_reason] ? t(SCREEN_END_REASON[s.end_reason]) : s.end_reason)}
                </div>
              </div>
              {s.has_recording && (
                <Button size="sm" variant="outline" onClick={() => void downloadRecording(s.id)}>
                  {t("screenSession.recording")}
                </Button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// downloadRecording выгружает запись сеанса.
//
// Просмотр записи — отдельное поднадзорное действие: сервер требует отзываемый грант
// can_view_session_recording и пишет САМ ФАКТ обращения в аудит fail-closed. Отказ здесь
// нормальный ответ, а не сбой интерфейса.
async function downloadRecording(sessionId: string) {
  const res = await api.get(`/screen-sessions/${sessionId}/recording`, { responseType: "blob" })
  const url = URL.createObjectURL(res.data as Blob)
  const a = document.createElement("a")
  a.href = url
  a.download = `screen-session-${sessionId}.bin`
  a.click()
  URL.revokeObjectURL(url)
}

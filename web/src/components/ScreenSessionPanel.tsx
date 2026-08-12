import { useCallback, useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { Link } from "react-router-dom"

import ConfirmDialog from "@/components/ConfirmDialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import api, {
  errMessage,
  errStatus,
  SCREEN_CONSENT,
  SCREEN_END_REASON,
  SCREEN_TRUNCATION,
  type ScreenSession,
} from "@/lib/api"
import { formatBytes, formatDuration } from "@/lib/format"
import { drawPart, parseRecords } from "@/lib/screenframe"
import {
  FLUSH_MS,
  InputCollector,
  inputOutcome,
  keyEvents,
  toFrame,
  wheelClicks,
} from "@/lib/screeninput"
import { formatDistanceToNow } from "@/lib/time"

// Вкладка «Экран» карточки устройства (docs/remote-desktop-contract.md).
//
// Два режима, и различие между ними объявляется ДО начала сеанса, а не переключается по
// ходу: наблюдение и управление — разные права, разные строки аудита и разный текст,
// который видит сотрудник. Область сеанса фиксируется приглашением, и агент расширить её
// не даст (§9.10) — поэтому «взять управление» это всегда НОВЫЙ сеанс, а «вернуть» —
// необратимое сужение текущего.
//
// Транспорт кадров — long-poll (§3.3): поток идёт ВНИЗ, и WS упирался бы в три мины разом
// (WriteTimeout переживает Hijack, nginx без proxy_http_version 1.1, CSP connect-src).
// Ввод идёт ВВЕРХ и едет обычным POST пачками — long-poll тут ни при чём, а WS ради одного
// направления не окупает ни одной из трёх мин.

interface Props {
  deviceId: string
}

// Пауза long-poll. Держится ниже серверного потолка (25 с), чтобы ответ не обрубался
// таймаутом записи.
const WAIT_MS = 20000

// Пауза между опросами, пока агент ещё не открыл стрим. Секунда, а не long-poll: сервер
// на 202 отвечает сразу, и без паузы это был бы цикл без задержки.
const WAITING_POLL_MS = 1000

const sleep = (ms: number) => new Promise((done) => setTimeout(done, ms))

// Что панель предлагает сделать с записью сеанса.
//
// Развилка вынесена из разметки намеренно — иначе её нечем гейтить (тот же приём, что у
// inputOutcome после Q-82). Правило неочевидно ровно в одном месте: «право неизвестно».
//
//   - grant === false — право спрошено и его нет. Кнопки быть не должно: сервер ответит
//     403, а оператор увидит голый код отказа за действие, которое ему предложили сами.
//   - grant === null — спросить НЕ УДАЛОСЬ (ручки нет, сеть, 500). Кнопку оставляем:
//     сказать «права нет» из-за собственного сбоя значило бы соврать тому, у кого право
//     есть, и отправить его просить уже выданный грант. Отказ, если он всё-таки придёт,
//     виден тостом.
export type RecordingAffordance = "download" | "locked" | "none"

export function recordingAffordance(hasRecording: boolean, grant: boolean | null): RecordingAffordance {
  if (!hasRecording) return "none"
  return grant === false ? "locked" : "download"
}

// Признак применяемости ввода (Ф3), как его отдаёт заголовок X-Screen-Control.
//
// Три состояния, и «неизвестно» — НЕ «работает»: агент старше поля X-Screen-Control не
// пришлёт признак вовсе, и молчание, прочитанное как успех, оставило бы ложный зелёный.
// Панель рисует индикатор только у сеанса с управлением; у смотрового заголовка нет.
export type ControlIndicator = {
  state: "unknown" | "effective" | "ineffective"
  reason: string
}

// parseControlHeader разбирает X-Screen-Control. Пустое или незнакомое → unknown:
// отсутствие сигнала не должно читаться как «работает».
export function parseControlHeader(raw: string | undefined): ControlIndicator {
  const v = String(raw || "").trim()
  if (v === "effective") return { state: "effective", reason: "" }
  if (v.startsWith("ineffective:")) return { state: "ineffective", reason: v.slice("ineffective:".length) }
  return { state: "unknown", reason: "" }
}

// controlIneffectiveKey переводит причину неприменимости в ключ подсказки. Пустая строка
// означает «подписи нет» — тогда показывается САМ КОД, а не общая формулировка.
//
// 🔴 Незнакомый код обязан доехать до оператора текстом (§«Честный признак управления»:
// reason строкой именно затем, чтобы код, которого панель не знает, не схлопывался). Общий
// фолбэк здесь был бы тем же `UNSPECIFIED`, от которого контракт и отказался: сервер новее
// панели — штатная ситуация, и в этот момент код в интерфейсе единственный способ понять,
// что происходит.
export function controlIneffectiveKey(reason: string): string {
  switch (reason) {
    case "DESKTOP_LOST":
    case "SECURE_DESKTOP":
      return "screenSession.controlIneffectiveDesktop"
    case "INPUT_REJECTED":
      return "screenSession.controlIneffectiveRejected"
    default:
      return ""
  }
}

// controlIneffectiveText — что показать под индикатором «не действует». Известная причина
// переводится, незнакомая выводится кодом рядом с общей рамкой «ввод не доходит», чтобы
// строка оставалась понятной оператору и не теряла код для разбора.
export function controlIneffectiveText(reason: string, t: (k: string) => string): string {
  const key = controlIneffectiveKey(reason)
  if (key !== "") return t(key)
  const code = reason.trim()
  if (code === "") return t("screenSession.controlUipiHint")
  return t("screenSession.controlUipiHint") + " (" + code + ")"
}

export function ScreenSessionPanel({ deviceId }: Props) {
  const { t } = useTranslation()
  const [sessions, setSessions] = useState<ScreenSession[]>([])
  // available=false — ручек нет вовсе (open-core). Секция в этом случае не рисуется:
  // «фича не в этой редакции» лучше показать отсутствием, чем кнопкой, которая всегда
  // отвечает ошибкой.
  const [available, setAvailable] = useState(true)
  const [reason, setReason] = useState("")
  // Право открывать записи (§5). null — спросить не удалось; см. recordingAffordance.
  const [recordingGrant, setRecordingGrant] = useState<boolean | null>(null)
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState("")
  const [live, setLive] = useState<ScreenSession | null>(null)
  const [status, setStatus] = useState("")
  // Сеанс, который оператор собирается прекратить из журнала (null — диалога нет).
  //
  // Подтверждение стоит ТОЛЬКО здесь, а не у кнопки живого просмотра, и это не
  // непоследовательность: из журнала обрывается в том числе ЧУЖОЙ идущий сеанс —
  // другой администратор в этот момент разбирает инцидент, и его работа прекращается
  // без предупреждения. Свой сеанс оператор обрывает себе же и тут же начинает заново.
  const [confirmStop, setConfirmStop] = useState<ScreenSession | null>(null)

  // Запрошено ли управление ДО начала сеанса. Отдельный флаг от `live.control`: первый —
  // намерение оператора, второй — то, что реально выдал сервер и объявил агенту.
  const [wantControl, setWantControl] = useState(false)
  // Управление отдано сотруднику обратно. Необратимо в пределах сеанса (§9.10), поэтому
  // кнопка после нажатия исчезает, а не превращается в «взять снова».
  const [controlReturned, setControlReturned] = useState(false)
  const [inputWarning, setInputWarning] = useState("")
  // Применяемость ввода (Ф3), как её на каждом опросе сообщает сервер заголовком
  // X-Screen-Control. Три состояния, и «неизвестно» — не «работает»: агент старше поля
  // молчит, и молчание не должно читаться как зелёное. Живёт только у сеанса с управлением.
  const [controlState, setControlState] = useState<ControlIndicator>({ state: "unknown", reason: "" })
  // Открыт ли стрим агента. Отдельно от `live`: сеанс СОЗДАН с момента ответа 201, а
  // стрим появляется через 3.5 с — приглашение едет на устройство, захватчик поднимается
  // в сессии пользователя, в режиме согласия отвечает сотрудник. Управление сервер выдаёт
  // сразу при создании, поэтому одного `live.control` мало: петля отправки стартовала бы
  // в окно, когда принимать ввод ещё некому.
  const [streamOpen, setStreamOpen] = useState(false)

  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const stopRef = useRef(false)
  // Собиратель ввода живёт в ref, а не в состоянии: он мутируется на каждое движение
  // мыши, и перерисовка компонента на этом такте съела бы кадры, нужные самому экрану.
  const inputRef = useRef<InputCollector | null>(null)
  const controlOnRef = useRef(false)

  const loadJournal = useCallback(async () => {
    try {
      const r = await api.get<ScreenSession[]>(`/devices/${deviceId}/screen-sessions`)
      setSessions(r.data ?? [])
      setAvailable(true)
    } catch (e) {
      if (errStatus(e) === 404) setAvailable(false)
    }
  }, [deviceId])

  // Свой грант на просмотр записей. Спрашивается один раз на монтирование, а не на каждое
  // обновление журнала: право отзывается администратором вручную, а не по ходу сеанса.
  // Сбой запроса оставляет null — см. recordingAffordance, он трактует это как «не знаем»,
  // а не как «нельзя».
  useEffect(() => {
    let dropped = false
    api
      .get<{ can_view_session_recording: boolean }>("/screen-recording-grants/me")
      .then((r) => {
        if (!dropped) setRecordingGrant(r.data?.can_view_session_recording === true)
      })
      .catch(() => {})
    return () => {
      dropped = true
    }
  }, [])

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

        // 202 — сеанс создан, агент ещё не открыл стрим (доставка приглашения, запуск
        // захватчика, а в режиме согласия ещё и ответ сотрудника). Это НЕ конец сеанса:
        // продолжаем опрос, а не закрываем просмотр.
        if (res.status === 202) {
          setStatus(t("screenSession.waitingAgent"))
          await sleep(WAITING_POLL_MS)
          continue
        }

        // Первый не-202 ответ = стрим зарегистрирован в хабе. Только с этого момента
        // ввод есть кому принять — до него петля отправки не запускается вовсе.
        setStreamOpen(true)

        const w = Number(res.headers["x-screen-width"] || 0)
        const h = Number(res.headers["x-screen-height"] || 0)
        const canvas = canvasRef.current
        if (canvas && w > 0 && h > 0 && (!sized || canvas.width !== w || canvas.height !== h)) {
          canvas.width = w
          canvas.height = h
          sized = true
        }
        since = Number(res.headers["x-screen-seq"] || since)
        // Признак применяемости ввода (Ф3): сервер шлёт его только у сеанса с управлением.
        // Заголовка нет — состояние не трогаем (у смотрового сеанса его и не будет).
        const ctrlHeader = res.headers["x-screen-control"]
        if (ctrlHeader !== undefined) {
          setControlState(parseControlHeader(ctrlHeader as string))
        }

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
      setStreamOpen(false)
      void loadJournal()
    },
    [loadJournal, t],
  )

  useEffect(() => {
    return () => {
      stopRef.current = true
    }
  }, [])

  // Управление активно ровно тогда, когда сервер его выдал и оператор его не вернул.
  const controlOn = Boolean(live?.control) && !controlReturned
  useEffect(() => {
    controlOnRef.current = controlOn
  }, [controlOn])

  // Петля отправки ввода.
  //
  // Отдельный таймер, а не отправка из обработчиков событий: мышь порождает до сотни
  // событий в секунду, и запрос на каждое положил бы очередь соединений браузера раньше,
  // чем сервер. Пачка раз в 50 мс добавляет к задержке 25 мс в среднем — на фоне
  // врождённых 80–250 мс ретрансляции кадра это не различимо.
  useEffect(() => {
    // streamOpen — обязательное условие, а не оптимизация: пачка, отправленная до
    // открытия стрима, раньше получала 409 и гасила управление до конца сеанса. Сервер
    // теперь отвечает на этот случай 503 (временный отказ), но не отправлять её вовсе
    // строго лучше: печатать всё равно некуда — картинки ещё нет.
    if (!controlOn || !live || !streamOpen) {
      inputRef.current = null
      return
    }
    const collector = new InputCollector()
    inputRef.current = collector
    let sending = false

    const flush = async () => {
      const canvas = canvasRef.current
      if (!canvas || sending) return
      const batch = collector.take(canvas.width, canvas.height)
      if (!batch) return
      sending = true
      try {
        await api.post(`/screen-sessions/${live.id}/input`, batch)
        setInputWarning("")
      } catch (e) {
        switch (inputOutcome(errStatus(e))) {
          case "retry":
            // Временный отказ. Сервер отказал ЯВНО, а не выбросил пачку молча: оператор
            // должен знать, что его нажатия не доехали, — иначе он будет давить сильнее.
            setInputWarning(t("screenSession.inputBacklog"))
            break
          case "dead":
            // Управление отозвано либо сеанс кончился. Дальше слать нечего.
            setControlReturned(true)
            break
          default:
            setInputWarning(errMessage(e))
        }
      } finally {
        sending = false
      }
    }

    const timer = window.setInterval(() => void flush(), FLUSH_MS)
    return () => {
      window.clearInterval(timer)
      inputRef.current = null
    }
  }, [controlOn, live, streamOpen, t])

  // Отпустить всё зажатое при потере фокуса окна.
  //
  // Обязательно, и не для порядка: оператор нажал Ctrl и переключился на другую вкладку —
  // keyup придёт уже не нам, а на машине сотрудника модификатор останется зажатым. Снять
  // его сможет только он сам.
  useEffect(() => {
    if (!controlOn) return
    const release = () => inputRef.current?.release()
    window.addEventListener("blur", release)
    document.addEventListener("visibilitychange", release)
    return () => {
      window.removeEventListener("blur", release)
      document.removeEventListener("visibilitychange", release)
      release()
    }
  }, [controlOn])

  // Возврат управления. Наблюдение при этом продолжается.
  const returnControl = async () => {
    if (!live) return
    inputRef.current?.release()
    setControlReturned(true)
    try {
      await api.delete(`/screen-sessions/${live.id}/control`)
      void loadJournal()
    } catch (e) {
      setError(errMessage(e))
    }
  }

  const start = async () => {
    setError("")
    const text = reason.trim()
    if (!text) {
      setError(t("screenSession.reasonRequired"))
      return
    }
    setStarting(true)
    try {
      const r = await api.post<ScreenSession>(`/devices/${deviceId}/screen-sessions`, {
        reason: text,
        control: wantControl,
      })
      setLive(r.data)
      setStreamOpen(false)
      setControlReturned(false)
      setInputWarning("")
      setControlState({ state: "unknown", reason: "" })
      setStatus(t("screenSession.waitingAgent"))
      setReason("")
      void runViewer(r.data.id)
    } catch (e) {
      // Отказы 409 — не сбои, а ответы: устройство не на связи либо агент этой редакции
      // удалённого стола не содержит. Оператор обязан прочитать причину, а не «ошибку».
      const body = (e as { response?: { data?: { error?: string } } })?.response?.data
      if (body?.error === "device_offline") setError(t("screenSession.deviceOffline"))
      else if (body?.error === "agent_unsupported") setError(t("screenSession.agentUnsupported"))
      else if (body?.error === "agent_no_control") setError(t("screenSession.agentNoControl"))
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

  // Прекратить сеанс ИЗ ЖУРНАЛА — в том числе чужой и начатый в другой вкладке.
  //
  // Раньше кнопка Stop была только у сеанса, начатого этой самой вкладкой: оператор,
  // закрывший вкладку, терял единственный способ его остановить, а второй администратор
  // видел идущее наблюдение и ничего не мог с ним сделать. Сторож закрыл бы сеанс сам,
  // но через минуту без зрителя (§9.9) — целая минута чужого экрана.
  const stopFromJournal = async (id: string) => {
    setError("")
    try {
      await api.post(`/screen-sessions/${id}/stop`)
    } catch (e) {
      setError(errMessage(e))
    }
    if (live?.id === id) {
      stopRef.current = true
      setLive(null)
    }
    void loadJournal()
  }

  // Подключиться к УЖЕ ИДУЩЕМУ сеансу. Права те же, что у начала нового: сервер проверяет
  // роль, человека и тенант на каждом запросе /live, а сам факт просмотра продлевает
  // liveness — то есть подключившийся становится зрителем по-настоящему.
  const watch = (s: ScreenSession) => {
    setError("")
    setLive(s)
    setStreamOpen(false)
    // Подключение к ЧУЖОМУ идущему сеансу — всегда просмотр: ввод сервер примет только
    // от того оператора, который сеанс начал (иначе действия одного человека легли бы в
    // журнал под именем другого). Кнопка управления здесь не появляется.
    setControlReturned(true)
    setInputWarning("")
    setControlState({ state: "unknown", reason: "" })
    setStatus(t("screenSession.waitingAgent"))
    void runViewer(s.id)
  }

  const download = async (id: string) => {
    setError("")
    try {
      await downloadRecording(id)
    } catch (e) {
      // 🔴 Раньше вызов уходил через void, и 403 «нужен грант can_view_session_recording»
      // становился необработанным reject: оператор видел, что «ничего не произошло», и
      // шёл жаловаться на кнопку. Отказ здесь — нормальный ответ, и он обязан быть виден.
      setError(errStatus(e) === 403 ? t("screenSession.recordingForbidden") : errMessage(e))
    }
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
                <Badge variant={controlOn ? "destructive" : "outline"}>
                  {controlOn ? t("screenSession.controlling") : t("screenSession.watching")}
                </Badge>
                <span className="text-xs text-muted-foreground">{status}</span>
              </div>
              <div className="flex items-center gap-2">
                {controlOn && (
                  <Button size="sm" variant="outline" onClick={() => void returnControl()}>
                    {t("screenSession.returnControl")}
                  </Button>
                )}
                <Button size="sm" variant="outline" onClick={stop}>
                  {t("screenSession.stop")}
                </Button>
              </div>
            </div>
            {/* Холст получает фокус только в режиме управления: tabIndex у картинки, по
                которой нельзя кликнуть, — это лишняя остановка при обходе с клавиатуры. */}
            <canvas
              ref={canvasRef}
              tabIndex={controlOn ? 0 : undefined}
              className={
                "w-full rounded-xl border bg-black outline-none " +
                (controlOn
                  ? "border-destructive cursor-crosshair focus-visible:ring-2 focus-visible:ring-destructive"
                  : "border-border")
              }
              aria-label={controlOn ? t("screenSession.canvasControlLabel") : t("screenSession.canvasLabel")}
              onPointerDown={(e) => {
                if (!controlOn) return
                // Фокус на холст обязателен: без него клавиатурные события уедут в
                // документ, а не сюда, и Ctrl+C оператора сработает в его собственном
                // браузере вместо машины сотрудника.
                e.currentTarget.focus()
                const p = toFrame(e.currentTarget, e.clientX, e.clientY)
                if (p) inputRef.current?.add({ kind: "mouse_down", ...p, button: e.button })
              }}
              onPointerUp={(e) => {
                if (!controlOn) return
                const p = toFrame(e.currentTarget, e.clientX, e.clientY)
                if (p) inputRef.current?.add({ kind: "mouse_up", ...p, button: e.button })
              }}
              onPointerMove={(e) => {
                if (!controlOn) return
                const p = toFrame(e.currentTarget, e.clientX, e.clientY)
                if (p) inputRef.current?.add({ kind: "mouse_move", ...p })
              }}
              onPointerLeave={() => controlOn && inputRef.current?.release()}
              onContextMenu={(e) => {
                // Правая кнопка уезжает НА УДАЛЁННУЮ машину, а не открывает меню браузера:
                // иначе контекстное меню в проводнике сотрудника недостижимо в принципе.
                if (controlOn) e.preventDefault()
              }}
              onWheel={(e) => {
                if (!controlOn) return
                inputRef.current?.add({ kind: "wheel", ...wheelClicks(e.nativeEvent) })
              }}
              onKeyDown={(e) => {
                if (!controlOn) return
                const evs = keyEvents(e.nativeEvent, true)
                if (evs.length) e.preventDefault()
                evs.forEach((ev) => inputRef.current?.add(ev))
              }}
              onKeyUp={(e) => {
                if (!controlOn) return
                const evs = keyEvents(e.nativeEvent, false)
                if (evs.length) e.preventDefault()
                evs.forEach((ev) => inputRef.current?.add(ev))
              }}
              onPaste={(e) => {
                // Вставка буфера обмена — текстом, а не набором клавиш: раскладка на
                // машине сотрудника своя, и «нажать те же кнопки» дало бы другие символы.
                if (!controlOn) return
                const text = e.clipboardData.getData("text/plain")
                if (!text) return
                e.preventDefault()
                inputRef.current?.add({ kind: "text", text })
              }}
            />
            {controlOn && (
              <p className="text-xs text-destructive">{t("screenSession.controlHint")}</p>
            )}
            {/*
              Применяемость ввода называется ЗДЕСЬ живым признаком, а не статичной
              оговоркой. Раньше тут висело предупреждение про UIAccess «ввод в окна
              администратора молча пропадает»; с захватчиком под SYSTEM это больше не так,
              а на потерю входного стола (UAC, локскрин) сервер теперь шлёт настоящий
              признак X-Screen-Control. Ложный зелёный хуже честного «не доходит»: пока
              состояние неизвестно — так и говорим, а не показываем работающее управление.
            */}
            {controlOn && controlState.state === "effective" && (
              <p className="text-xs text-emerald-600 dark:text-emerald-500">{t("screenSession.controlActive")}</p>
            )}
            {controlOn && controlState.state === "unknown" && (
              <p className="text-xs text-muted-foreground">{t("screenSession.controlUnknown")}</p>
            )}
            {controlOn && controlState.state === "ineffective" && (
              <p className="text-xs text-destructive">{controlIneffectiveText(controlState.reason, t)}</p>
            )}
            {inputWarning && <p className="text-xs text-amber-600 dark:text-amber-500">{inputWarning}</p>}
            <p className="text-xs text-muted-foreground">{t("screenSession.recordingNotice")}</p>
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
              <input
                className="flex-1 rounded-lg border border-border bg-transparent px-3 py-2 text-sm"
                placeholder={t("screenSession.reasonPlaceholder")}
                value={reason}
                maxLength={500}
                onChange={(e) => setReason(e.target.value)}
              />
              <Button size="sm" disabled={starting} onClick={start}>
                {starting ? "…" : wantControl ? t("screenSession.connectControl") : t("screenSession.connect")}
              </Button>
            </div>
            {/* Управление выбирается ДО начала сеанса, и это не про удобство: область
                фиксируется приглашением, агент расширить её не даст, поэтому «взять
                управление» посреди наблюдения невозможно построением. */}
            <label className="flex items-center gap-2 text-xs text-muted-foreground">
              <input
                type="checkbox"
                className="h-3.5 w-3.5 accent-[hsl(var(--brand))]"
                checked={wantControl}
                onChange={(e) => setWantControl(e.target.checked)}
              />
              {t("screenSession.withControl")}
            </label>
          </div>
        )}
        {error && <p className="mt-2 text-xs text-destructive">{error}</p>}
      </div>

      {sessions.length > 0 && (
        <div>
          {sessions.map((s) => {
            const affordance = recordingAffordance(s.has_recording, recordingGrant)
            return (
            <div key={s.id} className="flex items-center justify-between gap-4 border-t border-border px-5 py-3 last:rounded-b-2xl">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="truncate text-sm font-medium text-foreground">{s.reason}</span>
                  {s.control && <Badge variant="destructive">{t("screenSession.controlBadge")}</Badge>}
                  {s.mode === "consent_required" && <Badge variant="outline">{t("screenSession.consentMode")}</Badge>}
                  {s.status !== "ended" && <Badge variant="outline">{t("screenSession.live")}</Badge>}
                  {/* Исход согласия. Показывается ТОЛЬКО когда он есть: пустое значение
                      означает «вопрос не задавался» (unattended), и рисовать это как исход
                      значило бы утверждать, что сотрудника спросили. */}
                  {/* Профиль понижен самим агентом: он не опознал запрошенный. Это
                      расхождение версий, и оператору важнее объяснение, чем сам факт. */}
                  {s.profile_fallback && (
                    <Badge variant="outline" title={t("screenSession.profileFallbackHint")}>
                      {t("screenSession.profileFallback")}
                    </Badge>
                  )}
                  {s.consent_state && SCREEN_CONSENT[s.consent_state] && (
                    <Badge variant={s.consent_state === "GRANTED" ? "outline" : "destructive"}>
                      {t(SCREEN_CONSENT[s.consent_state])}
                    </Badge>
                  )}
                </div>
                <div className="text-xs text-muted-foreground">
                  {t("screenSession.byOperator", { who: s.operator_email })}
                  {" · "}
                  {formatDistanceToNow(s.created_at)}
                  {/* Длительность требует §4 п.3 контракта прямым текстом. Считается от
                      начала СЪЁМКИ, а не от запроса: время ожидания агента и ответа
                      сотрудника — не наблюдение. */}
                  {s.started_at && " · " + formatDuration(s.started_at, s.ended_at)}
                  {s.end_reason && " · " + (SCREEN_END_REASON[s.end_reason] ? t(SCREEN_END_REASON[s.end_reason]) : s.end_reason)}
                </div>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                {s.status !== "ended" && (
                  <>
                    {live?.id !== s.id && (
                      <Button size="sm" variant="outline" onClick={() => watch(s)}>
                        {t("screenSession.watch")}
                      </Button>
                    )}
                    <Button size="sm" variant="outline" onClick={() => setConfirmStop(s)}>
                      {t("screenSession.stop")}
                    </Button>
                  </>
                )}
                {affordance !== "none" && (
                  <>
                    {/* Отметка рядом с кнопкой, а не вместо неё: неполную запись всё равно
                        смотрят — просто знают заранее, что в ней есть не всё. */}
                    {s.recording_truncated && (
                      <span className="text-xs text-amber-600 dark:text-amber-500" title={
                        s.recording_truncated_reason && SCREEN_TRUNCATION[s.recording_truncated_reason]
                          ? t(SCREEN_TRUNCATION[s.recording_truncated_reason])
                          : undefined
                      }>
                        {t("screenSession.truncated.badge")}
                      </span>
                    )}
                    {affordance === "download" ? (
                      <Button size="sm" variant="outline" onClick={() => void download(s.id)}>
                        {t("screenSession.recording")}
                        {s.recording_bytes ? ` · ${formatBytes(s.recording_bytes)}` : ""}
                      </Button>
                    ) : (
                      // Запись есть, права на неё нет. Показываем ФАКТ записи, но не
                      // предлагаем действие: сама строка журнала — тоже сведение, и
                      // прятать её значило бы скрывать, что сеанс писался.
                      //
                      // Не `<Button disabled>`: неактивная кнопка выпадает из обхода с
                      // клавиатуры вместе со своей подсказкой, то есть объяснение
                      // достаётся только мыши. Объяснение целиком — в сноске под
                      // журналом, здесь только пометка.
                      <span className="text-xs text-muted-foreground">
                        {t("screenSession.recordingLocked")}
                        {s.recording_bytes ? ` · ${formatBytes(s.recording_bytes)}` : ""}
                      </span>
                    )}
                  </>
                )}
              </div>
            </div>
            )
          })}
          {/* Сноска одна на панель, а не подпись у каждой строки: причина у всех записей
              одна и та же, и повторять её на каждом сеансе значит спрятать её в шуме.
              Ссылка ведёт туда, где грант выдают, — «попросите права» без адреса это и
              есть тот самый голый отказ, только словами. */}
          {recordingGrant === false && sessions.some((s) => s.has_recording) && (
            <p className="border-t border-border px-5 py-3 text-xs text-muted-foreground">
              {t("screenSession.recordingLockedHint")}{" "}
              <Link to="/screen-access" className="underline underline-offset-2 hover:text-foreground">
                {t("nav.screenAccess")}
              </Link>
            </p>
          )}
        </div>
      )}

      {/* Диалог называет ИМЕННО тот сеанс, который оборвётся: оператора и причину, с
          которой он его начал. Без них подтверждение вырождается в лишний клик — в
          журнале активных строк может быть несколько, и «вы уверены?» без предмета не
          даёт отличить свой сеанс от чужого. */}
      <ConfirmDialog
        open={confirmStop !== null}
        onOpenChange={(open) => !open && setConfirmStop(null)}
        title={t("screenSession.stopConfirmTitle")}
        description={
          confirmStop
            ? t("screenSession.stopConfirmBody", {
                who: confirmStop.operator_email,
                reason: confirmStop.reason,
              })
            : undefined
        }
        confirmLabel={t("screenSession.stop")}
        destructive
        onConfirm={() => {
          if (confirmStop) void stopFromJournal(confirmStop.id)
          setConfirmStop(null)
        }}
      />
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

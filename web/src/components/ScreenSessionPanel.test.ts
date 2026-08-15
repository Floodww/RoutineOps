import { describe, it, expect } from "vitest"
import {
  recordingAffordance,
  parseControlHeader,
  controlIneffectiveKey,
  controlIneffectiveText,
  parseFramesHeader,
  framesPausedText,
} from "./ScreenSessionPanel"

// Гейт Q-84: панель не предлагает действие, которое заведомо упрётся в 403.
//
// До этого кнопка «Запись» рисовалась каждому администратору, а грант
// can_view_session_recording есть далеко не у каждого: сервер отвечал 403, писал отказ в
// аудит (screen_recording_view_denied) — то есть отрабатывал ПРАВИЛЬНО, — а оператор
// получал код отказа за действие, которое ему сами же и предложили.
describe("recordingAffordance", () => {
  it("без записи не показывает ничего", () => {
    expect(recordingAffordance(false, true)).toBe("none")
    expect(recordingAffordance(false, false)).toBe("none")
    expect(recordingAffordance(false, null)).toBe("none")
  })

  it("с грантом даёт кнопку скачивания", () => {
    expect(recordingAffordance(true, true)).toBe("download")
  })

  it("🔴 без гранта кнопки нет — только пометка", () => {
    // Тот самый случай Q-84. На прежнем поведении здесь стояло бы "download".
    expect(recordingAffordance(true, false)).toBe("locked")
  })

  it("неизвестное право оставляет кнопку, а не отбирает её", () => {
    // null — это «спросить не удалось» (ручки нет, сеть, 500), а не «нельзя». Показать
    // здесь «доступа нет» значило бы соврать тому, у кого право есть, и отправить его
    // просить уже выданный грант. Отказ, если он придёт, виден тостом.
    expect(recordingAffordance(true, null)).toBe("download")
  })
})

// Признак применяемости ввода (Ф3): «неизвестно» — не «работает».
describe("parseControlHeader", () => {
  it("🔴 пустой/отсутствующий заголовок — НЕИЗВЕСТНО, а не работает", () => {
    // Ровно та ловушка, ради которой поле и заведено: агент старше поля молчит, и
    // молчание, прочитанное как успех, оставило бы ложный зелёный на всём парке.
    expect(parseControlHeader(undefined).state).toBe("unknown")
    expect(parseControlHeader("").state).toBe("unknown")
  })

  it("effective и unknown читаются как есть", () => {
    expect(parseControlHeader("effective")).toEqual({ state: "effective", reason: "" })
    expect(parseControlHeader("unknown")).toEqual({ state: "unknown", reason: "" })
  })

  it("ineffective несёт причину после двоеточия", () => {
    expect(parseControlHeader("ineffective:DESKTOP_LOST")).toEqual({
      state: "ineffective",
      reason: "DESKTOP_LOST",
    })
  })

  it("незнакомое значение не притворяется работающим", () => {
    expect(parseControlHeader("garbage").state).toBe("unknown")
  })
})

describe("controlIneffectiveKey", () => {
  it("потеря стола и защищённый стол ведут в одну подсказку", () => {
    expect(controlIneffectiveKey("DESKTOP_LOST")).toBe("screenSession.controlIneffectiveDesktop")
    expect(controlIneffectiveKey("SECURE_DESKTOP")).toBe("screenSession.controlIneffectiveDesktop")
  })

  it("отказ ОС — своя подсказка", () => {
    expect(controlIneffectiveKey("INPUT_REJECTED")).toBe("screenSession.controlIneffectiveRejected")
  })

  it("у незнакомой причины подписи НЕТ — её показывают кодом", () => {
    // Сервер новее панели — штатная ситуация. Схлопывать незнакомый код в общую строку
    // нельзя: контракт держит reason строкой ровно затем, чтобы код доехал до оператора.
    expect(controlIneffectiveKey("SOMETHING_NEW")).toBe("")
  })
})

describe("controlIneffectiveText", () => {
  const t = (k: string) => k

  it("известная причина показывается подписью, без кода", () => {
    expect(controlIneffectiveText("SECURE_DESKTOP", t)).toBe("screenSession.controlIneffectiveDesktop")
    expect(controlIneffectiveText("INPUT_REJECTED", t)).toBe("screenSession.controlIneffectiveRejected")
  })

  it("незнакомая причина доезжает КОДОМ, а не «неизвестной ошибкой»", () => {
    // Гейт в обе стороны: строка обязана остаться понятной (общая рамка) И сохранить код,
    // иначе разбор у оператора упирается в текст, из которого ничего не следует.
    const got = controlIneffectiveText("QUEUE_STALLED", t)
    expect(got).toContain("QUEUE_STALLED")
    expect(got).toContain("screenSession.controlUipiHint")
  })

  it("пустая причина не даёт пустых скобок", () => {
    expect(controlIneffectiveText("", t)).toBe("screenSession.controlUipiHint")
    expect(controlIneffectiveText("   ", t)).toBe("screenSession.controlUipiHint")
  })
})

// §9.11: приостановка выдачи кадров — ОТДЕЛЬНОЕ состояние сеанса, и читается оно не так,
// как применяемость ввода. Здесь молчание честно означает «кадры идут»: агент старше поля
// паузы не делает вовсе, он на защищённом столе заканчивал сеанс.
describe("parseFramesHeader", () => {
  it("🔴 отсутствие заголовка — кадры ИДУТ, а не «неизвестно»", () => {
    // Обратная ошибка тоже реальна: показать «изображение приостановлено» там, где сервер
    // просто старше поля, значит объяснить движущуюся картинку паузой.
    expect(parseFramesHeader(undefined)).toEqual({ paused: false, reason: "" })
    expect(parseFramesHeader("flowing")).toEqual({ paused: false, reason: "" })
  })

  it("пауза несёт причину после двоеточия", () => {
    expect(parseFramesHeader("paused:SECURE_DESKTOP")).toEqual({
      paused: true,
      reason: "SECURE_DESKTOP",
    })
    expect(parseFramesHeader("paused")).toEqual({ paused: true, reason: "" })
  })

  it("незнакомое значение не притворяется паузой", () => {
    expect(parseFramesHeader("garbage")).toEqual({ paused: false, reason: "" })
  })
})

describe("framesPausedText", () => {
  const t = (k: string) => k

  it("защищённый стол объясняется своей строкой", () => {
    expect(framesPausedText("SECURE_DESKTOP", t)).toBe("screenSession.framesPausedSecureDesktop")
  })

  it("🔴 незнакомая причина доезжает до оператора КОДОМ", () => {
    // Сервер новее панели — штатная ситуация, и код в этот момент единственное, чем
    // объясняется замерший экран. Общий фолбэк был бы тем же UNSPECIFIED, от которого
    // контракт отказался.
    expect(framesPausedText("FUTURE_REASON", t)).toBe("screenSession.framesPaused (FUTURE_REASON)")
  })

  it("пустая причина оставляет общую формулировку без скобок", () => {
    expect(framesPausedText("", t)).toBe("screenSession.framesPaused")
  })
})

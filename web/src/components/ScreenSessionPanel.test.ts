import { describe, it, expect } from "vitest"
import { recordingAffordance } from "./ScreenSessionPanel"

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

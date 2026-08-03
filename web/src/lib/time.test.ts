import { describe, it, expect, beforeEach, afterEach, vi } from "vitest"
import i18n from "@/i18n/config"
import { formatDistanceToNow, formatDate, formatDateTime } from "./time"

// Опорный момент фиксируем: относительное время без замороженных часов
// зависит от секунды запуска и мигает в CI.
const NOW = new Date("2026-08-02T12:00:00Z")

describe("относительное время", () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(NOW)
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  function at(offsetMs: number): string {
    return new Date(NOW.getTime() + offsetMs).toISOString()
  }

  it("прошедшее время читается как прошедшее", async () => {
    await i18n.changeLanguage("ru")
    expect(formatDistanceToNow(at(-5 * 60_000))).toContain("назад")
    expect(formatDistanceToNow(at(-3 * 3_600_000))).toContain("назад")
    expect(formatDistanceToNow(at(-5 * 86_400_000))).toContain("назад")
    // numeric:"auto" ближние дни называет словом — «вчера» вместо «1 день назад».
    // Для колонки «последний раз на связи» это читается лучше, чем счёт.
    expect(formatDistanceToNow(at(-1 * 86_400_000))).toEqual("вчера")
  })

  // 🔴 Регрессия на реальный дефект: прежняя реализация считала now - iso и на
  // дате в будущем получала отрицательные секунды, проходившие `s < 60`. Столбец
  // «Истекает» показывал «только что» для КАЖДОГО живого токена, то есть ровно
  // обратное правде. Тест обязан отличать будущее от «сейчас» — иначе он зеленел
  // бы и на сломанном коде.
  it("будущее время не выдаётся за только что прошедшее", async () => {
    await i18n.changeLanguage("ru")
    const inFiveMinutes = formatDistanceToNow(at(5 * 60_000))
    const inAYear = formatDistanceToNow(at(365 * 86_400_000))
    expect(inFiveMinutes).not.toContain("назад")
    expect(inFiveMinutes).toContain("через")
    expect(inAYear).toContain("через")
  })

  it("меньше минуты — это «сейчас», без числа", async () => {
    await i18n.changeLanguage("ru")
    expect(formatDistanceToNow(at(-30_000))).not.toMatch(/\d/)
  })

  it("склонение берётся из языка, а не из строки в коде", async () => {
    await i18n.changeLanguage("ru")
    const oneRu = formatDistanceToNow(at(-60_000))
    const manyRu = formatDistanceToNow(at(-5 * 60_000))
    // «1 минуту назад» и «5 минут назад» — разные формы одного слова.
    expect(oneRu).not.toEqual(manyRu)
    expect(oneRu.replace(/\d+\s*/, "")).not.toEqual(manyRu.replace(/\d+\s*/, ""))

    await i18n.changeLanguage("en")
    expect(formatDistanceToNow(at(-5 * 60_000))).toMatch(/ago/)
    expect(formatDistanceToNow(at(5 * 60_000))).toMatch(/in /)
  })
})

describe("абсолютные дата и время", () => {
  it("следуют выбранному языку", async () => {
    const iso = "2026-08-02T12:00:00Z"
    await i18n.changeLanguage("ru")
    const ru = formatDate(iso)
    await i18n.changeLanguage("en")
    const en = formatDate(iso)
    // ru-RU даёт 02.08.2026, en-US — 8/2/2026: формат обязан различаться.
    expect(ru).not.toEqual(en)
    expect(formatDateTime(iso)).not.toEqual("")
  })
})

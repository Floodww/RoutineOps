import { describe, it, expect, beforeAll } from "vitest"

import i18n from "@/i18n/config"
import { formatBytes, formatDuration } from "@/lib/format"

// Длительность сеанса требует §4 п.3 контракта прямым текстом, а размер записи — то, по
// чему оператор решает, качать ли улику. Обе величины считаются здесь, поэтому здесь же
// и проверяются: ошибка в делителе видна только глазами на живом стенде.

beforeAll(async () => {
  await i18n.changeLanguage("ru")
})

describe("formatBytes", () => {
  it("основание 1024 — то же, что у квоты и потолка записи", () => {
    // 512 МБ потолка на сеанс в контракте — это 512*1024*1024. Десятичное основание
    // напечатало бы «536.9 МБ» и разошлось бы с настройкой, на которую смотрит тот же
    // администратор.
    expect(formatBytes(512 * 1024 * 1024)).toBe("512.0 МБ")
    expect(formatBytes(20 * 1024 * 1024 * 1024)).toBe("20.0 ГБ")
  })

  it("байты и килобайты — целыми, дальше один знак", () => {
    expect(formatBytes(999)).toBe("999 Б")
    expect(formatBytes(2048)).toBe("2 КБ")
    expect(formatBytes(1536 * 1024)).toBe("1.5 МБ")
  })

  it("отсутствие записи не превращается в «0.0 Б»", () => {
    expect(formatBytes(0)).toBe("0")
    expect(formatBytes(Number.NaN)).toBe("0")
  })
})

describe("formatDuration", () => {
  it("считает от начала съёмки до конца сеанса", () => {
    const from = "2026-08-05T10:00:00Z"
    expect(formatDuration(from, "2026-08-05T10:00:42Z")).toBe("42 с")
    expect(formatDuration(from, "2026-08-05T10:12:30Z")).toBe("12 мин 30 с")
    expect(formatDuration(from, "2026-08-05T11:05:00Z")).toBe("1 ч 5 мин")
  })

  it("идущий сеанс считается до текущего момента, а не прочерком", () => {
    const started = new Date(Date.now() - 90_000).toISOString()
    expect(formatDuration(started)).toBe("1 мин 30 с")
  })

  it("часы сервера впереди клиентских — не отрицательная длительность", () => {
    const future = new Date(Date.now() + 5_000).toISOString()
    expect(formatDuration(future)).toBe("0 с")
  })
})

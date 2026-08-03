import { describe, it, expect } from "vitest"
import ru from "../locales/ru.json"
import en from "../locales/en.json"

// Словари обязаны совпадать по ключам.
//
// 🔴 Разъезжаются они молча: недостающий ключ i18next подменяет фолбэком на ru, и
// англоязычный оператор видит русскую строку среди английского интерфейса — без
// единой ошибки в консоли. Ловится только сверкой, поэтому она здесь.
function keys(obj: unknown, prefix = ""): string[] {
  if (typeof obj !== "object" || obj === null) return [prefix]
  return Object.entries(obj as Record<string, unknown>).flatMap(([k, v]) =>
    keys(v, prefix ? `${prefix}.${k}` : k),
  )
}

describe("словари локализации", () => {
  it("ru и en содержат один и тот же набор ключей", () => {
    const a = new Set(keys(ru))
    const b = new Set(keys(en))
    const onlyRu = [...a].filter((k) => !b.has(k))
    const onlyEn = [...b].filter((k) => !a.has(k))
    expect({ onlyRu, onlyEn }).toEqual({ onlyRu: [], onlyEn: [] })
  })

  it("ни одно значение не пустое", () => {
    for (const dict of [ru, en]) {
      const empty = keys(dict).filter((path) => {
        const value = path.split(".").reduce<unknown>((o, k) => (o as Record<string, unknown>)?.[k], dict)
        return typeof value === "string" && value.trim() === ""
      })
      expect(empty).toEqual([])
    }
  })
})

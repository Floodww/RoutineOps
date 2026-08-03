import { describe, expect, it } from "vitest"
import i18n from "@/i18n/config"
import ru from "../locales/ru.json"
import en from "../locales/en.json"
import {
  eventNumber,
  hiddenFromFeed,
  actionCategory,
  ACTION_LABELS,
  actionLabel,
  actionLabelCap,
} from "./auditActions"

describe("eventNumber", () => {
  it("формат — четыре группы по восемь цифр", () => {
    expect(eventNumber(1)).toBe("00000000-00000000-00000000-00000001")
    expect(eventNumber(1043)).toBe("00000000-00000000-00000000-00001043")
    expect(eventNumber(123456789)).toBe("00000000-00000000-00000001-23456789")
  })

  // Строки старше хеш-цепочки (миграция 042 нумерует с момента введения) не имеют
  // номера. Прочерк, а не «…00000000»: ноль неотличим от первого события.
  it("нет номера — прочерк, а не ноль", () => {
    expect(eventNumber(null)).toBe("—")
    expect(eventNumber(undefined)).toBe("—")
  })

  // Ёмкость формата (10^32) на порядки выше потолка bigint (~9.2·10^18), поэтому
  // переполнения и обнуления счётчика не бывает — обнуление ломало бы ссылку на
  // событие. Проверяем на потолке ТОЧНОГО целого в JS (2^53-1): выше него число из
  // JSON уже теряет младшие цифры, и это ограничение транспорта, а не формата.
  it("не переполняется на больших номерах", () => {
    expect(eventNumber(Number.MAX_SAFE_INTEGER)).toBe("00000000-00000000-90071992-54740991")
  })
})

describe("лента дашборда", () => {
  // Кросс-тенантный просмотр пишется на КАЖДЫЙ GET (поиск дебаунсится), поэтому в
  // ленте он вытеснял реальные события и красил их собственную навигацию в красный.
  it("надзорный просмотр не попадает в ленту и не красный", () => {
    expect(hiddenFromFeed("devices.list_across_tenants")).toBe(true)
    expect(actionCategory("devices.list_across_tenants")).not.toBe("security")
  })

  it("настоящая граница доступа остаётся security и в ленте", () => {
    expect(hiddenFromFeed("switch_tenant_denied")).toBe(false)
    expect(actionCategory("switch_tenant_denied")).toBe("security")
    expect(actionCategory("login_failed")).toBe("security")
  })
})

// 🔴 Карта подписей и словарь — две отдельные вещи, и расходятся они молча:
// на отсутствующий ключ i18next возвращает сам ключ, поэтому в журнале вместо
// действия встало бы «auditAction.create_device» — без ошибки в консоли и без
// падения сборки.
describe("подписи действий", () => {
  const dicts: Record<string, { auditAction?: Record<string, string> }> = { ru, en }

  it("каждому действию соответствует ключ в обоих словарях", () => {
    for (const [lang, dict] of Object.entries(dicts)) {
      const missing = Object.entries(ACTION_LABELS)
        .filter(([, key]) => !dict.auditAction?.[key.replace("auditAction.", "")])
        .map(([action]) => `${lang}: ${action}`)
      expect(missing).toEqual([])
    }
  })

  it("в словаре нет подписей для действий, выпавших из карты", () => {
    const known = new Set(Object.values(ACTION_LABELS).map((k) => k.replace("auditAction.", "")))
    const orphans = Object.keys(ru.auditAction ?? {}).filter((k) => !known.has(k))
    expect(orphans).toEqual([])
  })

  it("подпись следует выбранному языку", async () => {
    await i18n.changeLanguage("ru")
    const rus = actionLabel("create_device")
    await i18n.changeLanguage("en")
    const eng = actionLabel("create_device")
    expect(rus).not.toEqual(eng)
    expect(rus).not.toContain("auditAction.")
    expect(eng).not.toContain("auditAction.")
    await i18n.changeLanguage("ru")
  })

  // Сервер может прислать действие раньше, чем интерфейс о нём узнает: журнал
  // tamper-evident, задним числом строки не правятся. Сырое имя честнее, чем
  // «auditAction.чего_то_там».
  it("неизвестное действие отдаётся как есть", () => {
    expect(actionLabel("totally_new_action")).toBe("totally_new_action")
  })

  it("заглавная буква не ломает перевод", async () => {
    await i18n.changeLanguage("ru")
    const cap = actionLabelCap("login")
    expect(cap.charAt(0)).toBe(cap.charAt(0).toUpperCase())
    expect(cap.toLowerCase()).toBe(actionLabel("login").toLowerCase())
  })
})

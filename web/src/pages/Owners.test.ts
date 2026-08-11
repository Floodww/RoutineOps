import { describe, it, expect } from "vitest"
import { canDelete, personTitle } from "./Owners"
import i18n from "@/i18n/config"
import ru from "../locales/ru.json"
import en from "../locales/en.json"

describe("кнопка удаления владельца", () => {
  it("синканная из каталога карточка удаляться не предлагает", () => {
    // Сервер отвечает на неё 409 «remove it in AD», и сделать с этим отказом
    // пользователь ничего не может: кнопка, которая гарантированно приводит к отказу,
    // — это обещание, которого интерфейс не выполняет.
    expect(canDelete({ source: "ldap" })).toBe(false)
  })

  it("заведённая руками — предлагает", () => {
    expect(canDelete({ source: "manual" })).toBe(true)
  })

  it("неизвестный источник считается ручным, а не прячет кнопку молча", () => {
    // Пустое значение приходило от старых записей до появления поля. Спрятать кнопку
    // значило бы сделать такие карточки неудаляемыми навсегда и без объяснения; отказ
    // сервера, если он всё же случится, виден в тосте.
    expect(canDelete({ source: "" as "manual" })).toBe(true)
  })
})

describe("подпись карточки", () => {
  it("падает на логин, затем на почту — пустой строки в таблице не бывает", () => {
    expect(personTitle({ display_name: "Иванов", sam_account: "ivanov", email: "i@x" })).toBe("Иванов")
    expect(personTitle({ display_name: "", sam_account: "ivanov", email: "i@x" })).toBe("ivanov")
    expect(personTitle({ display_name: "", sam_account: "", email: "i@x" })).toBe("i@x")
    expect(personTitle({ display_name: "", sam_account: "", email: "" })).toBe("—")
  })
})

describe("предупреждение перед удалением", () => {
  // 🔴 Единственное, что отличает удаление карточки от снятия владельца с устройства, —
  // область действия. Если предупреждение об этом не говорит, оператор нажимает его в
  // логике «уберу владельца у этой машины», а теряет владельца на всём парке.
  it("говорит про ВСЕ устройства, а не про одно", () => {
    for (const [loc, warn] of [["ru", ru.owners.deleteWarn], ["en", en.owners.deleteWarn]] as const) {
      expect(warn, `${loc}: нет текста предупреждения`).toBeTruthy()
      expect(warn, `${loc}: предупреждение не говорит про весь парк`).toMatch(/ВСЕХ|ALL/)
      expect(warn, `${loc}: в предупреждении нет имени карточки`).toContain("{{name}}")
    }
  })

  it("переведено на оба языка и подставляет имя", () => {
    for (const loc of ["ru", "en"]) {
      i18n.changeLanguage(loc)
      const s = i18n.t("owners.deleteWarn", { name: "Иванов" })
      expect(s, `${loc}: ключ не переведён`).not.toBe("owners.deleteWarn")
      expect(s).toContain("Иванов")
    }
    i18n.changeLanguage("ru")
  })
})

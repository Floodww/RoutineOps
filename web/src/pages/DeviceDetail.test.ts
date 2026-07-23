import { describe, it, expect } from "vitest"
import { decommissionArmed } from "./DeviceDetail"

describe("decommissionArmed", () => {
  it("разрешает снос только при совпадении имени", () => {
    expect(decommissionArmed("ws-042", "ws-042")).toBe(true)
    expect(decommissionArmed("ws-042", "ws-0422")).toBe(false)
    expect(decommissionArmed("ws-042", "ws")).toBe(false)
    expect(decommissionArmed("ws-042", "")).toBe(false)
  })

  it("прощает регистр и пробелы по краям", () => {
    expect(decommissionArmed("mac-lab-7", "  Mac-LAB-7 ")).toBe(true)
  })

  it("пустое имя устройства не открывает кнопку пустым вводом", () => {
    // Защита от вырожденного случая: hostname пуст (битый инвентарь) —
    // иначе кнопка была бы взведена сразу, без единого нажатия.
    expect(decommissionArmed("", "")).toBe(false)
  })
})

import { describe, it, expect } from "vitest"
import { pageLabel } from "./Pager"

describe("pageLabel", () => {
  it("показывает диапазон текущей страницы", () => {
    expect(pageLabel(0, 50, 320)).toBe("1–50 из 320")
    expect(pageLabel(50, 50, 320)).toBe("51–100 из 320")
  })

  it("последняя страница не выходит за total", () => {
    // Хвост короче страницы: «301–350 из 320» выглядело бы как потерянные записи.
    expect(pageLabel(300, 50, 320)).toBe("301–320 из 320")
  })

  it("выдача короче страницы", () => {
    expect(pageLabel(0, 50, 7)).toBe("1–7 из 7")
  })

  it("пусто", () => {
    expect(pageLabel(0, 50, 0)).toBe("0 записей")
  })
})

import { describe, expect, it } from "vitest"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

import { FrameFormatError, parseFramePart, parseRecords } from "./screenframe"

// Эталон собирает Go (internal/screenframe/frame_test.go, TestGoldenMatchesCheckedInFixture)
// и разбирает этот тест. Две реализации одного формата расходятся МОЛЧА: картинка просто
// не появляется, и объяснить это будет нечем. Общий эталон — единственное, что делает
// расхождение видимым сразу и на той стороне, которая его внесла.
const goldenPath = fileURLToPath(new URL("../../../internal/screenframe/testdata/golden.bin", import.meta.url))

function golden(): Uint8Array {
  return new Uint8Array(readFileSync(goldenPath))
}

describe("screenframe", () => {
  it("разбирает эталон, собранный Go", () => {
    const part = parseFramePart(golden())
    expect(part.seq).toBe(42)
    expect(part.keyframe).toBe(true)
    expect(part.last).toBe(true)
    expect(part.width).toBe(192)
    expect(part.height).toBe(160)
    expect(part.tiles).toHaveLength(3)

    expect(part.tiles[0]).toMatchObject({ x: 0, y: 0, w: 128, h: 128 })
    expect(Array.from(part.tiles[0].jpeg)).toEqual([0xff, 0xd8, 0xff, 0x01])
    expect(part.tiles[1]).toMatchObject({ x: 128, y: 0, w: 64, h: 128 })
    expect(Array.from(part.tiles[1].jpeg)).toEqual([0xff, 0xd8, 0xff, 0x02, 0x03])
    expect(part.tiles[2]).toMatchObject({ x: 0, y: 128, w: 128, h: 32 })
    expect(Array.from(part.tiles[2].jpeg)).toEqual([0xff, 0xd8, 0xff])
  })

  it("отвергает чужую сигнатуру", () => {
    const b = golden()
    b[0] = 0xde
    expect(() => parseFramePart(b)).toThrow(FrameFormatError)
  })

  it("отвергает обрезанный кадр", () => {
    expect(() => parseFramePart(golden().subarray(0, 20))).toThrow(FrameFormatError)
  })

  // Заявленной длине тайла доверять нельзя: она приходит по сети, и аллокация по ней до
  // проверки — способ уронить вкладку чужим кадром.
  it("отвергает тайл с длиной больше остатка", () => {
    const b = golden()
    const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
    view.setUint32(16 + 8, 0xffff00)
    expect(() => parseFramePart(b)).toThrow(FrameFormatError)
  })

  it("разбирает поток записей с отметками времени", () => {
    const payload = golden()
    const buf = new Uint8Array(2 * (8 + payload.byteLength))
    const view = new DataView(buf.buffer)
    let off = 0
    for (const relMs of [0, 1500]) {
      view.setUint32(off, payload.byteLength)
      view.setUint32(off + 4, relMs)
      buf.set(payload, off + 8)
      off += 8 + payload.byteLength
    }

    const records = parseRecords(buf)
    expect(records).toHaveLength(2)
    expect(records[0].relMs).toBe(0)
    expect(records[1].relMs).toBe(1500)
    expect(records[1].part.tiles).toHaveLength(3)
  })

  it("отвергает обрезанный хвост потока", () => {
    const payload = golden()
    const buf = new Uint8Array(8 + payload.byteLength + 3)
    const view = new DataView(buf.buffer)
    view.setUint32(0, payload.byteLength)
    view.setUint32(4, 0)
    buf.set(payload, 8)
    expect(() => parseRecords(buf)).toThrow(FrameFormatError)
  })
})

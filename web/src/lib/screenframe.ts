// Разбор кадра интерактивного сеанса (docs/remote-desktop-contract.md, ADR-8).
//
// Формат ОБЩИЙ с сервером и агентом: internal/screenframe/frame.go. Кадр не
// перекодируется нигде по пути захватчик → служба → сервер → браузер, поэтому и разбор
// здесь обязан совпадать с тамошним побайтово. Расхождение двух реализаций одного формата
// проявляется молча — картинка просто не появляется, — поэтому обе стороны разбирают ОДИН
// эталон: internal/screenframe/testdata/golden.bin (см. screenframe.test.ts).
//
// Тело ответа /live и файл записи — поток записей:
//   [u32 len][u32 rel_ms][payload]
// payload — часть кадра:
//   [u32 magic 'RSF1'][u32 seq][u16 flags][u16 ntiles][u16 w][u16 h] затем тайлы:
//   [u16 x][u16 y][u16 w][u16 h][u32 len][JPEG]

export const FRAME_MAGIC = 0x52534631 // 'RSF1'
export const FRAME_HEADER_LEN = 16
export const TILE_HEADER_LEN = 12
export const RECORD_HEADER_LEN = 8

const FLAG_KEYFRAME = 1 << 0
const FLAG_LAST = 1 << 1

export interface Tile {
  x: number
  y: number
  w: number
  h: number
  jpeg: Uint8Array
}

export interface FramePart {
  seq: number
  keyframe: boolean
  last: boolean
  width: number
  height: number
  tiles: Tile[]
}

export interface FrameRecord {
  relMs: number
  part: FramePart
}

// Сообщения ошибок здесь ПО-АНГЛИЙСКИ, в отличие от комментариев: это диагностика для
// разработчика, а не текст интерфейса. Пользователю показывается переведённая строка
// (screenSession.brokenStream) — иначе гейт полноты перевода справедливо считает такой
// текст непереведённым экраном.
export class FrameFormatError extends Error {}

/** parseFramePart разбирает одну часть кадра. */
export function parseFramePart(buf: Uint8Array): FramePart {
  if (buf.byteLength < FRAME_HEADER_LEN) {
    throw new FrameFormatError(`frame shorter than header: ${buf.byteLength} B`)
  }
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  if (view.getUint32(0) !== FRAME_MAGIC) {
    throw new FrameFormatError("foreign frame magic")
  }
  const flags = view.getUint16(8)
  const ntiles = view.getUint16(10)
  const part: FramePart = {
    seq: view.getUint32(4),
    keyframe: (flags & FLAG_KEYFRAME) !== 0,
    last: (flags & FLAG_LAST) !== 0,
    width: view.getUint16(12),
    height: view.getUint16(14),
    tiles: [],
  }

  let off = FRAME_HEADER_LEN
  for (let i = 0; i < ntiles; i++) {
    if (buf.byteLength - off < TILE_HEADER_LEN) {
      throw new FrameFormatError(`tile ${i} truncated at header`)
    }
    const x = view.getUint16(off)
    const y = view.getUint16(off + 2)
    const w = view.getUint16(off + 4)
    const h = view.getUint16(off + 6)
    const len = view.getUint32(off + 8)
    off += TILE_HEADER_LEN
    // Заявленной длине не доверяем: она приходит по сети, и аллокация по ней до
    // проверки — классический способ получить OOM во вкладке.
    if (len > buf.byteLength - off) {
      throw new FrameFormatError(`tile ${i}: declared ${len} B, ${buf.byteLength - off} B left`)
    }
    part.tiles.push({ x, y, w, h, jpeg: buf.subarray(off, off + len) })
    off += len
  }
  if (off !== buf.byteLength) {
    throw new FrameFormatError(`${buf.byteLength - off} trailing bytes after tiles`)
  }
  return part
}

/** parseRecords разбирает поток записей (ответ /live или файл записи). */
export function parseRecords(buf: Uint8Array): FrameRecord[] {
  const out: FrameRecord[] = []
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  let off = 0
  while (off < buf.byteLength) {
    if (buf.byteLength - off < RECORD_HEADER_LEN) {
      throw new FrameFormatError("stream tail shorter than record header")
    }
    const len = view.getUint32(off)
    const relMs = view.getUint32(off + 4)
    off += RECORD_HEADER_LEN
    if (len > buf.byteLength - off) {
      throw new FrameFormatError(`record: declared ${len} B, ${buf.byteLength - off} B left`)
    }
    out.push({ relMs, part: parseFramePart(buf.subarray(off, off + len)) })
    off += len
  }
  return out
}

/**
 * drawPart рисует тайлы части кадра на холст.
 *
 * Тайлы декодируются параллельно через createImageBitmap: это единственный способ отдать
 * JPEG декодеру браузера, не создавая <img> на каждый тайл. Порядок отрисовки внутри
 * одного кадра значения не имеет — тайлы не перекрываются.
 */
export async function drawPart(ctx: CanvasRenderingContext2D, part: FramePart): Promise<void> {
  const bitmaps = await Promise.all(
    part.tiles.map((t) =>
      createImageBitmap(new Blob([t.jpeg.slice()], { type: "image/jpeg" })).then((bmp) => ({ t, bmp })),
    ),
  )
  for (const { t, bmp } of bitmaps) {
    ctx.drawImage(bmp, t.x, t.y)
    bmp.close()
  }
}

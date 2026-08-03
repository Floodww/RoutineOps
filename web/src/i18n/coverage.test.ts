import { describe, it, expect } from "vitest"
import { readFileSync, readdirSync } from "node:fs"
import { join, relative, sep } from "node:path"

// Гейт полноты перевода интерфейса (Q-05).
//
// 🔴 Ручная проверка «grep по кириллице» этот класс ошибок пропускает: в файле
// остаются комментарии на русском (и должны оставаться), поэтому глазами
// отсеиваешь их — и вместе с ними теряешь строки разметки. Так уже уехали
// хвосты в Tenants/APITokens/Users: экран считался переведённым, а половина
// диалогов осталась русской в обеих локалях.
//
// Список PENDING перечисляет ещё НЕ переведённые файлы. Гейт двусторонний:
//   • кириллица вне комментариев в файле НЕ из списка — ошибка (регресс);
//   • файл из списка, в котором кириллицы уже нет, — тоже ошибка.
// Второе не даёт списку гнить: закончив экран, его обязаны вычеркнуть, иначе
// туда молча вернётся русский текст и гейт промолчит.

// Смотрим ВЕСЬ src, а не только pages/components.
//
// 🔴 Отображаемый текст живёт не только в разметке. lib/time.ts печатал «мин.
// назад», lib/api.ts держит подписи статусов устройств, lib/auditActions.ts — все
// названия действий журнала. Экран при этом числится переведённым: русского в его
// собственном файле нет, он приходит из импорта.
// Пропускаем только то, где русский текст не является интерфейсом: словари (там
// он и должен быть) и сам конфиг i18n. Примитивы components/ui НЕ исключены —
// подпись, забытая в примитиве, видна на каждом экране сразу.
const SKIP_DIRS = new Set(["locales", "node_modules"])

// Ещё не переведённые файлы. Список ПУСТ: перевод интерфейса закончен, и любая
// новая русская строка в разметке роняет гейт. Добавлять сюда файл — осознанный
// шаг назад, а не способ обойти проверку.
const PENDING = new Set<string>([])

// stripComments вырезает // и /* */, СОХРАНЯЯ строковые литералы — они и есть
// цель поиска. Наивная версия без учёта кавычек съедала бы всё после "https://"
// до конца строки вместе с соседним русским литералом.
function stripComments(src: string): string {
  const out: string[] = []
  let i = 0
  // Одно из: null | "line" | "block" | "'" | '"' | "`"
  let state: string | null = null
  while (i < src.length) {
    const ch = src[i]
    const next = src[i + 1]
    if (state === "line") {
      if (ch === "\n") { state = null; out.push("\n") } else { out.push(" ") }
      i++
    } else if (state === "block") {
      if (ch === "*" && next === "/") { state = null; out.push("  "); i += 2 } else { out.push(ch === "\n" ? "\n" : " "); i++ }
    } else if (state === "'" || state === '"' || state === "`") {
      // Экранированный символ проглатывается целиком, иначе \" закрыл бы строку.
      if (ch === "\\") { out.push(ch, next ?? ""); i += 2; continue }
      if (ch === state) state = null
      out.push(ch); i++
    } else if (ch === "/" && next === "/") {
      state = "line"; out.push("  "); i += 2
    } else if (ch === "/" && next === "*") {
      state = "block"; out.push("  "); i += 2
    } else {
      if (ch === "'" || ch === '"' || ch === "`") state = ch
      out.push(ch); i++
    }
  }
  return out.join("")
}

const CYRILLIC = /[А-Яа-яЁё]/

function uiFiles(): string[] {
  const root = join(__dirname, "..")
  const found: string[] = []
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(join(dir, entry.name))
        continue
      }
      if (!/\.tsx?$/.test(entry.name)) continue
      if (/\.test\.tsx?$/.test(entry.name)) continue
      const rel = relative(root, join(dir, entry.name)).split(sep).join("/")
      // Сам конфиг i18n держит русское название языка в переключателе — это
      // подпись языка на своём же языке, переводить её нечем и незачем.
      if (rel === "i18n/config.ts") continue
      found.push(rel)
    }
  }
  walk(root)
  return found.sort()
}

function russianLines(rel: string): string[] {
  const src = readFileSync(join(__dirname, "..", rel), "utf-8")
  return stripComments(src)
    .split("\n")
    .map((line, idx) => [idx + 1, line.trim()] as const)
    .filter(([, line]) => CYRILLIC.test(line))
    .map(([n, line]) => `${rel}:${n}  ${line.slice(0, 120)}`)
}

describe("полнота перевода интерфейса", () => {
  const files = uiFiles()

  it("в переведённых экранах не осталось русского текста", () => {
    const leftovers = files
      .filter((f) => !PENDING.has(f))
      .flatMap(russianLines)
    expect(leftovers).toEqual([])
  })

  it("список PENDING не содержит уже переведённых файлов", () => {
    const done = [...PENDING].filter((f) => files.includes(f) && russianLines(f).length === 0)
    expect(done).toEqual([])
  })

  it("список PENDING не содержит исчезнувших файлов", () => {
    const ghosts = [...PENDING].filter((f) => !files.includes(f))
    expect(ghosts).toEqual([])
  })
})

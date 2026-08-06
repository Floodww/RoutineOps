import i18n from "@/i18n/config"

// Единицы — КЛЮЧИ словаря, а не готовые строки: «МБ» и «MB» пишутся по-разному, и
// зашитая кириллица оставалась бы русской на английской локали.
const UNITS = ["format.bytes", "format.kb", "format.mb", "format.gb", "format.tb"]

// formatBytes — размер файла человеку.
//
// Основание 1024, как и у остальной инфраструктуры (квоты, диск): 512 МБ потолка записи
// в контракте — это 512 * 1024 * 1024, и показывать те же байты как «536.9 МБ» значило бы
// расходиться с настройкой, на которую смотрит тот же администратор.
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return "0"
  let value = n
  let unit = 0
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024
    unit++
  }
  // Целые для байт и килобайт, один знак дальше: «1.5 ГБ» полезно, «1536.0 Б» — нет.
  const digits = unit <= 1 ? 0 : 1
  return `${value.toFixed(digits)} ${i18n.t(UNITS[unit])}`
}

// formatDuration — длительность между двумя метками.
//
// §4 п.3 контракта требует длительность в журнале сеансов прямым текстом: «сколько
// смотрели» — это половина ответа на вопрос «что происходило», и без неё строка журнала
// говорит только о факте.
//
// Открытый (ещё идущий) сеанс считается до текущего момента, а не показывается прочерком:
// оператору важнее «идёт 12 минут», чем «конца пока нет».
export function formatDuration(fromISO: string, toISO?: string): string {
  const from = new Date(fromISO).getTime()
  const to = toISO ? new Date(toISO).getTime() : Date.now()
  const sec = Math.max(0, Math.round((to - from) / 1000))
  if (sec < 60) return i18n.t("format.durationSec", { n: sec })
  const min = Math.floor(sec / 60)
  if (min < 60) return i18n.t("format.durationMin", { n: min, s: sec % 60 })
  return i18n.t("format.durationHour", { n: Math.floor(min / 60), m: min % 60 })
}

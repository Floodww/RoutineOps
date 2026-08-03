import i18n from "@/i18n/config"

// Относительное время силами платформы.
//
// Intl.RelativeTimeFormat сам склоняет число («1 минуту назад», «5 минут назад»,
// "5 minutes ago"), и это не косметика: в русском три формы множественного числа
// против двух английских, поэтому словарные ключи под них не совпали бы наборами —
// а совпадения требует гейт словарей. Обрубок «5 мин. назад» этой разницы избегал,
// но ценой того, что на английской локали оставался русским.
//
// 🔴 Знак обязателен. Прежняя версия считала diff = now - iso и на дате В БУДУЩЕМ
// получала отрицательные секунды, которые проходили проверку `s < 60` и печатались
// как «только что». Столбец «Истекает» у любого живого токена показывал «только
// что» — ровно противоположное правде.
export function formatDistanceToNow(iso: string): string {
  const ms = new Date(iso).getTime() - Date.now() // > 0 — впереди, < 0 — позади
  const rtf = new Intl.RelativeTimeFormat(i18n.language, { numeric: "auto" })
  const abs = Math.abs(ms)
  const sign = ms < 0 ? -1 : 1
  const MINUTE = 60_000
  const HOUR = 3_600_000
  const DAY = 86_400_000
  if (abs < MINUTE) return rtf.format(0, "second")
  if (abs < HOUR) return rtf.format(sign * Math.floor(abs / MINUTE), "minute")
  if (abs < DAY) return rtf.format(sign * Math.floor(abs / HOUR), "hour")
  return rtf.format(sign * Math.floor(abs / DAY), "day")
}

// Абсолютные дата и время — тоже по выбранному языку, а не по зашитому "ru-RU":
// иначе английский интерфейс печатает «02.08.2026, 14:30» вперемешку со своими.
export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(i18n.language)
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(i18n.language)
}

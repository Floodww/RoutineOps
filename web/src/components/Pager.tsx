import { ChevronLeft, ChevronRight } from "lucide-react"
import { Button } from "@/components/ui/button"

interface Props {
  offset: number
  limit: number
  total: number
  onChange: (offset: number) => void
}

// pageLabel — «51–100 из 320». Диапазон, а не номер страницы: оператор ищет запись,
// а не листает по номерам, и ему важно, какую часть выдачи он сейчас видит.
export function pageLabel(offset: number, limit: number, total: number): string {
  if (total === 0) return "0 записей"
  const from = offset + 1
  const to = Math.min(offset + limit, total)
  return `${from}–${to} из ${total}`
}

// Пагинатор постраничных списков. Прячется целиком, когда вся выдача уместилась на
// одной странице: кнопки «назад/вперёд» при десяти записях — чистый шум.
export default function Pager({ offset, limit, total, onChange }: Props) {
  if (total <= limit && offset === 0) return null
  const last = offset + limit >= total
  return (
    <div className="flex items-center justify-between gap-3 px-5 py-3 border-t border-border">
      <p className="text-xs text-muted-foreground">{pageLabel(offset, limit, total)}</p>
      <div className="flex gap-2">
        <Button
          variant="outline"
          size="sm"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
        >
          <ChevronLeft className="h-3.5 w-3.5" strokeWidth={2} />
          Назад
        </Button>
        <Button variant="outline" size="sm" disabled={last} onClick={() => onChange(offset + limit)}>
          Вперёд
          <ChevronRight className="h-3.5 w-3.5" strokeWidth={2} />
        </Button>
      </div>
    </div>
  )
}

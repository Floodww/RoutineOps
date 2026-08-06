import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react"
import { createPortal } from "react-dom"
import { useTranslation } from "react-i18next"
import { ChevronDown, Check } from "lucide-react"
import { cn } from "@/lib/utils"

export interface SelectOption {
  value: string
  label: string
  disabled?: boolean
}

interface SelectProps {
  value: string
  onChange: (value: string) => void
  options: SelectOption[]
  placeholder?: string
  className?: string
}

// Выпадающее меню рисуется ПОРТАЛОМ, а не внутри собственной карточки.
//
// Причина конкретная, а не стилистическая. Карточки панели — `.glass`, а `backdrop-filter`
// создаёт stacking context: z-index ребёнка внутри такой карточки сравнивается не с
// соседними элементами, а с контекстом целиком, и поднять его выше СОСЕДНЕЙ карточки
// нельзя никаким числом. Список владельцев в карточке устройства честно уезжал под
// следующую карточку — «z-50» ему не помогал и помочь не мог. Второй источник той же
// поломки — любой предок с `overflow: hidden`: он список ещё и обрезает.
//
// 🔴 Но портал В BODY ломает КАЖДЫЙ список внутри модалки, и молча. Radix Dialog в
// модальном режиме ставит `pointer-events: none` на `body`: меню, вынесенное туда,
// рисуется правильно, выглядит нормально — и не реагирует на клики вовсе. Вторым слоем
// та же беда: Radix считает pointerdown вне DialogContent «кликом снаружи» и закрывает
// диалог, то есть выбор варианта закрывал бы форму целиком.
//
// Поэтому цель портала — БЛИЖАЙШАЯ модалка, если она есть, и body во всех остальных
// случаях. Внутри модалки меню и кликабельно, и «своё» для её обработчика закрытия.
//
// Цена — координаты считаются руками (и пересчитываются на скролле и ресайзе), причём в
// модалке ещё и с поправкой: `DialogContent` центрируется через `translate(-50%,-50%)`, а
// трансформированный предок становится содержащим блоком для `position: fixed`. Отсчёт
// там идёт не от окна, а от ПОЛЯ ПАДДИНГА этого предка — то есть от его рамки, а не от
// границы. Без поправки меню уезжает ровно на половину окна.

// GAP — зазор между кнопкой и меню.
const GAP = 4

// MIN_SPACE — сколько места по вертикали считаем достаточным, чтобы раскрыться вниз.
// Меньше — меню переворачивается вверх, иначе у нижнего края окна оно вырождается в
// полоску в две строки.
const MIN_SPACE = 160

interface MenuPos {
  left: number
  width: number
  top?: number
  bottom?: number
  maxHeight: number
}

// portalTarget — куда вынести меню.
//
// Ближайшая модалка, если список внутри неё; иначе body. `alertdialog` учитывается
// наравне с `dialog`: у подтверждений ровно та же модальная механика.
function portalTarget(el: HTMLElement | null): HTMLElement {
  const modal = el?.closest('[role="dialog"], [role="alertdialog"]')
  return (modal as HTMLElement | null) ?? document.body
}

// originOf — начало системы координат портала в координатах окна.
//
// Для body это ноль. Для модалки — её поле паддинга: `position: fixed` внутри
// трансформированного предка отсчитывается именно от него, поэтому вычитается и
// положение рамки, и её толщина. У `.glass` рамка в 1px, и без этой поправки меню
// смещалось бы на пиксель — мелочь, но мелочь, которую потом ищут глазами.
function originOf(target: HTMLElement): { x: number; y: number } {
  if (target === document.body) return { x: 0, y: 0 }
  const r = target.getBoundingClientRect()
  const cs = window.getComputedStyle(target)
  return {
    x: r.left + parseFloat(cs.borderLeftWidth || "0"),
    y: r.top + parseFloat(cs.borderTopWidth || "0"),
  }
}

export function Select({ value, onChange, options, placeholder, className }: SelectProps) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [pos, setPos] = useState<MenuPos | null>(null)
  // host — узел портала. В состоянии, а не в ref: смена узла обязана перерисовать
  // портал, иначе меню осталось бы в прежнем контейнере.
  const [host, setHost] = useState<HTMLElement | null>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)

  const place = useCallback(() => {
    const el = containerRef.current
    if (!el) return
    const target = portalTarget(el)
    setHost(target)

    const r = el.getBoundingClientRect()
    // Ширина берётся из ЛАЙАУТА, а не из прямоугольника.
    //
    // getBoundingClientRect учитывает transform, а модалка на открытии проигрывает
    // анимацию масштаба. Список, раскрытый в эти 200 мс, запоминал бы ширину сжатого
    // состояния — и оставался бы у́же своей кнопки на все 22 пикселя после того, как
    // анимация закончится. offsetWidth про transform не знает и потому не врёт.
    const width = el.offsetWidth || r.width
    const below = window.innerHeight - r.bottom - GAP
    const above = r.top - GAP
    // Вверх разворачиваемся только если снизу тесно И сверху просторнее: «просто снизу
    // мало» без второго условия перекидывало бы меню вверх там, где и вверху не лучше.
    const up = below < MIN_SPACE && above > below

    // Место считается в координатах ОКНА, а затем переводится в координаты портала.
    // Порядок именно такой: вверх/вниз решается по окну (это про то, влезет ли меню на
    // экран), а рисуется относительно содержащего блока.
    const o = originOf(target)
    setPos({
      left: r.left - o.x,
      width,
      top: up ? undefined : r.bottom + GAP - o.y,
      bottom: up ? window.innerHeight - r.top + GAP - (window.innerHeight - o.y) : undefined,
      maxHeight: Math.max(120, up ? above : below),
    })
  }, [])

  // Позиция считается ДО отрисовки кадра: useEffect дал бы один кадр меню в левом верхнем
  // углу, и на медленной машине это видно глазом.
  useLayoutEffect(() => {
    if (open) place()
  }, [open, place])

  // Пересчёт после того, как предок домотал свою анимацию.
  //
  // Модалка открывается с анимацией масштаба, и меню, раскрытое в эти миллисекунды,
  // считает координаты по промежуточному состоянию. Один кадр спустя и по концу анимации
  // всё встаёт на место; ловится и то, и другое, потому что animationend не придёт, если
  // анимации не было вовсе.
  useEffect(() => {
    if (!open) return
    const again = () => place()
    const frame = window.requestAnimationFrame(again)
    const host = containerRef.current?.closest('[role="dialog"], [role="alertdialog"]')
    host?.addEventListener("animationend", again)
    return () => {
      window.cancelAnimationFrame(frame)
      host?.removeEventListener("animationend", again)
    }
  }, [open, place])

  useEffect(() => {
    if (!open) return

    function onPointerDown(e: PointerEvent) {
      const target = e.target as Node
      // Меню живёт в другом поддереве DOM — одной проверки контейнера мало: клик по
      // варианту закрывал бы список ДО того, как сработает onClick, и выбрать было бы
      // нельзя ничего.
      if (containerRef.current?.contains(target) || menuRef.current?.contains(target)) return
      setOpen(false)
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false)
    }
    // capture: скролл любого предка, а не только окна — карточка может лежать в
    // прокручиваемой области, и меню обязано ехать вместе с кнопкой.
    const onScroll = () => place()
    document.addEventListener("pointerdown", onPointerDown)
    document.addEventListener("keydown", onKey)
    window.addEventListener("scroll", onScroll, true)
    window.addEventListener("resize", onScroll)
    return () => {
      document.removeEventListener("pointerdown", onPointerDown)
      document.removeEventListener("keydown", onKey)
      window.removeEventListener("scroll", onScroll, true)
      window.removeEventListener("resize", onScroll)
    }
  }, [open, place])

  const selected = options.find((o) => o.value === value)

  return (
    <div ref={containerRef} className={cn("relative", className)}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="listbox"
        aria-expanded={open}
        className="flex h-9 w-full items-center justify-between rounded-md border border-input bg-transparent px-3 py-1 text-sm transition-colors hover:bg-accent/30 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
      >
        <span className={cn("truncate", selected ? "text-foreground" : "text-muted-foreground")}>
          {selected ? selected.label : (placeholder ?? t("common.select"))}
        </span>
        <ChevronDown className={cn("h-4 w-4 shrink-0 text-muted-foreground transition-transform duration-150", open && "rotate-180")} />
      </button>

      {open && pos && host && createPortal(
        // Поверхность НЕПРОЗРАЧНАЯ (`.popover-surface`, не `.glass`): вынесенное порталом
        // меню теряет подложку, на которой держалось стекло, и внутри модалки — тоже
        // `.glass` — вложенный backdrop-filter второго размытия не даёт. Со стеклом список
        // читался насквозь вместе с текстом под ним; разбор — в index.css.
        <div
          ref={menuRef}
          role="listbox"
          className="popover-surface fixed z-[100] overflow-y-auto py-1"
          style={{
            left: pos.left,
            width: pos.width,
            top: pos.top,
            bottom: pos.bottom,
            maxHeight: pos.maxHeight,
            // Явные pointer-events: модальный слой Radix глушит их на body целиком, и
            // меню, попавшее туда при закрытой модалке и оставшееся при открытой, было бы
            // видно и нельзя было бы нажать.
            pointerEvents: "auto",
          }}
        >
          {options.map((opt) => (
            <button
              key={opt.value}
              type="button"
              role="option"
              aria-selected={opt.value === value}
              disabled={opt.disabled}
              onClick={() => {
                if (!opt.disabled) { onChange(opt.value); setOpen(false) }
              }}
              className={cn(
                "flex w-full items-center gap-2 px-3 py-2 text-sm transition-colors text-left",
                opt.disabled ? "text-muted-foreground cursor-not-allowed opacity-50" : "hover:bg-accent hover:text-accent-foreground",
                opt.value === value && "text-foreground font-medium"
              )}
            >
              <span className="flex-1 truncate">{opt.label}</span>
              {opt.value === value && <Check className="h-3.5 w-3.5 shrink-0 text-emerald-600 dark:text-emerald-500" />}
            </button>
          ))}
        </div>,
        host,
      )}
    </div>
  )
}

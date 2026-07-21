import { useEffect, useRef, useState } from "react"
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

export function Select({ value, onChange, options, placeholder = "Выберите...", className }: SelectProps) {
  const [open, setOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    function onPointerDown(e: PointerEvent) {
      if (!containerRef.current?.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener("pointerdown", onPointerDown)
    return () => document.removeEventListener("pointerdown", onPointerDown)
  }, [open])

  const selected = options.find((o) => o.value === value)

  return (
    <div ref={containerRef} className={cn("relative", className)}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex h-9 w-full items-center justify-between rounded-md border border-input bg-transparent px-3 py-1 text-sm transition-colors hover:bg-accent/30 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
      >
        <span className={selected ? "text-foreground" : "text-muted-foreground"}>
          {selected ? selected.label : placeholder}
        </span>
        <ChevronDown className={cn("h-4 w-4 text-muted-foreground transition-transform duration-150", open && "rotate-180")} />
      </button>

      {open && (
        // Выпадающий список — контрол: стекло, но радиус меньше карточного.
        <div className="glass rounded-lg absolute left-0 right-0 top-full mt-1 z-50 overflow-hidden py-1">
          {options.map((opt) => (
            <button
              key={opt.value}
              type="button"
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
              <span className="flex-1">{opt.label}</span>
              {opt.value === value && <Check className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-500" />}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

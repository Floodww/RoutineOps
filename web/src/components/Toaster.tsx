import * as ToastPrimitive from "@radix-ui/react-toast"
import { useEffect, useState } from "react"
import { X } from "lucide-react"
import { cn } from "@/lib/utils"
import { registerToast, ToastInput, ToastVariant } from "@/lib/toast"

interface Item extends ToastInput {
  id: number
}

let counter = 0

// Поверхность тоста — общее стекло (.glass несёт блюр, бордер, радиус 16px и тень).
// Смысловые варианты перекрывают только фон и цвет текста: утилита bg-* идёт слоем
// выше .glass, поэтому форма стекла остаётся, а красный/зелёный читаются как раньше.
const variantClass: Record<ToastVariant, string> = {
  default: "glass text-foreground",
  destructive: "glass border-destructive/60 bg-destructive text-destructive-foreground",
  success: "glass border-emerald-500/60 bg-emerald-700 text-white",
}

export default function Toaster() {
  const [items, setItems] = useState<Item[]>([])

  useEffect(() => {
    registerToast((t) => setItems((prev) => [...prev, { ...t, id: ++counter }]))
    return () => registerToast(null)
  }, [])

  const remove = (id: number) => setItems((prev) => prev.filter((i) => i.id !== id))

  return (
    <ToastPrimitive.Provider swipeDirection="right" duration={5000}>
      {items.map((t) => (
        <ToastPrimitive.Root
          key={t.id}
          onOpenChange={(open) => { if (!open) remove(t.id) }}
          className={cn(
            "relative flex items-start gap-3 p-4 pr-8",
            variantClass[t.variant ?? "default"],
          )}
        >
          <div className="grid gap-0.5">
            {t.title && (
              <ToastPrimitive.Title className="text-sm font-medium">{t.title}</ToastPrimitive.Title>
            )}
            {t.description && (
              <ToastPrimitive.Description className="text-sm opacity-90 break-words">
                {t.description}
              </ToastPrimitive.Description>
            )}
          </div>
          <ToastPrimitive.Close className="absolute right-2 top-2 rounded p-0.5 opacity-70 hover:opacity-100">
            <X className="h-4 w-4" />
          </ToastPrimitive.Close>
        </ToastPrimitive.Root>
      ))}
      <ToastPrimitive.Viewport className="fixed bottom-0 right-0 z-[100] flex max-h-screen w-full flex-col gap-2 p-4 sm:max-w-sm" />
    </ToastPrimitive.Provider>
  )
}

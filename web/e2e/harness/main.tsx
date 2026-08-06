import { useState } from "react"
import { createRoot } from "react-dom/client"

import "@/index.css"
import "@/i18n/config"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Select } from "@/components/ui/select"

// Стенд выпадающего списка — НЕ часть продукта.
//
// Существует ровно затем, что этот компонент ломается в браузере и только в браузере:
// stacking context от `backdrop-filter`, `pointer-events: none` модального слоя и
// содержащий блок от `transform` — всё это в jsdom не существует вовсе, поэтому vitest
// зелёный ни о чём здесь не говорит. Стенд не попадает в продакшн-сборку: Vite собирает
// только index.html, а этот файл живёт отдельной страницей и нужен Playwright'у.

const OPTIONS = [
  { value: "linux", label: "Linux" },
  { value: "darwin", label: "macOS" },
  { value: "windows", label: "Windows" },
]

function Harness() {
  const [inCard, setInCard] = useState("linux")
  const [inDialog, setInDialog] = useState("linux")

  return (
    <main className="min-h-screen bg-background p-8 space-y-4">
      {/* Случай 1: две стеклянные карточки подряд. Меню первой обязано лежать ПОВЕРХ
          второй — именно здесь список владельцев уезжал под соседа. */}
      <div className="glass p-5">
        <h2 className="mb-3 text-sm font-semibold">Список в карточке</h2>
        <Select value={inCard} onChange={setInCard} options={OPTIONS} className="max-w-xs" />
        <p data-testid="card-value" className="mt-2 text-xs">{inCard}</p>
      </div>
      <div className="glass p-5" data-testid="next-card">
        <p className="text-sm">Соседняя карточка — она и перекрывала меню.</p>
      </div>

      {/* Случай 2: список внутри модалки. Портал в body делал его некликабельным, а
          клик по варианту закрывал саму модалку. */}
      <Dialog>
        <DialogTrigger asChild>
          <Button data-testid="open-dialog">Открыть модалку</Button>
        </DialogTrigger>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Список в модалке</DialogTitle>
          </DialogHeader>
          <Select value={inDialog} onChange={setInDialog} options={OPTIONS} />
          <p data-testid="dialog-value" className="text-xs">{inDialog}</p>
        </DialogContent>
      </Dialog>
    </main>
  )
}

createRoot(document.getElementById("root")!).render(<Harness />)

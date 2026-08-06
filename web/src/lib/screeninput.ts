// Снятие ввода оператора с холста и отправка его агенту (Ф3, docs/remote-desktop-contract.md).
//
// Три правила, из которых состоит весь файл.
//
//  1. **Пачками, а не событием на запрос.** Мышь порождает до сотни событий в секунду;
//     запрос на каждое означал бы сотню HTTP-запросов, и первым не выдержал бы не сервер,
//     а очередь соединений браузера. Пачка раз в 50 мс добавляет к задержке 25 мс в
//     среднем — на фоне врождённых 80–250 мс ретрансляции кадра это незаметно.
//
//  2. **Движения СХЛОПЫВАЮТСЯ, нажатия — никогда.** В пачке имеет смысл только последняя
//     позиция курсора: промежуточные точки никому не нужны, а вот потерянное отпускание
//     клавиши — это залипший Ctrl на машине сотрудника, и снять его сможет только он сам.
//     Поэтому схлопывается ровно один вид событий, и это записано здесь, а не выведено из
//     кода.
//
//  3. **Отпустить всё при любой потере фокуса.** Оператор нажал Ctrl и переключился на
//     другую вкладку — браузер не пришлёт keyup, потому что клавишу отпустили уже не над
//     нашим окном. Без release_all сотрудник остаётся с зажатым модификатором.

// Событие ввода в том виде, в каком его принимает сервер.
export interface InputEvent {
  kind: "mouse_move" | "mouse_down" | "mouse_up" | "wheel" | "key_down" | "key_up" | "text"
  x?: number
  y?: number
  button?: number
  wheel_x?: number
  wheel_y?: number
  code?: string
  text?: string
}

export interface InputBatch {
  frame_width: number
  frame_height: number
  release_all?: boolean
  events?: InputEvent[]
}

// FLUSH_MS — как часто пачка уходит на сервер.
export const FLUSH_MS = 50

// WHEEL_LINE — сколько пикселей прокрутки считаем одним «кликом» колеса.
//
// У браузеров три режима deltaMode (пиксели, строки, страницы) и разные величины на
// разных ОС; агент же принимает «клики», потому что и Windows, и X11 считают именно их.
// 100 — типичная величина одного щелчка в пиксельном режиме.
const WHEEL_LINE = 100

// Клавиши, которые НЕ перехватываются у браузера.
//
// F5 и F12 оставлены оператору намеренно: перезагрузка вкладки и devtools — это его
// собственные инструменты, и отнимать их у него ради полноты перехвата значит сделать
// отладку сеанса невозможной. Остальное уезжает на удалённую машину.
const PASSTHROUGH = new Set(["F5", "F12"])

// Собиратель ввода. Не React-хук намеренно: состояние здесь мутабельное и
// высокочастотное, и перерисовывать компонент на каждое движение мыши было бы худшим
// способом потратить кадры, которые нужны на отрисовку экрана.
export class InputCollector {
  private events: InputEvent[] = []
  private pendingMove: InputEvent | null = null
  private releaseAll = false
  // pressed — что оператор держит нажатым ПО НАШЕМУ УЧЁТУ. Нужен, чтобы отпустить всё
  // при потере фокуса: агент ведёт свой такой же учёт, но команду отпустить должен дать
  // тот, кто заметил потерю фокуса, — то есть браузер.
  private pressed = new Set<string>()

  // add кладёт событие в пачку.
  add(ev: InputEvent) {
    if (ev.kind === "mouse_move") {
      // Схлопывание: в пачке нужна только последняя позиция.
      this.pendingMove = ev
      return
    }
    // Порядок обязателен: движение, снятое ДО нажатия, должно уехать перед ним, иначе
    // клик придёт по старым координатам.
    if (this.pendingMove) {
      this.events.push(this.pendingMove)
      this.pendingMove = null
    }
    if (ev.kind === "key_down" && ev.code) this.pressed.add(ev.code)
    if (ev.kind === "key_up" && ev.code) this.pressed.delete(ev.code)
    this.events.push(ev)
  }

  // release просит отпустить всё зажатое — и на нашей стороне, и на стороне агента.
  release() {
    this.pressed.clear()
    this.releaseAll = true
  }

  // take забирает накопленное. Возвращает null, если отправлять нечего: пустая пачка
  // раз в 50 мс — это запрос в секунду на каждого простаивающего зрителя.
  take(frameWidth: number, frameHeight: number): InputBatch | null {
    if (this.pendingMove) {
      this.events.push(this.pendingMove)
      this.pendingMove = null
    }
    if (!this.events.length && !this.releaseAll) return null

    const batch: InputBatch = {
      frame_width: frameWidth,
      frame_height: frameHeight,
      events: this.events,
    }
    if (this.releaseAll) batch.release_all = true
    this.events = []
    this.releaseAll = false
    return batch
  }

  get pressedCount() {
    return this.pressed.size
  }
}

// toFrame переводит точку внутри элемента холста в пиксели КАДРА.
//
// Холст растянут по ширине карточки, а кадр приезжает в собственном разрешении (после
// даунскейла профиля). Считать по CSS-размеру значило бы кликать мимо тем сильнее, чем
// уже окно оператора; поэтому точка нормируется прямоугольником элемента и умножается на
// внутренний размер холста.
export function toFrame(canvas: HTMLCanvasElement, clientX: number, clientY: number) {
  const rect = canvas.getBoundingClientRect()
  if (rect.width <= 0 || rect.height <= 0) return null
  const x = Math.round(((clientX - rect.left) / rect.width) * canvas.width)
  const y = Math.round(((clientY - rect.top) / rect.height) * canvas.height)
  if (x < 0 || y < 0 || x >= canvas.width || y >= canvas.height) return null
  return { x, y }
}

// wheelClicks переводит прокрутку браузера в «клики» колеса.
//
// Знак инвертируется: в DOM положительная deltaY — это прокрутка ВНИЗ, а колесо и на
// Windows, и в X11 считает вниз отрицательным направлением.
export function wheelClicks(e: WheelEvent): { wheel_x: number; wheel_y: number } {
  const scale = e.deltaMode === 0 ? WHEEL_LINE : 1
  const x = -Math.trunc(e.deltaX / scale) || (e.deltaX > 0 ? -1 : e.deltaX < 0 ? 1 : 0)
  const y = -Math.trunc(e.deltaY / scale) || (e.deltaY > 0 ? -1 : e.deltaY < 0 ? 1 : 0)
  return { wheel_x: x, wheel_y: y }
}

// keyEvents превращает нажатие в события для агента.
//
// Развилка здесь ровно одна и она важная: **символ или клавиша**.
//
//   - С зажатым Ctrl/Alt/Meta это КОМБИНАЦИЯ: едет физическая клавиша (`code`), потому
//     что Ctrl+C должен остаться Ctrl+C. Отправить в этом случае символ значило бы
//     напечатать «c» при зажатом Ctrl — то есть ничего.
//   - Без модификаторов печатный символ едет ТЕКСТОМ. Раскладка на машине сотрудника
//     своя, и «нажать клавишу, где у меня Ы» дала бы у него другую букву; текст же
//     печатается как есть, минуя раскладку.
//
// Возвращает пустой список для клавиш, которые оставлены браузеру (см. PASSTHROUGH).
export function keyEvents(e: KeyboardEvent, down: boolean): InputEvent[] {
  if (PASSTHROUGH.has(e.key)) return []

  const combo = e.ctrlKey || e.altKey || e.metaKey
  const printable = e.key.length === 1 || e.key === "Unidentified"

  if (printable && !combo) {
    // Печатный символ отправляется ОДИН раз — на нажатии. Отпускание для текста смысла
    // не имеет: агент печатает строку целиком.
    if (!down) return []
    return e.key.length === 1 ? [{ kind: "text", text: e.key }] : []
  }
  if (!e.code) return []
  return [{ kind: down ? "key_down" : "key_up", code: e.code }]
}

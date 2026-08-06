import { test, expect, Page } from '@playwright/test'

// Выпадающий список — браузерный гейт, и другого быть не может.
//
// Этот компонент ломался дважды, и оба раза по причинам, которых в jsdom не существует:
// сначала меню уезжало ПОД соседнюю карточку (stacking context от `backdrop-filter`),
// потом — после выноса порталом в body — переставало нажиматься внутри модалки
// (`pointer-events: none`, который Radix ставит на body). Оба раза vitest был зелёным,
// потому что в jsdom нет ни слоёв, ни попадания курсора, ни компоновки вообще.
//
// Проверяется поэтому НЕ «меню в DOM», а то, ради чего оно существует: попадает ли клик
// именно в него и меняется ли значение. Стенд — /select-harness.html, вне продакшн-сборки.

const HARNESS = '/select-harness.html'

// topmostAt отвечает на вопрос «что лежит под этой точкой».
//
// Видимость меню (`toBeVisible`) на первый дефект не реагировала вовсе: меню было видимым
// по всем признакам DOM и при этом закрыто соседней карточкой. Ответ даёт только
// elementFromPoint.
async function coveredByOther(page: Page, selector: string) {
  return page.evaluate((sel) => {
    const menu = document.querySelector(sel)
    if (!menu) return 'меню не найдено'
    const r = menu.getBoundingClientRect()
    const hit = document.elementFromPoint(r.left + r.width / 2, r.top + Math.min(20, r.height / 2))
    if (!hit) return 'под точкой пусто'
    return menu.contains(hit) || hit === menu ? '' : `перекрыто: ${hit.className || hit.tagName}`
  }, selector)
}

const MENU = '[role="listbox"]'

// bgAlpha возвращает альфу фактического фона элемента.
//
// Браузер отдаёт вычисленный цвет как `rgb(r, g, b)` при непрозрачном фоне и как
// `rgba(r, g, b, a)` при полупрозрачном — иного способа отличить одно от другого из
// страницы нет, а отличие здесь и есть предмет проверки.
async function bgAlpha(page: Page, selector: string) {
  return page.evaluate((sel) => {
    const el = document.querySelector(sel)
    if (!el) return -1
    const bg = window.getComputedStyle(el).backgroundColor
    const m = bg.match(/^rgba?\(([^)]+)\)$/)
    if (!m) return -1
    const parts = m[1].split(',').map((p) => parseFloat(p))
    return parts.length < 4 ? 1 : parts[3]
  }, selector)
}

// animationsDone ждёт, пока на странице не останется идущих анимаций.
//
// Детерминированная замена паузе: ждём состояние, а не время. Годится ровно потому, что
// на стенде нет бесконечных анимаций (спиннеров) — иначе ожидание не завершилось бы.
async function animationsDone(page: Page) {
  await page.waitForFunction(() =>
    document.getAnimations().every((a) => a.playState === 'finished' || a.playState === 'idle')
  )
}

// overlapsBelow сообщает, лежит ли под меню посторонний контент.
//
// Без этой половины проверка непрозрачности зелёная вхолостую: меню над пустым фоном
// выглядит нормально при любой альфе. Дефект был именно в наложении.
async function overlapsBelow(page: Page, selector: string, otherTestId: string) {
  return page.evaluate(
    ({ sel, id }) => {
      const menu = document.querySelector(sel)?.getBoundingClientRect()
      const other = document.querySelector(`[data-testid="${id}"]`)?.getBoundingClientRect()
      if (!menu || !other) return false
      return menu.bottom > other.top && menu.top < other.bottom && menu.right > other.left && menu.left < other.right
    },
    { sel: selector, id: otherTestId }
  )
}

test.describe('выпадающий список', () => {
  test('в карточке: меню поверх соседней карточки, выбор работает', async ({ page }) => {
    await page.goto(HARNESS)

    await page.locator('[aria-haspopup="listbox"]').first().click()
    const menu = page.locator(MENU)
    await expect(menu).toBeVisible()

    // Главная проверка первого дефекта: меню не перекрыто ничем.
    expect(await coveredByOther(page, MENU)).toBe('')

    await menu.getByRole('option', { name: 'Windows' }).click()
    await expect(page.getByTestId('card-value')).toHaveText('windows')
  })

  test('в модалке: меню нажимается и не закрывает саму модалку', async ({ page }) => {
    await page.goto(HARNESS)
    await page.getByTestId('open-dialog').click()

    const dialog = page.locator('[role="dialog"]')
    await expect(dialog).toBeVisible()

    await dialog.locator('[aria-haspopup="listbox"]').click()
    const menu = page.locator(MENU)
    await expect(menu).toBeVisible()
    expect(await coveredByOther(page, MENU)).toBe('')

    await menu.getByRole('option', { name: 'macOS' }).click()

    // Обе половины обязательны. Значение поменялось — значит клик дошёл (при портале в
    // body он не доходил вовсе). Модалка на месте — значит выбор не был прочитан как
    // «клик снаружи» её обработчиком закрытия.
    await expect(page.getByTestId('dialog-value')).toHaveText('darwin')
    await expect(dialog).toBeVisible()
  })

  // Третий дефект, найденный в поле: список стал ПРОЗРАЧНЫМ.
  //
  // Причина — прямое следствие портала. `.glass` держится на `backdrop-filter`, а не на
  // фоне (в тёмной теме фона там 5.5% белого). Вынесенное из карточки меню теряет
  // подложку, а внутри модалки — тоже `.glass` — вложенный backdrop-filter второго
  // размытия не даёт вовсе. Обе проверки идут в тёмной теме: там альфа минимальна, и
  // светлая тема этот дефект прячет.
  for (const place of [
    { name: 'в карточке', open: async (page: Page) => page.locator('[aria-haspopup="listbox"]').first().click(), under: 'next-card' },
    {
      name: 'в модалке',
      open: async (page: Page) => {
        await page.getByTestId('open-dialog').click()
        await page.locator('[role="dialog"] [aria-haspopup="listbox"]').click()
      },
      under: 'dialog-value',
    },
  ]) {
    test(`${place.name}: меню непрозрачно — то, что под ним, сквозь него не читается`, async ({ page }) => {
      await page.goto(HARNESS)
      await page.evaluate(() => document.documentElement.classList.add('dark'))

      await place.open(page)
      await expect(page.locator(MENU)).toBeVisible()

      expect(await overlapsBelow(page, MENU, place.under)).toBe(true)
      expect(await bgAlpha(page, MENU)).toBe(1)
    })
  }

  test('в модалке: меню встаёт под своей кнопкой, а не уезжает от неё', async ({ page }) => {
    await page.goto(HARNESS)
    await page.getByTestId('open-dialog').click()
    // Замер геометрии — только после того, как модалка домотала анимацию масштаба. Пока
    // она идёт, и кнопка, и меню стоят в промежуточных координатах, и проверка «меню под
    // своей кнопкой» ловит не дефект, а кадр анимации (поймано флейком на этом тесте).
    await animationsDone(page)

    const trigger = page.locator('[role="dialog"] [aria-haspopup="listbox"]')
    await trigger.click()

    // `DialogContent` центрируется через translate(-50%,-50%), а трансформированный
    // предок становится содержащим блоком для position: fixed. Без поправки на это меню
    // уезжает на половину окна — видимое, кликабельное и не там, где его ищут глазами.
    const t = await trigger.boundingBox()
    const m = await page.locator(MENU).boundingBox()
    expect(t).not.toBeNull()
    expect(m).not.toBeNull()
    expect(Math.abs(m!.x - t!.x)).toBeLessThan(2)
    expect(Math.abs(m!.width - t!.width)).toBeLessThan(2)
    expect(m!.y).toBeGreaterThan(t!.y)
    expect(m!.y - (t!.y + t!.height)).toBeLessThan(12)
  })
})

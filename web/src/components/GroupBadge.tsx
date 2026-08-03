import i18n from "@/i18n/config"
import { DeviceGroupRef } from "@/lib/api"

// groupAccent — цвет, которым красится рамка устройства. Устройство может состоять в
// нескольких группах; берём ПЕРВУЮ (сервер отдаёт их отсортированными по имени, значит
// выбор стабилен между рендерами и между машинами). null = группы нет, рамку не красим.
export function groupAccent(groups?: DeviceGroupRef[]): string | null {
  return groups && groups.length > 0 ? groups[0].color : null
}

// GroupBadge — имя группы с цветной точкой. Цвет приходит из БД произвольным hex'ом,
// поэтому он в inline-style: класса Tailwind под него не существует.
export function GroupBadge({ group }: { group: DeviceGroupRef }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium"
      style={{
        borderColor: `${group.color}55`,
        backgroundColor: `${group.color}1a`,
        color: group.color,
      }}
      title={i18n.t("groups.badgeTitle", { name: group.name })}
    >
      <span className="h-1.5 w-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: group.color }} />
      {group.name}
    </span>
  )
}

// GroupBadges сворачивает хвост в «+N»: в строке таблицы место ограничено, а машина в
// пяти группах растянула бы колонку.
export function GroupBadges({ groups, max = 2 }: { groups?: DeviceGroupRef[]; max?: number }) {
  if (!groups || groups.length === 0) {
    return <span className="text-xs text-muted-foreground">—</span>
  }
  const shown = groups.slice(0, max)
  const rest = groups.slice(max)
  return (
    <span className="flex flex-wrap items-center gap-1">
      {shown.map((g) => (
        <GroupBadge key={g.id} group={g} />
      ))}
      {rest.length > 0 && (
        <span className="text-xs text-muted-foreground" title={rest.map((g) => g.name).join(", ")}>
          +{rest.length}
        </span>
      )}
    </span>
  )
}

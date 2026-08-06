package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/Floodww/RoutineOps/internal/version"
)

// ErrAgentTooOld — агент устройства не умеет тип задачи, которую ему ставят.
//
// Отказ НА СОЗДАНИИ, а не разбирательство постфактум. Сервер ставил задачу любому
// устройству, не спрашивая, умеет ли его агент такой тип, и до 2.5.8 агент на
// незнакомый тип отвечал `completed` с пустым логом: оператор видел «готово», хотя
// не происходило ничего. Агент починен (отвечает ошибкой с номером своей версии), но
// причина была здесь — и без гейта каждый НОВЫЙ тип задачи будет так же уезжать на
// парк агентов, которые о нём не знают. Разница между «нельзя, вот почему» в момент
// клика и ошибкой через минуту у одной машины из группы — это разница между
// эксплуатацией и расследованием.
var ErrAgentTooOld = errors.New("agent too old for this task type")

// minAgentVersion — минимальная версия АГЕНТА (не продукта — они версионируются
// раздельно) для типов задач, которые старые агенты не умеют.
//
// 🔴 Запись сюда добавляется, когда появляется НОВЫЙ тип задачи, — вместе с самим
// типом, в одном коммите. Уже существующие типы (script/lock/reboot/uninstall/
// decommission) намеренно не перечислены: парк давно на версиях, которые их умеют, а
// выдуманный «минимум» для них отказывал бы живым устройствам по догадке.
//
// Групповые операции (FanOutRebootToGroup) этот гейт НЕ проходят: у их типов минимума
// нет. Появится групповой тип с минимумом — фан-аут обязан отфильтровать неподходящие
// устройства и сказать оператору, скольких пропустил, а не падать целиком из-за одной
// отставшей машины.
var minAgentVersion = map[string]string{
	"filevault_provision": "2.5.8",
	// Удалённый рабочий стол. Версия — ПЕРВЫЙ гейт из двух: она отсекает старые агенты,
	// не знающие типа задачи вовсе. Второй, и более точный, — список способностей
	// (devices.capabilities): free-сборка ТОЙ ЖЕ версии удалённого стола не содержит,
	// файлы вырезаны тегом сборки, и по версии её от enterprise не отличить (§9.17).
	"screen_session": "2.6.0",
}

// AssertAgentSupports — тот же гейт для точек создания задач вне пакета storage
// (enterprise-оверлеи). Требования те же: тенант уже связан.
func (db *DB) AssertAgentSupports(ctx context.Context, deviceID, taskType string) error {
	return db.assertAgentSupports(ctx, deviceID, taskType)
}

// assertAgentSupports — гейт перед вставкой строки задачи.
//
// Живёт в storage, а не в хендлере, намеренно: точек создания задач шесть плюс
// фан-аут, и гейт в API обошёл бы любой не-HTTP вызывающий. Требует УЖЕ связанного
// тенанта (вызывать после BindTenantForDevice): `devices` под RLS.
//
// Неизвестная или неразбираемая версия — тоже отказ. Это выглядит строго, но
// альтернатива — поставить задачу устройству, про которое мы не знаем, умеет ли оно
// её, то есть ровно то состояние, ради выхода из которого гейт и заводился. Минимум
// есть только у новых типов, а на них «версия неизвестна» почти наверняка значит
// «агент старый».
func (db *DB) assertAgentSupports(ctx context.Context, deviceID, taskType string) error {
	need, gated := minAgentVersion[taskType]
	if !gated {
		return nil
	}
	var have string
	if err := db.Scoped(ctx).QueryRow(ctx,
		`SELECT COALESCE(agent_version, '') FROM devices WHERE id = $1`, deviceID).Scan(&have); err != nil {
		return err
	}
	older, err := version.IsNewer(have, need)
	if err != nil {
		return fmt.Errorf("%w: task type %q requires agent v%s, this device reports version %q",
			ErrAgentTooOld, taskType, need, have)
	}
	if older {
		return fmt.Errorf("%w: task type %q requires agent v%s, this device runs %s",
			ErrAgentTooOld, taskType, need, have)
	}
	return nil
}

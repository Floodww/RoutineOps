package admin

import pb "github.com/Floodww/RoutineOps/proto"

// sessionCollectFlags читает из ответа сервера, собирать ли улики сессии и с
// каким периодом снимать промежуточные окна.
//
// Нулевые значения (в том числе от сервера, не знающего этих полей) означают
// «не собирать» и «период по умолчанию». Это не осторожность, а требование
// раскатки: codes.Unimplemented не входит в терминальный список reportErr
// (cmd/agent/main.go), поэтому агент новее сервера копил бы неотправляемые
// записи, а FIFO-очередь блокировала бы ИБ-алерты, статусы лока и сам
// ReportAdminAccess. Аудит-фича не имеет права уронить отчётный канал.
//
// Период дополнительно клампится агентом (ClampWindowInterval) поверх
// серверного клампа: тот строже или равен, а «снимать инвентарь каждые две
// секунды» не должно быть достижимым состоянием парка, каким бы путём значение
// ни пришло.
func sessionCollectFlags(resp *pb.FetchAdminStatusResponse) (bool, int32) {
	return resp.GetCollectSessionChanges(), resp.GetSnapshotIntervalSec()
}

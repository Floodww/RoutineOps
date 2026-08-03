package gateway

import "context"

// InventoryHook — что делать со свежим инвентарём сверх его сохранения.
//
// Шов, а не прямой вызов, ровно по той же причине, что и у escrow: единственный
// сегодняшний потребитель — пересчёт уязвимостей (CVE), а это enterprise-фича, и
// open-core не должен ни компилировать её, ни ставить задачу, обработчика которой
// в его сборке нет. Без шва gateway тянул бы worker.CVEMatchTaskPayload в граф
// открытого ядра.
//
// Хук вызывается ПОСЛЕ успешного сохранения инвентаря и не влияет на ответ агенту:
// приём инвентаря не должен падать из-за побочной обработки.
type InventoryHook func(ctx context.Context, tenantID, deviceID string)

// RegisterInventoryHook ставит хук. Зовётся только из enterprise composition-root.
func (g *Gateway) RegisterInventoryHook(fn InventoryHook) { g.inventoryHook = fn }

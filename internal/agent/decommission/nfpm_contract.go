package decommission

// linuxPackageName — имя пакета агента из build/nfpm/nfpm.yaml (`name:`). Живёт БЕЗ
// build-тега, чтобы кросс-платформенный TestNfpmContract сверял его с манифестом:
// ренейм пакета иначе тихо сломал бы deregisterPackage (dpkg-query перестал бы
// находить пакет → регистрация в БД менеджера оставалась бы, и apt install
// --reinstall возвращал бы списанную машину в парк — исходный баг, ради которого
// шаг добавлен). Та же схема, что wxs_contract.go для MSI.
const linuxPackageName = "routineops-agent"

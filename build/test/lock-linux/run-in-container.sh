#!/bin/bash
# Прогон Linux-замка против настоящего X-сервера (Xvfb). Проверяем не «код собрался»,
# а поведение: окно перекрыло экран, override-redirect стоит, ввод доходит до замка,
# неверный пароль запроса не порождает, верный — порождает, снятие лока закрывает окно.
set -u

DISPLAY_NUM=":99"
export DISPLAY="$DISPLAY_NUM"
STATE_DIR=/harness/state
STATE="$STATE_DIR/lock.json"
OUT=/harness/out
FAILED=0

ok()   { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; FAILED=1; }

mkdir -p "$STATE_DIR" "$OUT"

echo "== 0. X-сервер =="
Xvfb "$DISPLAY_NUM" -screen 0 1280x800x24 -nolisten tcp >/dev/null 2>&1 &
for _ in $(seq 1 50); do xdpyinfo >/dev/null 2>&1 && break; sleep 0.2; done
xdpyinfo >/dev/null 2>&1 && ok "Xvfb 1280x800 поднят" || { fail "Xvfb не поднялся"; exit 1; }

echo "== 1. состояние: устройство заблокировано =="
cat > "$STATE" <<JSON
{"locked":true,"hash":"${LOCK_HASH}","reason":"Тестовая блокировка: обратитесь в IT","request_id":"req-1","locked_at":1}
JSON
ok "lock.json записан"

echo "== 2. запуск замка =="
/harness/agent lock-screen -lock-state "$STATE" >"$OUT/agent.log" 2>&1 &
AGENT_PID=$!
WIN=""
for _ in $(seq 1 50); do
  # Ищем ИМЕННО окно замка по имени: раньше здесь брался первый попавшийся id, и им
  # оказывался корневой экран — проверки геометрии зеленели, ничего не проверяя.
  WIN=$(xdotool search --name "RoutineOps lock" 2>/dev/null | head -1)
  [ -n "$WIN" ] && break
  sleep 0.2
done
if [ -z "$WIN" ]; then
  fail "окно замка не появилось"
  echo "--- лог агента ---"; cat "$OUT/agent.log"; exit 1
fi
ok "окно замка появилось: $WIN"

echo "== 3. геометрия и override-redirect =="
INFO=$(xwininfo -id "$WIN")
echo "$INFO" | grep -q "Width: 1280" && echo "$INFO" | grep -q "Height: 800" \
  && ok "окно перекрывает весь экран (1280x800)" \
  || fail "окно не на весь экран: $(echo "$INFO" | grep -E 'Width|Height' | tr '\n' ' ')"
echo "$INFO" | grep -qi "Override Redirect State: yes" \
  && ok "override-redirect: оконный менеджер окно не тронет" \
  || fail "override-redirect не выставлен"
echo "$INFO" | grep -qi "Map State: IsViewable" \
  && ok "окно отображается" || fail "окно не отображается"

echo "== 4. на экране что-то нарисовано =="
import -window root "$OUT/locked.png" 2>/dev/null
MEAN=$(convert "$OUT/locked.png" -format "%[fx:mean]" info: 2>/dev/null)
awk -v m="$MEAN" 'BEGIN{exit !(m>0.001)}' \
  && ok "текст замка отрисован (средняя яркость $MEAN > 0)" \
  || fail "экран пустой (средняя яркость $MEAN) — текст не нарисовался"

echo "== 5. неверный пароль не порождает запрос =="
xdotool type --delay 20 "wrong-password"; xdotool key Return; sleep 1
if ls "$STATE_DIR"/unlock-request-*.json >/dev/null 2>&1; then
  fail "на неверный пароль ушёл запрос разблокировки"
else
  ok "запроса нет — пароль отвергнут локально"
fi
import -window root "$OUT/wrong.png" 2>/dev/null

echo "== 6. верный пароль порождает запрос демону =="
xdotool type --delay 20 "$LOCK_PASSWORD"; xdotool key Return
REQ=""
for _ in $(seq 1 25); do
  REQ=$(ls "$STATE_DIR"/unlock-request-*.json 2>/dev/null | head -1)
  [ -n "$REQ" ] && break
  sleep 0.2
done
if [ -n "$REQ" ]; then
  ok "запрос разблокировки создан: $(basename "$REQ")"
  grep -q "$LOCK_PASSWORD" "$REQ" && ok "в запросе лежит введённый пароль (сверяет демон)" \
    || fail "в запросе нет пароля: $(cat "$REQ")"
  PERM=$(stat -c "%a" "$REQ")
  [ "$PERM" = "600" ] && ok "права запроса 600" || fail "права запроса $PERM, ожидали 600"
else
  fail "верный пароль не породил запрос разблокировки"
fi

echo "== 7. окно НЕ закрылось само (снимает только демон) =="
sleep 1
if kill -0 "$AGENT_PID" 2>/dev/null; then
  ok "замок висит, пока лок не снят в файле состояния"
else
  fail "замок закрылся по собственной сверке пароля — нарушен контракт разблокировки"
fi

echo "== 8. демон снял лок → окно закрывается =="
cat > "$STATE" <<'JSON'
{"locked":false,"hash":"","reason":"","request_id":"","locked_at":0}
JSON
CLOSED=0
for _ in $(seq 1 30); do
  kill -0 "$AGENT_PID" 2>/dev/null || { CLOSED=1; break; }
  sleep 0.2
done
[ "$CLOSED" = 1 ] && ok "замок закрылся, увидев снятый лок" || fail "замок не закрылся за 6 с"

echo "== 9. второй экземпляр не поднимается =="
cat > "$STATE" <<JSON
{"locked":true,"hash":"${LOCK_HASH}","reason":"Повторная блокировка","request_id":"req-2","locked_at":2}
JSON
rm -f "$STATE_DIR"/unlock-request-*.json
/harness/agent lock-screen -lock-state "$STATE" >"$OUT/agent2.log" 2>&1 &
sleep 2
/harness/agent lock-screen -lock-state "$STATE" >"$OUT/agent3.log" 2>&1
COUNT=$(pgrep -fc "agent lock-screen" || true)
[ "${COUNT:-0}" -le 1 ] && ok "второй процесс замка вышел сам (экземпляр один)" \
  || fail "поднялось несколько замков: $COUNT"
grep -qi "уже показан" "$OUT/agent3.log" && ok "второй экземпляр объяснил выход в лог" \
  || echo "  ℹ️  лог второго экземпляра: $(cat "$OUT/agent3.log")"

echo "== 10. Wayland: замок не притворяется, что запер =="
pkill -f "agent lock-screen" 2>/dev/null
sleep 0.5
WAYLAND_DISPLAY=wayland-0 /harness/agent lock-screen -lock-state "$STATE" >"$OUT/wayland.log" 2>&1
grep -qi "wayland" "$OUT/wayland.log" && ok "под Wayland замок отказался и сказал почему" \
  || fail "под Wayland нет внятного отказа: $(cat "$OUT/wayland.log")"

echo
[ "$FAILED" = 0 ] && echo "ИТОГ: ВСЕ ПРОВЕРКИ ЗЕЛЁНЫЕ" || echo "ИТОГ: ЕСТЬ КРАСНЫЕ"
exit "$FAILED"

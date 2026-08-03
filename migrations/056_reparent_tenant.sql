-- 056: перенос содержимого тенанта в другой одной DEFINER-операцией.
--
-- Почему это не может быть обычным UPDATE из приложения. Перенос по определению
-- затрагивает ДВА тенанта: строки читаются предикатом исходного, а записываются под
-- WITH CHECK целевого. GUC routineops.tenant_id — одно значение, и удовлетворить обе
-- половины предиката 046 одновременно нечем. Первая версия 055 пыталась сделать это
-- в обычной транзакции и падала `invalid input syntax for type uuid: ""` на первой же
-- таблице.
--
-- Приём тот же, что у auth_device_tenant (047) и auth_task_tenant (054): функция
-- владельца, RLS её не касается. Отличие в том, что эта функция ПИШЕТ, поэтому право
-- вызова ограничено: ручка DELETE /tenants/{id} сидит под requireProviderAdmin +
-- requireHuman, то есть надзор над инсталляцией и только живой человек.
--
-- audit_log и audit_anchors в переносе НЕ участвуют намеренно: цепочка хешей у
-- каждого тенанта своя (seq сквозной внутри тенанта, якоря фиксируют голову), и
-- слияние двух цепочек порвало бы обе. Журнал остаётся при своём тенанте — ради него
-- строка тенанта и сохраняется тумбстоуном (055).

CREATE OR REPLACE FUNCTION admin_reparent_tenant(p_src UUID, p_dst UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  src_name TEXT;
  t        TEXT;
BEGIN
  SELECT name INTO src_name FROM tenants WHERE id = p_src;

  -- Членства: если личность УЖЕ есть в целевом тенанте, переносить нечего —
  -- иначе упрёмся в уникальность e-mail внутри тенанта (045). Человек остаётся
  -- там, где был, лишняя строка просто исчезает вместе с тенантом.
  DELETE FROM users u
   WHERE u.tenant_id = p_src
     AND EXISTS (SELECT 1 FROM users d
                  WHERE d.tenant_id = p_dst AND d.identity_id = u.identity_id);

  -- Именованные сущности: имя уникально внутри тенанта (033). При совпадении
  -- дописываем имя исходного тенанта — «name (2)» не объяснило бы администратору,
  -- откуда взялась запись.
  FOREACH t IN ARRAY ARRAY['device_groups', 'scripts', 'policies'] LOOP
    EXECUTE format(
      'UPDATE %I s SET name = s.name || '' (из '' || $2 || '')''
         WHERE s.tenant_id = $1
           AND EXISTS (SELECT 1 FROM %I d
                        WHERE d.tenant_id = $3 AND lower(d.name) = lower(s.name))',
      t, t) USING p_src, COALESCE(src_name, 'удалённого тенанта'), p_dst;
  END LOOP;

  FOREACH t IN ARRAY ARRAY[
    'devices', 'device_software', 'alerts', 'tasks', 'process_events',
    'admin_access_requests', 'admin_session_changes', 'recovery_key_escrow',
    'device_groups', 'device_group_members', 'policy_assignments',
    'scripts', 'script_results', 'policies', 'software_policy_rules',
    'enrollment_tokens', 'invitation_tokens', 'password_reset_tokens',
    'directory_persons', 'api_tokens', 'oidc_providers', 'users'
  ] LOOP
    EXECUTE format('UPDATE %I SET tenant_id = $2 WHERE tenant_id = $1', t)
      USING p_src, p_dst;
  END LOOP;

  UPDATE tenants SET deleted_at = now() WHERE id = p_src;
END;
$$;

-- DOWN:
-- DROP FUNCTION IF EXISTS admin_reparent_tenant(UUID, UUID);

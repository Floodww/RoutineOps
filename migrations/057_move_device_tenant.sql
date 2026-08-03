-- 057: перенос одного устройства в другой тенант.
--
-- Та же природа, что у admin_reparent_tenant (056): операция затрагивает ДВА тенанта
-- сразу — строки читаются предикатом исходного, а пишутся под WITH CHECK целевого, и
-- одним значением GUC routineops.tenant_id обе половины предиката 046 не
-- удовлетворить. Поэтому SECURITY DEFINER, а право вызова ограничивает ручка
-- (requireProviderAdmin + requireHuman: перекладывать устройства между
-- подразделениями вправе только надзор над инсталляцией и только живой человек).
--
-- 🔴 Членство в группах СНИМАЕТСЯ, а не переносится. Группы принадлежат тенанту, и
-- устройство, оставшееся в группе покинутого тенанта, оказалось бы под чужими
-- политиками — то есть перенос молча протащил бы через границу изоляции ровно то,
-- ради чего она заведена. Пусть администратор назначит группы в новом тенанте явно.
--
-- Сертификат устройства НЕ трогаем: он удостоверяет машину, а не её принадлежность
-- подразделению. Перевыпуск потребовал бы переэнроллмента, то есть визита к машине,
-- — цена, несопоставимая с задачей «перевесить в другой отдел».

CREATE OR REPLACE FUNCTION admin_move_device_tenant(p_device UUID, p_dst UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  t TEXT;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM devices WHERE id = p_device) THEN
    RAISE EXCEPTION 'device % not found', p_device USING ERRCODE = 'no_data_found';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM tenants WHERE id = p_dst AND deleted_at IS NULL) THEN
    RAISE EXCEPTION 'tenant % not found', p_dst USING ERRCODE = 'no_data_found';
  END IF;

  DELETE FROM device_group_members WHERE device_id = p_device;

  FOREACH t IN ARRAY ARRAY[
    'device_software', 'alerts', 'tasks', 'process_events',
    'admin_access_requests', 'admin_session_changes', 'recovery_key_escrow'
  ] LOOP
    EXECUTE format('UPDATE %I SET tenant_id = $2 WHERE device_id = $1', t)
      USING p_device, p_dst;
  END LOOP;

  -- Владелец устройства — карточка человека, она тенантская. Ссылку снимаем: тащить
  -- карточку следом значило бы переносить человека из-за одной его машины.
  UPDATE devices SET tenant_id = p_dst, owner_directory_id = NULL WHERE id = p_device;
END;
$$;

-- DOWN:
-- DROP FUNCTION IF EXISTS admin_move_device_tenant(UUID, UUID);

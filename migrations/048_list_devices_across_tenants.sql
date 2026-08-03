-- 048: SECURITY DEFINER для ListDevicesAcrossTenants (контракт §4).
-- Кросс-тенантный список только через явную функцию; RLS на devices остаётся.
SET lock_timeout = '5s';

CREATE OR REPLACE FUNCTION list_devices_across_tenants(
  p_query TEXT,
  p_group_id TEXT,
  p_limit INT,
  p_offset INT
)
RETURNS TABLE (
  id UUID,
  hostname TEXT,
  os TEXT,
  os_version TEXT,
  ip_address TEXT,
  status TEXT,
  last_seen_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ,
  agent_version TEXT,
  mac_address TEXT,
  serial_number TEXT,
  public_ip TEXT,
  outbox_unavailable BOOLEAN,
  degraded_detail TEXT,
  degraded_since TIMESTAMPTZ,
  tenant_id UUID,
  total BIGINT
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  WITH q AS (
    SELECT
      NULLIF(btrim(p_query), '') AS raw,
      CASE
        WHEN NULLIF(btrim(p_query), '') IS NULL THEN NULL
        ELSE '%' || replace(replace(replace(btrim(p_query), '\', '\\'), '%', '\%'), '_', '\_') || '%'
      END AS pattern,
      CASE
        WHEN NULLIF(translate(btrim(COALESCE(p_query, '')), ':-. ', ''), '') IS NULL THEN NULL
        ELSE '%' || replace(replace(replace(translate(btrim(p_query), ':-. ', ''), '\', '\\'), '%', '\%'), '_', '\_') || '%'
      END AS stripped
  )
  SELECT
    d.id, d.hostname, d.os, COALESCE(d.os_version, ''), COALESCE(d.ip_address, ''),
    d.status, d.last_seen_at, d.created_at, COALESCE(d.agent_version, ''),
    COALESCE(d.mac_address, ''), COALESCE(d.serial_number, ''), COALESCE(d.public_ip, ''),
    d.outbox_unavailable, COALESCE(d.degraded_detail, ''), d.degraded_since,
    d.tenant_id,
    COUNT(*) OVER() AS total
  FROM devices d, q
  WHERE d.status != 'pending'
    AND (
      q.raw IS NULL
      OR COALESCE(d.hostname, '')       ILIKE q.pattern ESCAPE '\'
      OR COALESCE(d.os, '')             ILIKE q.pattern ESCAPE '\'
      OR COALESCE(d.os_version, '')     ILIKE q.pattern ESCAPE '\'
      OR COALESCE(d.ip_address, '')     ILIKE q.pattern ESCAPE '\'
      OR COALESCE(d.public_ip, '')      ILIKE q.pattern ESCAPE '\'
      OR COALESCE(d.mac_address, '')    ILIKE q.pattern ESCAPE '\'
      OR COALESCE(d.serial_number, '')  ILIKE q.pattern ESCAPE '\'
      OR COALESCE(d.cpu, '')            ILIKE q.pattern ESCAPE '\'
      OR COALESCE(d.disk, '')           ILIKE q.pattern ESCAPE '\'
      OR COALESCE(d.agent_version, '')  ILIKE q.pattern ESCAPE '\'
      OR COALESCE(d.cert_cn, '')        ILIKE q.pattern ESCAPE '\'
      OR COALESCE(d.ram::text, '')      ILIKE q.pattern ESCAPE '\'
      OR d.id::text                     ILIKE q.pattern ESCAPE '\'
      OR (q.stripped IS NOT NULL AND translate(COALESCE(d.mac_address, ''), ':-. ', '') ILIKE q.stripped ESCAPE '\')
      OR (q.stripped IS NOT NULL AND translate(COALESCE(d.serial_number, ''), ':-. ', '') ILIKE q.stripped ESCAPE '\')
    )
    AND (
      NULLIF(btrim(p_group_id), '') IS NULL
      OR EXISTS (
        SELECT 1 FROM device_group_members m
        WHERE m.device_id = d.id AND m.group_id::text = btrim(p_group_id)
      )
    )
  ORDER BY d.last_seen_at DESC NULLS LAST, d.id
  LIMIT GREATEST(1, LEAST(COALESCE(NULLIF(p_limit, 0), 50), 500))
  OFFSET GREATEST(0, COALESCE(p_offset, 0));
$$;

-- EXECUTE только для роли приложения (pool); не для anon/PUBLIC.
-- У новых функций в PostgreSQL часто по умолчанию GRANT EXECUTE TO PUBLIC — REVOKE безопаснее.
REVOKE ALL ON FUNCTION list_devices_across_tenants(TEXT, TEXT, INT, INT) FROM PUBLIC;

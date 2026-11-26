-- ============================================================================
-- SISTEM BERSEPADU SK MANTIN (SEMANES) - SUPABASE SCHEMA & KESELAMATAN
-- Pilihan 2: Jadual data_guru + pgcrypto (Bcrypt) + Server-Side Session Token
-- Jalankan skrip ini TERLEBIH DAHULU di Supabase SQL Editor.
-- ============================================================================

-- 1. Aktifkan sambungan pgcrypto untuk enkripsi kata laluan (bcrypt)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================================
-- 2. JADUAL TERAS
-- ============================================================================

-- A. Jadual Data Guru (Akses terus dari browser DISEKAT oleh RLS)
CREATE TABLE IF NOT EXISTS public.data_guru (
  id BIGSERIAL PRIMARY KEY,
  nama_guru TEXT NOT NULL,
  jawatan TEXT DEFAULT '',
  gambar TEXT DEFAULT '',
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  peranan TEXT DEFAULT 'Guru',
  uniform TEXT DEFAULT '',
  persatuan TEXT DEFAULT '',
  sukan TEXT DEFAULT '',
  rumah_sukan TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- B. Jadual Sesi Log Masuk (Server-Side Token Verification)
CREATE TABLE IF NOT EXISTS public.user_sessions (
  token UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  guru_id BIGINT REFERENCES public.data_guru(id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  nama TEXT NOT NULL,
  jawatan TEXT DEFAULT '',
  peranan TEXT NOT NULL DEFAULT 'Guru',
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- C. Jadual Data Murid
CREATE TABLE IF NOT EXISTS public.data_murid (
  id BIGSERIAL PRIMARY KEY,
  nama_murid TEXT NOT NULL,
  tahun TEXT DEFAULT '',
  kelas TEXT DEFAULT '',
  gambar TEXT DEFAULT '',
  uniform TEXT DEFAULT '',
  persatuan TEXT DEFAULT '',
  sukan TEXT DEFAULT '',
  rumah_sukan TEXT DEFAULT '',
  agama TEXT DEFAULT '',
  bacaan TEXT DEFAULT '',
  muka_surat TEXT DEFAULT '',
  nama_guru_tasmik TEXT DEFAULT '',
  catatan TEXT DEFAULT '',
  tarikh_kemaskini TEXT DEFAULT '',
  jawatan TEXT DEFAULT '',
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- D. Jadual Tetapan Pilihan / Dropdown (Data Sekolah, Kurikulum, KOKO, HEM)
CREATE TABLE IF NOT EXISTS public.tetapan_pilihan (
  id BIGSERIAL PRIMARY KEY,
  kategori_db TEXT NOT NULL, -- 'data_sekolah' | 'data_kurikulum' | 'data_koko' | 'data_hem'
  nama_kolum TEXT NOT NULL,
  nilai TEXT NOT NULL,
  susunan INT DEFAULT 0,
  UNIQUE(kategori_db, nama_kolum, nilai)
);

-- Indeks untuk carian pantas
CREATE INDEX IF NOT EXISTS idx_murid_tahun_kelas ON public.data_murid (tahun, kelas);
CREATE INDEX IF NOT EXISTS idx_murid_agama ON public.data_murid (agama);
CREATE INDEX IF NOT EXISTS idx_pilihan_kat_col ON public.tetapan_pilihan (kategori_db, nama_kolum, susunan);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON public.user_sessions (expires_at);

-- ============================================================================
-- 3. TRIGGER AUTO-HASH KATA LALUAN (BCRYPT)
-- ============================================================================
CREATE OR REPLACE FUNCTION public.hash_guru_password()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  IF NEW.password_hash IS NOT NULL AND NEW.password_hash <> '' THEN
    -- Hanya hash jika belum dalam format bcrypt ($2a$ atau $2b$)
    IF LEFT(NEW.password_hash, 4) NOT IN ('$2a$', '$2b$', '$2y$') THEN
      NEW.password_hash := crypt(NEW.password_hash, gen_salt('bf', 10));
    END IF;
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_hash_guru_password ON public.data_guru;
CREATE TRIGGER trg_hash_guru_password
BEFORE INSERT OR UPDATE ON public.data_guru
FOR EACH ROW
EXECUTE FUNCTION public.hash_guru_password();

-- ============================================================================
-- 4. VIEW SELAMAT GURU (TANPA KATA LALUAN)
-- ============================================================================
CREATE OR REPLACE VIEW public.v_data_guru AS
SELECT
  id,
  nama_guru,
  jawatan,
  gambar,
  username,
  peranan,
  uniform,
  persatuan,
  sukan,
  rumah_sukan
FROM public.data_guru
ORDER BY nama_guru ASC;

-- ============================================================================
-- 5. ROW LEVEL SECURITY (RLS)
-- ============================================================================
ALTER TABLE public.data_guru ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.data_murid ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tetapan_pilihan ENABLE ROW LEVEL SECURITY;

-- Sekat akses terus ke data_guru & user_sessions (tiada polisi untuk anon!)
DROP POLICY IF EXISTS "No direct access guru" ON public.data_guru;
DROP POLICY IF EXISTS "No direct access sessions" ON public.user_sessions;

-- Benarkan bacaan (SELECT) sahaja untuk data_murid & tetapan_pilihan
DROP POLICY IF EXISTS "Public read murid" ON public.data_murid;
CREATE POLICY "Public read murid" ON public.data_murid
  FOR SELECT TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "Public read pilihan" ON public.tetapan_pilihan;
CREATE POLICY "Public read pilihan" ON public.tetapan_pilihan
  FOR SELECT TO anon, authenticated USING (true);

-- Grant view selamat guru
GRANT SELECT ON public.v_data_guru TO anon, authenticated;
GRANT SELECT ON public.data_murid TO anon, authenticated;
GRANT SELECT ON public.tetapan_pilihan TO anon, authenticated;

-- ============================================================================
-- 6. FUNGSI HELPER PENGESAHAN SESI (DALAMAN)
-- ============================================================================
CREATE OR REPLACE FUNCTION public._check_session(p_token UUID, p_require_admin BOOLEAN DEFAULT FALSE)
RETURNS public.user_sessions
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_sess public.user_sessions;
BEGIN
  IF p_token IS NULL THEN
    RAISE EXCEPTION 'Sesi tidak sah. Sila log masuk semula.';
  END IF;

  SELECT * INTO v_sess
  FROM public.user_sessions
  WHERE token = p_token AND expires_at > now()
  LIMIT 1;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Sesi telah tamat tempoh. Sila log masuk semula.';
  END IF;

  IF p_require_admin AND LOWER(COALESCE(v_sess.peranan, '')) <> 'admin' THEN
    RAISE EXCEPTION 'Akses dinafikan. Tindakan ini memerlukan peranan Admin.';
  END IF;

  RETURN v_sess;
END;
$$;

-- ============================================================================
-- 7. FUNGSI RPC AUTENTIKASI (LOGIN, VERIFY, LOGOUT)
-- ============================================================================
CREATE OR REPLACE FUNCTION public.login_guru(
  p_username TEXT,
  p_password TEXT,
  p_remember BOOLEAN DEFAULT FALSE
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_guru public.data_guru;
  v_token UUID;
  v_expiry TIMESTAMPTZ;
BEGIN
  -- Padam sesi lama yang telah tamat tempoh
  DELETE FROM public.user_sessions WHERE expires_at <= now();

  SELECT * INTO v_guru
  FROM public.data_guru
  WHERE LOWER(TRIM(username)) = LOWER(TRIM(p_username))
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('success', false, 'message', 'Username atau Password salah.');
  END IF;

  IF v_guru.password_hash <> crypt(p_password, v_guru.password_hash) THEN
    RETURN jsonb_build_object('success', false, 'message', 'Username atau Password salah.');
  END IF;

  v_expiry := CASE WHEN p_remember THEN now() + INTERVAL '30 days' ELSE now() + INTERVAL '12 hours' END;

  INSERT INTO public.user_sessions (guru_id, username, nama, jawatan, peranan, expires_at)
  VALUES (v_guru.id, v_guru.username, v_guru.nama_guru, COALESCE(v_guru.jawatan, ''), COALESCE(v_guru.peranan, 'Guru'), v_expiry)
  RETURNING token INTO v_token;

  RETURN jsonb_build_object(
    'success', true,
    'token', v_token,
    'expires_at', v_expiry,
    'user', jsonb_build_object(
      'id', v_guru.id,
      'nama', v_guru.nama_guru,
      'jawatan', COALESCE(v_guru.jawatan, ''),
      'username', v_guru.username,
      'peranan', COALESCE(v_guru.peranan, 'Guru')
    )
  );
END;
$$;

CREATE OR REPLACE FUNCTION public.verify_session(p_token UUID)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_sess public.user_sessions;
BEGIN
  SELECT * INTO v_sess
  FROM public.user_sessions
  WHERE token = p_token AND expires_at > now()
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('valid', false);
  END IF;

  RETURN jsonb_build_object(
    'valid', true,
    'user', jsonb_build_object(
      'id', v_sess.guru_id,
      'nama', v_sess.nama,
      'jawatan', v_sess.jawatan,
      'username', v_sess.username,
      'peranan', v_sess.peranan
    )
  );
END;
$$;

CREATE OR REPLACE FUNCTION public.logout_guru(p_token UUID)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  DELETE FROM public.user_sessions WHERE token = p_token;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================================
-- 8. FUNGSI RPC PENGURUSAN DATA GURU (KHAS ADMIN)
-- ============================================================================
CREATE OR REPLACE FUNCTION public.admin_get_guru(p_token UUID)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_rows JSONB;
BEGIN
  PERFORM public._check_session(p_token, true);

  SELECT COALESCE(jsonb_agg(
    jsonb_build_object(
      'id', id,
      'nama_guru', nama_guru,
      'jawatan', COALESCE(jawatan, ''),
      'gambar', COALESCE(gambar, ''),
      'username', username,
      'password', '********',
      'peranan', COALESCE(peranan, 'Guru'),
      'uniform', COALESCE(uniform, ''),
      'persatuan', COALESCE(persatuan, ''),
      'sukan', COALESCE(sukan, ''),
      'rumah_sukan', COALESCE(rumah_sukan, '')
    ) ORDER BY id ASC
  ), '[]'::jsonb)
  INTO v_rows
  FROM public.data_guru;

  RETURN jsonb_build_object('success', true, 'data', v_rows);
END;
$$;

CREATE OR REPLACE FUNCTION public.admin_upsert_guru(
  p_token UUID,
  p_id BIGINT,
  p_data JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_pass TEXT;
  v_new_id BIGINT;
BEGIN
  PERFORM public._check_session(p_token, true);
  v_pass := TRIM(COALESCE(p_data->>'password', ''));

  IF p_id IS NULL THEN
    IF v_pass = '' OR v_pass = '********' THEN
      v_pass := '123456'; -- Kata laluan lalai jika dibiarkan kosong semasa daftar baru
    END IF;

    INSERT INTO public.data_guru (
      nama_guru, jawatan, gambar, username, password_hash, peranan, uniform, persatuan, sukan, rumah_sukan
    ) VALUES (
      TRIM(COALESCE(p_data->>'nama_guru', '')),
      TRIM(COALESCE(p_data->>'jawatan', '')),
      TRIM(COALESCE(p_data->>'gambar', '')),
      TRIM(COALESCE(p_data->>'username', '')),
      v_pass,
      COALESCE(NULLIF(TRIM(p_data->>'peranan'), ''), 'Guru'),
      TRIM(COALESCE(p_data->>'uniform', '')),
      TRIM(COALESCE(p_data->>'persatuan', '')),
      TRIM(COALESCE(p_data->>'sukan', '')),
      TRIM(COALESCE(p_data->>'rumah_sukan', ''))
    ) RETURNING id INTO v_new_id;
  ELSE
    UPDATE public.data_guru SET
      nama_guru = TRIM(COALESCE(p_data->>'nama_guru', nama_guru)),
      jawatan = TRIM(COALESCE(p_data->>'jawatan', '')),
      gambar = TRIM(COALESCE(p_data->>'gambar', '')),
      username = TRIM(COALESCE(p_data->>'username', username)),
      password_hash = CASE
        WHEN v_pass <> '' AND v_pass <> '********' THEN v_pass
        ELSE password_hash
      END,
      peranan = COALESCE(NULLIF(TRIM(p_data->>'peranan'), ''), 'Guru'),
      uniform = TRIM(COALESCE(p_data->>'uniform', '')),
      persatuan = TRIM(COALESCE(p_data->>'persatuan', '')),
      sukan = TRIM(COALESCE(p_data->>'sukan', '')),
      rumah_sukan = TRIM(COALESCE(p_data->>'rumah_sukan', ''))
    WHERE id = p_id;
    v_new_id := p_id;
  END IF;

  RETURN jsonb_build_object('success', true, 'id', v_new_id);
END;
$$;

CREATE OR REPLACE FUNCTION public.admin_delete_guru(p_token UUID, p_id BIGINT)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_sess public.user_sessions;
BEGIN
  v_sess := public._check_session(p_token, true);
  IF v_sess.guru_id = p_id THEN
    RAISE EXCEPTION 'Anda tidak boleh memadam akaun anda sendiri.';
  END IF;

  DELETE FROM public.data_guru WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================================
-- 9. FUNGSI RPC PENGURUSAN DATA MURID & TASMIK & PENGAWAS
-- ============================================================================
CREATE OR REPLACE FUNCTION public.admin_upsert_murid(
  p_token UUID,
  p_id BIGINT,
  p_data JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_new_id BIGINT;
BEGIN
  PERFORM public._check_session(p_token, false);

  IF p_id IS NULL THEN
    INSERT INTO public.data_murid (
      nama_murid, tahun, kelas, gambar, uniform, persatuan, sukan, rumah_sukan,
      agama, bacaan, muka_surat, nama_guru_tasmik, catatan, tarikh_kemaskini, jawatan
    ) VALUES (
      TRIM(COALESCE(p_data->>'nama_murid', '')),
      TRIM(COALESCE(p_data->>'tahun', '')),
      TRIM(COALESCE(p_data->>'kelas', '')),
      TRIM(COALESCE(p_data->>'gambar', '')),
      TRIM(COALESCE(p_data->>'uniform', '')),
      TRIM(COALESCE(p_data->>'persatuan', '')),
      TRIM(COALESCE(p_data->>'sukan', '')),
      TRIM(COALESCE(p_data->>'rumah_sukan', '')),
      TRIM(COALESCE(p_data->>'agama', '')),
      TRIM(COALESCE(p_data->>'bacaan', '')),
      TRIM(COALESCE(p_data->>'muka_surat', '')),
      TRIM(COALESCE(p_data->>'nama_guru_tasmik', '')),
      TRIM(COALESCE(p_data->>'catatan', '')),
      TRIM(COALESCE(p_data->>'tarikh_kemaskini', '')),
      TRIM(COALESCE(p_data->>'jawatan', ''))
    ) RETURNING id INTO v_new_id;
  ELSE
    UPDATE public.data_murid SET
      nama_murid = TRIM(COALESCE(p_data->>'nama_murid', nama_murid)),
      tahun = TRIM(COALESCE(p_data->>'tahun', '')),
      kelas = TRIM(COALESCE(p_data->>'kelas', '')),
      gambar = TRIM(COALESCE(p_data->>'gambar', '')),
      uniform = TRIM(COALESCE(p_data->>'uniform', '')),
      persatuan = TRIM(COALESCE(p_data->>'persatuan', '')),
      sukan = TRIM(COALESCE(p_data->>'sukan', '')),
      rumah_sukan = TRIM(COALESCE(p_data->>'rumah_sukan', '')),
      agama = TRIM(COALESCE(p_data->>'agama', '')),
      bacaan = TRIM(COALESCE(p_data->>'bacaan', '')),
      muka_surat = TRIM(COALESCE(p_data->>'muka_surat', '')),
      nama_guru_tasmik = TRIM(COALESCE(p_data->>'nama_guru_tasmik', '')),
      catatan = TRIM(COALESCE(p_data->>'catatan', '')),
      tarikh_kemaskini = TRIM(COALESCE(p_data->>'tarikh_kemaskini', '')),
      jawatan = TRIM(COALESCE(p_data->>'jawatan', '')),
      updated_at = now()
    WHERE id = p_id;
    v_new_id := p_id;
  END IF;

  RETURN jsonb_build_object('success', true, 'id', v_new_id);
END;
$$;

CREATE OR REPLACE FUNCTION public.admin_delete_murid(p_token UUID, p_id BIGINT)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  PERFORM public._check_session(p_token, false);
  DELETE FROM public.data_murid WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

CREATE OR REPLACE FUNCTION public.admin_naik_tahun_murid(p_token UUID)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_deleted INT := 0;
  v_updated INT := 0;
BEGIN
  PERFORM public._check_session(p_token, true);

  DELETE FROM public.data_murid WHERE TRIM(tahun) = '6';
  GET DIAGNOSTICS v_deleted = ROW_COUNT;

  UPDATE public.data_murid
  SET tahun = (CAST(TRIM(tahun) AS INT) + 1)::TEXT,
      updated_at = now()
  WHERE TRIM(tahun) IN ('1', '2', '3', '4', '5');
  GET DIAGNOSTICS v_updated = ROW_COUNT;

  RETURN jsonb_build_object(
    'success', true,
    'message', format('Berjaya! %s murid Tahun 6 dipadam dan %s murid dinaikkan tahun.', v_deleted, v_updated)
  );
END;
$$;

CREATE OR REPLACE FUNCTION public.admin_bulk_insert_murid(p_token UUID, p_rows JSONB)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_count INT := 0;
BEGIN
  PERFORM public._check_session(p_token, true);

  INSERT INTO public.data_murid (
    nama_murid, tahun, kelas, gambar, uniform, persatuan, sukan, rumah_sukan,
    agama, bacaan, muka_surat, nama_guru_tasmik, catatan, tarikh_kemaskini, jawatan
  )
  SELECT
    TRIM(COALESCE(r->>'nama_murid', '')),
    TRIM(COALESCE(r->>'tahun', '')),
    TRIM(COALESCE(r->>'kelas', '')),
    TRIM(COALESCE(r->>'gambar', '')),
    TRIM(COALESCE(r->>'uniform', '')),
    TRIM(COALESCE(r->>'persatuan', '')),
    TRIM(COALESCE(r->>'sukan', '')),
    TRIM(COALESCE(r->>'rumah_sukan', '')),
    TRIM(COALESCE(r->>'agama', '')),
    TRIM(COALESCE(r->>'bacaan', '')),
    TRIM(COALESCE(r->>'muka_surat', '')),
    TRIM(COALESCE(r->>'nama_guru_tasmik', '')),
    TRIM(COALESCE(r->>'catatan', '')),
    TRIM(COALESCE(r->>'tarikh_kemaskini', '')),
    TRIM(COALESCE(r->>'jawatan', ''))
  FROM jsonb_array_elements(p_rows) AS r
  WHERE TRIM(COALESCE(r->>'nama_murid', '')) <> '';

  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN jsonb_build_object('success', true, 'count', v_count, 'message', format('%s rekod murid berjaya diimport!', v_count));
END;
$$;

CREATE OR REPLACE FUNCTION public.update_tasmik_murid(
  p_token UUID,
  p_id BIGINT,
  p_bacaan TEXT,
  p_muka_surat TEXT,
  p_guru_tasmik TEXT,
  p_catatan TEXT,
  p_gambar TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_tarikh TEXT;
BEGIN
  PERFORM public._check_session(p_token, false);
  v_tarikh := to_char(now() AT TIME ZONE 'Asia/Kuala_Lumpur', 'DD/MM/YYYY');

  UPDATE public.data_murid SET
    bacaan = COALESCE(p_bacaan, ''),
    muka_surat = COALESCE(p_muka_surat, ''),
    nama_guru_tasmik = COALESCE(p_guru_tasmik, ''),
    catatan = COALESCE(p_catatan, ''),
    tarikh_kemaskini = v_tarikh,
    gambar = CASE WHEN p_gambar IS NOT NULL AND p_gambar <> '' THEN p_gambar ELSE gambar END,
    updated_at = now()
  WHERE id = p_id;

  RETURN jsonb_build_object('success', true, 'tarikh_kemaskini', v_tarikh);
END;
$$;

CREATE OR REPLACE FUNCTION public.update_jawatan_murid_bulk(
  p_token UUID,
  p_ids BIGINT[],
  p_jawatan TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_count INT := 0;
BEGIN
  PERFORM public._check_session(p_token, false);

  UPDATE public.data_murid
  SET jawatan = COALESCE(p_jawatan, ''),
      updated_at = now()
  WHERE id = ANY(p_ids);

  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN jsonb_build_object('success', true, 'count', v_count);
END;
$$;

-- ============================================================================
-- 10. FUNGSI RPC PENGURUSAN TETAPAN PILIHAN / DROPDOWN (KHAS ADMIN)
-- ============================================================================
CREATE OR REPLACE FUNCTION public.admin_sync_pilihan(
  p_token UUID,
  p_kategori_db TEXT,
  p_nama_kolum TEXT,
  p_items TEXT[]
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_idx INT := 1;
  v_item TEXT;
BEGIN
  PERFORM public._check_session(p_token, true);

  DELETE FROM public.tetapan_pilihan
  WHERE kategori_db = p_kategori_db AND nama_kolum = p_nama_kolum;

  IF p_items IS NOT NULL THEN
    FOREACH v_item IN ARRAY p_items LOOP
      v_item := TRIM(COALESCE(v_item, ''));
      IF v_item <> '' THEN
        INSERT INTO public.tetapan_pilihan (kategori_db, nama_kolum, nilai, susunan)
        VALUES (p_kategori_db, p_nama_kolum, v_item, v_idx)
        ON CONFLICT (kategori_db, nama_kolum, nilai) DO NOTHING;
        v_idx := v_idx + 1;
      END IF;
    END LOOP;
  END IF;

  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================================
-- 11. KEBENARAN EXECUTE UNTUK RPC
-- ============================================================================
GRANT EXECUTE ON FUNCTION public.login_guru(TEXT, TEXT, BOOLEAN) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.verify_session(UUID) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.logout_guru(UUID) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_get_guru(UUID) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_upsert_guru(UUID, BIGINT, JSONB) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_delete_guru(UUID, BIGINT) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_upsert_murid(UUID, BIGINT, JSONB) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_delete_murid(UUID, BIGINT) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_naik_tahun_murid(UUID) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_bulk_insert_murid(UUID, JSONB) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.update_tasmik_murid(UUID, BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.update_jawatan_murid_bulk(UUID, BIGINT[], TEXT) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_sync_pilihan(UUID, TEXT, TEXT, TEXT[]) TO anon, authenticated;

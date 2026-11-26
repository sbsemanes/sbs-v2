// ============================================================================
// KONFIGURASI PUSAT SUPABASE & KESELAMATAN SESI - SISTEM BERSEPADU SK MANTIN
// ============================================================================
const SUPABASE_URL = "https://kqazvoakxecweipweeyt.supabase.co";
const SUPABASE_ANON_KEY = "sb_publishable_WrkFIV_2YN_gwFGzDmwCZQ_6mzTeCFC";

window.supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

window.SemanesAuth = {
  getToken() {
    return sessionStorage.getItem("semanes_token") || localStorage.getItem("semanes_token") || null;
  },

  getUser() {
    try {
      const raw = sessionStorage.getItem("semanes_user") || localStorage.getItem("semanes_user");
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  },

  saveSession(token, user, remember = false) {
    sessionStorage.setItem("semanes_token", token);
    sessionStorage.setItem("semanes_user", JSON.stringify(user));
    // Buang simpanan kata laluan lama (tidak selamat) jika ada
    localStorage.removeItem("semanes_remembered_user");
    if (remember) {
      localStorage.setItem("semanes_token", token);
      localStorage.setItem("semanes_user", JSON.stringify(user));
    } else {
      localStorage.removeItem("semanes_token");
      localStorage.removeItem("semanes_user");
    }
  },

  clearSession() {
    sessionStorage.removeItem("semanes_token");
    sessionStorage.removeItem("semanes_user");
    localStorage.removeItem("semanes_token");
    localStorage.removeItem("semanes_user");
    localStorage.removeItem("semanes_remembered_user");
  },

  async login(username, password, remember = false) {
    const { data, error } = await window.supabaseClient.rpc("login_guru", {
      p_username: username,
      p_password: password,
      p_remember: remember
    });
    if (error) throw error;
    if (data && data.success) {
      this.saveSession(data.token, data.user, remember);
    }
    return data;
  },

  async verify(requireAdmin = false, loginPath = "./login.html") {
    const token = this.getToken();
    if (!token) {
      this.clearSession();
      window.location.href = loginPath;
      return null;
    }
    try {
      const { data, error } = await window.supabaseClient.rpc("verify_session", { p_token: token });
      if (error || !data || !data.valid) {
        this.clearSession();
        window.location.href = loginPath;
        return null;
      }
      // Kemaskini sesi tempatan daripada pengesahan pelayan (halang manipulasi sessionStorage)
      const isRemembered = !!localStorage.getItem("semanes_token");
      this.saveSession(token, data.user, isRemembered);

      if (requireAdmin && (!data.user.peranan || data.user.peranan.toLowerCase() !== "admin")) {
        alert("Akses dinafikan! Halaman ini dikhaskan untuk Admin sahaja.");
        window.location.href = loginPath;
        return null;
      }
      return data.user;
    } catch (e) {
      console.warn("Gagal mengesahkan sesi dengan pelayan:", e);
      return this.getUser();
    }
  },

  async logout(loginPath = "./login.html") {
    const token = this.getToken();
    if (token) {
      try {
        await window.supabaseClient.rpc("logout_guru", { p_token: token });
      } catch (e) {}
    }
    this.clearSession();
    window.location.href = loginPath;
  }
};

window.SemanesDB = {
  // Muat turun semua rekod tetapan_pilihan dan susun ikut kategori_db -> nama_kolum -> [nilai]
  async getPilihanMap() {
    const { data, error } = await window.supabaseClient
      .from("tetapan_pilihan")
      .select("kategori_db, nama_kolum, nilai, susunan")
      .order("susunan", { ascending: true })
      .order("id", { ascending: true });
    if (error) throw error;

    const map = {
      data_sekolah: {},
      data_kurikulum: {},
      data_koko: {},
      data_hem: {}
    };
    (data || []).forEach(r => {
      if (!map[r.kategori_db]) map[r.kategori_db] = {};
      if (!map[r.kategori_db][r.nama_kolum]) map[r.kategori_db][r.nama_kolum] = [];
      map[r.kategori_db][r.nama_kolum].push(r.nilai);
    });
    return map;
  },

  // Senarai guru selamat (tanpa kata laluan) daripada View v_data_guru
  async getGuruList() {
    const { data, error } = await window.supabaseClient
      .from("v_data_guru")
      .select("*")
      .order("nama_guru", { ascending: true });
    if (error) throw error;
    return data || [];
  },

  // Senarai penuh semua murid (sokong > 1,000 rekod melalui pagination automatik)
  async getMuridList() {
    const allRows = [];
    const pageSize = 1000;
    let from = 0;
    while (true) {
      const { data, error } = await window.supabaseClient
        .from("data_murid")
        .select("*")
        .order("id", { ascending: true })
        .range(from, from + pageSize - 1);
      if (error) throw error;
      if (!data || data.length === 0) break;
      allRows.push(...data);
      if (data.length < pageSize) break;
      from += pageSize;
    }
    return allRows;
  },

  // Bina pemetaan opsyen dropdown standard untuk Admin & semua modul
  buildDropdownOptions(pilihanMap, guruList) {
    const ds = pilihanMap.data_sekolah || {};
    const dk = pilihanMap.data_kurikulum || {};
    const dko = pilihanMap.data_koko || {};
    const dh = pilihanMap.data_hem || {};

    const guruNames = (guruList || []).map(g => g.nama_guru).filter(Boolean);
    const guruTasmik = (guruList || [])
      .filter(g => (g.jawatan || "").toLowerCase().includes("pendidikan islam"))
      .map(g => g.nama_guru);

    return {
      sesiPersekolahan: ds["Sesi Persekolahan"] || [],
      sesi: ds["Sesi"] || [],
      minggu: ds["Minggu Persekolahan"] || [],
      tahun: ds["Tahun"] || [],
      kelas: ds["Kelas"] || [],
      bilikKhas: ds["Bilik Khas"] || [],
      peringkat: ds["Peringkat"] || [],
      agama: ds["Agama"] || [],
      bacaan: ds["Bacaan"] || [],
      jawatanMurid: ds["Jawatan Murid"] || [],

      guru: guruNames,
      guruTasmik: guruTasmik.length > 0 ? guruTasmik : guruNames,
      peranan: ["Guru", "Admin"],

      panitiaNames: dk["Panitia"] || [],
      unitNames: dk["Unit Kurikulum"] || [],
      namaFailList: dk["Nama Fail"] || [],
      kandunganFailList: dk["Kandungan Fail"] || [],
      namaDokumenList: dk["Nama Dokumen"] || [],

      uniform: dko["Uniform"] || [],
      persatuan: dko["Persatuan"] || [],
      sukan: dko["Sukan"] || [],
      rumahSukan: dko["Rumah Sukan"] || [],
      jawatanKoko: dko["JAWATAN"] || [],
      pencapaianKoko: dko["PENCAPAIAN"] || [],
      peringkatKoko: dko["PERINGKAT"] || [],
      sivikKoko: dko["SIVIK"] || [],
      kokoNamaFail: dko["Nama Fail"] || [],
      kokoKandunganFail: dko["Kandungan Fail"] || [],
      kokoNamaDokumen: dko["Nama Dokumen"] || [],

      kumpulan: dh["KUMPULAN GURU BERTUGAS"] || [],
      kpi: dh["KPI"] || [],
      unitHEM: dh["UNIT"] || [],
      hemNoFail: dh["No Fail"] || [],
      hemNamaDokumen: dh["Nama Fail / Dokumen"] || [],
      hemKategori: dh["Kategori / Keterangan"] || [],
      jawatankuasaKelas: dh["Jawatankuasa Kelas"] || []
    };
  }
};

import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = os.getenv("OAUTHLIB_INSECURE_TRANSPORT", "1")
import pickle
import json
import base64
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, send_file, session, flash, jsonify, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash
import mysql.connector
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request


# ---------- CONFIG ----------
APP_SECRET = os.getenv("APP_SECRET", "rahasia123")  # ganti dengan secret yang aman
CLIENT_SECRET_FILE = "credentials.json"     # file yang di-download dari Google Cloud
SCOPES = ["https://www.googleapis.com/auth/drive.file"]  # cukup untuk upload & lihat file
TOKEN_FILE = "token.json"

app = Flask(__name__)
app.secret_key = APP_SECRET

# Folder sementara
app.config["UPLOAD_FOLDER"] = os.path.join(os.getcwd(), "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# ===================== DATABASE =====================
def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("MYSQLHOST", "mainline.proxy.rlwy.net"),
        user=os.getenv("MYSQLUSER", "root"),
        password=os.getenv("MYSQLPASSWORD", "YNtEQyIpMYdwsxSkYrrksJhsupNpnMCz"),
        database=os.getenv("MYSQLDATABASE", "railway"),
        port=int(os.getenv("MYSQLPORT", 25378))
    )
    
# ---------------- OAuth helpers ----------------
creds_json = os.getenv("GOOGLE_CREDENTIALS_JSON", None)
if creds_json:
    """Simpan token ke token.json"""
    with open(TOKEN_FILE, "w") as f:
        f.write(creds_json())
        
def save_credentials_to_file(creds: Credentials):
    with open(CLIENT_SECRET_FILE, "w") as f:
        f.write(creds.to_json())

def load_credentials_from_file():
    if not os.path.exists(TOKEN_FILE):
        return None
    return Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

def save_credentials_to_session(creds: Credentials):
    session["credentials"] = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes
    }

def get_drive_service():
    # Prioritas: session -> token.json
    creds = None
    if "credentials" in session:
        creds = Credentials.from_authorized_user_info(session["credentials"], SCOPES)
    else:
        creds = load_credentials_from_file()

    if not creds:
        return None

    # Refresh jika perlu
    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            # update penyimpanan
            save_credentials_to_file(creds)
            save_credentials_to_session(creds)
        except Exception as e:
            print("Gagal refresh token:", e)
            return None

    return build("drive", "v3", credentials=creds)

# ---------------- Routes untuk OAuth ----------------
@app.route("/authorize")
def authorize():
    # Flow yang akan redirect ke Google
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRET_FILE,
        scopes=SCOPES,
        redirect_uri=url_for("oauth2callback", _external=True)
    )
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"   # pastikan dapat refresh_token pada pertama kali
    )
    session["state"] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state", None)
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRET_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for("oauth2callback", _external=True)
    )
    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials
    # Simpan token ke file dan session
    save_credentials_to_file(creds)
    save_credentials_to_session(creds)

    flash("Google Drive berhasil diotorisasi. Kamu bisa upload sekarang.", "success")
    return redirect(url_for("index"))

# ---------------- Upload helper ----------------
def upload_to_drive(local_path, filename):
    drive_service = get_drive_service()
    if not drive_service:
        return None, None  # belum login
    file_metadata = {
        "name": filename,
        "parents": ["root"]   # <--- penting biar muncul di My Drive
    }
    media = MediaFileUpload(local_path, resumable=True)
    file = drive_service.files().create(
        body=file_metadata,
        media_body=media,
        fields="id, webViewLink"
    ).execute()

    return file.get("id"), file.get("webViewLink")

# ===================== LOGIN =====================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form["username"]
        sandi = request.form["password"]

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE username=%s", (user,))
        akun = cursor.fetchone()
        cursor.close()
        conn.close()

        if akun and check_password_hash(akun["password"], sandi):
            session["user_id"] = akun["id"]
            session["username"] = akun["username"]
            flash("Login berhasil!", "success")
            return redirect(url_for("index"))
        else:
            flash("Username atau password salah!", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Anda sudah logout!", "info")
    return redirect(url_for("login"))

# ===================== REGISTER =====================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm = request.form["confirm"]

        if password != confirm:
            flash("❌ Password tidak cocok!", "danger")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO admin (username, password) VALUES (%s, %s)", (username, hashed_password))
        conn.commit()
        cursor.close()
        conn.close()

        flash("✅ Akun berhasil dibuat! Silakan login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# ===================== FORGOT PASSWORD =====================
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form["username"]

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE username=%s", (username,))
        akun = cursor.fetchone()
        cursor.close()
        conn.close()

        if not akun:
            flash("❌ Username tidak ditemukan!", "danger")
            return redirect(url_for("forgot_password"))

        # Untuk sementara, reset password ke "123456"
        new_password = generate_password_hash("123456")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE admin SET password=%s WHERE username=%s", (new_password, username))
        conn.commit()
        cursor.close()
        conn.close()

        flash("🔄 Password berhasil direset! Password baru: 123456", "info")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")

# ===================== PROTEKSI ROUTE =====================
@app.before_request
def require_login():
    allowed_routes = ["login", "static"]
    if request.endpoint not in allowed_routes and "user_id" not in session:
        return redirect(url_for("login"))

# ===================== DASHBOARD =====================
@app.route("/")
def index():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Total dokumen
    cursor.execute("SELECT COUNT(*) AS total FROM dokumen")
    total_docs = cursor.fetchone()['total']

    # Total kategori
    cursor.execute("SELECT COUNT(*) AS total FROM kategori")
    total_cat = cursor.fetchone()['total']

    # Total ukuran file (pastikan ada kolom size di tabel dokumen)
    cursor.execute("SELECT IFNULL(SUM(size),0) AS total_size FROM dokumen")
    total_size = cursor.fetchone()['total_size']

    # Data kategori (untuk chart)
    cursor.execute("""
        SELECT k.nama, COUNT(d.id) AS jumlah 
        FROM kategori k LEFT JOIN dokumen d ON k.id=d.kategori_id 
        GROUP BY k.id
    """)
    kategori_data = cursor.fetchall()
    kategori_labels = [row['nama'] for row in kategori_data]
    kategori_counts = [row['jumlah'] for row in kategori_data]

    # 5 dokumen terbaru
    cursor.execute("""
        SELECT nomor_surat, nama_pemilik, nama_perusahaan, tgl_upload
        FROM dokumen
        ORDER BY tgl_upload DESC 
        LIMIT 5
    """)
    recent_docs = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("index.html",
                           total_docs=total_docs,
                           total_cat=total_cat,
                           total_size=total_size,
                           kategori_labels=kategori_labels,
                           kategori_counts=kategori_counts,
                           recent_docs=recent_docs)

# ===================== DOKUMEN =====================
@app.route("/dokumen", methods=["GET", "POST"])
def dokumen():
    search = request.args.get("search", "")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM kategori")
    kategori = cursor.fetchall()
    cursor.execute("SELECT * FROM jenis")
    jenis = cursor.fetchall()

    query = """
        SELECT d.*, k.nama AS kategori, j.nama AS jenis
        FROM dokumen d
        LEFT JOIN kategori k ON d.kategori_id = k.id
        LEFT JOIN jenis j ON d.jenis_id = j.id
    """
    params = []

    if search:
        query += """ WHERE 
            d.nama_pemilik LIKE %s OR
            d.nama_perusahaan LIKE %s OR
            d.nomor_surat LIKE %s OR
            d.alamat LIKE %s OR
            k.nama LIKE %s OR
            j.nama LIKE %s
        """
        params = [f"%{search}%"] * 6

    query += " ORDER BY d.tgl_upload DESC"
    cursor.execute(query, params)
    dokumen = cursor.fetchall()

    cursor.close()
    conn.close()
    return render_template("dokumen.html", dokumen=dokumen, kategori=kategori, jenis=jenis, search=search)

@app.route("/form_tambah_dokumen", methods=["GET"])
def form_tambah_dokumen():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM kategori")
    kategori = cursor.fetchall()
    cursor.execute("SELECT * FROM jenis")
    jenis = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("form_tambah_dokumen.html", kategori=kategori, jenis=jenis)

# =================================
# Route Tambah Dokumen
# =================================
@app.route("/tambah_dokumen", methods=["POST"])
def tambah_dokumen():
    nama_pemilik = request.form["nama_pemilik"]
    nama_perusahaan = request.form["nama_perusahaan"]
    nomor_surat = request.form["nomor_surat"]
    tahun = request.form["tahun"]
    alamat = request.form["alamat"]
    kategori_id = request.form["kategori_id"]
    jenis_id = request.form["jenis_id"] or None

    file_url = None  # default

    file = request.files.get("file")
    if file and file.filename != "":
        local_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(local_path)

        drive_service = get_drive_service()
        if not drive_service:
            return redirect(url_for("authorize"))  # login dulu

        try:
            file_id, webViewLink = upload_to_drive(local_path, file.filename)
            file_url = webViewLink
            print("✅ Uploaded to Drive:", webViewLink)
        finally:
            pass
            # try:
            #     os.remove(local_path)
            # except PermissionError:
            #     print(f"⚠ File {local_path} tidak bisa dihapus (masih digunakan).")

    # Simpan data ke database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO dokumen 
        (nama_pemilik, nama_perusahaan, nomor_surat, tahun, alamat, kategori_id, jenis_id, file_url, tgl_upload)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,NOW())
        """,
        (nama_pemilik, nama_perusahaan, nomor_surat, tahun, alamat, kategori_id, jenis_id, file_url),
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("✅ Dokumen berhasil ditambahkan dan diupload ke Google Drive!", "success")
    return redirect(url_for("dokumen"))

@app.route("/edit_dokumen/<int:id>", methods=["GET", "POST"])
def edit_dokumen(id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == "POST":
        nama_pemilik = request.form["nama_pemilik"]
        nama_perusahaan = request.form["nama_perusahaan"]
        nomor_surat = request.form["nomor_surat"]
        alamat = request.form["alamat"]
        kategori_id = request.form.get("kategori_id")
        jenis_id = request.form.get("jenis_id")

        file = request.files.get("file")
        file_path = None
        file_name = None

        if file and file.filename:
            file_name = file.filename
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], file_name)
            file.save(file_path)

            # Update dengan file baru
            cursor.execute("""
                UPDATE dokumen
                SET nama_pemilik=%s, nama_perusahaan=%s, nomor_surat=%s, alamat=%s,
                    kategori_id=%s, jenis_id=%s, file_path=%s, file_name=%s
                WHERE id=%s
            """, (nama_pemilik, nama_perusahaan, nomor_surat, alamat,
                  kategori_id, jenis_id, file_path, file_name, id))
        else:
            # Update tanpa ubah file
            cursor.execute("""
                UPDATE dokumen
                SET nama_pemilik=%s, nama_perusahaan=%s, nomor_surat=%s, alamat=%s,
                    kategori_id=%s, jenis_id=%s
                WHERE id=%s
            """, (nama_pemilik, nama_perusahaan, nomor_surat, alamat,
                  kategori_id, jenis_id, id))

        conn.commit()
        cursor.close()
        conn.close()
        flash("✅ Dokumen berhasil diperbarui!", "success")
        return redirect(url_for("dokumen"))

    # Ambil data dokumen
    cursor.execute("SELECT * FROM dokumen WHERE id=%s", (id,))
    dokumen = cursor.fetchone()

    # Ambil semua kategori
    cursor.execute("SELECT * FROM kategori")
    kategori = cursor.fetchall()

    # Ambil jenis sesuai kategori dokumen
    cursor.execute("SELECT * FROM jenis WHERE kategori_id=%s", (dokumen["kategori_id"],))
    jenis = cursor.fetchall()

    cursor.close()
    conn.close()
    return render_template("edit_dokumen.html", dokumen=dokumen, kategori=kategori, jenis=jenis)

@app.route("/dokumen/hapus/<int:id>")
def hapus_dokumen(id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT file_path FROM dokumen WHERE id=%s", (id,))
    dok = cursor.fetchone()

    if dok and dok["file_path"]:
        # Pastikan path file lengkap
        file_path = os.path.join(app.root_path, dok["file_path"])
        if os.path.exists(file_path):
            os.remove(file_path)

    cursor.execute("DELETE FROM dokumen WHERE id=%s", (id,))
    conn.commit()
    cursor.close()
    conn.close()

    flash("🗑️ Dokumen berhasil dihapus!", "info")
    return redirect(url_for("dokumen"))

@app.route("/dokumen/download/<int:id>")
def download_dokumen(id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT file_path, file_name FROM dokumen WHERE id=%s", (id,))
    dok = cursor.fetchone()
    cursor.close()
    conn.close()

    if dok and dok["file_path"] and os.path.exists(dok["file_path"]):
        return send_file(
            dok["file_path"],
            as_attachment=True,
            download_name=dok["file_name"] if dok["file_name"] else os.path.basename(dok["file_path"])
        )
    return "❌ File tidak ditemukan", 404

# ===================== KATEGORI =====================
@app.route("/kategori")
def kategori():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Ambil semua kategori beserta jumlah jenis
    cursor.execute("""
        SELECT k.id, k.nama, COUNT(d.id) as jumlah
        FROM kategori k
        LEFT JOIN dokumen d ON d.kategori_id = k.id
        GROUP BY k.id
    """)

    kategori = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("kategori.html", kategori=kategori)


@app.route("/kategori/<int:id>")
def detail_kategori(id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM kategori WHERE id=%s", (id,))
    kategori = cursor.fetchone()

    cursor.execute("SELECT * FROM jenis WHERE kategori_id=%s", (id,))
    jenis = cursor.fetchall()

    cursor.close()
    conn.close()

    if not kategori:
        flash("Kategori tidak ditemukan", "danger")
        return redirect(url_for("kategori"))
    
    return render_template("detail_kategori.html", kategori=kategori, jenis=jenis)

@app.route("/kategori/form_tambah")
def form_tambah_kategori():
    return render_template("tambah_kategori.html")

@app.route("/kategori/tambah", methods=["POST"])
def tambah_kategori():
    nama = request.form["nama"]
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO kategori (nama) VALUES (%s)", (nama,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("✅ Kategori berhasil ditambahkan!", "success")
    return redirect(url_for("kategori"))

@app.route("/kategori/edit/<int:id>", methods=["POST"])
def edit_kategori(id):
    nama = request.form["nama"]
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE kategori SET nama=%s WHERE id=%s", (nama, id))
    conn.commit()
    cursor.close()
    conn.close()
    flash("✏️ Kategori berhasil diupdate!", "success")
    return redirect(url_for("kategori"))

@app.route("/kategori/hapus/<int:id>")
def hapus_kategori(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM kategori WHERE id=%s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("🗑️ Kategori dihapus!", "info")
    return redirect(url_for("kategori"))

# ===================== JENIS =====================
@app.route("/jenis/tambah", methods=["POST"])
def tambah_jenis():
    nama = request.form["nama"]
    kategori_id = request.form["kategori_id"]
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO jenis (nama, kategori_id) VALUES (%s, %s)", (nama, kategori_id))
    conn.commit()
    cursor.close()
    conn.close()
    flash("✅ Jenis berhasil ditambahkan ke kategori!", "success")
    return redirect(url_for("kategori"))

@app.route("/jenis/hapus/<int:id>")
def hapus_jenis(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM jenis WHERE id = %s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("🗑️ Jenis berhasil dihapus!", "warning")
    return redirect(url_for("kategori"))

@app.route("/jenis/edit/<int:id>", methods=["GET", "POST"])
def edit_jenis(id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == "POST":
        nama = request.form["nama"]
        cursor.execute("UPDATE jenis SET nama = %s WHERE id = %s", (nama, id))
        conn.commit()
        cursor.close()
        conn.close()
        flash("✏️ Jenis berhasil diperbarui!", "success")
        return redirect(url_for("kategori"))

    # Ambil data jenis untuk form edit
    cursor.execute("SELECT * FROM jenis WHERE id = %s", (id,))
    jenis = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template("edit_jenis.html", jenis=jenis)

@app.route("/get_jenis/<int:kategori_id>")
def get_jenis(kategori_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM jenis WHERE kategori_id = %s", (kategori_id,))
    jenis = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(jenis)

# ======= Helper cek image =======
def is_image(filename):
    ext = os.path.splitext(filename)[1].lower()
    return ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']

# ===================== TENTANG =====================
@app.route("/tentang")
def tentang():
    return render_template("tentang.html")

# ===================== FILE MANAGER =====================
@app.route("/file_manager")
def file_manager():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    files = []
    for f in os.listdir(app.config["UPLOAD_FOLDER"]):
        path = os.path.join(app.config["UPLOAD_FOLDER"], f)
        
        if os.path.isfile(path):  # pastikan file, bukan folder
            size = os.path.getsize(path)  # ukuran (bytes)
            mtime = os.path.getmtime(path)  # last modified timestamp
            date = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")

            files.append({
                "name": f,
                "path": path,
                "is_image": is_image(f),
                "size": size,
                "date": date
            })
    
    # Ambil info dokumen dari database untuk sinkronisasi hapus
    cursor.execute("SELECT file_name FROM dokumen")
    dokumen_files = [row['file_name'] for row in cursor.fetchall()]
    
    cursor.close()
    conn.close()
    
    return render_template("file_manager.html", files=files, dokumen_files=dokumen_files)

@app.route("/file_manager/hapus/<filename>")
def hapus_file(filename):
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    
    # Hapus file fisik
    if os.path.exists(path):
        os.remove(path)
    
    # Hapus record dokumen di database jika ada
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM dokumen WHERE file_name=%s", (filename,))
    conn.commit()
    cursor.close()
    conn.close()

    flash(f"🗑️ File '{filename}' berhasil dihapus!", "info")
    return redirect(url_for("file_manager"))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory('uploads', filename)

# ===================== CONTEXT PROCESSOR =====================
@app.context_processor
def inject_now():
    return {'current_year': datetime.now().year}

@app.route("/profil")
def profil():
    # Contoh data admin (bisa ambil dari database jika ingin dinamis)
    admin = {
        "nama": "Administrator",
        "email": "dpmptsp_kupang@gmail.com",
        "telepon": "0812-4630-2986"
    }
    return render_template("profil.html", admin=admin)


# ===================== RUN =====================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

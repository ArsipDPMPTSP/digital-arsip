from werkzeug.security import generate_password_hash
import mysql.connector

# ====== KONFIGURASI DATABASE ======
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "arsip_db"
}

# ====== DATA RESET ======
username_admin = input("Masukkan username admin: ")
password_baru = input("Masukkan password baru: ")

# Generate hash password
password_hash = generate_password_hash(password_baru)

# ====== UPDATE DATABASE ======
try:
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    query = "UPDATE admin SET password=%s WHERE username=%s"
    cursor.execute(query, (password_hash, username_admin))
    conn.commit()

    if cursor.rowcount > 0:
        print(f"✅ Password untuk '{username_admin}' berhasil di-reset!")
    else:
        print(f"❌ Username '{username_admin}' tidak ditemukan di database.")

    cursor.close()
    conn.close()

except mysql.connector.Error as err:
    print("❌ Terjadi error:", err)

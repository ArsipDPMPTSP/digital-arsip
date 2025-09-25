import os
from werkzeug.security import generate_password_hash
import mysql.connector
from dotenv import load_dotenv

# ====== BACA ENVIRONMENT VARIABLES DARI FILE .ENV ======
load_dotenv()  # otomatis membaca .env di folder yang sama

# ====== KONFIGURASI DATABASE ======
def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("MYSQLHOST"),
        user=os.getenv("MYSQLUSER"),
        password=os.getenv("MYSQLPASSWORD"),
        database=os.getenv("MYSQLDATABASE"),
        port=int(os.getenv("MYSQLPORT", 3306))  # default 3306 jika tidak ada
    )

# ====== DATA RESET ======
username_admin = input("Masukkan username admin: ")
password_baru = input("Masukkan password baru: ")

# Generate hash password
password_hash = generate_password_hash(password_baru)

# ====== UPDATE DATABASE ======
try:
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "UPDATE admin SET password=%s WHERE username=%s"
    cursor.execute(query, (password_hash, username_admin))
    conn.commit()

    if cursor.rowcount > 0:
        print(f"✅ Password untuk '{username_admin}' berhasil di-reset!")
    else:
        print(f"❌ Username '{username_admin}' tidak ditemukan di database.")

except mysql.connector.Error as err:
    print("❌ Terjadi error:", err)

finally:
    if 'cursor' in locals():
        cursor.close()
    if 'conn' in locals():
        conn.close()

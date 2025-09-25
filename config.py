import os

class Config:
    SECRET_KEY = 'your-secret-key-here'
    # Database configuration
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = ''
    MYSQL_DB = 'arsip_db'
    # Google Drive API configuration
    GOOGLE_DRIVE_CREDENTIALS = 'credentials.json'
    GOOGLE_DRIVE_FOLDER_ID = '1Z4vOmCj2PJKOYZqOzajOPCJoPAOKwxTg?usp=share_link'
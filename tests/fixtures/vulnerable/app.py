# FIXTURE UJI — semua nilai di berkas ini SINTETIS dan tidak berfungsi.
# Tujuannya memverifikasi bahwa `keris audit` benar-benar mendeteksi pola
# yang seharusnya. Jangan pakai berkas ini sebagai contoh kode.

import hashlib
import os

import requests

AWS_ACCESS_KEY_ID = "AKIAQWERTYUIOPASDFGH"
GITHUB_TOKEN = "ghp_9fXk2mQz7pLw4nRt8vBc3dHs6jYe1aUo5iKp"
db_password = "Tr0ub4dor&3xKp9"


def fetch(url):
    # Verifikasi sertifikat TLS dimatikan
    return requests.get(url, verify=False)


def run(cmd):
    # Argumen masuk langsung ke shell
    os.system("ls " + cmd)


def find_user(cursor, name):
    # Query disusun dengan konkatenasi string
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")


def digest(data):
    # Hash lemah
    return hashlib.md5(data)

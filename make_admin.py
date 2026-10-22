"""Promote one existing account to the initial super admin.

Run once with the production database configured:
    python make_admin.py
"""
from getpass import getpass

from app import app, db, User


with app.app_context():
    existing_super_admin = User.query.filter_by(role="super_admin").first()
    email = input("Email akun super admin yang sudah terdaftar: ").strip().lower()
    user = User.query.filter_by(email=email).first()
    if user is None:
        raise SystemExit("Email tidak ditemukan. Daftarkan akun tersebut terlebih dahulu.")
    if existing_super_admin and existing_super_admin.id != user.id:
        raise SystemExit(
            "Super admin sudah dikonfigurasi. Promosi awal hanya boleh dilakukan sekali."
        )

    print(f"Akun yang dipilih: {user.name} <{user.email}>")
    confirmation = getpass("Ketik PROMOSIKAN untuk menetapkan akun ini sebagai super admin: ")
    if confirmation != "PROMOSIKAN":
        raise SystemExit("Promosi dibatalkan.")

    user.role = "super_admin"
    user.approval_status = "approved"
    db.session.commit()
    print(f"Berhasil. {user.name} sekarang menjadi super admin.")

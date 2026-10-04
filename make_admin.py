"""
Jalankan ini SEKALI untuk menjadikan sebuah akun sebagai admin.
Cara pakai: python make_admin.py
"""
from app import app, db, User

with app.app_context():
    email = input("Email akun yang mau dijadikan admin: ").strip()
    user = User.query.filter_by(email=email).first()
    if user:
        user.role = 'admin'
        db.session.commit()
        print(f"Berhasil. {user.name} ({user.email}) sekarang admin.")
    else:
        print("Email tidak ditemukan. Pastikan sudah register dulu lewat /register.")

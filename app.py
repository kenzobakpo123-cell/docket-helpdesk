from flask import Flask, render_template, redirect, url_for, request, flash, make_response, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from sqlalchemy import case, func, inspect, or_, text
from sqlalchemy.exc import SQLAlchemyError
from requests.exceptions import RequestException
import hmac
import csv
import io
import json
import os
import re
import secrets
from urllib.parse import urlsplit

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['VAPID_PUBLIC_KEY'] = os.getenv('VAPID_PUBLIC_KEY', '')
app.config['VAPID_PRIVATE_KEY'] = os.getenv('VAPID_PRIVATE_KEY', '')
app.config['VAPID_CLAIMS_EMAIL'] = os.getenv('VAPID_CLAIMS_EMAIL', '')

# ===== KEAMANAN COOKIE SESSION =====
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

limiter = Limiter(get_remote_address, app=app, default_limits=[])

ALLOWED_STATUSES = {'open', 'in_progress', 'resolved', 'closed'}
ALLOWED_PRIORITIES = {'low', 'medium', 'high'}
ALLOWED_CATEGORIES = {'Hardware', 'Software', 'Jaringan', 'Akun & Akses', 'Lainnya'}
SLA_TARGET_HOURS = {'high': 4, 'medium': 24, 'low': 72}
EMAIL_PATTERN = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
HELP_ARTICLES = [
    {
        'id': 'wifi',
        'category': 'Jaringan',
        'title': 'Tidak bisa terhubung ke Wi-Fi kantor',
        'summary': 'Langkah awal untuk memeriksa koneksi jaringan di laptop atau ponsel.',
        'steps': [
            'Pastikan mode pesawat sudah dimatikan dan Wi-Fi perangkat aktif.',
            'Putuskan koneksi Wi-Fi kantor, lalu sambungkan kembali menggunakan akun kantor.',
            'Coba buka situs internal dan situs publik untuk memastikan apakah gangguan hanya terjadi pada satu layanan.',
            'Jika masih gagal, catat nama jaringan dan pesan kesalahan yang muncul sebelum membuat tiket.',
        ],
        'ticket_title': 'Tidak bisa terhubung ke Wi-Fi kantor',
    },
    {
        'id': 'password',
        'category': 'Akun & Akses',
        'title': 'Lupa kata sandi atau akun terkunci',
        'summary': 'Periksa metode pemulihan akun sebelum meminta bantuan admin.',
        'steps': [
            'Pastikan alamat email kantor yang digunakan sudah benar.',
            'Gunakan halaman pemulihan kata sandi resmi perusahaan jika tersedia.',
            'Jangan kirim kata sandi atau kode verifikasi melalui tiket.',
            'Jika akun tetap terkunci, sertakan nama layanan dan pesan kesalahan saat membuat tiket.',
        ],
        'ticket_title': 'Bantuan akses akun kantor',
    },
    {
        'id': 'printer',
        'category': 'Hardware',
        'title': 'Printer kantor tidak mencetak',
        'summary': 'Periksa koneksi, antrean, dan kertas sebelum melapor.',
        'steps': [
            'Pastikan printer menyala dan tidak menampilkan lampu atau pesan kesalahan.',
            'Periksa kertas dan tinta/toner, lalu pastikan komputer memilih printer yang benar.',
            'Hapus dokumen yang macet di antrean cetak dan coba cetak satu halaman uji.',
            'Sertakan nama atau lokasi printer serta pesan kesalahan jika masalah berlanjut.',
        ],
        'ticket_title': 'Printer kantor tidak bisa mencetak',
    },
    {
        'id': 'software',
        'category': 'Software',
        'title': 'Aplikasi kantor bermasalah',
        'summary': 'Kumpulkan informasi aplikasi dan pesan kesalahan agar tim IT lebih cepat membantu.',
        'steps': [
            'Tutup dan buka kembali aplikasi, lalu pastikan perangkat sudah tersambung ke internet.',
            'Catat nama aplikasi, kapan masalah mulai terjadi, dan langkah yang memunculkannya.',
            'Ambil tangkapan layar pesan kesalahan, tetapi tutupi informasi rahasia terlebih dahulu.',
            'Jangan memasang aplikasi dari sumber tidak resmi; minta tim IT jika perlu instalasi.',
        ],
        'ticket_title': 'Bantuan aplikasi kantor',
    },
]

def _utc_now():
    # Keep timestamps naive because the existing database columns store naive UTC.
    return datetime.now(timezone.utc).replace(tzinfo=None)

# ===== MODELS =====

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # 'admin' atau 'user'
    approval_status = db.Column(db.String(20), nullable=False, default='approved')

    tickets_created = db.relationship(
        'Ticket',
        foreign_keys='Ticket.user_id',
        backref='creator',
        lazy=True
    )
    tickets_assigned = db.relationship(
        'Ticket',
        foreign_keys='Ticket.assigned_to_id',
        backref='assignee',
        lazy=True
    )

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    priority = db.Column(db.String(20), nullable=False, default='medium')
    status = db.Column(db.String(20), nullable=False, default='open')
    created_at = db.Column(db.DateTime, default=_utc_now)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    comments = db.relationship('Comment', backref='ticket', lazy=True, cascade='all, delete-orphan')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=_utc_now)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User')

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id', ondelete='SET NULL'),
        nullable=True,
    )
    actor_name = db.Column(db.String(100), nullable=False)
    actor_email = db.Column(db.String(150), nullable=False)
    action = db.Column(db.String(40), nullable=False, index=True)
    description = db.Column(db.String(300), nullable=False)
    target_type = db.Column(db.String(40), nullable=True)
    target_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_utc_now, index=True)

class PushSubscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    endpoint = db.Column(db.String(2048), nullable=False, unique=True)
    p256dh = db.Column(db.String(256), nullable=False)
    auth = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_utc_now)
    user = db.relationship('User')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def record_activity(action, description, target_type=None, target_id=None, actor=None):
    activity_actor = actor or current_user
    db.session.add(AuditLog(
        actor_id=activity_actor.id if activity_actor.is_authenticated else None,
        actor_name=activity_actor.name if activity_actor.is_authenticated else 'Pengunjung',
        actor_email=activity_actor.email if activity_actor.is_authenticated else '',
        action=action,
        description=description,
        target_type=target_type,
        target_id=target_id,
    ))

def push_is_configured():
    return all((
        app.config['VAPID_PUBLIC_KEY'],
        app.config['VAPID_PRIVATE_KEY'],
        app.config['VAPID_CLAIMS_EMAIL'],
    ))

def notify_user(user_id, title, body, path):
    if not push_is_configured():
        return

    from pywebpush import WebPushException, webpush

    subscriptions = PushSubscription.query.filter_by(user_id=user_id).all()
    for subscription in subscriptions:
        try:
            webpush(
                subscription_info={
                    'endpoint': subscription.endpoint,
                    'keys': {'p256dh': subscription.p256dh, 'auth': subscription.auth},
                },
                data=json.dumps({'title': title, 'body': body, 'path': path}),
                vapid_private_key=app.config['VAPID_PRIVATE_KEY'],
                vapid_claims={'sub': f"mailto:{app.config['VAPID_CLAIMS_EMAIL']}"},
                timeout=10,
            )
        except (WebPushException, RequestException, OSError, ValueError) as error:
            response = (
                error.response
                if isinstance(error, (WebPushException, RequestException))
                else None
            )
            status_code = response.status_code if response is not None else None
            if status_code in {404, 410}:
                db.session.delete(subscription)
                app.logger.info('Removed expired push subscription for user %s', user_id)
            else:
                app.logger.warning(
                    'Web push failed for user %s with status %s (%s).',
                    user_id,
                    status_code,
                    type(error).__name__,
                )
    db.session.commit()

# ===== SECURITY HEADERS =====
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    return response

@app.context_processor
def inject_csrf_token():
    token = session.get('_csrf_token')
    if token is None:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    pending_user_count = (
        User.query.filter_by(approval_status='pending').count()
        if current_user.is_authenticated and current_user.role == 'super_admin'
        else 0
    )
    return {
        'csrf_token': token,
        'pending_user_count': pending_user_count,
        'push_public_key': app.config['VAPID_PUBLIC_KEY'],
        'push_configured': push_is_configured(),
    }

def valid_csrf_token():
    submitted = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token', '')
    expected = session.get('_csrf_token', '')
    return bool(submitted and expected and hmac.compare_digest(submitted, expected))

@app.before_request
def protect_post_requests():
    if request.method == 'POST' and not valid_csrf_token():
        return 'Permintaan tidak valid. Muat ulang halaman lalu coba lagi.', 400

@app.route('/service-worker.js')
def service_worker():
    response = send_from_directory(app.static_folder, 'service-worker.js')
    response.headers['Service-Worker-Allowed'] = '/'
    response.headers['Cache-Control'] = 'no-cache'
    return response

@app.route('/push/subscribe', methods=['POST'])
@login_required
def push_subscribe():
    if not push_is_configured():
        return jsonify(error='Notifikasi push belum dikonfigurasi di server.'), 503

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error='Data langganan tidak valid.'), 400
    endpoint = payload.get('endpoint')
    keys = payload.get('keys')
    try:
        parsed_endpoint = urlsplit(endpoint) if isinstance(endpoint, str) else None
        hostname = parsed_endpoint.hostname if parsed_endpoint else None
        valid_port = parsed_endpoint is not None and parsed_endpoint.port in {None, 443}
    except ValueError:
        hostname = None
        valid_port = False
    push_hosts = (
        'fcm.googleapis.com',
        'push.services.mozilla.com',
        'web.push.apple.com',
        'notify.windows.com',
        'wns.windows.com',
    )
    if (
        not isinstance(endpoint, str)
        or len(endpoint) > 2048
        or parsed_endpoint is None
        or parsed_endpoint.scheme != 'https'
        or not hostname
        or not any(hostname == host or hostname.endswith(f'.{host}') for host in push_hosts)
        or not valid_port
        or parsed_endpoint.username is not None
        or parsed_endpoint.password is not None
        or parsed_endpoint.fragment
        or not isinstance(keys, dict)
        or not isinstance(keys.get('p256dh'), str)
        or not isinstance(keys.get('auth'), str)
        or len(keys['p256dh']) > 256
        or len(keys['auth']) > 256
        or not keys['p256dh']
        or not keys['auth']
    ):
        return jsonify(error='Data langganan tidak valid.'), 400

    subscription = PushSubscription.query.filter_by(endpoint=endpoint).first()
    if subscription is None:
        subscription = PushSubscription(endpoint=endpoint)
        db.session.add(subscription)
    subscription.user_id = current_user.id
    subscription.p256dh = keys['p256dh']
    subscription.auth = keys['auth']
    db.session.commit()
    return jsonify(message='Notifikasi berhasil diaktifkan pada perangkat ini.'), 201

@app.route('/push/unsubscribe', methods=['POST'])
@login_required
def push_unsubscribe():
    payload = request.get_json(silent=True)
    endpoint = payload.get('endpoint') if isinstance(payload, dict) else None
    if not isinstance(endpoint, str) or len(endpoint) > 2048:
        return jsonify(error='Data langganan tidak valid.'), 400

    subscription = PushSubscription.query.filter_by(
        endpoint=endpoint,
        user_id=current_user.id,
    ).first()
    if subscription is not None:
        db.session.delete(subscription)
        db.session.commit()
    return jsonify(message='Notifikasi dinonaktifkan pada perangkat ini.')

@app.before_request
def expire_unapproved_sessions():
    if current_user.is_authenticated and current_user.approval_status != 'approved':
        logout_user()
        flash('Akses akun ini sudah dinonaktifkan. Hubungi super admin.')
        return redirect(url_for('login'))

# ===== ROUTES =====

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register():
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''

        if not name or len(name) > 100 or not email or len(email) > 150 or not password:
            flash('Semua kolom wajib diisi.')
            return redirect(url_for('register'))

        if not EMAIL_PATTERN.match(email):
            flash('Format email tidak valid.')
            return redirect(url_for('register'))

        if len(password) < 8:
            flash('Password minimal 8 karakter.')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email sudah terdaftar, silakan login.')
            return redirect(url_for('register'))

        new_user = User(
            name=name,
            email=email,
            password_hash=generate_password_hash(password),
            role='user',
            approval_status='pending',
        )
        db.session.add(new_user)
        db.session.flush()
        record_activity(
            'account_registered',
            f'{new_user.name} mendaftar dan menunggu persetujuan.',
            'user',
            new_user.id,
            actor=new_user,
        )
        db.session.commit()
        flash('Pendaftaran berhasil. Tunggu persetujuan super admin sebelum masuk.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            if user.approval_status == 'pending':
                flash('Akun masih menunggu persetujuan super admin.')
                return redirect(url_for('login'))
            if user.approval_status != 'approved':
                flash('Akses akun ini belum aktif. Hubungi super admin.')
                return redirect(url_for('login'))
            session['_csrf_token'] = secrets.token_urlsafe(32)
            login_user(user)
            record_activity('login', 'Berhasil masuk ke portal.')
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            flash('Email atau password salah.')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    record_activity('logout', 'Keluar dari portal.')
    db.session.commit()
    logout_user()
    session.pop('_csrf_token', None)
    return redirect(url_for('login'))

@app.route('/superadmin/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'super_admin':
        flash('Hanya super admin yang dapat mengatur akun dan peran.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        if not valid_csrf_token():
            flash('Permintaan tidak valid. Muat ulang halaman lalu coba lagi.')
            return redirect(url_for('manage_users'))

        try:
            user_id = int(request.form.get('user_id', ''))
        except ValueError:
            flash('Akun yang dipilih tidak valid.')
            return redirect(url_for('manage_users'))

        user = db.session.get(User, user_id)
        if user is None:
            flash('Akun tidak ditemukan.')
            return redirect(url_for('manage_users'))
        if user.id == current_user.id:
            flash('Peran dan status akun super admin yang sedang digunakan tidak dapat diubah.')
            return redirect(url_for('manage_users'))

        approval_status = request.form.get('approval_status', '')
        role = request.form.get('role', '')
        if approval_status not in {'pending', 'approved', 'rejected'} or role not in {'user', 'admin'}:
            flash('Status persetujuan atau peran tidak valid.')
            return redirect(url_for('manage_users'))

        previous_status = user.approval_status
        previous_role = user.role
        user.approval_status = approval_status
        user.role = role
        if previous_status != approval_status or previous_role != role:
            status_labels = {'pending': 'menunggu', 'approved': 'aktif', 'rejected': 'ditolak'}
            role_labels = {'user': 'karyawan', 'admin': 'tim IT', 'super_admin': 'super admin'}
            record_activity(
                'account_access_changed',
                (
                    f'{user.name}: status {status_labels[previous_status]} menjadi '
                    f'{status_labels[approval_status]}; peran {role_labels.get(previous_role, previous_role)} '
                    f'menjadi {role_labels[role]}.'
                ),
                'user',
                user.id,
            )
        db.session.commit()
        if approval_status == 'approved' and previous_status != 'approved':
            notify_user(
                user.id,
                'Akun Docket disetujui',
                'Akunmu sudah aktif. Kamu dapat masuk ke portal.',
                url_for('login'),
            )
        flash(f'Akun {user.name} diperbarui.')
        return redirect(url_for('manage_users'))

    users = User.query.order_by(
        case(
            (User.approval_status == 'pending', 0),
            else_=1,
        ),
        User.name.asc(),
    ).all()
    pending_count = User.query.filter_by(approval_status='pending').count()
    return render_template('manage_users.html', users=users, pending_count=pending_count)

@app.route('/superadmin/activity')
@login_required
def activity_log():
    if current_user.role != 'super_admin':
        flash('Hanya super admin yang dapat melihat aktivitas.')
        return redirect(url_for('dashboard'))

    action_labels = {
        'login': 'Masuk',
        'logout': 'Keluar',
        'account_registered': 'Pendaftaran',
        'account_access_changed': 'Akses akun',
        'ticket_created': 'Laporan dibuat',
        'ticket_comment': 'Komentar',
        'ticket_updated': 'Tiket diperbarui',
    }
    action = request.args.get('action', '')
    if action not in action_labels:
        action = ''
    actor = (request.args.get('actor') or '').strip()[:100]
    query = AuditLog.query
    if action:
        query = query.filter_by(action=action)
    if actor:
        query = query.filter(AuditLog.actor_name.ilike(f'%{actor}%'))

    total_count = query.count()
    try:
        page = max(1, int(request.args.get('page', '1')))
    except ValueError:
        flash('Nomor halaman tidak valid.')
        page = 1
    page_size = 25
    page_count = max(1, (total_count + page_size - 1) // page_size)
    page = min(page, page_count)
    activities = (
        query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return render_template(
        'activity_log.html',
        activities=activities,
        action_labels=action_labels,
        selected_action=action,
        actor=actor,
        page=page,
        page_count=page_count,
        total_count=total_count,
    )

@app.route('/dashboard')
@login_required
def dashboard():
    is_it_staff = current_user.role in {'admin', 'super_admin'}
    base_query, filtered_query, categories, assignees, filters = get_dashboard_ticket_queries()
    now = _utc_now()
    status_counts = dict(
        base_query.with_entities(Ticket.status, func.count(Ticket.id))
        .group_by(Ticket.status)
        .all()
    )
    total_tickets = sum(status_counts.values())
    overdue_conditions = [
        (Ticket.priority == priority) & (
            Ticket.created_at < now - timedelta(hours=target_hours)
        )
        for priority, target_hours in SLA_TARGET_HOURS.items()
    ]
    overdue_count = base_query.filter(
        Ticket.status.in_(['open', 'in_progress']),
        or_(*overdue_conditions),
    ).count()
    filtered_count = filtered_query.count()

    try:
        page = max(1, int(request.args.get('page', '1')))
    except ValueError:
        flash('Nomor halaman tidak valid.')
        page = 1

    page_size = 10
    page_count = max(1, (filtered_count + page_size - 1) // page_size)
    page = min(page, page_count)
    sort = filters['sort']
    tickets = (
        filtered_query.order_by(*ticket_sort_columns()[sort])
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return render_template(
        'dashboard.html',
        tickets=tickets,
        total_tickets=total_tickets,
        overdue_count=overdue_count,
        is_it_staff=is_it_staff,
        filtered_count=filtered_count,
        status_counts=status_counts,
        categories=categories,
        assignees=assignees,
        filters=filters,
        page=page,
        page_count=page_count,
        sla_by_ticket={
            ticket.id: get_ticket_sla(ticket, now)
            for ticket in tickets
        },
    )

@app.route('/tickets/export')
@login_required
def export_tickets():
    _, filtered_query, _, _, filters = get_dashboard_ticket_queries()
    tickets = filtered_query.order_by(*ticket_sort_columns()[filters['sort']]).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Nomor tiket',
        'Judul',
        'Kategori',
        'Prioritas',
        'Status',
        'Dibuat oleh',
        'Penanggung jawab',
        'Tanggal dibuat (UTC)',
        'Deskripsi',
    ])
    priority_labels = {'low': 'Rendah', 'medium': 'Sedang', 'high': 'Tinggi'}
    status_labels = {
        'open': 'Terbuka',
        'in_progress': 'Diproses',
        'resolved': 'Selesai',
        'closed': 'Ditutup',
    }
    for ticket in tickets:
        writer.writerow([
            _safe_csv_cell(f'#{ticket.id:04d}'),
            _safe_csv_cell(ticket.title),
            _safe_csv_cell(ticket.category),
            priority_labels.get(ticket.priority, ticket.priority),
            status_labels.get(ticket.status, ticket.status),
            _safe_csv_cell(ticket.creator.name),
            _safe_csv_cell(ticket.assignee.name if ticket.assignee else 'Belum ada'),
            ticket.created_at.strftime('%Y-%m-%d %H:%M') if ticket.created_at else '',
            _safe_csv_cell(ticket.description),
        ])

    response = make_response('\ufeff' + output.getvalue())
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    response.headers['Content-Disposition'] = (
        f'attachment; filename="docket-tickets-{_utc_now():%Y%m%d}.csv"'
    )
    return response

def get_dashboard_ticket_queries():
    ticket_query = Ticket.query
    if current_user.role not in {'admin', 'super_admin'}:
        ticket_query = ticket_query.filter_by(user_id=current_user.id)

    categories = [
        row[0]
        for row in ticket_query.with_entities(Ticket.category)
        .distinct()
        .order_by(Ticket.category.asc())
        .all()
    ]
    assignees = User.query.filter(
        User.role.in_(['admin', 'super_admin']),
        User.approval_status == 'approved',
    ).order_by(User.name.asc()).all()
    search = (request.args.get('q') or '').strip()
    status = request.args.get('status', '')
    category = request.args.get('category', '')
    priority = request.args.get('priority', '')
    assignee = request.args.get('assignee', '')
    sort = request.args.get('sort', 'newest')

    if len(search) > 100:
        flash('Kata pencarian maksimal 100 karakter.')
        search = ''
    if status and status not in ALLOWED_STATUSES:
        flash('Filter status tidak valid.')
        status = ''
    if category and category not in categories:
        flash('Filter kategori tidak valid.')
        category = ''
    if priority and priority not in {'low', 'medium', 'high'}:
        flash('Filter prioritas tidak valid.')
        priority = ''
    assignee_ids = {str(user.id) for user in assignees}
    if assignee and (
        current_user.role not in {'admin', 'super_admin'}
        or (assignee != 'unassigned' and assignee not in assignee_ids)
    ):
        flash('Filter penanggung jawab tidak valid.')
        assignee = ''
    if sort not in {'newest', 'oldest', 'priority', 'title'}:
        flash('Urutan tiket tidak valid.')
        sort = 'newest'

    filtered_query = ticket_query
    if search:
        escaped_search = search.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        search_pattern = f'%{escaped_search}%'
        search_conditions = [
            Ticket.title.ilike(search_pattern, escape='\\'),
            Ticket.description.ilike(search_pattern, escape='\\'),
            Ticket.category.ilike(search_pattern, escape='\\'),
            Ticket.creator.has(User.name.ilike(search_pattern, escape='\\')),
            Ticket.assignee.has(User.name.ilike(search_pattern, escape='\\')),
        ]
        if search.isdigit():
            search_conditions.append(Ticket.id == int(search))
        filtered_query = filtered_query.filter(or_(*search_conditions))
    if status:
        filtered_query = filtered_query.filter_by(status=status)
    if category:
        filtered_query = filtered_query.filter_by(category=category)
    if priority:
        filtered_query = filtered_query.filter_by(priority=priority)
    if assignee == 'unassigned':
        filtered_query = filtered_query.filter(Ticket.assigned_to_id.is_(None))
    elif assignee:
        filtered_query = filtered_query.filter_by(assigned_to_id=int(assignee))

    return (
        ticket_query,
        filtered_query,
        categories,
        assignees,
        {
            'q': search,
            'status': status,
            'category': category,
            'priority': priority,
            'assignee': assignee,
            'sort': sort,
        },
    )

def ticket_sort_columns():
    return {
        'newest': (Ticket.created_at.desc(), Ticket.id.desc()),
        'oldest': (Ticket.created_at.asc(), Ticket.id.asc()),
        'priority': (
            case(
                (Ticket.priority == 'high', 0),
                (Ticket.priority == 'medium', 1),
                else_=2,
            ),
            Ticket.created_at.desc(),
            Ticket.id.desc(),
        ),
        'title': (Ticket.title.asc(), Ticket.id.asc()),
    }

def _safe_csv_cell(value):
    text = str(value or '')
    if text.lstrip(' \t\r\n').startswith(('=', '+', '-', '@')):
        return "'" + text
    return text

def get_ticket_sla(ticket, now=None):
    if ticket.status in {'resolved', 'closed'}:
        return {'label': 'Selesai', 'state': 'complete', 'deadline': None}
    if ticket.created_at is None:
        return {'label': 'Target tidak tersedia', 'state': 'unknown', 'deadline': None}

    current_time = now or _utc_now()
    deadline = ticket.created_at + timedelta(
        hours=SLA_TARGET_HOURS.get(ticket.priority, SLA_TARGET_HOURS['medium'])
    )
    remaining = deadline - current_time
    if remaining.total_seconds() <= 0:
        elapsed = abs(remaining)
        if elapsed.days:
            label = f'Lewat {elapsed.days} hari'
        else:
            label = f'Lewat {max(1, int(elapsed.total_seconds() // 3600))} jam'
        return {'label': label, 'state': 'overdue', 'deadline': deadline}

    hours_left = max(1, int((remaining.total_seconds() + 3599) // 3600))
    return {
        'label': f'Sisa {hours_left} jam',
        'state': 'on-track',
        'deadline': deadline,
    }

@app.route('/ticket/new', methods=['GET', 'POST'])
@login_required
def new_ticket():
    if request.method == 'POST':
        title = (request.form.get('title') or '').strip()
        description = (request.form.get('description') or '').strip()
        category = request.form.get('category', '')
        priority = request.form.get('priority', '')
        if not title or len(title) > 150 or not description:
            flash('Judul (maksimal 150 karakter) dan deskripsi wajib diisi.')
            return redirect(url_for('new_ticket'))
        if category not in ALLOWED_CATEGORIES or priority not in ALLOWED_PRIORITIES:
            flash('Pilih kategori dan prioritas yang tersedia.')
            return redirect(url_for('new_ticket'))

        new_t = Ticket(
            title=title,
            category=category,
            priority=priority,
            description=description,
            user_id=current_user.id
        )
        db.session.add(new_t)
        db.session.flush()
        record_activity(
            'ticket_created',
            'Membuat laporan kendala baru.',
            'ticket',
            new_t.id,
        )
        db.session.commit()
        staff_ids = [
            staff_id for (staff_id,) in User.query.with_entities(User.id).filter(
                User.role.in_(['admin', 'super_admin']),
                User.approval_status == 'approved',
                User.id != current_user.id,
            ).all()
        ]
        for staff_id in staff_ids:
            notify_user(
                staff_id,
                'Laporan IT baru',
                'Ada laporan baru yang perlu ditinjau.',
                url_for('ticket_detail', ticket_id=new_t.id),
            )
        flash('Tiket berhasil dibuat.')
        return redirect(url_for('dashboard'))

    requested_category = request.args.get('category', '')
    requested_category = (
        requested_category if requested_category in ALLOWED_CATEGORIES else ''
    )
    requested_title = request.args.get('title', '').strip()[:150]
    return render_template(
        'new_ticket.html',
        categories=sorted(ALLOWED_CATEGORIES),
        selected_category=requested_category,
        requested_title=requested_title,
    )

@app.route('/help')
@login_required
def help_center():
    search = (request.args.get('q') or '').strip()[:100]
    searchable_articles = [
        article for article in HELP_ARTICLES
        if not search or search.casefold() in ' '.join([
            article['title'],
            article['summary'],
            article['category'],
            *article['steps'],
        ]).casefold()
    ]
    return render_template(
        'help_center.html',
        articles=searchable_articles,
        search=search,
    )

@app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def ticket_detail(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.role not in {'admin', 'super_admin'} and ticket.user_id != current_user.id:
        flash('Kamu tidak punya akses ke tiket ini.')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        if 'comment_content' in request.form:
            content = request.form.get('comment_content', '').strip()
            if content:
                db.session.add(Comment(content=content, ticket_id=ticket.id, user_id=current_user.id))
                record_activity(
                    'ticket_comment',
                    'Menambahkan komentar pada laporan.',
                    'ticket',
                    ticket.id,
                )
                db.session.commit()
                recipient_ids = {
                    ticket.user_id,
                    ticket.assigned_to_id,
                } - {None, current_user.id}
                for recipient_id in recipient_ids:
                    notify_user(
                        recipient_id,
                        'Pembaruan laporan IT',
                        'Ada komentar baru pada laporanmu.',
                        url_for('ticket_detail', ticket_id=ticket.id),
                    )
                flash('Komentar ditambahkan.')
        elif 'update_status' in request.form and current_user.role in {'admin', 'super_admin'}:
            previous_status = ticket.status
            previous_assignee_id = ticket.assigned_to_id
            previous_assignee_name = ticket.assignee.name if ticket.assignee else 'Belum ditugaskan'
            new_status = request.form.get('status')
            if new_status in ALLOWED_STATUSES:
                ticket.status = new_status
            else:
                flash('Status tidak valid.')
                return redirect(url_for('ticket_detail', ticket_id=ticket.id))

            assigned = request.form.get('assigned_to_id')
            if assigned:
                try:
                    assigned_id = int(assigned)
                    assigned_staff = User.query.filter(
                        User.id == assigned_id,
                        User.role.in_(['admin', 'super_admin']),
                        User.approval_status == 'approved',
                    ).first()
                    if assigned_staff:
                        ticket.assigned_to_id = assigned_id
                        new_assignee_name = assigned_staff.name
                    else:
                        flash('Staff tidak valid.')
                        return redirect(url_for('ticket_detail', ticket_id=ticket.id))
                except ValueError:
                    flash('Staff tidak valid.')
                    return redirect(url_for('ticket_detail', ticket_id=ticket.id))
            else:
                ticket.assigned_to_id = None
                new_assignee_name = 'Belum ditugaskan'

            changes = []
            if previous_status != ticket.status:
                status_labels = {
                    'open': 'terbuka',
                    'in_progress': 'diproses',
                    'resolved': 'selesai',
                    'closed': 'ditutup',
                }
                changes.append(
                    f'status {status_labels[previous_status]} menjadi {status_labels[ticket.status]}'
                )
            if previous_assignee_id != ticket.assigned_to_id:
                changes.append(
                    f'penanggung jawab {previous_assignee_name} menjadi {new_assignee_name}'
                )
            if changes:
                record_activity(
                    'ticket_updated',
                    f'Memperbarui laporan: {", ".join(changes)}.',
                    'ticket',
                    ticket.id,
                )
            db.session.commit()
            recipients = set()
            if previous_status != ticket.status and ticket.user_id != current_user.id:
                recipients.add(ticket.user_id)
            if previous_assignee_id != ticket.assigned_to_id:
                if ticket.user_id != current_user.id:
                    recipients.add(ticket.user_id)
                if previous_assignee_id is not None:
                    recipients.add(previous_assignee_id)
                if ticket.assigned_to_id is not None:
                    recipients.add(ticket.assigned_to_id)
            recipients.discard(current_user.id)
            for recipient_id in recipients:
                notify_user(
                    recipient_id,
                    'Laporan IT diperbarui',
                    'Status atau penanggung jawab laporanmu telah berubah.',
                    url_for('ticket_detail', ticket_id=ticket.id),
                )
            flash('Tiket diperbarui.')
        return redirect(url_for('ticket_detail', ticket_id=ticket.id))
    staff_list = (
        User.query.filter(
            User.role.in_(['admin', 'super_admin']),
            User.approval_status == 'approved',
        ).all()
        if current_user.role in {'admin', 'super_admin'}
        else []
    )
    return render_template(
        'ticket_detail.html',
        ticket=ticket,
        staff_list=staff_list,
        sla_info=get_ticket_sla(ticket),
    )

with app.app_context():
    db.create_all()
    user_columns = {column['name'] for column in inspect(db.engine).get_columns('user')}
    if 'approval_status' not in user_columns:
        quoted_table = db.engine.dialect.identifier_preparer.quote(User.__tablename__)
        quoted_column = db.engine.dialect.identifier_preparer.quote('approval_status')
        try:
            with db.engine.begin() as connection:
                connection.execute(text(
                    f"ALTER TABLE {quoted_table} ADD COLUMN {quoted_column} "
                    "VARCHAR(20) NOT NULL DEFAULT 'approved'"
                ))
        except SQLAlchemyError:
            refreshed_columns = {
                column['name'] for column in inspect(db.engine).get_columns('user')
            }
            if 'approval_status' not in refreshed_columns:
                raise

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False)
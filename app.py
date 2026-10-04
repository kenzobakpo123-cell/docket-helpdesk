from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ===== MODELS =====

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # 'admin' atau 'user'

    # Tiket yang DIBUAT oleh user ini
    tickets_created = db.relationship(
        'Ticket',
        foreign_keys='Ticket.user_id',
        backref='creator',
        lazy=True
    )
    # Tiket yang DITANGANI oleh user ini (kalau dia admin/staff)
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
    priority = db.Column(db.String(20), nullable=False, default='medium')  # low, medium, high
    status = db.Column(db.String(20), nullable=False, default='open')  # open, in_progress, resolved, closed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    comments = db.relationship('Comment', backref='ticket', lazy=True, cascade='all, delete-orphan')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ===== ROUTES =====

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email sudah terdaftar, silakan login.')
            return redirect(url_for('register'))

        new_user = User(
            name=name,
            email=email,
            password_hash=generate_password_hash(password),
            role='user'
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registrasi berhasil, silakan login.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Email atau password salah.')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        tickets = Ticket.query.order_by(Ticket.created_at.desc()).all()
    else:
        tickets = Ticket.query.filter_by(user_id=current_user.id).order_by(Ticket.created_at.desc()).all()
    return render_template('dashboard.html', tickets=tickets)

@app.route('/ticket/new', methods=['GET', 'POST'])
@login_required
def new_ticket():
    if request.method == 'POST':
        new_t = Ticket(
            title=request.form.get('title'),
            category=request.form.get('category'),
            priority=request.form.get('priority'),
            description=request.form.get('description'),
            user_id=current_user.id
        )
        db.session.add(new_t)
        db.session.commit()
        flash('Tiket berhasil dibuat.')
        return redirect(url_for('dashboard'))

    return render_template('new_ticket.html')

@app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def ticket_detail(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    # Hanya pembuat tiket atau admin yang boleh lihat
    if current_user.role != 'admin' and ticket.user_id != current_user.id:
        flash('Kamu tidak punya akses ke tiket ini.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        if 'comment_content' in request.form:
            content = request.form.get('comment_content', '').strip()
            if content:
                db.session.add(Comment(content=content, ticket_id=ticket.id, user_id=current_user.id))
                db.session.commit()
                flash('Komentar ditambahkan.')
        elif 'update_status' in request.form and current_user.role == 'admin':
            ticket.status = request.form.get('status')
            assigned = request.form.get('assigned_to_id')
            ticket.assigned_to_id = int(assigned) if assigned else None
            db.session.commit()
            flash('Tiket diperbarui.')
        return redirect(url_for('ticket_detail', ticket_id=ticket.id))

    staff_list = User.query.filter_by(role='admin').all() if current_user.role == 'admin' else []
    return render_template('ticket_detail.html', ticket=ticket, staff_list=staff_list)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
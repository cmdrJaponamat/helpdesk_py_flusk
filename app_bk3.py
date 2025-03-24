from datetime import datetime
from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_bcrypt import Bcrypt
from typing import Optional

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://helpdesk:123@localhost/request_tracking'
app.config['SECRET_KEY'] = '9fe2f6e1edbddb186ee0c5d5aaafc121'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

# Модель пользователя
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)

# Модель заявки
class Request(db.Model):
    __tablename__ = 'requests'
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    status_id = db.Column(db.Integer, db.ForeignKey('status.id'))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    assignee_id = db.Column(db.Integer, db.ForeignKey('users.id'))

# Модель статуса
class Status(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)

# Модель истории изменения статусов
class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'))
    status_id = db.Column(db.Integer, db.ForeignKey('status.id'))
    changed_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    changed_by = db.Column(db.Integer, db.ForeignKey('users.id'))

# Модель комментария
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'))
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return User.query.get(int(user_id))

# Домашняя страница (авторизация)
@app.route('/')
def home():
    return render_template('index.html')

# Регистрация
@app.route('/register', methods=['GET'])
def show_register_form():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.form
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')

    if not name or not email or not password or not role:
        return jsonify({'message': 'Все поля обязательны'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email уже существует'}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(name=name, email=email, password_hash=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Пользователь зарегистрирован успешно', 'id': new_user.id}), 201

# Авторизация
@app.route('/login', methods=['GET'])
def show_login_form():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.form
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email и пароль обязательны'}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Неверные учетные данные'}), 401

    login_user(user)

    if user.role == 'employee':
        return jsonify({'message': 'Login successful', 'redirect': '/create-request'}), 200
    elif user.role in ['admin', 'specialist']:
        return jsonify({'message': 'Login successful', 'redirect': '/requests-table'}), 200

# Выход
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout successful'}), 200

# Создание заявки (для employee)
@app.route('/create-request', methods=['GET'])
@login_required
def create_request_page():
    if current_user.role != 'employee':
        return jsonify({'message': 'Unauthorized'}), 401
    return render_template('create-request.html')

@app.route('/requests', methods=['POST'])
@login_required
def create_request():
    data = request.form
    description = data.get('description')

    if not description:
        return jsonify({'message': 'Описание обязательно'}), 400

    new_request = Request(description=description, status_id=1, author_id=current_user.id)
    db.session.add(new_request)
    db.session.commit()

    return jsonify({'message': 'Заявка создана успешно', 'id': new_request.id}), 201

# Таблица заявок (для admin/specialist)
@app.route('/requests-table', methods=['GET'])
@login_required
def requests_table():
    if current_user.role not in ['admin', 'specialist']:
        return jsonify({'message': 'Unauthorized'}), 401

    requests = Request.query.all()
    result = []
    for r in requests:
        author_record = User.query.get(r.author_id)
        status_record = Status.query.get(r.status_id)
        result.append({
            'author': author_record.name if author_record else 'Неизвестно',
            'created_at': r.created_at.isoformat(),
            'status': status_record.name if status_record else 'Неизвестно'
        })

    return render_template('requests-table.html', requests=result)

# Просмотр статуса заявок (для employee)
@app.route('/view-status', methods=['GET'])
@login_required
def view_status():
    if current_user.role != 'employee':
        return jsonify({'message': 'Unauthorized'}), 401

    requests = Request.query.filter_by(author_id=current_user.id).all()
    result = []
    for r in requests:
        status_record = Status.query.get(r.status_id)
        result.append({
            'description': r.description,
            'created_at': r.created_at.isoformat(),
            'status': status_record.name if status_record else 'Неизвестно'
        })

    return render_template('view-status.html', requests=result)

# Формирование отчетов (для admin/specialist)
@app.route('/create-report', methods=['GET'])
@login_required
def create_report_page():
    if current_user.role not in ['admin', 'specialist']:
        return jsonify({'message': 'Unauthorized'}), 401
    return render_template('create-report.html')

@app.route('/generate-report', methods=['POST'])
@login_required
def generate_report():
    if current_user.role not in ['admin', 'specialist']:
        return jsonify({'message': 'Unauthorized'}), 401

    data = request.form
    date_from = data.get('date_from')
    date_to = data.get('date_to')

    if not date_from or not date_to:
        return jsonify({'message': 'Укажите период (date_from и date_to)'}), 400

    try:
        date_from = datetime.strptime(date_from, '%Y-%m-%d').date()
        date_to = datetime.strptime(date_to, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'message': 'Неверный формат даты. Используйте YYYY-MM-DD.'}), 400

    requests = Request.query.filter(
        Request.created_at >= date_from,
        Request.created_at <= date_to
    ).all()

    if not requests:
        return jsonify({'message': 'За указанный период заявок не найдено'}), 200

    result = []
    for r in requests:
        author_record = User.query.get(r.author_id)
        status_record = Status.query.get(r.status_id)
        result.append({
            'author': author_record.name if author_record else 'Неизвестно',
            'created_at': r.created_at.isoformat(),
            'status': status_record.name if status_record else 'Неизвестно'
        })

    return jsonify(result), 200

if __name__ == '__main__':
    app.run(debug=True)

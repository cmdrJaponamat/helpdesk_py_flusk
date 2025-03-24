from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from typing import Optional

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://helpdesk:123@localhost/request_tracking'
app.config['SECRET_KEY'] = '9fe2f6e1edbddb186ee0c5d5aaafc121'

db = SQLAlchemy(app)
login_manager = LoginManager(app)

# Модель пользователя
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False)

# Модель заявки
class Request(db.Model):
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
    data = request.json
    name = data.get('name')
    email = data.get('email')
    role = data.get('role')

    if not name or not email or not role:
        return jsonify({'message': 'Name, email, and role are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 409

    new_user = User(name=name, email=email, role=role)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully', 'id': new_user.id}), 201

# Авторизация
@app.route('/login', methods=['GET'])
def show_login_form():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({'message': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401

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
    data = request.json
    description = data.get('description')

    if not description:
        return jsonify({'message': 'Description is required'}), 400

    new_request = Request(description=description, status_id=1, author_id=current_user.id)
    db.session.add(new_request)
    db.session.commit()

    return jsonify({'message': 'Request created successfully', 'id': new_request.id}), 201

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

# Создание отчета (для admin/specialist)
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

    data = request.json
    date_from = data.get('date_from')
    date_to = data.get('date_to')

    if not date_from or not date_to:
        return jsonify({'message': 'Date range is required'}), 400

    requests = Request.query.filter(
        Request.created_at >= date_from,
        Request.created_at <= date_to
    ).all()

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

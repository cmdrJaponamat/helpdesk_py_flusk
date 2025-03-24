from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from typing import Optional

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://helpdesk:123@127.0.0.1/request_tracking'
app.config['SECRET_KEY'] = 'dd8471020213068c018335de705ecd22'  # Замените на ваш секретный ключ

db = SQLAlchemy(app)
login_manager = LoginManager(app)

# Модель пользователя
class User(UserMixin, db.Model):
    __tablename__ = 'users'  # Явно указываем имя таблицы
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
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'))

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
    changed_by = db.Column(db.Integer, db.ForeignKey('user.id'))

# Модель комментария
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return User.query.get(int(user_id))

# Маршрут для отображения формы регистрации
@app.route('/register', methods=['GET'])
def show_register_form():
    return render_template('register.html')

# Маршрут для обработки регистрации
@app.route('/register', methods=['POST'])
def register():
    data = request.json

    # Проверяем наличие обязательных полей
    name = data.get('name')
    email = data.get('email')
    role = data.get('role')

    if not name or not email or not role:
        return jsonify({'message': 'Name, email, and role are required'}), 400

    # Проверяем, что email уникален
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 409

    # Создаем нового пользователя
    new_user = User(name=name, email=email, role=role)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully', 'id': new_user.id}), 201

# Маршрут для отображения формы входа
@app.route('/login', methods=['GET'])
def show_login_form():
    return render_template('login.html')

# Маршрут для обработки входа
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({'message': 'Email is required'}), 400

    # Ищем пользователя в базе данных
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401

    # Аутентифицируем пользователя
    login_user(user)
    return jsonify({'message': 'Login successful', 'role': user.role}), 200

# Маршрут для выхода из системы
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout successful'}), 200

# Создание заявки
@app.route('/requests', methods=['POST'])
@login_required
def create_request():
    data = request.json

    # Проверяем наличие description
    description = data.get('description')
    if not description:
        return jsonify({'message': 'Description is required'}), 400

    # Создаем данные для новой заявки
    new_request_data = {
        "description": description,
        "status_id": 1,  # По умолчанию "новая"
        "author_id": current_user.id
    }

    # Создаем новую заявку
    new_request = Request(**new_request_data)
    db.session.add(new_request)
    db.session.commit()

    return jsonify({'message': 'Request created successfully', 'id': new_request.id}), 201

# Обновление статуса заявки (только для специалистов)
@app.route('/requests/<int:request_id>/status', methods=['PUT'])
@login_required
def update_status(request_id: int):
    if current_user.role != 'specialist':
        return jsonify({'message': 'Unauthorized'}), 401

    data = request.json
    if not data:
        return jsonify({'message': 'Invalid request data'}), 400

    new_status_id = data.get('status_id')
    if new_status_id is None:
        return jsonify({'message': 'Status ID is required'}), 400

    req = Request.query.get_or_404(request_id)
    history = History(
        request_id=request_id,
        status_id=new_status_id,
        changed_by=current_user.id
    )
    db.session.add(history)

    req.status_id = new_status_id
    db.session.commit()

    return jsonify({'message': 'Status updated successfully'}), 200

# Получение всех заявок
@app.route('/requests', methods=['GET'])
@login_required
def get_requests():
    requests = Request.query.all()
    result = []
    for r in requests:
        # Явная проверка на None
        status_record = Status.query.get(r.status_id) if r.status_id else None
        status_name = status_record.name if status_record else 'Неизвестно'

        author_record = User.query.get(r.author_id) if r.author_id else None
        author_name = author_record.name if author_record else 'Неизвестно'

        result.append({
            'id': r.id,
            'description': r.description,
            'status': status_name,
            'author': author_name,
            'created_at': r.created_at.isoformat()
        })
    return jsonify(result), 200

@app.route('/')
def home():
    return render_template('login.html')  # Возвращает файл index.html из папки templates



if __name__ == '__main__':
    app.run(debug=True)

# app.py
import os
import io

import qrcode
import base64
from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from sqlalchemy import func
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

# Загружаем переменные окружения
load_dotenv()

# --- Инициализация Приложения и Расширений ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS').lower() in ['true', 'on', '1']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')
mail = Mail(app)

# Генератор токенов для сброса пароля
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Указываем view для редиректа, если пользователь не авторизован
login_manager.login_message = "Пожалуйста, войдите, чтобы получить доступ к этой странице."

# --- Модели Базы Данных ---
favorites = db.Table('favorites',
                     db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                     db.Column('product_id', db.Integer, db.ForeignKey('product.id'), primary_key=True)
                     )


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(256))

    # Связь с отзывами
    reviews = db.relationship('Review', backref='author', lazy='dynamic')
    # Связь с избранными товарами
    favorites = db.relationship('Product', secondary=favorites, lazy='dynamic',
                                backref=db.backref('favorited_by', lazy=True))

    def add_to_favorites(self, product):
        if not self.is_favorite(product):
            self.favorites.append(product)

    def remove_from_favorites(self, product):
        if self.is_favorite(product):
            self.favorites.remove(product)

    def is_favorite(self, product):
        return self.favorites.filter(favorites.c.product_id == product.id).count() > 0

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    icon_class = db.Column(db.String(50), nullable=True)
    products = db.relationship('Product', backref='category', lazy=True)

    def __repr__(self):
        return f'<Category {self.name}>'


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

    # Связь с отзывами
    reviews = db.relationship('Review', backref='product_reviewed', lazy='dynamic')

    def __repr__(self):
        return f'<Product {self.name}>'


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False) # Оценка от 1 до 5
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)

    def __repr__(self):
        return f'<Review by {self.author.username} for {self.product_reviewed.name}>'


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    total_cost = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='В обработке')
    created_at = db.Column(db.DateTime, default=func.now())

    user = db.relationship('User', backref=db.backref('orders', lazy=True))
    items = db.relationship('OrderItem', backref='order', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Order {self.id}>'


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)  # Цена на момент покупки

    product = db.relationship('Product')

    def __repr__(self):
        return f'<OrderItem {self.product.name} x{self.quantity}>'

# Функция для загрузки пользователя из сессии
@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# --- Формы (WTForms) ---
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')


class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()]) # Проверка формата остается
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField(
        'Повторите пароль', validators=[DataRequired(), EqualTo('password', message='Пароли должны совпадать')])
    submit = SubmitField('Зарегистрироваться')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Это имя пользователя уже занято.')


class ReviewForm(FlaskForm):
    rating = SelectField('Оценка', choices=[('5', '★★★★★'), ('4', '★★★★☆'), ('3', '★★★☆☆'), ('2', '★★☆☆☆'), ('1', '★☆☆☆☆')], validators=[DataRequired()])
    text = TextAreaField('Ваш отзыв', validators=[DataRequired(), Length(min=10, max=500)])
    submit = SubmitField('Оставить отзыв')


class CheckoutForm(FlaskForm):
    first_name = StringField('Имя', validators=[DataRequired()])
    last_name = StringField('Фамилия', validators=[DataRequired()])
    phone = StringField('Телефон', validators=[DataRequired()])
    address = StringField('Адрес доставки', validators=[DataRequired()])
    city = StringField('Город', validators=[DataRequired()])
    submit = SubmitField('Перейти к оплате')


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Отправить ссылку для сброса')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Аккаунт с таким email не найден. Зарегистрируйтесь.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Новый пароль', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Повторите новый пароль', validators=[DataRequired(), EqualTo('password', message='Пароли должны совпадать')])
    submit = SubmitField('Сбросить пароль')


class CallbackForm(FlaskForm):
    name = StringField('Ваше имя', validators=[DataRequired(), Length(max=100)])
    phone = StringField('Номер телефона', validators=[DataRequired(), Length(min=10, max=20)])
    submit = SubmitField('Жду звонка!')


# --- Маршруты (Views) ---
@app.route('/')
@app.route('/index')
def index():
    # <<< ИЗМЕНЕНО: Возвращаем логику для отображения популярных товаров из Части 2
    featured_products = Product.query.order_by(func.random()).limit(4).all()
    return render_template('index.html', title='Главная', products=featured_products)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Неправильный email или пароль', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        flash(f'Добро пожаловать, {user.username}!', 'success')
        return redirect(url_for('profile'))
    return render_template('login.html', title='Вход', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('Вы успешно вышли из системы.', 'info')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Поздравляем, вы успешно зарегистрировались!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Регистрация', form=form)

@app.route('/catalog')
def catalog():
    categories = Category.query.all()
    return render_template('catalog.html', title='Каталог', categories=categories)

@app.route('/catalog/<int:category_id>')
def category_products(category_id):
    # first_or_404 - если категория не найдена, вернет ошибку 404 Not Found
    category = Category.query.get_or_404(category_id)
    products = Product.query.filter_by(category_id=category.id).all()
    return render_template('category_products.html', title=category.name, category=category, products=products)

@app.route('/product/<int:product_id>', methods=['GET', 'POST'])
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    form = None
    if current_user.is_authenticated:
        form = ReviewForm()
        if form.validate_on_submit():
            review = Review(rating=int(form.rating.data),
                            text=form.text.data,
                            author=current_user,
                            product_reviewed=product)
            db.session.add(review)
            db.session.commit()
            flash('Ваш отзыв был добавлен!', 'success')
            return redirect(url_for('product_detail', product_id=product.id))

    reviews = Review.query.filter_by(product_id=product.id).order_by(Review.timestamp.desc()).all()
    return render_template('product_detail.html', title=product.name, product=product, form=form, reviews=reviews)

@app.route('/profile')
@login_required
def profile():
    favorite_products = current_user.favorites.all()
    # Получаем заказы пользователя, сортируя по дате (сначала новые)
    user_orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template('profile.html', title='Профиль', favorites=favorite_products, orders=user_orders)

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'cart' not in session:
        session['cart'] = {}

    product_id_str = str(product_id)
    quantity = int(request.form.get('quantity', 1))

    if product_id_str in session['cart']:
        session['cart'][product_id_str]['quantity'] += quantity
    else:
        product = Product.query.get_or_404(product_id)
        session['cart'][product_id_str] = {
            'quantity': quantity,
            'name': product.name,
            'price': product.price
        }

    session.modified = True
    flash(f'Товар "{session["cart"][product_id_str]["name"]}" добавлен в корзину!', 'success')
    return redirect(request.referrer or url_for('index'))


@app.route('/cart')
def cart_detail():
    cart_items = session.get('cart', {})
    total_price = 0
    products_in_cart = []
    for product_id, item_data in cart_items.items():
        product = Product.query.get(int(product_id))
        if product:
            subtotal = item_data['quantity'] * product.price
            total_price += subtotal
            products_in_cart.append({
                'id': product.id,
                'name': product.name,
                'price': product.price,
                'quantity': item_data['quantity'],
                'subtotal': subtotal,
                'product': product
            })

    return render_template('cart.html', title='Корзина', products_in_cart=products_in_cart, total_price=total_price)

@app.route('/remove_from_cart/<int:product_id>')
def remove_from_cart(product_id):
    product_id_str = str(product_id)
    if 'cart' in session and product_id_str in session['cart']:
        del session['cart'][product_id_str]
        session.modified = True
        flash('Товар удален из корзины.', 'info')
    return redirect(url_for('cart_detail'))


@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart = session.get('cart', {})
    if not cart:
        flash('Ваша корзина пуста. Нечего оформлять!', 'warning')
        return redirect(url_for('cart_detail'))

    form = CheckoutForm()

    # Заполняем форму данными пользователя, если они есть
    if request.method == 'GET':
        form.first_name.data = current_user.username  # Предположим, что username это имя

    total_price = 0
    products_in_cart = []
    for product_id, item_data in cart.items():
        product = Product.query.get(int(product_id))
        if product:
            total_price += item_data['quantity'] * product.price
            products_in_cart.append({'product': product, 'quantity': item_data['quantity']})

    if form.validate_on_submit():
        # Создаем новый заказ
        order = Order(
            user_id=current_user.id,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            phone=form.phone.data,
            address=form.address.data,
            city=form.city.data,
            total_cost=total_price
        )
        db.session.add(order)
        # Важно! Сначала коммитим Order, чтобы получить его ID
        db.session.flush()

        # Создаем элементы заказа
        for item in products_in_cart:
            order_item = OrderItem(
                order_id=order.id,
                product_id=item['product'].id,
                quantity=item['quantity'],
                price=item['product'].price  # Сохраняем цену на момент покупки
            )
            db.session.add(order_item)

        db.session.commit()

        # Очищаем корзину
        session.pop('cart', None)

        flash('Заказ успешно создан! Теперь вы можете его оплатить.', 'success')
        return redirect(url_for('order_payment', order_id=order.id))

    return render_template('checkout.html', title='Оформление заказа', form=form,
                           products_in_cart=products_in_cart, total_price=total_price)


@app.route('/order/<int:order_id>')
@login_required
def order_payment(order_id):
    order = Order.query.get_or_404(order_id)
    # Проверка, что текущий пользователь является владельцем заказа
    if order.user_id != current_user.id:
        flash('У вас нет доступа к этому заказу.', 'danger')
        return redirect(url_for('index'))

    # --- Генерация QR-кода ---
    # В реальном приложении здесь будет сложная строка из стандарта СБП
    sbp_payload = f"ST00012|Name=Мой Магазин|PersonalAcc=40817810400000001234|BankName=АО 'Мой Банк'|BIC=044525225|Sum={int(order.total_cost * 100)}|Purpose=Оплата заказа №{order.id}"

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(sbp_payload)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    # Сохраняем изображение в байтовый поток в памяти
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    # Кодируем в Base64 для передачи в HTML
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return render_template('order_payment.html', title='Оплата заказа', order=order, qr_code=img_str)
@app.route('/toggle_favorite/<int:product_id>')
@login_required
def toggle_favorite(product_id):
    product = Product.query.get_or_404(product_id)
    if current_user.is_favorite(product):
        current_user.remove_from_favorites(product)
        flash(f'Товар "{product.name}" удален из избранного.', 'info')
    else:
        current_user.add_to_favorites(product)
        flash(f'Товар "{product.name}" добавлен в избранное!', 'success')
    db.session.commit()
    return redirect(request.referrer or url_for('index'))

def send_reset_email(user):
    token = s.dumps(user.email, salt='password-reset-salt')
    msg = Message('Сброс пароля для вашего аккаунта',
                  recipients=[user.email])
    link = url_for('reset_token', token=token, _external=True)
    msg.body = f'''Чтобы сбросить ваш пароль, перейдите по следующей ссылке:
{link}

Если вы не запрашивали сброс пароля, просто проигнорируйте это письмо.
Ссылка действительна в течение 30 минут.
'''
    mail.send(msg)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('На ваш email отправлено письмо с инструкциями по сбросу пароля.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Сброс пароля', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=1800) # Ссылка живет 30 минут
    except SignatureExpired:
        flash('Срок действия ссылки для сброса пароля истек.', 'warning')
        return redirect(url_for('reset_request'))
    except Exception:
        flash('Недействительная или поврежденная ссылка.', 'danger')
        return redirect(url_for('reset_request'))

    user = User.query.filter_by(email=email).first()
    if user is None:
        flash('Пользователь не найден.', 'danger')
        return redirect(url_for('index'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Ваш пароль был успешно обновлен! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Сброс пароля', form=form, token=token)

@app.route('/delivery')
def delivery():
    return render_template('delivery.html', title='Доставка')


@app.route('/stores')
def stores():
    # В будущем здесь можно передавать список адресов из БД
    return render_template('stores.html', title='Адреса магазинов')


@app.route('/callback', methods=['GET', 'POST'])
def callback():
    form = CallbackForm()
    if form.validate_on_submit():
        # В реальном приложении здесь будет логика отправки email или сохранения в БД
        print(f"Новый запрос на звонок: Имя - {form.name.data}, Телефон - {form.phone.data}")
        flash('Спасибо! Мы скоро с вами свяжемся.', 'success')
        return redirect(url_for('index'))
    return render_template('callback.html', title='Заказать звонок', form=form)

@app.context_processor
def inject_cart_count():
    if 'cart' in session:
        # Считаем общее количество товаров, а не количество позиций
        count = sum(item['quantity'] for item in session['cart'].values())
        return dict(cart_count=count)
    return dict(cart_count=0)

@app.cli.command("init-db")
def init_db_command():
    """Наполняет базу данных тестовыми товарами и категориями для мебельного магазина."""
    if Category.query.first() is not None:
        print('База данных уже содержит данные. Пропускаем наполнение.')
        return

    print('Обновление тестовых данных для мебельного магазина...')
    # Создаем категории
    cat1 = Category(name='Диваны')
    cat2 = Category(name='Кровати')
    cat3 = Category(name='Столы и стулья')
    cat4 = Category(name='Шкафы и хранение')

    db.session.add_all([cat1, cat2, cat3, cat4])
    db.session.commit()

    # Создаем товары
    prod1 = Product(name='Угловой диван "Монреаль"', description='Просторный и стильный диван для всей семьи. Механизм трансформации "Дельфин".', price=59990.00, category_id=cat1.id, image_file='sofa_1.jpg')
    prod2 = Product(name='Диван-кровать "Сканди"', description='Компактный диван в скандинавском стиле. Идеален для небольших комнат.', price=28900.00, category_id=cat1.id, image_file='sofa_2.jpg')
    prod3 = Product(name='Кровать "Лофт" с подъемным механизмом', description='Кровать из массива дерева с вместительным ящиком для белья.', price=42500.00, category_id=cat2.id, image_file='bed_1.jpg')
    prod4 = Product(name='Двуспальная кровать "Верона"', description='Элегантная кровать с мягким изголовьем из велюра.', price=35000.00, category_id=cat2.id, image_file='bed_2.jpg')
    prod5 = Product(name='Обеденный стол "Дублин"', description='Раздвижной стол из дуба на 6-8 персон.', price=21000.00, category_id=cat3.id, image_file='table_1.jpg')
    prod6 = Product(name='Комплект стульев "Эймс" (2 шт.)', description='Современные стулья с пластиковым сиденьем и деревянными ножками.', price=7800.00, category_id=cat3.id, image_file='chairs_1.jpg')
    prod7 = Product(name='Шкаф-купе "Экспресс"', description='Вместительный трехдверный шкаф с зеркальной вставкой.', price=31500.00, category_id=cat4.id, image_file='wardrobe_1.jpg')

    db.session.add_all([prod1, prod2, prod3, prod4, prod5, prod6, prod7])
    db.session.commit()
    print('Тестовые данные для мебельного магазина успешно добавлены.')

if __name__ == '__main__':
    app.run(debug=True)
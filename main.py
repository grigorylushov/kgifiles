import os
import logging
import sqlite3
import secrets
import string
import asyncio
import time
from datetime import datetime
import hashlib

# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Конфигурация
BOT_TOKEN = "8493433461:AAEZxG0Ix7em5ff3XHF36EZCmZyPMkf6WZE"
DEFAULT_ADMIN_PASSWORD = "admin123"  # Пароль по умолчанию для первого админа

# Настройки переподключения
RECONNECT_DELAY = 5  # секунды между попытками переподключения
MAX_RECONNECT_ATTEMPTS = 10  # максимальное количество попыток переподключения

# Хеширование паролей
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect('files.db', check_same_thread=False)
    cursor = conn.cursor()
    
    # Создаем таблицу files
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id TEXT NOT NULL,
            file_name TEXT NOT NULL,
            file_type TEXT NOT NULL,
            download_id TEXT UNIQUE NOT NULL,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            description TEXT,
            uploaded_by INTEGER
        )
    ''')
    
    # Создаем таблицу requests
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT,
            first_name TEXT,
            request_text TEXT NOT NULL,
            request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending',
            file_id TEXT,
            file_type TEXT,
            file_name TEXT
        )
    ''')
    
    # Создаем таблицу пользователей
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            username TEXT,
            first_name TEXT,
            password_hash TEXT,
            is_admin BOOLEAN DEFAULT FALSE,
            registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Создаем таблицу сессий
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')
    
    # Создаем первого администратора, если его нет
    cursor.execute('SELECT * FROM users WHERE is_admin = TRUE')
    if not cursor.fetchone():
        admin_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
        cursor.execute('''
            INSERT OR IGNORE INTO users (user_id, username, first_name, password_hash, is_admin)
            VALUES (?, ?, ?, ?, ?)
        ''', (1, 'admin', 'Administrator', admin_hash, True))
        logger.info("Создан администратор по умолчанию")
    
    conn.commit()
    conn.close()
    logger.info("База данных инициализирована")

# Генерация уникального ID для скачивания
def generate_download_id():
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(10))

# Генерация токена сессии
def generate_session_token():
    return secrets.token_hex(32)

# Проверка авторизации пользователя
def get_user_session(user_id):
    conn = sqlite3.connect('files.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.user_id, u.username, u.first_name, u.is_admin 
        FROM users u 
        JOIN sessions s ON u.user_id = s.user_id 
        WHERE u.user_id = ? AND s.expires_at > datetime('now')
    ''', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

# Создание сессии пользователя
def create_user_session(user_id, is_admin=False):
    conn = sqlite3.connect('files.db', check_same_thread=False)
    cursor = conn.cursor()
    
    # Удаляем старые сессии
    cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
    
    # Создаем новую сессию (действует 30 дней)
    session_token = generate_session_token()
    expires_at = datetime.now().timestamp() + 30 * 24 * 60 * 60  # 30 дней
    
    cursor.execute('''
        INSERT INTO sessions (user_id, session_token, expires_at)
        VALUES (?, ?, datetime(?, 'unixepoch'))
    ''', (user_id, session_token, expires_at))
    
    conn.commit()
    conn.close()
    return session_token

# Регистрация нового пользователя
def register_user(user_id, username, first_name, password):
    conn = sqlite3.connect('files.db', check_same_thread=False)
    cursor = conn.cursor()
    
    password_hash = hash_password(password)
    
    try:
        cursor.execute('''
            INSERT INTO users (user_id, username, first_name, password_hash, is_admin)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, username, first_name, password_hash, False))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    
    conn.close()
    return success

# Аутентификация пользователя
def authenticate_user(user_id, password):
    conn = sqlite3.connect('files.db', check_same_thread=False)
    cursor = conn.cursor()
    
    cursor.execute('SELECT password_hash, is_admin FROM users WHERE user_id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user and user[0] == hash_password(password):
        return user[1]  # Возвращаем is_admin
    return None

# Получение статистики пользователя
def get_user_stats(user_id):
    conn = sqlite3.connect('files.db', check_same_thread=False)
    cursor = conn.cursor()
    
    # Количество загруженных файлов
    cursor.execute('SELECT COUNT(*) FROM files WHERE uploaded_by = ?', (user_id,))
    files_count = cursor.fetchone()[0]
    
    # Количество отправленных запросов
    cursor.execute('SELECT COUNT(*) FROM requests WHERE user_id = ?', (user_id,))
    requests_count = cursor.fetchone()[0]
    
    # Количество одобренных запросов
    cursor.execute('SELECT COUNT(*) FROM requests WHERE user_id = ? AND status = "approved"', (user_id,))
    approved_requests = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        'files_count': files_count,
        'requests_count': requests_count,
        'approved_requests': approved_requests
    }

# Добавление администратора
def add_admin(user_id, current_admin_id):
    conn = sqlite3.connect('files.db', check_same_thread=False)
    cursor = conn.cursor()
    
    # Проверяем, что текущий пользователь - администратор
    cursor.execute('SELECT is_admin FROM users WHERE user_id = ?', (current_admin_id,))
    current_user = cursor.fetchone()
    
    if not current_user or not current_user[0]:
        conn.close()
        return False
    
    # Делаем пользователя администратором
    cursor.execute('UPDATE users SET is_admin = TRUE WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    return True

async def start(update, context):
    user = update.effective_user
    
    if context.args and len(context.args) > 0 and context.args[0].startswith('download-'):
        download_id = context.args[0].replace('download-', '')
        await handle_download(update, context, download_id)
        return
    
    # Проверяем авторизацию пользователя
    user_session = get_user_session(user.id)
    
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    
    if user_session:
        # Пользователь авторизован
        is_admin = user_session[3]
        
        if is_admin:
            keyboard = [
                [InlineKeyboardButton("👤 Личный кабинет", callback_data='personal_cabinet')],
                [InlineKeyboardButton("👨‍💻 Админ-панель", callback_data='admin_panel')],
                [InlineKeyboardButton("📥 Скачать файл", callback_data='download')],
                [InlineKeyboardButton("📤 Запросить размещение файла", callback_data='request_upload')],
                [InlineKeyboardButton("ℹ️ Помощь", callback_data='help')]
            ]
        else:
            keyboard = [
                [InlineKeyboardButton("👤 Личный кабинет", callback_data='personal_cabinet')],
                [InlineKeyboardButton("📥 Скачать файл", callback_data='download')],
                [InlineKeyboardButton("📤 Запросить размещение файла", callback_data='request_upload')],
                [InlineKeyboardButton("ℹ️ Помощь", callback_data='help')]
            ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        welcome_text = f"👋 Привет, {user.first_name}!\n\n"
        if is_admin:
            welcome_text += "🔧 Вы вошли как администратор\n\n"
        welcome_text += "Выберите действие:"
        
    else:
        # Пользователь не авторизован
        keyboard = [
            [InlineKeyboardButton("🔐 Войти", callback_data='login')],
            [InlineKeyboardButton("📝 Зарегистрироваться", callback_data='register')],
            [InlineKeyboardButton("📥 Скачать файл", callback_data='download')],
            [InlineKeyboardButton("ℹ️ Помощь", callback_data='help')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        welcome_text = f"👋 Привет, {user.first_name}!\n\n" \
                      "🔐 Для доступа ко всем функциям требуется авторизация\n\n" \
                      "Выберите действие:"
    
    if update.message:
        await update.message.reply_text(welcome_text, reply_markup=reply_markup)

async def handle_download(update, context, download_id):
    conn = sqlite3.connect('files.db', check_same_thread=False)
    cursor = conn.cursor()
    
    cursor.execute('SELECT file_id, file_name, file_type, description FROM files WHERE download_id = ?', (download_id,))
    file_data = cursor.fetchone()
    conn.close()
    
    if file_data:
        file_id, file_name, file_type, description = file_data
        
        caption = f"📁 {file_name}"
        if description:
            caption += f"\n📝 {description}"
        
        try:
            if file_type == 'photo':
                await update.message.reply_photo(file_id, caption=caption)
            elif file_type == 'video':
                await update.message.reply_video(file_id, caption=caption)
            elif file_type == 'document':
                await update.message.reply_document(file_id, caption=caption)
            elif file_type == 'audio':
                await update.message.reply_audio(file_id, caption=caption)
            else:
                await update.message.reply_document(file_id, caption=caption)
        except Exception as e:
            await update.message.reply_text(f"❌ Ошибка при отправке файла: {e}")
    else:
        await update.message.reply_text("❌ Файл не найден или ссылка недействительна.")

async def login(update, context):
    user = update.effective_user
    
    if len(context.args) == 0:
        await update.message.reply_text(
            "🔐 Вход в систему\n\n"
            "Введите пароль:\n"
            "Пример: /login ваш_пароль"
        )
        return
    
    password = context.args[0]
    
    # Проверяем аутентификацию
    is_admin = authenticate_user(user.id, password)
    
    if is_admin is not None:
        # Создаем сессию
        create_user_session(user.id, is_admin)
        
        if is_admin:
            await update.message.reply_text("✅ Успешный вход как администратор!")
        else:
            await update.message.reply_text("✅ Успешный вход!")
        
        # Показываем главное меню
        await start(update, context)
    else:
        await update.message.reply_text("❌ Неверный пароль или пользователь не найден!")

async def register(update, context):
    user = update.effective_user
    
    if len(context.args) == 0:
        await update.message.reply_text(
            "📝 Регистрация\n\n"
            "Введите пароль для регистрации:\n"
            "Пример: /register ваш_пароль\n\n"
            "⚠️ Пароль должен быть не менее 6 символов"
        )
        return
    
    password = context.args[0]
    
    if len(password) < 6:
        await update.message.reply_text("❌ Пароль должен содержать не менее 6 символов!")
        return
    
    # Регистрируем пользователя
    success = register_user(user.id, user.username, user.first_name, password)
    
    if success:
        # Создаем сессию
        create_user_session(user.id, False)
        await update.message.reply_text("✅ Регистрация прошла успешно!")
        await start(update, context)
    else:
        await update.message.reply_text("❌ Пользователь уже зарегистрирован!")

async def logout(update, context):
    user = update.effective_user
    
    # Удаляем сессию
    conn = sqlite3.connect('files.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user.id,))
    conn.commit()
    conn.close()
    
    await update.message.reply_text("✅ Вы вышли из системы")
    await start(update, context)

async def personal_cabinet(update, context):
    query = update.callback_query
    await query.answer()
    
    user = query.from_user
    user_session = get_user_session(user.id)
    
    if not user_session:
        await query.edit_message_text("❌ Для доступа к личному кабинету требуется авторизация!")
        return
    
    is_admin = user_session[3]
    stats = get_user_stats(user.id)
    
    cabinet_text = f"👤 Личный кабинет\n\n" \
                  f"📛 Имя: {user.first_name}\n" \
                  f"👤 Username: @{user.username or 'не указан'}\n" \
                  f"🆔 ID: {user.id}\n" \
                  f"🔧 Статус: {'Администратор' if is_admin else 'Пользователь'}\n\n" \
                  f"📊 Статистика:\n" \
                  f"• Загружено файлов: {stats['files_count']}\n" \
                  f"• Отправлено запросов: {stats['requests_count']}\n" \
                  f"• Одобрено запросов: {stats['approved_requests']}\n\n" \
                  f"💾 Используйте /logout для выхода"
    
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    
    keyboard = [
        [InlineKeyboardButton("📊 Мои файлы", callback_data='my_files')],
        [InlineKeyboardButton("📨 Мои запросы", callback_data='my_requests')],
    ]
    
    if is_admin:
        keyboard.append([InlineKeyboardButton("👨‍💻 Админ-панель", callback_data='admin_panel')])
    
    keyboard.append([InlineKeyboardButton("🔙 Назад", callback_data='back_to_main')])
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(cabinet_text, reply_markup=reply_markup)

async def admin_panel(update, context):
    query = update.callback_query
    await query.answer()
    
    user = query.from_user
    user_session = get_user_session(user.id)
    
    if not user_session or not user_session[3]:
        await query.edit_message_text("❌ Доступ запрещен! Требуются права администратора.")
        return
    
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    
    keyboard = [
        [InlineKeyboardButton("📊 Статистика", callback_data='admin_stats')],
        [InlineKeyboardButton("📁 Список файлов", callback_data='admin_files')],
        [InlineKeyboardButton("📨 Запросы на размещение", callback_data='admin_requests')],
        [InlineKeyboardButton("➕ Добавить файл", callback_data='admin_add_file')],
        [InlineKeyboardButton("👥 Управление пользователями", callback_data='admin_users')],
        [InlineKeyboardButton("🔙 Назад", callback_data='back_to_main')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(
        "👨‍💻 Админ-панель\n\n"
        "Выберите действие:",
        reply_markup=reply_markup
    )

async def admin_users(update, context):
    query = update.callback_query
    await query.answer()
    
    user = query.from_user
    user_session = get_user_session(user.id)
    
    if not user_session or not user_session[3]:
        await query.edit_message_text("❌ Доступ запрещен!")
        return
    
    conn = sqlite3.connect('files.db', check_same_thread=False)
    cursor = conn.cursor()
    
    # Получаем список пользователей
    cursor.execute('''
        SELECT user_id, username, first_name, is_admin, registration_date 
        FROM users 
        ORDER BY registration_date DESC 
        LIMIT 20
    ''')
    users = cursor.fetchall()
    conn.close()
    
    if users:
        users_text = "👥 Список пользователей:\n\n"
        for user_data in users:
            user_id, username, first_name, is_admin, reg_date = user_data
            status = "👑 Админ" if is_admin else "👤 Пользователь"
            username_display = f"@{username}" if username else "без username"
            users_text += f"• {first_name} ({username_display})\nID: {user_id}\n{status}\nДата: {reg_date[:10]}\n\n"
        
        users_text += "Для добавления администратора используйте:\n/addadmin user_id"
    else:
        users_text = "👥 Пользователи не найдены"
    
    await query.edit_message_text(users_text)

async def add_admin_command(update, context):
    user = update.effective_user
    user_session = get_user_session(user.id)
    
    if not user_session or not user_session[3]:
        await update.message.reply_text("❌ Доступ запрещен! Требуются права администратора.")
        return
    
    if len(context.args) == 0:
        await update.message.reply_text("Использование: /addadmin user_id")
        return
    
    try:
        new_admin_id = int(context.args[0])
        
        # Добавляем администратора
        success = add_admin(new_admin_id, user.id)
        
        if success:
            await update.message.reply_text(f"✅ Пользователь {new_admin_id} теперь администратор!")
        else:
            await update.message.reply_text("❌ Ошибка при добавлении администратора!")
    
    except ValueError:
        await update.message.reply_text("❌ Неверный формат user_id!")

async def button_handler(update, context):
    query = update.callback_query
    await query.answer()
    
    data = query.data
    user_id = query.from_user.id
    
    if data == 'back_to_main':
        await start(update, context)
        return
    
    if data == 'login':
        await query.edit_message_text(
            "🔐 Вход в систему\n\n"
            "Используйте команду:\n"
            "/login ваш_пароль"
        )
        return
    
    if data == 'register':
        await query.edit_message_text(
            "📝 Регистрация\n\n"
            "Используйте команду:\n"
            "/register ваш_пароль\n\n"
            "⚠️ Пароль должен быть не менее 6 символов"
        )
        return
    
    if data == 'personal_cabinet':
        await personal_cabinet(update, context)
        return
    
    if data == 'admin_panel':
        await admin_panel(update, context)
        return
    
    if data == 'admin_users':
        await admin_users(update, context)
        return
    
    # Остальные обработчики кнопок остаются без изменений
    if data == 'download':
        await query.edit_message_text(
            "📥 Для скачивания файла используйте специальную ссылку, "
            "которую вам предоставил администратор."
        )
    
    elif data == 'request_upload':
        user_session = get_user_session(user_id)
        if not user_session:
            await query.edit_message_text("❌ Для отправки запросов требуется авторизация!")
            return
            
        await query.edit_message_text(
            "📤 Запрос на размещение файла\n\n"
            "Пожалуйста, отправьте файл, который хотите разместить, "
            "и в подписи к нему укажите описание файла.\n\n"
            "Ваш запрос будет отправлен администратору на

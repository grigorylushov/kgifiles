import os
import logging
import sqlite3
import secrets
import string
import asyncio
import time
from datetime import datetime
import hashlib
import shutil
import requests
import json

# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Конфигурация
BOT_TOKEN = "8493433461:AAEZxG0Ix7em5ff3XHF36EZCmZyPMkf6WZE"  # ЗАМЕНИТЕ НА ВАШ РЕАЛЬНЫЙ ТОКЕН
DEFAULT_ADMIN_PASSWORD = "34613461"

# GitHub конфигурация - ЗАПОЛНИТЕ ЭТИ ДАННЫЕ!
GITHUB_TOKEN = "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"  # Замените на ваш токен
GITHUB_USERNAME = "grigorylushov"
GITHUB_REPO = "kgifiles"
GITHUB_BRANCH = "main"

# Предустановленные администраторы
PRESET_ADMINS = [8112565926, 1]  # Добавляем вашего ID и ID по умолчанию

# Хеширование паролей
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Получение пути к БД
def get_db_path():
    return 'files.db'

# Функции для работы с GitHub
def upload_to_github():
    """Загружает files.db в GitHub"""
    try:
        if not os.path.exists('files.db'):
            logger.error("❌ Файл files.db не найден для загрузки в GitHub")
            return False
        
        if GITHUB_TOKEN == "YOUR_GITHUB_TOKEN_HERE":
            logger.warning("⚠️ GitHub токен не настроен, пропускаем загрузку")
            return False
        
        # Читаем содержимое файла
        with open('files.db', 'rb') as f:
            content = f.read()
        
        # Кодируем в base64
        import base64
        content_b64 = base64.b64encode(content).decode('utf-8')
        
        # URL для API GitHub
        url = f"https://api.github.com/repos/{GITHUB_USERNAME}/{GITHUB_REPO}/contents/files.db"
        
        # Проверяем существование файла
        headers = {
            'Authorization': f'token {GITHUB_TOKEN}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        # Получаем текущий sha файла (если существует)
        response = requests.get(url, headers=headers)
        sha = None
        if response.status_code == 200:
            sha = response.json().get('sha')
        
        # Данные для загрузки
        data = {
            "message": f"Auto-backup: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "content": content_b64,
            "branch": GITHUB_BRANCH
        }
        
        if sha:
            data["sha"] = sha
        
        # Загружаем файл
        response = requests.put(url, headers=headers, data=json.dumps(data))
        
        if response.status_code in [200, 201]:
            logger.info("✅ База данных успешно загружена в GitHub")
            return True
        else:
            logger.error(f"❌ Ошибка загрузки в GitHub: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Ошибка при загрузке в GitHub: {e}")
        return False

def download_from_github():
    """Скачивает files.db из GitHub"""
    try:
        if GITHUB_TOKEN == "YOUR_GITHUB_TOKEN_HERE":
            logger.warning("⚠️ GitHub токен не настроен, пропускаем скачивание")
            return False
        
        url = f"https://api.github.com/repos/{GITHUB_USERNAME}/{GITHUB_REPO}/contents/files.db"
        
        headers = {
            'Authorization': f'token {GITHUB_TOKEN}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            file_data = response.json()
            download_url = file_data.get('download_url')
            
            if download_url:
                file_response = requests.get(download_url)
                if file_response.status_code == 200:
                    with open('files.db', 'wb') as f:
                        f.write(file_response.content)
                    logger.info("✅ База данных успешно скачана из GitHub")
                    return True
        
        logger.warning("⚠️ Файл не найден в GitHub, будет создана новая БД")
        return False
        
    except Exception as e:
        logger.error(f"❌ Ошибка при скачивании из GitHub: {e}")
        return False

# Функция для резервного копирования БД
def backup_database():
    """Создает резервную копию и загружает в GitHub"""
    try:
        if os.path.exists('files.db'):
            # Локальная резервная копия
            backup_dir = 'backups'
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"{backup_dir}/files_backup_{timestamp}.db"
            
            shutil.copy2('files.db', backup_file)
            logger.info(f"✅ Создана локальная резервная копия: {backup_file}")
            
            # Загружаем в GitHub
            if upload_to_github():
                logger.info("✅ Резервная копия загружена в GitHub")
            else:
                logger.warning("⚠️ Не удалось загрузить в GitHub")
            
            # Удаляем старые локальные резервные копии (оставляем последние 3)
            backups = sorted([f for f in os.listdir(backup_dir) if f.startswith('files_backup_')])
            if len(backups) > 3:
                for old_backup in backups[:-3]:
                    os.remove(os.path.join(backup_dir, old_backup))
                    logger.info(f"🗑️ Удалена старая резервная копия: {old_backup}")
                    
    except Exception as e:
        logger.error(f"❌ Ошибка при создании резервной копии: {e}")

# Инициализация базы данных
def init_db():
    try:
        # Пробуем скачать из GitHub
        logger.info("🔄 Проверяем наличие базы данных в GitHub...")
        downloaded = download_from_github()
        
        if not downloaded and not os.path.exists('files.db'):
            logger.info("📝 Создаем новую базу данных")
        
        conn = sqlite3.connect(get_db_path(), check_same_thread=False)
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
        
        # Создаем администраторов по умолчанию
        cursor.execute('SELECT user_id FROM users WHERE is_admin = TRUE')
        existing_admins = [row[0] for row in cursor.fetchall()]
        
        for admin_id in PRESET_ADMINS:
            if admin_id not in existing_admins:
                admin_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
                cursor.execute('''
                    INSERT OR IGNORE INTO users (user_id, username, first_name, password_hash, is_admin)
                    VALUES (?, ?, ?, ?, ?)
                ''', (admin_id, f'admin_{admin_id}', 'Administrator', admin_hash, True))
                logger.info(f"✅ Создан администратор с ID: {admin_id}")
        
        conn.commit()
        conn.close()
        
        # Создаем резервную копию после инициализации
        backup_database()
        
        logger.info("База данных инициализирована")
    except Exception as e:
        logger.error(f"Ошибка инициализации БД: {e}")

# Генерация уникального ID для скачивания
def generate_download_id():
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(10))

# Генерация токена сессии
def generate_session_token():
    return secrets.token_hex(32)

# Проверка авторизации пользователя
def get_user_session(user_id):
    try:
        conn = sqlite3.connect(get_db_path(), check_same_thread=False)
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
    except Exception as e:
        logger.error(f"Ошибка получения сессии: {e}")
        return None

# Создание сессии пользователя
def create_user_session(user_id, is_admin=False):
    try:
        conn = sqlite3.connect(get_db_path(), check_same_thread=False)
        cursor = conn.cursor()
        
        # Удаляем старые сессии
        cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
        
        # Создаем новую сессию (действует 30 дней)
        session_token = generate_session_token()
        expires_at = datetime.now().timestamp() + 30 * 24 * 60 * 60
        
        cursor.execute('''
            INSERT INTO sessions (user_id, session_token, expires_at)
            VALUES (?, ?, datetime(?, 'unixepoch'))
        ''', (user_id, session_token, expires_at))
        
        conn.commit()
        conn.close()
        return session_token
    except Exception as e:
        logger.error(f"Ошибка создания сессии: {e}")
        return None

# Регистрация нового пользователя
def register_user(user_id, username, first_name, password):
    try:
        conn = sqlite3.connect(get_db_path(), check_same_thread=False)
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
    except Exception as e:
        logger.error(f"Ошибка регистрации: {e}")
        return False

# Аутентификация пользователя
def authenticate_user(user_id, password):
    try:
        conn = sqlite3.connect(get_db_path(), check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('SELECT password_hash, is_admin FROM users WHERE user_id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        if user and user[0] == hash_password(password):
            return user[1]
        return None
    except Exception as e:
        logger.error(f"Ошибка аутентификации: {e}")
        return None

# Получение статистики пользователя
def get_user_stats(user_id):
    try:
        conn = sqlite3.connect(get_db_path(), check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM files WHERE uploaded_by = ?', (user_id,))
        files_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM requests WHERE user_id = ?', (user_id,))
        requests_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM requests WHERE user_id = ? AND status = "approved"', (user_id,))
        approved_requests = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'files_count': files_count,
            'requests_count': requests_count,
            'approved_requests': approved_requests
        }
    except Exception as e:
        logger.error(f"Ошибка получения статистики: {e}")
        return {'files_count': 0, 'requests_count': 0, 'approved_requests': 0}

# Добавление администратора
def add_admin(user_id, current_admin_id):
    try:
        conn = sqlite3.connect(get_db_path(), check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('SELECT is_admin FROM users WHERE user_id = ?', (current_admin_id,))
        current_user = cursor.fetchone()
        
        if not current_user or not current_user[0]:
            conn.close()
            return False
        
        cursor.execute('UPDATE users SET is_admin = TRUE WHERE user_id = ?', (user_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Ошибка добавления админа: {e}")
        return False

async def start(update, context):
    try:
        user = update.effective_user
        
        if context.args and len(context.args) > 0 and context.args[0].startswith('download-'):
            download_id = context.args[0].replace('download-', '')
            await handle_download(update, context, download_id)
            return
        
        user_session = get_user_session(user.id)
        
        from telegram import InlineKeyboardButton, InlineKeyboardMarkup
        
        if user_session:
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
    except Exception as e:
        logger.error(f"Ошибка в start: {e}")

async def handle_download(update, context, download_id):
    try:
        conn = sqlite3.connect(get_db_path(), check_same_thread=False)
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
    except Exception as e:
        logger.error(f"Ошибка в handle_download: {e}")
        await update.message.reply_text("❌ Ошибка при обработке запроса")

async def login(update, context):
    try:
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
    except Exception as e:
        logger.error(f"Ошибка в login: {e}")
        await update.message.reply_text("❌ Ошибка при входе")

async def register(update, context):
    try:
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
    except Exception as e:
        logger.error(f"Ошибка в register: {e}")
        await update.message.reply_text("❌ Ошибка при регистрации")

async def logout(update, context):
    try:
        user = update.effective_user
        
        # Удаляем сессию
        conn = sqlite3.connect(get_db_path(), check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user.id,))
        conn.commit()
        conn.close()
        
        await update.message.reply_text("✅ Вы вышли из системы")
        await start(update, context)
    except Exception as e:
        logger.error(f"Ошибка в logout: {e}")
        await update.message.reply_text("❌ Ошибка при выходе")

async def personal_cabinet(update, context):
    try:
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
    except Exception as e:
        logger.error(f"Ошибка в personal_cabinet: {e}")

async def admin_panel(update, context):
    try:
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
            [InlineKeyboardButton("💾 Резервная копия", callback_data='admin_backup')],
            [InlineKeyboardButton("🔙 Назад", callback_data='back_to_main')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            "👨‍💻 Админ-панель\n\n"
            "Выберите действие:",
            reply_markup=reply_markup
        )
    except Exception as e:
        logger.error(f"Ошибка в admin_panel: {e}")

async def admin_users(update, context):
    try:
        query = update.callback_query
        await query.answer()
        
        user = query.from_user
        user_session = get_user_session(user.id)
        
        if not user_session or not user_session[3]:
            await query.edit_message_text("❌ Доступ запрещен!")
            return
        
        conn = sqlite3.connect(get_db_path(), check_same_thread=False)
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
    except Exception as e:
        logger.error(f"Ошибка в admin_users: {e}")

async def add_admin_command(update, context):
    try:
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
    except Exception as e:
        logger.error(f"Ошибка в add_admin_command: {e}")

# Новая команда для резервного копирования
async def backup_command(update, context):
    try:
        user = update.effective_user
        user_session = get_user_session(user.id)
        
        if not user_session or not user_session[3]:
            await update.message.reply_text("❌ Доступ запрещен! Требуются права администратора.")
            return
        
        await update.message.reply_text("🔄 Создаю резервную копию...")
        backup_database()
        await update.message.reply_text("✅ Резервная копия создана и загружена в GitHub!")
        
    except Exception as e:
        logger.error(f"Ошибка в backup_command: {e}")
        await update.message.reply_text("❌ Ошибка при создании резервной копии")

async def button_handler(update, context):
    try:
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
        
        if data == 'admin_backup':
            user_session = get_user_session(user_id)
            if not user_session or not user_session[3]:
                await query.edit_message_text("❌ Доступ запрещен!")
                return
                
            await query.edit_message_text("🔄 Создаю резервную копию...")
            backup_database()
            await query.edit_message_text("✅ Резервная копия создана и загружена в GitHub!")
            return
        
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
                "Ваш запрос будет отправлен администратору на рассмотрение."
            )
            context.user_data['awaiting_file'] = True
        
        elif data == 'help':
            await query.edit_message_text(
                "ℹ️ Помощь\n\n"
                "Как использовать бот:\n"
                "• Для скачивания - используйте ссылку вида: https://t.me/your_bot?start=download-UNIQUE_ID\n"
                "• Для запроса размещения файла - нажмите соответствующую кнопку и отправьте файл с описанием\n"
                "• Администраторы могут управлять файлами через админ-панель\n"
                "• Пользователи могут регистрироваться и входить в личный кабинет\n\n"
                "По вопросам обращайтесь к администратору."
            )
        
        elif data == 'my_files':
            user_session = get_user_session(user_id)
            if not user_session:
                await query.edit_message_text("❌ Для просмотра файлов требуется авторизация!")
                return
                
            conn = sqlite3.connect(get_db_path(), check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute('SELECT file_name, download_id, upload_date FROM files WHERE uploaded_by = ? ORDER BY upload_date DESC LIMIT 10', (user_id,))
            files = cursor.fetchall()
            conn.close()
            
            if files:
                files_text = "📁 Ваши файлы:\n\n"
                for file in files:
                    file_name, download_id, upload_date = file
                    files_text += f"• {file_name}\nID: {download_id}\nДата: {upload_date[:10]}\n\n"
            else:
                files_text = "📁 У вас пока нет файлов"
            
            await query.edit_message_text(files_text)
        
        elif data == 'my_requests':
            user_session = get_user_session(user_id)
            if not user_session:
                await query.edit_message_text("❌ Для просмотра запросов требуется авторизация!")
                return
                
            conn = sqlite3.connect(get_db_path(), check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute('SELECT request_text, status, request_date FROM requests WHERE user_id = ? ORDER BY request_date DESC LIMIT 10', (user_id,))
            requests = cursor.fetchall()
            conn.close()
            
            if requests:
                requests_text = "📨 Ваши запросы:\n\n"
                for req in requests:
                    text, status, date = req
                    status_icon = "✅" if status == "approved" else "❌" if status == "rejected" else "⏳"
                    requests_text += f"{status_icon} {text}\nСтатус: {status}\nДата: {date[:10]}\n\n"
            else:
                requests_text = "📨 У вас пока нет запросов"
            
            await query.edit_message_text(requests_text)
        
        elif data.startswith('admin_'):
            user_session = get_user_session(user_id)
            if not user_session or not user_session[3]:
                await query.edit_message_text("❌ Доступ запрещен!")
                return
            
            if data == 'admin_stats':
                conn = sqlite3.connect(get_db_path(), check_same_thread=False)
                cursor = conn.cursor()
                
                cursor.execute('SELECT COUNT(*) FROM files')
                files_count = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM requests WHERE status = "pending"')
                pending_requests = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM users')
                users_count = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM users WHERE is_admin = TRUE')
                admins_count = cursor.fetchone()[0]
                
                conn.close()
                
                await query.edit_message_text(
                    f"📊 Статистика системы\n\n"
                    f"• Всего файлов: {files_count}\n"
                    f"• Ожидающих запросов: {pending_requests}\n"
                    f"• Всего пользователей: {users_count}\n"
                    f"• Администраторов: {admins_count}"
                )
            
            elif data == 'admin_files':
                conn = sqlite3.connect(get_db_path(), check_same_thread=False)
                cursor = conn.cursor()
                cursor.execute('SELECT id, file_name, download_id, upload_date FROM files ORDER BY upload_date DESC LIMIT 10')
                files = cursor.fetchall()
                conn.close()
                
                if files:
                    files_list = "📁 Последние файлы:\n\n"
                    for file in files:
                        file_id, file_name, download_id, upload_date = file
                        files_list += f"• {file_name}\nID: {download_id}\nДата: {upload_date[:10]}\n\n"
                    
                    # Получаем username бота безопасно
                    try:
                        bot_username = context.bot.username
                        files_list += f"Ссылка для скачивания:\nhttps://t.me/{bot_username}?start=download-"
                    except:
                        files_list += "Ссылка для скачивания:\nhttps://t.me/your_bot?start=download-"
                else:
                    files_list = "📁 Файлы отсутствуют"
                
                await query.edit_message_text(files_list)
            
            elif data == 'admin_requests':
                conn = sqlite3.connect(get_db_path(), check_same_thread=False)
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, user_id, username, first_name, request_text, request_date, file_id, file_type, file_name
                    FROM requests 
                    WHERE status = "pending" 
                    ORDER BY request_date DESC
                ''')
                requests = cursor.fetchall()
                conn.close()
                
                if requests:
                    requests_text = "📨 Ожидающие запросы:\n\n"
                    for req in requests:
                        req_id, user_id, username, first_name, request_text, request_date, file_id, file_type, file_name = req
                        username = username or "Не указан"
                        file_name_display = file_name or "Не указано"
                        requests_text += f"🆔 {req_id}\n👤 {first_name} (@{username})\nID: {user_id}\n📝 {request_text}\n📁 Файл: {file_name_display}\n📅 {request_date[:10]}\n\n"
                    
                    requests_text += "Для обработки запроса используйте /approve <id> или /reject <id>"
                else:
                    requests_text = "✅ Нет ожидающих запросов"
                
                await query.edit_message_text(requests_text)
            
            elif data == 'admin_add_file':
                await query.edit_message_text(
                    "➕ Добавление файла\n\n"
                    "Отправьте файл, который хотите добавить. "
                    "В подписи к файлу можно указать описание."
                )
                context.user_data['admin_adding_file'] = True
    except Exception as e:
        logger.error(f"Ошибка в button_handler: {e}")

def get_file_name(message):
    if message.document:
        return message.document.file_name or "document"
    elif message.photo:
        return "photo.jpg"
    elif message.video:
        return message.video.file_name or "video.mp4"
    elif message.audio:
        return message.audio.file_name or "audio.mp3"
    return "file"

async def handle_file(update, context):
    try:
        user_id = update.effective_user.id
        message = update.message
        
        if not message:
            return
        
        # Проверяем авторизацию для запросов на размещение
        if context.user_data.get('awaiting_file'):
            user_session = get_user_session(user_id)
            if not user_session:
                await message.reply_text("❌ Для отправки запросов требуется авторизация!")
                context.user_data['awaiting_file'] = False
                return
            
            # Сохраняем запрос в базу данных С ФАЙЛОМ
            conn = sqlite3.connect(get_db_path(), check_same_thread=False)
            cursor = conn.cursor()
            
            file_type = None
            file_id = None
            file_name = None
            
            if message.document:
                file_type = 'document'
                file_id = message.document.file_id
                file_name = message.document.file_name or "document"
            elif message.photo:
                file_type = 'photo'
                file_id = message.photo[-1].file_id
                file_name = "photo.jpg"
            elif message.video:
                file_type = 'video'
                file_id = message.video.file_id
                file_name = message.video.file_name or "video.mp4"
            elif message.audio:
                file_type = 'audio'
                file_id = message.audio.file_id
                file_name = message.audio.file_name or "audio.mp3"
            
            description = message.caption or "Без описания"
            
            try:
                # Сохраняем запрос с информацией о файле
                cursor.execute('''
                    INSERT INTO requests (user_id, username, first_name, request_text, file_id, file_type, file_name)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (user_id, update.effective_user.username, update.effective_user.first_name, description, file_id, file_type, file_name))
                
                conn.commit()
                request_id = cursor.lastrowid
                conn.close()
                
                # Уведомляем администраторов
                conn = sqlite3.connect(get_db_path(), check_same_thread=False)
                cursor = conn.cursor()
                cursor.execute('SELECT user_id FROM users WHERE is_admin = TRUE')
                admins = cursor.fetchall()
                conn.close()
                
                for admin in admins:
                    try:
                        await context.bot.send_message(
                            admin[0],
                            f"📨 Новый запрос на размещение файла!\n\n"
                            f"🆔 ID запроса: {request_id}\n"
                            f"👤 Пользователь: {update.effective_user.first_name} (@{update.effective_user.username or 'нет'})\n"
                            f"🆔 User ID: {user_id}\n"
                            f"📁 Файл: {file_name}\n"
                            f"📝 Описание: {description}\n\n"
                            f"Для одобрения: /approve {request_id}\n"
                            f"Для отклонения: /reject {request_id}"
                        )
                    except Exception as e:
                        logger.error(f"Ошибка при отправке уведомления администратору {admin[0]}: {e}")
                
                await message.reply_text(
                    "✅ Ваш запрос отправлен администратору на рассмотрение. "
                    "Вы получите уведомление, когда запрос будет обработан."
                )
                context.user_data['awaiting_file'] = False
                
            except Exception as e:
                logger.error(f"Ошибка при сохранении запроса: {e}")
                await message.reply_text(
                    "❌ Произошла ошибка при обработке запроса. "
                    "Пожалуйста, попробуйте еще раз позже."
                )
                conn.close()
        
        # Проверяем, добавляет ли администратор файл напрямую
        elif context.user_data.get('admin_adding_file'):
            user_session = get_user_session(user_id)
            if not user_session or not user_session[3]:
                await message.reply_text("❌ Доступ запрещен! Требуются права администратора.")
                context.user_data['admin_adding_file'] = False
                return
                
            file_type = None
            file_id = None
            
            if message.document:
                file_type = 'document'
                file_id = message.document.file_id
            elif message.photo:
                file_type = 'photo'
                file_id = message.photo[-1].file_id
            elif message.video:
                file_type = 'video'
                file_id = message.video.file_id
            elif message.audio:
                file_type = 'audio'
                file_id = message.audio.file_id
            
            if file_id:
                download_id = generate_download_id()
                file_name = get_file_name(message)
                description = message.caption or "Без описания"
                
                conn = sqlite3.connect(get_db_path(), check_same_thread=False)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO files (file_id, file_name, file_type, download_id, description, uploaded_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (file_id, file_name, file_type, download_id, description, user_id))
                conn.commit()
                conn.close()
                
                # Получаем username бота безопасно
                try:
                    bot_username = context.bot.username
                    download_link = f"https://t.me/{bot_username}?start=download-{download_id}"
                except:
                    download_link = f"Ссылка будет доступна после перезапуска"
                
                await message.reply_text(
                    f"✅ Файл успешно добавлен!\n\n"
                    f"📁 Имя: {file_name}\n"
                    f"📝 Описание: {description}\n"
                    f"🔗 Ссылка для скачивания:\n{download_link}"
                )
            
            context.user_data['admin_adding_file'] = False
    except Exception as e:
        logger.error(f"Ошибка в handle_file: {e}")

async def approve_request(update, context):
    try:
        user = update.effective_user
        user_session = get_user_session(user.id)
        
        if not user_session or not user_session[3]:
            await update.message.reply_text("❌ Доступ запрещен! Требуются права администратора.")
            return
        
        if len(context.args) == 0:
            await update.message.reply_text("Использование: /approve <id_запроса>")
            return
        
        request_id = context.args[0]
        
        conn = sqlite3.connect(get_db_path(), check_same_thread=False)
        cursor = conn.cursor()
        
        # Получаем информацию о запросе ВКЛЮЧАЯ ДАННЫЕ О ФАЙЛЕ
        cursor.execute('''
            SELECT user_id, request_text, file_id, file_type, file_name 
            FROM requests 
            WHERE id = ? AND status = "pending"
        ''', (request_id,))
        request_data = cursor.fetchone()
        
        if not request_data:
            await update.message.reply_text("❌ Запрос не найден или уже обработан!")
            conn.close()
            return
        
        user_id, description, file_id, file_type, file_name = request_data
        
        # СОЗДАЕМ ЗАПИСЬ В ТАБЛИЦЕ ФАЙЛОВ
        download_id = generate_download_id()
        
        try:
            cursor.execute('''
                INSERT INTO files (file_id, file_name, file_type, download_id, description, uploaded_by)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (file_id, file_name, file_type, download_id, description, user_id))
            
            # Обновляем статус запроса
            cursor.execute('UPDATE requests SET status = "approved" WHERE id = ?', (request_id,))
            conn.commit()
            
            # Получаем username бота безопасно
            try:
                bot_username = context.bot.username
                download_link = f"https://t.me/{bot_username}?start=download-{download_id}"
            except:
                download_link = f"Ссылка будет доступна после перезапуска"
            
            # Уведомляем пользователя
            try:
                await context.bot.send_message(
                    user_id,
                    f"✅ Ваш запрос на размещение файла одобрен!\n\n"
                    f"📁 Файл: {file_name}\n"
                    f"📝 Описание: {description}\n"
                    f"🔗 Ссылка для скачивания:\n{download_link}"
                )
            except Exception as e:
                logger.error(f"Не удалось уведомить пользователя {user_id}: {e}")
            
            await update.message.reply_text(
                f"✅ Запрос одобрен!\n\n"
                f"Ссылка для скачивания:\n{download_link}"
            )
            
        except Exception as e:
            logger.error(f"Ошибка при одобрении запроса: {e}")
            await update.message.reply_text("❌ Ошибка при обработке запроса")
        
        conn.close()
    except Exception as e:
        logger.error(f"Ошибка в approve_request: {e}")

async def reject_request(update, context):
    try:
        user = update.effective_user
        user_session = get_user_session(user.id)
        
        if not user_session or not user_session[3]:
            await update.message.reply_text("❌ Доступ запрещен! Требуются права администратора.")
            return
        
        if len(context.args) == 0:
            await update.message.reply_text("Использование: /reject <id_запроса>")
            return
        
        request_id = context.args[0]
        
        conn = sqlite3.connect(get_db_path(), check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_id FROM requests WHERE id = ? AND status = "pending"', (request_id,))
        request_data = cursor.fetchone()
        
        if not request_data:
            await update.message.reply_text("❌ Запрос не найден или уже обработан!")
            conn.close()
            return
        
        user_id = request_data[0]
        
        cursor.execute('UPDATE requests SET status = "rejected" WHERE id = ?', (request_id,))
        conn.commit()
        conn.close()
        
        # Уведомляем пользователя
        try:
            await context.bot.send_message(
                user_id,
                "❌ Ваш запрос на размещение файла отклонен администратором."
            )
        except Exception as e:
            logger.error(f"Не удалось уведомить пользователя {user_id}: {e}")
        
        await update.message.reply_text("✅ Запрос отклонен!")
    except Exception as e:
        logger.error(f"Ошибка в reject_request: {e}")

async def handle_text(update, context):
    try:
        if not update.message:
            return
            
        if update.message.text and not update.message.text.startswith('/'):
            if not context.user_data.get('awaiting_file') and not context.user_data.get('admin_adding_file'):
                await update.message.reply_text(
                    "Используйте /start для начала работы с ботом."
                )
    except Exception as e:
        logger.error(f"Ошибка в handle_text: {e}")

async def error_handler(update, context):
    """Обработчик ошибок"""
    logger.error(f"Ошибка при обработке обновления: {context.error}")
    try:
        raise context.error
    except Exception as e:
        logger.exception("Исключение в обработчике ошибок:")

def main():
    """Основная функция запуска бота - СИНХРОННАЯ для Railway"""
    try:
        # Проверяем наличие необходимых библиотек
        try:
            from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackQueryHandler
        except ImportError:
            print("❌ Библиотека python-telegram-bot не установлена!")
            print("Добавьте в requirements.txt: python-telegram-bot==20.7")
            return
        
        # Инициализация базы данных
        init_db()
        
        # Проверяем наличие токена
        if not BOT_TOKEN:
            logger.error("❌ BOT_TOKEN не установлен! Укажите токен в коде.")
            return
        
        logger.info(f"🚀 Запуск бота с токеном: {BOT_TOKEN[:10]}...")
        
        # Создаем и запускаем приложение СИНХРОННО
        application = Application.builder().token(BOT_TOKEN).build()
        
        # Обработчики команд
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("login", login))
        application.add_handler(CommandHandler("register", register))
        application.add_handler(CommandHandler("logout", logout))
        application.add_handler(CommandHandler("addadmin", add_admin_command))
        application.add_handler(CommandHandler("approve", approve_request))
        application.add_handler(CommandHandler("reject", reject_request))
        application.add_handler(CommandHandler("backup", backup_command))
        
        # Обработчики callback запросов
        application.add_handler(CallbackQueryHandler(button_handler))
        
        # Обработчики сообщений с файлами
        application.add_handler(MessageHandler(
            filters.Document.ALL | filters.PHOTO | filters.VIDEO | filters.AUDIO,
            handle_file
        ))
        
        # Обработчик текстовых сообщений
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
        
        # Обработчик ошибок
        application.add_error_handler(error_handler)
        
        # Запуск бота
        logger.info("🤖 Бот запускается...")
        print("🚀 Бот запущен!")
        print(f"📍 Токен: {BOT_TOKEN[:10]}...")
        print("⏹️ Для остановки нажмите Ctrl+C")
        
        # ЗАПУСКАЕМ БОТА СИНХРОННО
        application.run_polling()
        
    except KeyboardInterrupt:
        # Создаем резервную копию при остановке
        backup_database()
        logger.info("Бот остановлен пользователем")
        print("\n🛑 Бот остановлен")
    except Exception as e:
        logger.error(f"Фатальная ошибка: {e}")
        print(f"❌ Фатальная ошибка: {e}")

if __name__ == '__main__':
    main()

import os
import logging
import sqlite3
import secrets
import string
import asyncio
import time
from datetime import datetime
import hashlib

# Настройка логирования для Railway
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Детальная проверка переменных окружения
logger.info("🔍 Проверяем переменные окружения...")
all_env_vars = dict(os.environ)
logger.info(f"Доступные переменные: {list(all_env_vars.keys())}")

# Получаем токен бота из переменных окружения Railway
BOT_TOKEN = os.environ.get('BOT_TOKEN')

# Если токен не найден, проверяем альтернативные имена
if not BOT_TOKEN:
    BOT_TOKEN = os.environ.get('TOKEN')
if not BOT_TOKEN:
    BOT_TOKEN = os.environ.get('BOT_TOKEN')

logger.info(f"📋 BOT_TOKEN из переменных окружения: {'***УСТАНОВЛЕН***' if BOT_TOKEN else 'НЕ НАЙДЕН'}")

# Если все еще нет токена, используем заглушку для тестирования
if not BOT_TOKEN:
    logger.warning("⚠️ BOT_TOKEN не найден в переменных окружения")
    # Для тестирования можно временно использовать ваш токен
BOT_TOKEN = "8493433461:AAEZxG0Ix7em5ff3XHF36EZCmZyPMkf6WZE"
    # Но лучше настроить переменные окружения правильно

DEFAULT_ADMIN_PASSWORD = "34613461"

# Настройки переподключения
RECONNECT_DELAY = 5
MAX_RECONNECT_ATTEMPTS = 10

# Остальной код остается без изменений..


# Хеширование паролей
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Инициализация базы данных
def init_db():
    try:
        # Используем абсолютный путь для Railway
        db_path = '/tmp/files.db' if 'RAILWAY_ENVIRONMENT' in os.environ else 'files.db'
        conn = sqlite3.connect(db_path, check_same_thread=False)
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
    except Exception as e:
        logger.error(f"Ошибка инициализации БД: {e}")

# Получение пути к БД
def get_db_path():
    return '/tmp/files.db' if 'RAILWAY_ENVIRONMENT' in os.environ else 'files.db'

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

# Остальные функции остаются аналогичными, но с добавлением try-except блоков
# Для экономии места покажу только измененные части...

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

# Все остальные функции (login, register, button_handler и т.д.) 
# должны быть аналогично обернуты в try-except блоки

async def error_handler(update, context):
    """Обработчик ошибок"""
    logger.error(f"Ошибка при обработке обновления: {context.error}")
    try:
        raise context.error
    except Exception as e:
        logger.exception("Исключение в обработчике ошибок:")

async def run_bot():
    """Запуск бота с обработкой ошибок для Railway"""
    try:
        from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackQueryHandler
        
        # Инициализация базы данных
        init_db()
        
        # Проверяем наличие токена
        if not BOT_TOKEN or BOT_TOKEN == '8493433461:AAEZxG0Ix7em5ff3XHF36EZCmZyPMkf6WZE':
            logger.error("❌ BOT_TOKEN не установлен! Добавьте его в переменные окружения Railway.")
            return
        
        application = Application.builder().token(BOT_TOKEN).build()
        
        # Обработчики команд
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("login", login))
        application.add_handler(CommandHandler("register", register))
        application.add_handler(CommandHandler("logout", logout))
        application.add_handler(CommandHandler("addadmin", add_admin_command))
        application.add_handler(CommandHandler("approve", approve_request))
        application.add_handler(CommandHandler("reject", reject_request))
        
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
        logger.info("🤖 Бот запускается на Railway...")
        print("🚀 Бот запущен на Railway!")
        print("📍 Используется БД:", get_db_path())
        print("🔑 Токен установлен:", bool(BOT_TOKEN and BOT_TOKEN != '8493433461:AAEZxG0Ix7em5ff3XHF36EZCmZyPMkf6WZE'))
        
        await application.run_polling()
        
    except Exception as e:
        logger.error(f"Критическая ошибка при запуске бота: {e}")
        raise

def main():
    """Основная функция запуска бота для Railway"""
    try:
        # Проверяем наличие необходимых библиотек
        try:
            from telegram.ext import Application
        except ImportError:
            print("❌ Библиотека python-telegram-bot не установлена!")
            print("Добавьте в requirements.txt: python-telegram-bot==20.7")
            return
        
        # Запускаем бота
        asyncio.run(run_bot())
        
    except KeyboardInterrupt:
        logger.info("Бот остановлен пользователем")
        print("\n🛑 Бот остановлен")
    except Exception as e:
        logger.error(f"Фатальная ошибка: {e}")
        print(f"❌ Фатальная ошибка: {e}")

if __name__ == '__main__':
    main()

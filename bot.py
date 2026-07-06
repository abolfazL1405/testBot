#!/usr/bin/env python3
"""
🤖 Telegram Bot Interactive v4.0 - Fully Interactive Edition
ربات تعاملی کامل با دستورات، دکمه‌ها و قابلیت‌های پیشرفته
"""

import os
import sys
import json
import time
import signal
import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from collections import defaultdict
from contextlib import contextmanager

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv


# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class Config:
    """Application configuration"""
    bot_token: str
    data_dir: Path = Path("telegram_data")
    db_file: str = "collector.db"
    log_level: str = "INFO"
    log_file: str = "logs/collector.log"
    log_max_bytes: int = 10 * 1024 * 1024  # 10MB
    log_backup_count: int = 5
    polling_timeout: int = 30
    max_retries: int = 3
    rate_limit_delay: float = 0.1
    batch_save_size: int = 50
    health_check_interval: int = 300  # 5 minutes
    @classmethod
    def from_env(cls) -> 'Config':
        """Load configuration from environment variables or .env file"""
        load_dotenv()
        
        # Try environment variable first (for GitHub Actions)
        token = os.getenv('TELEGRAM_BOT_TOKEN')
        
        # If not found, try to read from .env file
        if not token:
            token = os.getenv('TELEGRAM_BOT_TOKEN', '').strip()
        
        if not token:
            raise ValueError(
                "TELEGRAM_BOT_TOKEN not found. "
                "Set it as environment variable or in .env file"
            )
        
        return cls(
            bot_token=token,
            data_dir=Path(os.getenv('DATA_DIR', 'telegram_data')),
            db_file=os.getenv('DB_FILE', 'collector.db'),
            log_level=os.getenv('LOG_LEVEL', 'INFO'),
            log_file=os.getenv('LOG_FILE', 'logs/collector.log'),
            log_max_bytes=int(os.getenv('LOG_MAX_BYTES', str(10 * 1024 * 1024))),
            log_backup_count=int(os.getenv('LOG_BACKUP_COUNT', '5')),
            polling_timeout=int(os.getenv('POLLING_TIMEOUT', '30')),
            max_retries=int(os.getenv('MAX_RETRIES', '3')),
            batch_save_size=int(os.getenv('BATCH_SAVE_SIZE', '50')),
            health_check_interval=int(os.getenv('HEALTH_CHECK_INTERVAL', '300')),
        )


# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging(config: Config) -> logging.Logger:
    """Setup production logging"""
    from logging.handlers import RotatingFileHandler
    
    logger = logging.getLogger('telegram_bot')
    logger.setLevel(getattr(logging, config.log_level.upper()))
    
    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    log_path = Path(config.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger


# ============================================================================
# DATABASE MANAGER
# ============================================================================

class DatabaseManager:
    """SQLite database manager"""
    
    def __init__(self, db_path: Path, logger: logging.Logger):
        self.db_path = db_path
        self.logger = logger
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    first_name TEXT,
                    last_name TEXT,
                    username TEXT,
                    language_code TEXT,
                    is_premium BOOLEAN DEFAULT FALSE,
                    messages_count INTEGER DEFAULT 0,
                    commands_count INTEGER DEFAULT 0,
                    first_seen TEXT,
                    last_seen TEXT,
                    is_admin BOOLEAN DEFAULT FALSE
                );
                
                CREATE TABLE IF NOT EXISTS chats (
                    chat_id INTEGER PRIMARY KEY,
                    chat_type TEXT,
                    title TEXT,
                    username TEXT,
                    messages_count INTEGER DEFAULT 0,
                    first_message TEXT,
                    last_message TEXT
                );
                
                CREATE TABLE IF NOT EXISTS user_stats (
                    user_id INTEGER,
                    stat_key TEXT,
                    stat_value INTEGER DEFAULT 0,
                    PRIMARY KEY (user_id, stat_key),
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                );
                
                CREATE TABLE IF NOT EXISTS settings (
                    user_id INTEGER,
                    setting_key TEXT,
                    setting_value TEXT,
                    PRIMARY KEY (user_id, setting_key),
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                );
            ''')
        self.logger.info(f"✅ Database initialized: {self.db_path}")
    
    @contextmanager
    def _get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def save_user(self, user_data: Dict):
        """Save or update user"""
        user_id = user_data.get('user_id')
        
        with self._get_connection() as conn:
            existing = conn.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone()
            
            if existing:
                conn.execute('''
                    UPDATE users SET 
                        first_name = ?, last_name = ?, username = ?, 
                        language_code = ?, is_premium = ?, messages_count = ?,
                        last_seen = ?
                    WHERE user_id = ?
                ''', (
                    user_data.get('first_name'),
                    user_data.get('last_name'),
                    user_data.get('username'),
                    user_data.get('language_code'),
                    user_data.get('is_premium', False),
                    user_data.get('messages_count', 0),
                    user_data.get('last_seen'),
                    user_id
                ))
            else:
                conn.execute('''
                    INSERT INTO users 
                    (user_id, first_name, last_name, username, language_code, 
                     is_premium, messages_count, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user_id,
                    user_data.get('first_name'),
                    user_data.get('last_name'),
                    user_data.get('username'),
                    user_data.get('language_code'),
                    user_data.get('is_premium', False),
                    user_data.get('messages_count', 0),
                    user_data.get('first_seen'),
                    user_data.get('last_seen'),
                ))
    
    def increment_user_stat(self, user_id: int, stat_key: str):
        """Increment user statistic"""
        with self._get_connection() as conn:
            conn.execute('''
                INSERT INTO user_stats (user_id, stat_key, stat_value)
                VALUES (?, ?, 1)
                ON CONFLICT(user_id, stat_key) DO UPDATE SET stat_value = stat_value + 1
            ''', (user_id, stat_key))
    
    def get_user(self, user_id: int) -> Optional[Dict]:
        """Get user by ID"""
        with self._get_connection() as conn:
            row = conn.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone()
            return dict(row) if row else None
    
    def get_user_stats(self, user_id: int) -> Dict:
        """Get user statistics"""
        with self._get_connection() as conn:
            rows = conn.execute(
                'SELECT stat_key, stat_value FROM user_stats WHERE user_id = ?',
                (user_id,)
            ).fetchall()
            return {r[0]: r[1] for r in rows}
    
    def save_chat(self, chat_data: Dict):
        """Save or update chat"""
        chat_id = chat_data.get('chat_id')
        
        with self._get_connection() as conn:
            existing = conn.execute('SELECT * FROM chats WHERE chat_id = ?', (chat_id,)).fetchone()
            
            if existing:
                conn.execute('''
                    UPDATE chats SET 
                        chat_type = ?, title = ?, username = ?,
                        messages_count = ?, last_message = ?
                    WHERE chat_id = ?
                ''', (
                    chat_data.get('chat_type'),
                    chat_data.get('title'),
                    chat_data.get('username'),
                    chat_data.get('messages_count', 0),
                    chat_data.get('last_message'),
                    chat_id
                ))
            else:
                conn.execute('''
                    INSERT INTO chats 
                    (chat_id, chat_type, title, username, messages_count, first_message, last_message)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    chat_id,
                    chat_data.get('chat_type'),
                    chat_data.get('title'),
                    chat_data.get('username'),
                    chat_data.get('messages_count', 0),
                    chat_data.get('first_message'),
                    chat_data.get('last_message'),
                ))
    
    def get_stats(self) -> Dict:
        """Get overall statistics"""
        with self._get_connection() as conn:
            return {
                'total_users': conn.execute('SELECT COUNT(*) FROM users').fetchone()[0],
                'total_chats': conn.execute('SELECT COUNT(*) FROM chats').fetchone()[0],
                'total_messages': conn.execute('SELECT SUM(messages_count) FROM users').fetchone()[0] or 0,
            }
    
    def get_top_users(self, limit: int = 10) -> List[Dict]:
        """Get top users by message count"""
        with self._get_connection() as conn:
            rows = conn.execute(
                'SELECT * FROM users ORDER BY messages_count DESC LIMIT ?',
                (limit,)
            ).fetchall()
            return [dict(row) for row in rows]


# ============================================================================
# TELEGRAM API CLIENT
# ============================================================================

class TelegramAPI:
    """Telegram Bot API client"""
    
    def __init__(self, bot_token: str, config: Config, logger: logging.Logger):
        self.bot_token = bot_token
        self.base_url = f"https://api.telegram.org/bot{bot_token}"
        self.config = config
        self.logger = logger
        
        self.session = requests.Session()
        retry_strategy = Retry(
            total=config.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
    
    def _api_call(self, method: str, data: Optional[Dict] = None) -> Dict:
        """Make API call"""
        url = f"{self.base_url}/{method}"
        
        try:
            response = self.session.post(url, json=data, timeout=30)
            response.raise_for_status()
            result = response.json()
            
            if not result.get('ok'):
                error_msg = result.get('description', 'Unknown error')
                self.logger.error(f"API error: {error_msg}")
                return {'ok': False, 'error': error_msg}
            
            return result
            
        except Exception as e:
            self.logger.error(f"API call error: {e}")
            return {'ok': False, 'error': str(e)}
    
    def send_message(self, chat_id: int, text: str, reply_markup: Optional[Dict] = None, 
                    parse_mode: str = 'HTML') -> Dict:
        """Send message"""
        data = {
            'chat_id': chat_id,
            'text': text,
            'parse_mode': parse_mode
        }
        if reply_markup:
            data['reply_markup'] = reply_markup
        
        return self._api_call('sendMessage', data)
    
    def edit_message(self, chat_id: int, message_id: int, text: str, 
                    reply_markup: Optional[Dict] = None, parse_mode: str = 'HTML') -> Dict:
        """Edit message"""
        data = {
            'chat_id': chat_id,
            'message_id': message_id,
            'text': text,
            'parse_mode': parse_mode
        }
        if reply_markup:
            data['reply_markup'] = reply_markup
        
        return self._api_call('editMessageText', data)
    
    def answer_callback(self, callback_query_id: str, text: str = None, 
                       show_alert: bool = False) -> Dict:
        """Answer callback query"""
        data = {'callback_query_id': callback_query_id}
        if text:
            data['text'] = text
            data['show_alert'] = show_alert
        
        return self._api_call('answerCallbackQuery', data)
    
    def get_updates(self, offset: Optional[int] = None, timeout: int = 30) -> List[Dict]:
        """Get updates"""
        data = {
            'timeout': timeout,
            'allowed_updates': ['message', 'callback_query']
        }
        if offset:
            data['offset'] = offset
        
        result = self._api_call('getUpdates', data)
        return result.get('result', []) if result.get('ok') else []


# ============================================================================
# KEYBOARD BUILDER
# ============================================================================

class KeyboardBuilder:
    """Build keyboards for messages"""
    
    @staticmethod
    def inline_keyboard(buttons: List[List[Dict]]) -> Dict:
        """Build inline keyboard"""
        return {
            'inline_keyboard': [
                [{'text': btn['text'], 'callback_data': btn['callback_data']} for btn in row]
                for row in buttons
            ]
        }
    
    @staticmethod
    def reply_keyboard(buttons: List[List[str]], resize: bool = True, 
                      one_time: bool = False) -> Dict:
        """Build reply keyboard"""
        return {
            'keyboard': [[{'text': text} for text in row] for row in buttons],
            'resize_keyboard': resize,
            'one_time_keyboard': one_time
        }
    
    @staticmethod
    def remove_keyboard() -> Dict:
        """Remove keyboard"""
        return {'remove_keyboard': True}


# ============================================================================
# BOT HANDLER
# ============================================================================

class TelegramBot:
    """Interactive Telegram Bot"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = setup_logging(config)
        self.api = TelegramAPI(config.bot_token, config, self.logger)
        self.db = DatabaseManager(config.data_dir / config.db_file, self.logger)
        self.kb = KeyboardBuilder()
        
        self.running = False
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers"""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"\n⚠️  Received signal {signum}, shutting down...")
        self.running = False
    
    def _get_or_create_user(self, user_data: Dict) -> Dict:
        """Get or create user"""
        user_id = user_data.get('id')
        existing = self.db.get_user(user_id)
        
        if existing:
            return existing
        
        now = datetime.now().isoformat()
        new_user = {
            'user_id': user_id,
            'first_name': user_data.get('first_name'),
            'last_name': user_data.get('last_name'),
            'username': user_data.get('username'),
            'language_code': user_data.get('language_code'),
            'is_premium': user_data.get('is_premium', False),
            'messages_count': 0,
            'first_seen': now,
            'last_seen': now,
        }
        
        self.db.save_user(new_user)
        return new_user
    
    def _update_user_activity(self, user_id: int, is_command: bool = False):
        """Update user activity"""
        user = self.db.get_user(user_id)
        if user:
            user['messages_count'] = user.get('messages_count', 0) + 1
            user['last_seen'] = datetime.now().isoformat()
            if is_command:
                user['commands_count'] = user.get('commands_count', 0) + 1
            self.db.save_user(user)
    
    def _update_chat(self, chat_data: Dict):
        """Update chat data"""
        chat_id = chat_data.get('id')
        now = datetime.now().isoformat()
        
        chat = {
            'chat_id': chat_id,
            'chat_type': chat_data.get('type'),
            'title': chat_data.get('title'),
            'username': chat_data.get('username'),
            'messages_count': 1,
            'first_message': now,
            'last_message': now,
        }
        
        self.db.save_chat(chat)
    
    # ========================================================================
    # COMMAND HANDLERS
    # ========================================================================
    
    def handle_start(self, message: Dict):
        """Handle /start command"""
        chat_id = message['chat']['id']
        user = message['from']
        
        self._get_or_create_user(user)
        self._update_user_activity(user['id'], is_command=True)
        self.db.increment_user_stat(user['id'], 'start_commands')
        
        text = (
            f"👋 سلام {user.get('first_name', '')}!\n\n"
            f"به ربات تعاملی خوش اومدی!\n\n"
            f"📋 دستورات موجود:\n"
            f"• /menu - منوی اصلی\n"
            f"• /stats - آمار شما\n"
            f"• /help - راهنما\n"
            f"• /about - درباره ربات\n"
            f"• /settings - تنظیمات\n\n"
            f"روی دکمه‌ها کلیک کن یا دستورات رو تایپ کن!"
        )
        
        keyboard = self.kb.inline_keyboard([
            [{'text': '📊 آمار', 'callback_data': 'stats'}, {'text': '⚙️ تنظیمات', 'callback_data': 'settings'}],
            [{'text': 'ℹ️ درباره', 'callback_data': 'about'}, {'text': '❓ راهنما', 'callback_data': 'help'}],
        ])
        
        self.api.send_message(chat_id, text, reply_markup=keyboard)
    
    def handle_menu(self, message: Dict):
        """Handle /menu command"""
        chat_id = message['chat']['id']
        user_id = message['from']['id']
        
        self._update_user_activity(user_id, is_command=True)
        self.db.increment_user_stat(user_id, 'menu_commands')
        
        text = "📋 منوی اصلی\n\nیکی از گزینه‌ها رو انتخاب کن:"
        
        keyboard = self.kb.inline_keyboard([
            [{'text': '📊 آمار من', 'callback_data': 'stats'}, {'text': '🏆 برترین‌ها', 'callback_data': 'top_users'}],
            [{'text': '⚙️ تنظیمات', 'callback_data': 'settings'}, {'text': '📝 راهنما', 'callback_data': 'help'}],
            [{'text': '🔄 به‌روزرسانی', 'callback_data': 'refresh'}],
        ])
        
        self.api.send_message(chat_id, text, reply_markup=keyboard)
    
    def handle_stats(self, message: Dict):
        """Handle /stats command"""
        chat_id = message['chat']['id']
        user_id = message['from']['id']
        
        self._update_user_activity(user_id, is_command=True)
        
        user = self.db.get_user(user_id)
        user_stats = self.db.get_user_stats(user_id)
        
        if not user:
            self.api.send_message(chat_id, "❌ اطلاعات کاربر یافت نشد")
            return
        
        text = (
            f"📊 آمار شما\n\n"
            f"👤 نام: {user.get('first_name', 'N/A')} {user.get('last_name', '')}\n"
            f"🆔 آیدی: <code>{user_id}</code>\n"
            f"💬 پیام‌ها: {user.get('messages_count', 0)}\n"
            f"📅 اولین بازدید: {user.get('first_seen', 'N/A')[:10]}\n"
            f"🕐 آخرین بازدید: {user.get('last_seen', 'N/A')[:10]}\n\n"
            f"📈 آمار دستورات:\n"
            f"• /start: {user_stats.get('start_commands', 0)}\n"
            f"• /menu: {user_stats.get('menu_commands', 0)}\n"
            f"• /stats: {user_stats.get('stats_commands', 0)}\n"
            f"• /help: {user_stats.get('help_commands', 0)}"
        )
        
        keyboard = self.kb.inline_keyboard([
            [{'text': '🔙 بازگشت', 'callback_data': 'menu'}]
        ])
        
        self.api.send_message(chat_id, text, reply_markup=keyboard)
    
    def handle_help(self, message: Dict):
        """Handle /help command"""
        chat_id = message['chat']['id']
        user_id = message['from']['id']
        
        self._update_user_activity(user_id, is_command=True)
        self.db.increment_user_stat(user_id, 'help_commands')
        
        text = (
            "❓ راهنمای استفاده\n\n"
            "📋 دستورات:\n"
            "• /start - شروع و خوش‌آمدگویی\n"
            "• /menu - منوی اصلی\n"
            "• /stats - نمایش آمار شما\n"
            "• /help - این راهنما\n"
            "• /about - درباره ربات\n"
            "• /settings - تنظیمات\n\n"
            "🎮 دکمه‌ها:\n"
            "• روی دکمه‌های زیر پیام کلیک کن\n"
            "• هر دکمه یه عملکرد خاص داره\n\n"
            "💡 نکته: می‌تونی هر متنی رو بفرستی تا ذخیره بشه!"
        )
        
        keyboard = self.kb.inline_keyboard([
            [{'text': '🔙 منو', 'callback_data': 'menu'}]
        ])
        
        self.api.send_message(chat_id, text, reply_markup=keyboard)
    
    def handle_about(self, message: Dict):
        """Handle /about command"""
        chat_id = message['chat']['id']
        user_id = message['from']['id']
        
        self._update_user_activity(user_id, is_command=True)
        
        stats = self.db.get_stats()
        
        text = (
            "ℹ️ درباره ربات\n\n"
            "🤖 ربات تعاملی تلگرام\n"
            "📌 نسخه: 4.0\n"
            "🛠️ ساخته شده با: Python + SQLite\n\n"
            f"📊 آمار کلی:\n"
            f"• 👥 کاربران: {stats['total_users']}\n"
            f"• 💬 چت‌ها: {stats['total_chats']}\n"
            f"• 📨 پیام‌ها: {stats['total_messages']}\n\n"
            "✨ این ربات برای تست و یادگیری ساخته شده"
        )
        
        keyboard = self.kb.inline_keyboard([
            [{'text': '🔙 بازگشت', 'callback_data': 'menu'}]
        ])
        
        self.api.send_message(chat_id, text, reply_markup=keyboard)
    
    def handle_settings(self, message: Dict):
        """Handle /settings command"""
        chat_id = message['chat']['id']
        user_id = message['from']['id']
        
        self._update_user_activity(user_id, is_command=True)
        
        text = "⚙️ تنظیمات\n\nتنظیمات مورد نظر رو انتخاب کن:"
        
        keyboard = self.kb.inline_keyboard([
            [{'text': '🌐 زبان', 'callback_data': 'settings_language'}, {'text': '🔔 اعلان‌ها', 'callback_data': 'settings_notifications'}],
            [{'text': '🎨 تم', 'callback_data': 'settings_theme'}, {'text': '🔙 بازگشت', 'callback_data': 'menu'}],
        ])
        
        self.api.send_message(chat_id, text, reply_markup=keyboard)
    
    def handle_unknown(self, message: Dict):
        """Handle unknown message"""
        chat_id = message['chat']['id']
        user_id = message['from']['id']
        
        self._update_user_activity(user_id)
        
        text = message.get('text', '')
        
        if text.startswith('/'):
            response = f"❓ دستور ناشناخته: {text}\n\nاز /help برای دیدن دستورات استفاده کن"
        else:
            response = f"✅ پیام شما دریافت شد:\n\n«{text}»\n\nاین پیام ذخیره شد!"
            self.db.increment_user_stat(user_id, 'text_messages')
        
        keyboard = self.kb.inline_keyboard([
            [{'text': '📋 منو', 'callback_data': 'menu'}]
        ])
        
        self.api.send_message(chat_id, response, reply_markup=keyboard)
    
    # ========================================================================
    # CALLBACK HANDLERS
    # ========================================================================
    
    def handle_callback(self, callback_query: Dict):
        """Handle callback query"""
        callback_id = callback_query['id']
        data = callback_query.get('data', '')
        chat_id = callback_query['message']['chat']['id']
        message_id = callback_query['message']['message_id']
        user_id = callback_query['from']['id']
        
        self._update_user_activity(user_id)
        
        # Answer callback to remove loading indicator
        self.api.answer_callback(callback_id)
        
        # Route to appropriate handler
        if data == 'stats':
            self._callback_stats(chat_id, message_id, user_id)
        elif data == 'menu':
            self._callback_menu(chat_id, message_id, user_id)
        elif data == 'help':
            self._callback_help(chat_id, message_id, user_id)
        elif data == 'about':
            self._callback_about(chat_id, message_id, user_id)
        elif data == 'settings':
            self._callback_settings(chat_id, message_id, user_id)
        elif data == 'top_users':
            self._callback_top_users(chat_id, message_id, user_id)
        elif data == 'refresh':
            self._callback_refresh(chat_id, message_id, user_id)
        elif data.startswith('settings_'):
            self._callback_settings_option(chat_id, message_id, user_id, data)
        else:
            self.api.send_message(chat_id, f"⚠️ گزینه ناشناخته: {data}")
    
    def _callback_stats(self, chat_id: int, message_id: int, user_id: int):
        """Callback for stats"""
        user = self.db.get_user(user_id)
        user_stats = self.db.get_user_stats(user_id)
        
        text = (
            f"📊 آمار شما\n\n"
            f"👤 نام: {user.get('first_name', 'N/A')}\n"
            f"💬 پیام‌ها: {user.get('messages_count', 0)}\n"
            f"📅 اولین بازدید: {user.get('first_seen', 'N/A')[:10]}\n\n"
            f"📈 آمار دستورات:\n"
            f"• /start: {user_stats.get('start_commands', 0)}\n"
            f"• /menu: {user_stats.get('menu_commands', 0)}\n"
            f"• /stats: {user_stats.get('stats_commands', 0)}"
        )
        
        keyboard = self.kb.inline_keyboard([
            [{'text': '🔙 بازگشت', 'callback_data': 'menu'}]
        ])
        
        self.api.edit_message(chat_id, message_id, text, reply_markup=keyboard)
    
    def _callback_menu(self, chat_id: int, message_id: int, user_id: int):
        """Callback for menu"""
        text = "📋 منوی اصلی\n\nیکی از گزینه‌ها رو انتخاب کن:"
        
        keyboard = self.kb.inline_keyboard([
            [{'text': '📊 آمار من', 'callback_data': 'stats'}, {'text': '🏆 برترین‌ها', 'callback_data': 'top_users'}],
            [{'text': '⚙️ تنظیمات', 'callback_data': 'settings'}, {'text': '📝 راهنما', 'callback_data': 'help'}],
            [{'text': '🔄 به‌روزرسانی', 'callback_data': 'refresh'}],
        ])
        
        self.api.edit_message(chat_id, message_id, text, reply_markup=keyboard)
    
    def _callback_help(self, chat_id: int, message_id: int, user_id: int):
        """Callback for help"""
        text = (
            "❓ راهنما\n\n"
            "📋 دستورات:\n"
            "• /start - شروع\n"
            "• /menu - منو\n"
            "• /stats - آمار\n"
            "• /help - راهنما\n"
            "• /about - درباره\n"
            "• /settings - تنظیمات"
        )
        
        keyboard = self.kb.inline_keyboard([
            [{'text': '🔙 بازگشت', 'callback_data': 'menu'}]
        ])
        
        self.api.edit_message(chat_id, message_id, text, reply_markup=keyboard)
    
    def _callback_about(self, chat_id: int, message_id: int, user_id: int):
        """Callback for about"""
        stats = self.db.get_stats()
        
        text = (
            "ℹ️ درباره ربات\n\n"
            "🤖 ربات تعاملی تلگرام\n"
            "📌 نسخه: 4.0\n\n"
            f"📊 آمار:\n"
            f"• 👥 کاربران: {stats['total_users']}\n"
            f"• 💬 چت‌ها: {stats['total_chats']}\n"
            f"• 📨 پیام‌ها: {stats['total_messages']}"
        )
        
        keyboard = self.kb.inline_keyboard([
            [{'text': '🔙 بازگشت', 'callback_data': 'menu'}]
        ])
        
        self.api.edit_message(chat_id, message_id, text, reply_markup=keyboard)
    
    def _callback_settings(self, chat_id: int, message_id: int, user_id: int):
        """Callback for settings"""
        text = "⚙️ تنظیمات\n\nتنظیمات مورد نظر رو انتخاب کن:"
        
        keyboard = self.kb.inline_keyboard([
            [{'text': '🌐 زبان', 'callback_data': 'settings_language'}, {'text': '🔔 اعلان‌ها', 'callback_data': 'settings_notifications'}],
            [{'text': '🎨 تم', 'callback_data': 'settings_theme'}, {'text': '🔙 بازگشت', 'callback_data': 'menu'}],
        ])
        
        self.api.edit_message(chat_id, message_id, text, reply_markup=keyboard)
    
    def _callback_top_users(self, chat_id: int, message_id: int, user_id: int):
        """Callback for top users"""
        top_users = self.db.get_top_users(10)
        
        text = "🏆 برترین کاربران\n\n"
        
        if not top_users:
            text += "هنوز کاربری ثبت نشده!"
        else:
            for i, user in enumerate(top_users, 1):
                name = user.get('first_name', 'ناشناس')
                count = user.get('messages_count', 0)
                text += f"{i}. {name} - {count} پیام\n"
        
        keyboard = self.kb.inline_keyboard([
            [{'text': '🔙 بازگشت', 'callback_data': 'menu'}]
        ])
        
        self.api.edit_message(chat_id, message_id, text, reply_markup=keyboard)
    
    def _callback_refresh(self, chat_id: int, message_id: int, user_id: int):
        """Callback for refresh"""
        self.api.answer_callback(
            f"refresh_{user_id}",
            text="✅ به‌روزرسانی شد!",
            show_alert=False
        )
        
        text = "🔄 به‌روزرسانی شد!\n\nمنو دوباره بارگذاری شد."
        
        keyboard = self.kb.inline_keyboard([
            [{'text': '📊 آمار من', 'callback_data': 'stats'}, {'text': '🏆 برترین‌ها', 'callback_data': 'top_users'}],
            [{'text': '⚙️ تنظیمات', 'callback_data': 'settings'}, {'text': '📝 راهنما', 'callback_data': 'help'}],
            [{'text': '🔄 به‌روزرسانی', 'callback_data': 'refresh'}],
        ])
        
        self.api.edit_message(chat_id, message_id, text, reply_markup=keyboard)
    
    def _callback_settings_option(self, chat_id: int, message_id: int, 
                                 user_id: int, option: str):
        """Callback for settings options"""
        option_name = option.replace('settings_', '')
        
        text = f"⚙️ تنظیمات {option_name}\n\nاین گزینه در نسخه بعدی فعال می‌شود!"
        
        keyboard = self.kb.inline_keyboard([
            [{'text': '🔙 بازگشت', 'callback_data': 'settings'}]
        ])
        
        self.api.edit_message(chat_id, message_id, text, reply_markup=keyboard)
    
    # ========================================================================
    # MESSAGE PROCESSOR
    # ========================================================================
    
    def process_message(self, message: Dict):
        """Process incoming message"""
        chat = message.get('chat', {})
        user = message.get('from', {})
        text = message.get('text', '')
        
        # Update chat
        self._update_chat(chat)
        
        # Route to command handler
        if text.startswith('/'):
            command = text.split()[0].lower().split('@')[0]
            
            if command == '/start':
                self.handle_start(message)
            elif command == '/menu':
                self.handle_menu(message)
            elif command == '/stats':
                self.handle_stats(message)
            elif command == '/help':
                self.handle_help(message)
            elif command == '/about':
                self.handle_about(message)
            elif command == '/settings':
                self.handle_settings(message)
            else:
                self.handle_unknown(message)
        else:
            self.handle_unknown(message)
    
    def process_callback(self, callback_query: Dict):
        """Process callback query"""
        self.handle_callback(callback_query)
    
    # ========================================================================
    # MAIN LOOP
    # ========================================================================
    
    def start_polling(self):
        """Start polling loop"""
        self.logger.info("=" * 70)
        self.logger.info("🚀 Starting Interactive Telegram Bot v4.0")
        self.logger.info("=" * 70)
        
        # Test connection
        result = self.api._api_call('getMe')
        if not result.get('ok'):
            self.logger.error(f"❌ Cannot connect: {result.get('error')}")
            return False
        
        bot_info = result.get('result', {})
        self.logger.info(f"✅ Bot connected: @{bot_info.get('username')} (ID: {bot_info.get('id')})")
        
        self.running = True
        offset = None
        
        self.logger.info("📡 Starting polling...")
        self.logger.info(f"📁 Data directory: {self.config.data_dir.absolute()}")
        
        try:
            while self.running:
                updates = self.api.get_updates(offset=offset, timeout=self.config.polling_timeout)
                
                if updates:
                    for update in updates:
                        offset = update['update_id'] + 1
                        
                        if 'message' in update:
                            self.process_message(update['message'])
                        elif 'callback_query' in update:
                            self.process_callback(update['callback_query'])
                
                time.sleep(self.config.rate_limit_delay)
                
        except KeyboardInterrupt:
            self.logger.info("\n⚠️  Interrupted by user")
        except Exception as e:
            self.logger.error(f"❌ Error: {e}", exc_info=True)
            raise
        finally:
            self.logger.info("✅ Bot stopped")
        
        return True


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main entry point"""
    try:
        config = Config.from_env()
        bot = TelegramBot(config)
        success = bot.start_polling()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

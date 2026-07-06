#!/usr/bin/env python3
import os
import sys
import json
import time
import signal
import sqlite3
import logging
import argparse
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


@dataclass
class Config:
    bot_token: str
    data_dir: Path = Path("telegram_data")
    db_file: str = "collector.db"
    log_level: str = "INFO"
    log_file: str = "logs/collector.log"
    log_max_bytes: int = 10 * 1024 * 1024
    log_backup_count: int = 5
    polling_timeout: int = 30
    max_retries: int = 3
    retry_delay: int = 5
    rate_limit_delay: float = 0.1
    batch_save_size: int = 50
    health_check_interval: int = 300
    
    @classmethod
    def from_env(cls) -> 'Config':
        load_dotenv()
        token = os.getenv('TELEGRAM_BOT_TOKEN')
        if not token:
            raise ValueError("TELEGRAM_BOT_TOKEN not found")
        
        return cls(
            bot_token=token,
            data_dir=Path(os.getenv('DATA_DIR', 'telegram_data')),
            db_file=os.getenv('DB_FILE', 'collector.db'),
            log_level=os.getenv('LOG_LEVEL', 'INFO'),
            log_file=os.getenv('LOG_FILE', 'logs/collector.log'),
            polling_timeout=int(os.getenv('POLLING_TIMEOUT', '30')),
            max_retries=int(os.getenv('MAX_RETRIES', '3')),
            batch_save_size=int(os.getenv('BATCH_SAVE_SIZE', '50')),
            health_check_interval=int(os.getenv('HEALTH_CHECK_INTERVAL', '300')),
        )


def setup_logging(config: Config) -> logging.Logger:
    from logging.handlers import RotatingFileHandler
    
    logger = logging.getLogger('telegram_collector')
    logger.setLevel(getattr(logging, config.log_level.upper()))
    
    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    log_path = Path(config.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=config.log_max_bytes,
        backupCount=config.log_backup_count,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger


class DatabaseManager:
    def __init__(self, db_path: Path, logger: logging.Logger):
        self.db_path = db_path
        self.logger = logger
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    def _init_database(self):
        with self._get_connection() as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS updates (
                    update_id INTEGER PRIMARY KEY,
                    update_type TEXT,
                    data TEXT,
                    timestamp TEXT,
                    processed BOOLEAN DEFAULT FALSE
                );
                
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    first_name TEXT,
                    last_name TEXT,
                    username TEXT,
                    language_code TEXT,
                    is_premium BOOLEAN DEFAULT FALSE,
                    messages_count INTEGER DEFAULT 0,
                    first_seen TEXT,
                    last_seen TEXT
                );
                
                CREATE TABLE IF NOT EXISTS chats (
                    chat_id INTEGER PRIMARY KEY,
                    chat_type TEXT,
                    title TEXT,
                    username TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    messages_count INTEGER DEFAULT 0,
                    first_message TEXT,
                    last_message TEXT
                );
                
                CREATE TABLE IF NOT EXISTS chat_users (
                    chat_id INTEGER,
                    user_id INTEGER,
                    PRIMARY KEY (chat_id, user_id),
                    FOREIGN KEY (chat_id) REFERENCES chats(chat_id),
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                );
                
                CREATE TABLE IF NOT EXISTS message_types (
                    user_id INTEGER,
                    message_type TEXT,
                    count INTEGER DEFAULT 0,
                    PRIMARY KEY (user_id, message_type),
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                );
                
                CREATE INDEX IF NOT EXISTS idx_updates_timestamp ON updates(timestamp);
                CREATE INDEX IF NOT EXISTS idx_users_last_seen ON users(last_seen);
            ''')
        self.logger.info(f"✅ Database initialized: {self.db_path}")
    
    @contextmanager
    def _get_connection(self):
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
    
    def save_update(self, update: Dict):
        update_id = update.get('update_id')
        update_type = self._get_update_type(update)
        
        with self._get_connection() as conn:
            conn.execute(
                'INSERT OR REPLACE INTO updates (update_id, update_type, data, timestamp, processed) VALUES (?, ?, ?, ?, ?)',
                (update_id, update_type, json.dumps(update, ensure_ascii=False), datetime.now().isoformat(), True)
            )
    
    def save_user(self, user_data: Dict):
        user_id = user_data.get('user_id')
        
        with self._get_connection() as conn:
            conn.execute('''
                INSERT OR REPLACE INTO users 
                (user_id, first_name, last_name, username, language_code, is_premium, 
                 messages_count, first_seen, last_seen)
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
            
            for msg_type, count in user_data.get('message_types', {}).items():
                conn.execute('''
                    INSERT OR REPLACE INTO message_types (user_id, message_type, count)
                    VALUES (?, ?, ?)
                ''', (user_id, msg_type, count))
    
    def save_chat(self, chat_data: Dict):
        chat_id = chat_data.get('chat_id')
        
        with self._get_connection() as conn:
            conn.execute('''
                INSERT OR REPLACE INTO chats 
                (chat_id, chat_type, title, username, first_name, last_name,
                 messages_count, first_message, last_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                chat_id,
                chat_data.get('type'),
                chat_data.get('title'),
                chat_data.get('username'),
                chat_data.get('first_name'),
                chat_data.get('last_name'),
                chat_data.get('messages_count', 0),
                chat_data.get('first_message'),
                chat_data.get('last_message'),
            ))
            
            for user_id in chat_data.get('active_users', []):
                conn.execute('''
                    INSERT OR IGNORE INTO chat_users (chat_id, user_id)
                    VALUES (?, ?)
                ''', (chat_id, user_id))
    
    def get_last_update_id(self) -> int:
        with self._get_connection() as conn:
            result = conn.execute('SELECT MAX(update_id) FROM updates').fetchone()
            return result[0] if result[0] else 0
    
    def get_user(self, user_id: int) -> Optional[Dict]:
        with self._get_connection() as conn:
            row = conn.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone()
            if row:
                user = dict(row)
                msg_types = conn.execute(
                    'SELECT message_type, count FROM message_types WHERE user_id = ?',
                    (user_id,)
                ).fetchall()
                user['message_types'] = {r[0]: r[1] for r in msg_types}
                return user
        return None
    
    def get_chat(self, chat_id: int) -> Optional[Dict]:
        with self._get_connection() as conn:
            row = conn.execute('SELECT * FROM chats WHERE chat_id = ?', (chat_id,)).fetchone()
            if row:
                chat = dict(row)
                users = conn.execute(
                    'SELECT user_id FROM chat_users WHERE chat_id = ?',
                    (chat_id,)
                ).fetchall()
                chat['active_users'] = [u[0] for u in users]
                return chat
        return None
    
    def get_stats(self) -> Dict:
        with self._get_connection() as conn:
            stats = {
                'total_updates': conn.execute('SELECT COUNT(*) FROM updates').fetchone()[0],
                'total_users': conn.execute('SELECT COUNT(*) FROM users').fetchone()[0],
                'total_chats': conn.execute('SELECT COUNT(*) FROM chats').fetchone()[0],
                'last_update_id': self.get_last_update_id(),
            }
        return stats
    
    def get_top_users(self, limit: int = 20) -> List[Dict]:
        with self._get_connection() as conn:
            rows = conn.execute(
                'SELECT * FROM users ORDER BY messages_count DESC LIMIT ?',
                (limit,)
            ).fetchall()
            return [dict(row) for row in rows]
    
    def get_top_chats(self, limit: int = 20) -> List[Dict]:
        with self._get_connection() as conn:
            rows = conn.execute(
                'SELECT * FROM chats ORDER BY messages_count DESC LIMIT ?',
                (limit,)
            ).fetchall()
            return [dict(row) for row in rows]
    
    def _get_update_type(self, update: Dict) -> str:
        if 'message' in update:
            return 'message'
        elif 'edited_message' in update:
            return 'edited_message'
        elif 'callback_query' in update:
            return 'callback_query'
        elif 'channel_post' in update:
            return 'channel_post'
        return 'unknown'


class TelegramAPIClient:
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
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def _api_call(self, method: str, params: Optional[Dict] = None) -> Dict:
        url = f"{self.base_url}/{method}"
        
        try:
            response = self.session.get(url, params=params, timeout=self.config.polling_timeout)
            response.raise_for_status()
            data = response.json()
            
            if not data.get('ok'):
                error_msg = data.get('description', 'Unknown error')
                error_code = data.get('error_code')
                self.logger.error(f"API error [{error_code}]: {error_msg}")
                
                if error_code == 429:
                    retry_after = data.get('parameters', {}).get('retry_after', 5)
                    self.logger.warning(f"Rate limited. Waiting {retry_after}s...")
                    time.sleep(retry_after)
                    return self._api_call(method, params)
                
                return {'error': error_msg, 'error_code': error_code}
            
            return data.get('result', {})
            
        except requests.exceptions.Timeout:
            self.logger.warning(f"Timeout on {method}")
            return {'error': 'Timeout'}
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"Connection error: {e}")
            return {'error': f'Connection error: {e}'}
        except Exception as e:
            self.logger.error(f"Unexpected error in {method}: {e}")
            return {'error': str(e)}
    
    def get_me(self) -> Dict:
        return self._api_call('getMe')
    
    def get_updates(self, offset: Optional[int] = None, timeout: int = 30) -> List[Dict]:
        params = {
            'timeout': timeout,
            'allowed_updates': ['message', 'edited_message', 'callback_query', 'channel_post']
        }
        if offset:
            params['offset'] = offset
        
        result = self._api_call('getUpdates', params)
        return result if isinstance(result, list) else []


class DataProcessor:
    def __init__(self, db: DatabaseManager, logger: logging.Logger):
        self.db = db
        self.logger = logger
        self._users_cache: Dict[int, Dict] = {}
        self._chats_cache: Dict[int, Dict] = {}
    
    def process_update(self, update: Dict):
        self.db.save_update(update)
        
        message = update.get('message') or update.get('edited_message')
        if message:
            self._process_message(message)
        
        callback = update.get('callback_query')
        if callback:
            self._process_callback(callback)
        
        channel_post = update.get('channel_post')
        if channel_post:
            self._process_message(channel_post)
    
    def _process_message(self, message: Dict):
        from_user = message.get('from', {})
        chat = message.get('chat', {})
        timestamp = datetime.fromtimestamp(message['date']).isoformat()
        
        if from_user:
            user_id = from_user.get('id')
            user_data = self._get_or_create_user(user_id, from_user, timestamp)
            
            user_data['messages_count'] += 1
            user_data['last_seen'] = timestamp
            
            chat_type = chat.get('type', 'unknown')
            user_data.setdefault('chat_types', defaultdict(int))
            user_data['chat_types'][chat_type] += 1
            
            msg_type = self._get_message_type(message)
            user_data.setdefault('message_types', defaultdict(int))
            user_data['message_types'][msg_type] += 1
            
            self._users_cache[user_id] = user_data
        
        if chat:
            chat_id = chat.get('id')
            chat_data = self._get_or_create_chat(chat_id, chat, timestamp)
            
            chat_data['messages_count'] += 1
            chat_data['last_message'] = timestamp
            
            if from_user:
                chat_data.setdefault('active_users', set()).add(from_user.get('id'))
            
            self._chats_cache[chat_id] = chat_data
    
    def _process_callback(self, callback: Dict):
        from_user = callback.get('from', {})
        if from_user:
            user_id = from_user.get('id')
            if user_id in self._users_cache:
                self._users_cache[user_id]['messages_count'] += 1
                self._users_cache[user_id]['last_seen'] = datetime.now().isoformat()
    
    def _get_or_create_user(self, user_id: int, user_data: Dict, timestamp: str) -> Dict:
        if user_id in self._users_cache:
            return self._users_cache[user_id]
        
        existing = self.db.get_user(user_id)
        if existing:
            return existing
        
        return {
            'user_id': user_id,
            'first_name': user_data.get('first_name'),
            'last_name': user_data.get('last_name'),
            'username': user_data.get('username'),
            'language_code': user_data.get('language_code'),
            'is_premium': user_data.get('is_premium', False),
            'messages_count': 0,
            'first_seen': timestamp,
            'last_seen': None,
            'chat_types': defaultdict(int),
            'message_types': defaultdict(int),
        }
    
    def _get_or_create_chat(self, chat_id: int, chat_data: Dict, timestamp: str) -> Dict:
        if chat_id in self._chats_cache:
            return self._chats_cache[chat_id]
        
        existing = self.db.get_chat(chat_id)
        if existing:
            return existing
        
        return {
            'chat_id': chat_id,
            'type': chat_data.get('type'),
            'title': chat_data.get('title'),
            'username': chat_data.get('username'),
            'first_name': chat_data.get('first_name'),
            'last_name': chat_data.get('last_name'),
            'messages_count': 0,
            'first_message': timestamp,
            'last_message': None,
            'active_users': set(),
        }
    
    def _get_message_type(self, message: Dict) -> str:
        if 'text' in message:
            return 'text'
        elif 'photo' in message:
            return 'photo'
        elif 'video' in message:
            return 'video'
        elif 'document' in message:
            return 'document'
        elif 'audio' in message:
            return 'audio'
        elif 'voice' in message:
            return 'voice'
        elif 'sticker' in message:
            return 'sticker'
        elif 'animation' in message:
            return 'animation'
        elif 'location' in message:
            return 'location'
        elif 'contact' in message:
            return 'contact'
        return 'other'
    
    def save_batch(self):
        for user_data in self._users_cache.values():
            self.db.save_user(user_data)
        
        for chat_data in self._chats_cache.values():
            if 'active_users' in chat_data:
                chat_data['active_users'] = list(chat_data['active_users'])
            self.db.save_chat(chat_data)
        
        self._users_cache.clear()
        self._chats_cache.clear()


class TelegramPollingCollector:
    def __init__(self, config: Config):
        self.config = config
        self.logger = setup_logging(config)
        self.api = TelegramAPIClient(config.bot_token, config, self.logger)
        self.db = DatabaseManager(config.data_dir / config.db_file, self.logger)
        self.processor = DataProcessor(self.db, self.logger)
        
        self.running = False
        self.last_health_check = 0
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        self.logger.info(f"\n⚠️  Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    def _health_check(self):
        current_time = time.time()
        if current_time - self.last_health_check >= self.config.health_check_interval:
            stats = self.db.get_stats()
            self.logger.info(
                f"📊 Health Check - Updates: {stats['total_updates']}, "
                f"Users: {stats['total_users']}, Chats: {stats['total_chats']}"
            )
            self.last_health_check = current_time
    
    def start_polling(self):
        self.logger.info("=" * 70)
        self.logger.info("🚀 Starting Telegram Polling Collector v4.0 - Server Mode")
        self.logger.info("=" * 70)
        
        bot_info = self.api.get_me()
        
        if 'error' in bot_info:
            self.logger.error(f"❌ Cannot start polling: {bot_info.get('error')}")
            return False
        
        self.logger.info(f"✅ Bot connected: @{bot_info.get('username')} (ID: {bot_info.get('id')})")
        
        self.running = True
        offset = self.db.get_last_update_id() + 1
        updates_processed = 0
        
        self.logger.info(f"📡 Starting polling from offset {offset}...")
        self.logger.info(f"📁 Data directory: {self.config.data_dir.absolute()}")
        self.logger.info(f"📝 Log file: {self.config.log_file}")
        
        try:
            while self.running:
                updates = self.api.get_updates(offset=offset, timeout=self.config.polling_timeout)
                
                if updates:
                    self.logger.info(f"📥 Received {len(updates)} updates")
                    
                    for update in updates:
                        self.processor.process_update(update)
                        offset = update['update_id'] + 1
                        updates_processed += 1
                    
                    if updates_processed >= self.config.batch_save_size:
                        self.processor.save_batch()
                        self.logger.info(f"💾 Saved batch ({updates_processed} updates)")
                        updates_processed = 0
                
                self._health_check()
                time.sleep(self.config.rate_limit_delay)
                
        except KeyboardInterrupt:
            self.logger.info("\n⚠️  Interrupted by user")
        except Exception as e:
            self.logger.error(f"❌ Polling error: {e}", exc_info=True)
            raise
        finally:
            self.running = False
            self.processor.save_batch()
            self.logger.info("✅ Data saved successfully")
            self._print_stats()
        
        return True
    
    def _print_stats(self):
        stats = self.db.get_stats()
        
        self.logger.info("\n" + "=" * 70)
        self.logger.info("📊 Final Statistics:")
        self.logger.info("=" * 70)
        self.logger.info(f"  📥 Total updates: {stats['total_updates']}")
        self.logger.info(f"  👥 Total users: {stats['total_users']}")
        self.logger.info(f"  💬 Total chats: {stats['total_chats']}")
        self.logger.info(f"  🔢 Last update ID: {stats['last_update_id']}")


def main():
    try:
        config = Config.from_env()
        collector = TelegramPollingCollector(config)
        success = collector.start_polling()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

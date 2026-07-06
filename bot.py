#!/usr/bin/env python3
import os
import sys
import json
import time
import sqlite3
import requests
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

if not TOKEN:
    print("❌ توکن پیدا نشد!")
    exit(1)

URL = f"https://api.telegram.org/bot{TOKEN}"
DATA_DIR = Path("telegram_data")
DB_FILE = DATA_DIR / "collector.db"

DATA_DIR.mkdir(exist_ok=True)

# ============================================================================
# DATABASE
# ============================================================================

def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            first_name TEXT,
            last_name TEXT,
            username TEXT,
            language_code TEXT,
            is_premium INTEGER DEFAULT 0,
            messages_count INTEGER DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT
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
        
        CREATE TABLE IF NOT EXISTS updates (
            update_id INTEGER PRIMARY KEY,
            data TEXT,
            timestamp TEXT
        );
    ''')
    conn.commit()
    conn.close()
    print("✅ دیتابیس آماده شد")

def save_user(user_data):
    conn = sqlite3.connect(DB_FILE)
    now = datetime.now().isoformat()
    
    conn.execute('''
        INSERT INTO users (user_id, first_name, last_name, username, language_code, 
                          is_premium, messages_count, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            first_name = COALESCE(excluded.first_name, users.first_name),
            last_name = COALESCE(excluded.last_name, users.last_name),
            username = COALESCE(excluded.username, users.username),
            language_code = COALESCE(excluded.language_code, users.language_code),
            is_premium = COALESCE(excluded.is_premium, users.is_premium),
            messages_count = users.messages_count + 1,
            last_seen = ?
    ''', (
        user_data.get('id'),
        user_data.get('first_name'),
        user_data.get('last_name'),
        user_data.get('username'),
        user_data.get('language_code'),
        user_data.get('is_premium', False),
        now,
        now,
        now
    ))
    
    conn.commit()
    conn.close()

def save_chat(chat_data):
    conn = sqlite3.connect(DB_FILE)
    now = datetime.now().isoformat()
    
    conn.execute('''
        INSERT INTO chats (chat_id, chat_type, title, username, messages_count, first_message, last_message)
        VALUES (?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(chat_id) DO UPDATE SET
            chat_type = COALESCE(excluded.chat_type, chats.chat_type),
            title = COALESCE(excluded.title, chats.title),
            username = COALESCE(excluded.username, chats.username),
            messages_count = chats.messages_count + 1,
            last_message = ?
    ''', (
        chat_data.get('id'),
        chat_data.get('type'),
        chat_data.get('title'),
        chat_data.get('username'),
        now,
        now,
        now
    ))
    
    conn.commit()
    conn.close()

def save_update(update_id, data):
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        'INSERT OR REPLACE INTO updates (update_id, data, timestamp) VALUES (?, ?, ?)',
        (update_id, json.dumps(data, ensure_ascii=False), datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

def get_stats():
    conn = sqlite3.connect(DB_FILE)
    stats = {
        'users': conn.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'chats': conn.execute('SELECT COUNT(*) FROM chats').fetchone()[0],
        'updates': conn.execute('SELECT COUNT(*) FROM updates').fetchone()[0],
    }
    conn.close()
    return stats

def get_top_users(limit=10):
    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute(
        'SELECT * FROM users ORDER BY messages_count DESC LIMIT ?',
        (limit,)
    ).fetchall()
    conn.close()
    return [
        {
            'user_id': r[0],
            'first_name': r[1],
            'last_name': r[2],
            'username': r[3],
            'language_code': r[4],
            'is_premium': bool(r[5]),
            'messages_count': r[6],
            'first_seen': r[7],
            'last_seen': r[8],
        }
        for r in rows
    ]

def get_user(user_id):
    conn = sqlite3.connect(DB_FILE)
    row = conn.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone()
    conn.close()
    if row:
        return {
            'user_id': row[0],
            'first_name': row[1],
            'last_name': row[2],
            'username': row[3],
            'language_code': row[4],
            'is_premium': bool(row[5]),
            'messages_count': row[6],
            'first_seen': row[7],
            'last_seen': row[8],
        }
    return None

def export_json(output_file):
    report = {
        'timestamp': datetime.now().isoformat(),
        'stats': get_stats(),
        'top_users': get_top_users(100),
    }
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"💾 گزارش ذخیره شد: {output_file}")

# ============================================================================
# TELEGRAM API
# ============================================================================

def send_message(chat_id, text):
    try:
        requests.post(f"{URL}/sendMessage", json={
            'chat_id': chat_id,
            'text': text
        })
    except Exception as e:
        print(f"️ خطا در ارسال پیام: {e}")

# ============================================================================
# MAIN
# ============================================================================

def run_bot():
    print("🚀 ربات شروع شد...")
    
    r = requests.get(f"{URL}/getMe").json()
    if not r.get('ok'):
        print(f"❌ خطا: {r}")
        return
    
    print(f"✅ ربات: @{r['result']['username']} (ID: {r['result']['id']})")
    
    offset = None
    last_stats = time.time()
    
    while True:
        try:
            r = requests.get(f"{URL}/getUpdates", params={
                'offset': offset,
                'timeout': 30
            }).json()
            
            if r.get('result'):
                for update in r['result']:
                    offset = update['update_id'] + 1
                    
                    # ذخیره آپدیت خام
                    save_update(update['update_id'], update)
                    
                    # پردازش پیام
                    if 'message' in update:
                        msg = update['message']
                        chat_id = msg['chat']['id']
                        user = msg.get('from', {})
                        chat = msg.get('chat', {})
                        
                        # ذخیره کاربر
                        if user:
                            save_user(user)
                            name = user.get('first_name', 'ناشناس')
                            username = user.get('username', 'N/A')
                            print(f"💬 [{datetime.now().strftime('%H:%M:%S')}] {name} (@{username}): {msg.get('text', '[بدون متن]')[:50]}")
                        
                        # ذخیره چت
                        if chat:
                            save_chat(chat)
                        
                        # پاسخ به سلام
                        text = msg.get('text', '')
                        if text and text.lower() in ['/start', 'سلام', 'hi', 'hello']:
                            if user:
                                send_message(chat_id, f"👋 سلام {user.get('first_name', 'ناشناس')}!\n\nاطلاعات شما ذخیره شد ✅")
            
            # نمایش آمار هر 5 دقیقه
            if time.time() - last_stats > 300:
                stats = get_stats()
                print(f"\n📊 آمار: {stats['users']} کاربر | {stats['chats']} چت | {stats['updates']} آپدیت\n")
                last_stats = time.time()
            
            time.sleep(0.1)
            
        except Exception as e:
            print(f"⚠️ خطا: {e}")
            time.sleep(5)

def show_stats():
    stats = get_stats()
    print("\n" + "=" * 50)
    print("📊 آمار کلی:")
    print("=" * 50)
    print(f"  👥 کاربران: {stats['users']}")
    print(f"  💬 چت‌ها: {stats['chats']}")
    print(f"  📨 آپدیت‌ها: {stats['updates']}")
    
    print("\n🏆 برترین کاربران:")
    for i, user in enumerate(get_top_users(10), 1):
        name = user.get('first_name', 'ناشناس')
        username = f"@{user['username']}" if user.get('username') else "N/A"
        print(f"  {i}. {name} ({username}) - {user['messages_count']} پیام")

def show_user(user_id):
    user = get_user(int(user_id))
    if user:
        print("\n" + "=" * 50)
        print(f"👤 کاربر {user['user_id']}:")
        print("=" * 50)
        print(f"  • نام: {user.get('first_name', 'N/A')} {user.get('last_name', '')}")
        print(f"  • یوزرنیم: @{user.get('username', 'N/A')}")
        print(f"  • زبان: {user.get('language_code', 'N/A')}")
        print(f"  • پریمیوم: {'بله' if user.get('is_premium') else 'خیر'}")
        print(f"  • پیام‌ها: {user.get('messages_count', 0)}")
        print(f"  • اولین بازدید: {user.get('first_seen', 'N/A')}")
        print(f"  • آخرین بازدید: {user.get('last_seen', 'N/A')}")
    else:
        print(f"❌ کاربر {user_id} پیدا نشد")

if __name__ == "__main__":
    init_db()
    
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == 'stats':
            show_stats()
        elif cmd == 'user' and len(sys.argv) > 2:
            show_user(sys.argv[2])
        elif cmd == 'export':
            export_json('exports/report.json')
        else:
            print("دستورات: stats, user <id>, export")
    else:
        run_bot()

#!/usr/bin/env python3
import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

if not TOKEN:
    print("❌ توکن در .env پیدا نشد!")
    exit(1)

URL = f"https://api.telegram.org/bot{TOKEN}"

print("🚀 شروع ربات تست...")
print("=" * 50)

# تست اتصال
me = requests.get(f"{URL}/getMe").json()
if not me.get('ok'):
    print(f"❌ خطا: {me.get('description')}")
    exit(1)

print(f"✅ ربات وصل شد: @{me['result']['username']}")
print("📡 در انتظار پیام‌ها...")
print("=" * 50)

offset = 0
while True:
    try:
        updates = requests.get(f"{URL}/getUpdates", params={
            'offset': offset,
            'timeout': 30
        }).json()
        
        if updates.get('result'):
            for update in updates['result']:
                offset = update['update_id'] + 1
                
                msg = update.get('message')
                if msg:
                    chat_id = msg['chat']['id']
                    user = msg['from'].get('first_name', 'کاربر')
                    text = msg.get('text', '')
                    
                    print(f"📥 پیام از {user}: {text}")
                    
                    # پاسخ ساده
                    reply = f"سلام {user}! 👋\nپیامت رو دریافت کردم: {text}"
                    requests.get(f"{URL}/sendMessage", params={
                        'chat_id': chat_id,
                        'text': reply
                    })
                    print(f"✅ پاسخ ارسال شد")
        
        time.sleep(1)
        
    except KeyboardInterrupt:
        print("\n⚠️ توقف توسط کاربر")
        break
    except Exception as e:
        print(f"❌ خطا: {e}")
        time.sleep(5)

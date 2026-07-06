#!/usr/bin/env python3
import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

if not TOKEN:
    print("❌ توکن پیدا نشد!")
    exit(1)

URL = f"https://api.telegram.org/bot{TOKEN}"

print("🚀 ربات شروع شد...")

r = requests.get(f"{URL}/getMe").json()
print(f"✅ ربات: @{r['result']['username']}")

offset = None

while True:
    try:
        r = requests.get(f"{URL}/getUpdates", params={'offset': offset, 'timeout': 30}).json()
        
        if r.get('result'):
            for update in r['result']:
                offset = update['update_id'] + 1
                
                if 'message' in update:
                    msg = update['message']
                    chat_id = msg['chat']['id']
                    name = msg['from'].get('first_name', 'ناشناس')
                    
                    print(f"💬 پیام از: {name}")
                    
                    requests.post(f"{URL}/sendMessage", json={
                        'chat_id': chat_id,
                        'text': f"👋 سلام {name}!"
                    })
        
        time.sleep(0.1)
        
    except Exception as e:
        print(f"⚠️ {e}")
        time.sleep(5)

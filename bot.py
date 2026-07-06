#!/usr/bin/env python3
import os
import time
import requests
from dotenv import load_dotenv

# بارگذاری توکن
load_dotenv()
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

if not TOKEN:
    print("❌ توکن پیدا نشد!")
    exit(1)

URL = f"https://api.telegram.org/bot{TOKEN}"

def send_message(chat_id, text):
    """ارسال پیام"""
    requests.post(f"{URL}/sendMessage", json={
        'chat_id': chat_id,
        'text': text
    })

def main():
    print("🚀 ربات شروع شد...")
    
    # تست اتصال
    r = requests.get(f"{URL}/getMe").json()
    if not r.get('ok'):
        print(f"❌ خطا: {r}")
        return
    
    print(f"✅ ربات متصل شد: @{r['result']['username']}")
    
    offset = None
    
    while True:
        try:
            # دریافت پیام‌ها
            r = requests.get(f"{URL}/getUpdates", params={
                'offset': offset,
                'timeout': 30
            }).json()
            
            if r.get('ok') and r.get('result'):
                for update in r['result']:
                    offset = update['update_id'] + 1
                    
                    if 'message' in update:
                        msg = update['message']
                        chat_id = msg['chat']['id']
                        user = msg.get('from', {})
                        name = user.get('first_name', 'ناشناس')
                        text = msg.get('text', '')
                        
                        print(f"💬 پیام از {name}: {text}")
                        
                        # پاسخ به سلام
                        if text.lower() in ['/start', 'سلام', 'hi', 'hello']:
                            response = f"👋 سلام {name}!\n\nخوش اومدی!"
                            send_message(chat_id, response)
                            print(f"✅ پاسخ ارسال شد به {name}")
            
            time.sleep(0.1)
            
        except Exception as e:
            print(f"⚠️ خطا: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()

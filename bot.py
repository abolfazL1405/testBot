#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telegram Intelligence Collector Bot v2.0
ربات forensics تلگرام بدون نیاز به api_id/api_hash از کاربر
(فقط شماره تلفن + کد تأیید + رمز عبور رمزنگاری)
"""

import os
import sys
import hashlib
import hmac
import base64
import gzip
import json
import re
import time
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict

from dotenv import load_dotenv
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup,
    ReplyKeyboardRemove,
)
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, ConversationHandler, ContextTypes, filters,
)
from telegram.constants import ParseMode

try:
    from telethon import TelegramClient
    from telethon.tl.types import (
        User, Chat, Channel, InputPeerUser, InputPeerChat, InputPeerChannel,
        MessageMediaPhoto, MessageMediaDocument, MessageMediaGeo,
        MessageMediaContact, MessageMediaVenue,
        PeerUser, PeerChat, PeerChannel,
        DocumentAttributeFilename, DocumentAttributeVideo, DocumentAttributeAudio,
        UserStatusOnline, UserStatusRecently, UserStatusOffline,
    )
    from telethon.tl.functions.account import (
        GetFullUserRequest, GetAuthorizationsRequest,
        GetWebAuthorizationsRequest,
    )
    from telethon.tl.functions.contacts import (
        GetContactsRequest, GetBlockedRequest,
    )
    from telethon.tl.functions.messages import (
        GetDialogsRequest,
    )
    from telethon.tl.functions.channels import GetAdminedPublicChannelsRequest
    from telethon.errors import SessionPasswordNeededError, FloodWaitError
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False
    print("❌ نصب: pip install telethon")

# ==================== بارگذاری .env ====================
load_dotenv()

# ==================== تنظیمات ====================
VERSION = "2.0"
PBKDF2_ITERATIONS = 600_000
MODULE_TIMEOUT = 180

BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
if not BOT_TOKEN:
    print("❌ متغیر TELEGRAM_BOT_TOKEN در .env تنظیم نشده!")
    sys.exit(1)

# 🔑 API Credentials از سازنده ربات (از .env)
API_ID_STR = os.environ.get('API_ID')
API_HASH = os.environ.get('API_HASH')
if not API_ID_STR or not API_HASH:
    print("❌ API_ID و API_HASH باید در .env تنظیم شوند (از my.telegram.org سازنده)")
    sys.exit(1)
try:
    API_ID = int(API_ID_STR)
except ValueError:
    print("❌ API_ID باید عدد باشد!")
    sys.exit(1)

# لیست کاربران مجاز (توصیه می‌شود حتماً پر شود!)
AUTHORIZED_USERS_STR = os.environ.get('AUTHORIZED_USERS', '')
AUTHORIZED_USERS: Set[int] = set()
if AUTHORIZED_USERS_STR.strip():
    try:
        AUTHORIZED_USERS = {int(uid.strip()) for uid in AUTHORIZED_USERS_STR.split(',') if uid.strip()}
    except ValueError:
        print("⚠️  فرمت AUTHORIZED_USERS اشتباه!")

SESSION_DIR = Path("sessions")
SESSION_DIR.mkdir(exist_ok=True)
OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

# Conversation States
(SELECT_LEVEL, ENTER_PHONE, ENTER_CODE, ENTER_2FA, 
 ENTER_ENC_PASSWORD, CONFIRM_ENC_PASSWORD,
 DECRYPT_UPLOAD, DECRYPT_PASSWORD) = range(8)

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


@dataclass
class CollectionConfig:
    level: str = "full"
    include_sensitive: bool = True
    max_messages_per_chat: int = 200
    max_dialogs: int = 2000
    max_contacts: int = 5000


class TelegramIntelCollector:
    """جمع‌آوری forensics از اکانت تلگرام"""
    
    def __init__(self, phone: str, user_id: int, config: CollectionConfig = None,
                 progress_callback=None):
        self.phone = phone
        self.user_id = user_id
        self.config = config or CollectionConfig()
        # session file منحصر به فرد برای هر user_id + phone
        safe_phone = phone.replace('+', '').replace(' ', '')
        self.session_file = str(SESSION_DIR / f"user_{user_id}_{safe_phone}")
        self.client: Optional[TelegramClient] = None
        self.me = None
        self.start_time = time.time()
        self.stats = {'executed': 0, 'failed': 0}
        self.progress_callback = progress_callback
    
    async def _progress(self, msg: str):
        if self.progress_callback:
            try:
                await self.progress_callback(msg)
            except:
                pass
    
    async def connect(self) -> Tuple[bool, Optional[str]]:
        """اتصال اولیه - برمی‌گرداند (success, stage)"""
        try:
            self.client = TelegramClient(self.session_file, API_ID, API_HASH)
            await self.client.connect()
            
            if not await self.client.is_user_authorized():
                await self.client.send_code_request(self.phone)
                return False, "awaiting_code"
            
            self.me = await self.client.get_me()
            return True, None
        except Exception as e:
            return False, str(e)
    
    async def verify_code(self, code: str) -> Tuple[bool, Optional[str]]:
        try:
            await self.client.sign_in(self.phone, code)
            self.me = await self.client.get_me()
            return True, None
        except SessionPasswordNeededError:
            return False, "awaiting_2fa"
        except Exception as e:
            return False, str(e)
    
    async def verify_2fa(self, password: str) -> Tuple[bool, Optional[str]]:
        try:
            await self.client.sign_in(password=password)
            self.me = await self.client.get_me()
            return True, None
        except Exception as e:
            return False, str(e)
    
    async def disconnect(self):
        if self.client:
            try:
                await self.client.disconnect()
            except:
                pass
    
    def _ts(self, dt) -> str:
        try:
            if dt is None: return "N/A"
            if isinstance(dt, datetime): return dt.isoformat()
            return datetime.fromtimestamp(dt).isoformat()
        except:
            return "N/A"
    
    def _peer_id(self, peer) -> Optional[int]:
        try:
            if isinstance(peer, PeerUser): return peer.user_id
            if isinstance(peer, PeerChat): return peer.chat_id
            if isinstance(peer, PeerChannel): return peer.channel_id
            for attr in ('user_id', 'chat_id', 'channel_id'):
                if hasattr(peer, attr): return getattr(peer, attr)
        except:
            pass
        return None
    
    def _user_info(self, u: User) -> Dict:
        if not u: return {}
        info = {
            'id': u.id, 'first_name': u.first_name, 'last_name': u.last_name,
            'username': u.username, 'is_bot': u.bot,
            'phone': u.phone if self.config.include_sensitive else ('[hidden]' if u.phone else None),
            'is_premium': getattr(u, 'premium', False),
            'is_verified': u.verified,
        }
        if hasattr(u, 'status') and u.status:
            if isinstance(u.status, UserStatusOnline): info['status'] = 'online'
            elif isinstance(u.status, UserStatusRecently): info['status'] = 'recently'
            elif isinstance(u.status, UserStatusOffline):
                info['status'] = 'offline'
                info['last_seen'] = self._ts(u.status.was_online)
        return info
    
    def _chat_info(self, c) -> Dict:
        if not c: return {}
        info = {'id': c.id, 'title': getattr(c, 'title', None), 'type': type(c).__name__}
        if isinstance(c, Channel):
            info.update({
                'username': c.username, 'megagroup': c.megagroup,
                'participants': getattr(c, 'participants_count', None),
            })
        return info
    
    async def get_account(self) -> Dict:
        try:
            full = await self.client(GetFullUserRequest(self.me))
            return {
                'id': self.me.id, 'first_name': self.me.first_name,
                'last_name': self.me.last_name, 'username': self.me.username,
                'phone': self.me.phone if self.config.include_sensitive else '[hidden]',
                'is_premium': getattr(self.me, 'premium', False),
                'about': getattr(full.full_user, 'about', None),
                'common_chats': getattr(full.full_user, 'common_chats_count', 0),
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def get_dialogs(self) -> Dict:
        try:
            dialogs = []
            off_date, off_id, off_peer = None, 0, InputPeerUser(0, 0)
            while True:
                res = await self.client(GetDialogsRequest(
                    offset_date=off_date, offset_id=off_id,
                    offset_peer=off_peer, limit=100, hash=0,
                ))
                if not res.dialogs: break
                
                for d in res.dialogs:
                    ent = None
                    for u in (res.users or []):
                        if u.id == self._peer_id(d.peer): ent = u; break
                    if not ent:
                        for c in (res.chats or []):
                            if c.id == self._peer_id(d.peer): ent = c; break
                    
                    info = {
                        'peer_id': self._peer_id(d.peer),
                        'peer_type': type(d.peer).__name__,
                        'unread': d.unread_count,
                        'pinned': getattr(d, 'pinned', False),
                    }
                    if ent:
                        info['entity'] = self._user_info(ent) if isinstance(ent, User) else self._chat_info(ent)
                    dialogs.append(info)
                
                if len(dialogs) >= self.config.max_dialogs: break
                
                last = res.dialogs[-1]
                off_id = last.top_message
                off_peer = last.peer
                for m in (res.messages or []):
                    if m.id == off_id: off_date = m.date; break
                if len(res.dialogs) < 100: break
            
            return {'total': len(dialogs), 'dialogs': dialogs}
        except Exception as e:
            return {'error': str(e), 'total': 0}
    
    async def get_contacts(self) -> Dict:
        try:
            r = await self.client(GetContactsRequest(hash=0))
            contacts = [self._user_info(u) for u in (r.users or [])]
            bl = await self.client(GetBlockedRequest(offset=0, limit=100))
            blocked = [self._user_info(u) for u in (bl.users or [])]
            return {
                'total': len(contacts),
                'contacts': contacts[:self.config.max_contacts],
                'blocked': blocked, 'blocked_count': len(blocked),
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def get_messages_from_chat(self, peer, limit: int) -> List[Dict]:
        msgs = []
        try:
            async for m in self.client.iter_messages(peer, limit=limit):
                msg = {
                    'id': m.id, 'date': self._ts(m.date),
                    'out': m.out, 'text': m.text or m.message or '',
                    'views': getattr(m, 'views', None),
                }
                if m.media:
                    msg['media'] = type(m.media).__name__
                    if isinstance(m.media, MessageMediaGeo):
                        msg['geo'] = {'lat': m.media.geo.lat, 'long': m.media.geo.long}
                    elif isinstance(m.media, MessageMediaDocument):
                        for a in (m.media.document.attributes or []):
                            if isinstance(a, DocumentAttributeFilename):
                                msg['file'] = a.file_name
                if msg['text'] or 'media' in msg:
                    msgs.append(msg)
        except FloodWaitError as e:
            await asyncio.sleep(min(e.seconds, 60))
        except Exception:
            pass
        return msgs
    
    async def get_recent_messages(self) -> Dict:
        try:
            dialogs_data = await self.get_dialogs()
            if 'error' in dialogs_data: return dialogs_data
            
            chats = {}
            total = 0
            items = dialogs_data.get('dialogs', [])[:50]
            
            for i, d in enumerate(items):
                pid = d.get('peer_id')
                if not pid: continue
                pt = d.get('peer_type')
                if pt == 'PeerUser': peer = InputPeerUser(pid, 0)
                elif pt == 'PeerChat': peer = InputPeerChat(pid)
                elif pt == 'PeerChannel': peer = InputPeerChannel(pid, 0)
                else: continue
                
                await self._progress(f"📨 چت {i+1}/{len(items)}...")
                msgs = await self.get_messages_from_chat(peer, self.config.max_messages_per_chat)
                if msgs:
                    chats[str(pid)] = {
                        'entity': d.get('entity', {}),
                        'count': len(msgs), 'messages': msgs,
                    }
                    total += len(msgs)
            
            return {'total': total, 'chats_count': len(chats), 'chats': chats}
        except Exception as e:
            return {'error': str(e)}
    
    async def get_sessions(self) -> Dict:
        try:
            auths = await self.client(GetAuthorizationsRequest())
            sessions = []
            for a in (auths.authorizations or []):
                sessions.append({
                    'device': a.device_model, 'platform': a.platform,
                    'app': a.app_name, 'created': self._ts(a.date_created),
                    'active': self._ts(a.date_active),
                    'ip': a.ip if self.config.include_sensitive else '[hidden]',
                    'country': a.country,
                })
            
            web = await self.client(GetWebAuthorizationsRequest())
            web_sess = [{
                'domain': w.domain, 'browser': w.browser,
                'active': self._ts(w.date_active),
            } for w in (web.authorizations or [])]
            
            return {
                'active': sessions, 'active_count': len(sessions),
                'web': web_sess, 'web_count': len(web_sess),
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def get_groups_channels(self) -> Dict:
        try:
            dd = await self.get_dialogs()
            groups, channels, supers = [], [], []
            for d in dd.get('dialogs', []):
                e = d.get('entity', {})
                if not e: continue
                if e.get('type') == 'Channel':
                    info = {'id': e.get('id'), 'title': e.get('title'), 'username': e.get('username')}
                    (supers if e.get('megagroup') else channels).append(info)
                elif e.get('type') == 'Chat':
                    groups.append({'id': e.get('id'), 'title': e.get('title')})
            
            try:
                adm = await self.client(GetAdminedPublicChannelsRequest())
                admin = [{'id': c.id, 'title': c.title, 'username': c.username} 
                         for c in (adm.chats or [])]
            except:
                admin = []
            
            return {
                'groups': groups, 'groups_count': len(groups),
                'supers': supers, 'supers_count': len(supers),
                'channels': channels, 'channels_count': len(channels),
                'administered': admin, 'admin_count': len(admin),
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def get_saved(self) -> Dict:
        try:
            saved = []
            async for m in self.client.iter_messages('me', limit=100):
                saved.append({
                    'id': m.id, 'date': self._ts(m.date),
                    'text': m.text or m.message or '',
                })
            return {'count': len(saved), 'messages': saved}
        except Exception as e:
            return {'error': str(e)}
    
    async def osint(self, data: Dict) -> Dict:
        txt = self._extract_text(data)
        return {
            'emails': list(set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', txt)))[:200],
            'phones': list(set(re.findall(r'\+?\d{10,15}', txt)))[:200],
            'urls': list(set(re.findall(r'https?://[^\s<>"\']+', txt)))[:500],
            'bot_tokens': list(set(re.findall(r'\d{8,10}:[A-Za-z0-9_\-]{35}', txt)))[:10],
        }
    
    def _extract_text(self, obj, max_chars=5_000_000) -> str:
        out = []
        total = [0]
        def walk(o):
            if total[0] >= max_chars: return
            if isinstance(o, str): out.append(o); total[0] += len(o)
            elif isinstance(o, dict):
                for v in o.values(): walk(v)
            elif isinstance(o, list):
                for i in o: walk(i)
        walk(obj)
        return '\n'.join(out)
    
    async def collect_all(self) -> Dict:
        data = {
            '_metadata': {
                'version': VERSION,
                'timestamp': datetime.now().isoformat(),
                'target_id': self.me.id,
                'target_username': self.me.username,
            }
        }
        
        modules = [
            ('account', self.get_account),
            ('dialogs', self.get_dialogs),
            ('contacts', self.get_contacts),
            ('sessions', self.get_sessions),
            ('groups_channels', self.get_groups_channels),
            ('saved', self.get_saved),
            ('recent_messages', self.get_recent_messages),
        ]
        
        for i, (name, fn) in enumerate(modules):
            await self._progress(f"🔄 [{i+1}/{len(modules)}] {name}...")
            try:
                data[name] = await asyncio.wait_for(fn(), timeout=MODULE_TIMEOUT)
                self.stats['executed'] += 1
            except asyncio.TimeoutError:
                data[name] = {'error': 'Timeout'}
                self.stats['failed'] += 1
            except Exception as e:
                data[name] = {'error': str(e)}
                self.stats['failed'] += 1
        
        await self._progress("🧠 OSINT...")
        data['osint'] = await self.osint(data)
        
        elapsed = time.time() - self.start_time
        data['_metadata']['elapsed'] = round(elapsed, 2)
        data['_metadata']['stats'] = self.stats
        return data
    
    def encrypt_and_save(self, data: Dict, password: str, path: str) -> int:
        raw = json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8')
        compressed = gzip.compress(raw, compresslevel=9)
        salt = get_random_bytes(16)
        key = PBKDF2(password.encode('utf-8'), salt, dkLen=32, 
                     count=PBKDF2_ITERATIONS, prf=hmac_sha256)
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(compressed)
        blob = salt + nonce + tag + ct
        encoded = base64.b64encode(blob).decode('utf-8')
        Path(path).write_text(encoded, encoding='utf-8')
        return len(encoded)
    
    @staticmethod
    def decrypt(path: str, password: str) -> Dict:
        blob = base64.b64decode(Path(path).read_text(encoding='utf-8'))
        salt, nonce, tag = blob[:16], blob[16:28], blob[28:44]
        ct = blob[44:]
        key = PBKDF2(password.encode('utf-8'), salt, dkLen=32,
                     count=PBKDF2_ITERATIONS, prf=hmac_sha256)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        compressed = cipher.decrypt_and_verify(ct, tag)
        return json.loads(gzip.decompress(compressed).decode('utf-8'))


# ==================== ربات ====================

class IntelBot:
    def __init__(self):
        self.collectors: Dict[int, TelegramIntelCollector] = {}
    
    def _auth(self, uid: int) -> bool:
        return (not AUTHORIZED_USERS) or (uid in AUTHORIZED_USERS)
    
    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        u = update.effective_user
        if not self._auth(u.id):
            await update.message.reply_text("⛔ مجاز نیستید.")
            return ConversationHandler.END
        
        await update.message.reply_text(
            f"👋 سلام <b>{u.first_name}</b>!\n\n"
            "🤖 <b>Telegram Intel Collector v2.0</b>\n\n"
            "📊 <b>دستورات:</b>\n"
            "/collect - جمع‌آوری forensics\n"
            "/decrypt - رمزگشایی فایل\n"
            "/revoke - پایان session\n"
            "/help - راهنما\n\n"
            "✅ <b>تفاوت با نسخه قبلی:</b>\n"
            "نیازی به <code>api_id</code> و <code>api_hash</code> نیست!\n"
            "فقط شماره تلفن و کد تأیید.",
            parse_mode=ParseMode.HTML
        )
        return ConversationHandler.END
    
    async def cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(
            "📖 <b>راهنما</b>\n\n"
            "🔹 <b>/collect</b> - شروع جمع‌آوری\n"
            "🔹 <b>/decrypt</b> - رمزگشایی فایل .enc\n"
            "🔹 <b>/revoke</b> - حذف session ذخیره شده\n"
            "🔹 <b>/cancel</b> - لغو عملیات\n\n"
            "🔐 <b>امنیت:</b>\n"
            "• AES-256-GCM + PBKDF2 (600k iterations)\n"
            "• فایل‌ها بعد از ارسال پاک می‌شوند\n"
            "• Session file فقط روی سرور ذخیره می‌شود\n\n"
            "⚠️ <b>فقط برای استفاده قانونی روی اکانت خودتان</b>",
            parse_mode=ParseMode.HTML
        )
    
    async def cmd_cancel(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        collector = self.collectors.get(update.effective_user.id)
        if collector:
            await collector.disconnect()
            del self.collectors[update.effective_user.id]
        context.user_data.clear()
        await update.message.reply_text("❌ لغو شد.", reply_markup=ReplyKeyboardRemove())
        return ConversationHandler.END
    
    async def cmd_revoke(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """حذف session ذخیره شده"""
        uid = update.effective_user.id
        collector = self.collectors.pop(uid, None)
        if collector:
            await collector.disconnect()
        
        # پاک کردن همه session files این user
        count = 0
        for f in SESSION_DIR.glob(f"user_{uid}_*"):
            try:
                f.unlink()
                count += 1
            except:
                pass
        
        await update.message.reply_text(
            f"✅ {count} session file حذف شد.\n\n"
            "برای استفاده مجدد باید دوباره کد تأیید بگیرید.",
            parse_mode=ParseMode.HTML
        )
    
    async def collect_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        uid = update.effective_user.id
        if not self._auth(uid):
            await update.message.reply_text("⛔ مجاز نیستید.")
            return ConversationHandler.END
        
        keyboard = [
            [InlineKeyboardButton("1️⃣ Basic - پایه", callback_data="lvl_1")],
            [InlineKeyboardButton("2️⃣ Normal - کامل", callback_data="lvl_2")],
            [InlineKeyboardButton("3️⃣ Full - همه چیز ⭐", callback_data="lvl_3")],
            [InlineKeyboardButton("4️⃣ Extreme - حداکثر 🔥", callback_data="lvl_4")],
        ]
        
        await update.message.reply_text(
            "🎚️ <b>سطح جمع‌آوری:</b>\n\n"
            "• <b>Basic:</b> اطلاعات پایه فقط\n"
            "• <b>Normal:</b> بدون داده‌های حساس\n"
            "• <b>Full:</b> کامل + حساس ⭐\n"
            "• <b>Extreme:</b> همه چیز + OSINT 🔥\n\n"
            "یک گزینه انتخاب کنید:",
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode=ParseMode.HTML
        )
        return SELECT_LEVEL
    
    async def level_selected(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        q = update.callback_query
        await q.answer()
        level = q.data.split('_')[1]
        context.user_data['level'] = level
        
        names = {"1": "Basic", "2": "Normal", "3": "Full", "4": "Extreme"}
        await q.edit_message_text(
            f"✅ سطح <b>{names[level]}</b> انتخاب شد.\n\n"
            "📱 <b>شماره تلفن اکانت تلگرام</b> را وارد کنید:\n"
            "مثال: <code>+989121234567</code>",
            parse_mode=ParseMode.HTML
        )
        return ENTER_PHONE
    
    async def receive_phone(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        phone = update.message.text.strip()
        if not re.match(r'^\+\d{10,15}$', phone):
            await update.message.reply_text(
                "❌ فرمت اشتباه. مثال: <code>+989121234567</code>",
                parse_mode=ParseMode.HTML
            )
            return ENTER_PHONE
        
        context.user_data['phone'] = phone
        uid = update.effective_user.id
        
        config = CollectionConfig()
        level = context.user_data['level']
        if level == "1":
            config.level = "basic"
            config.include_sensitive = False
            config.max_messages_per_chat = 0
            config.max_dialogs = 100
        elif level == "2":
            config.level = "normal"
            config.include_sensitive = False
        elif level == "3":
            config.level = "full"
        else:
            config.level = "extreme"
            config.max_messages_per_chat = 500
            config.max_dialogs = 5000
        
        status = await update.message.reply_text("🔄 در حال اتصال...")
        
        collector = TelegramIntelCollector(phone, uid, config)
        self.collectors[uid] = collector
        
        success, msg = await collector.connect()
        
        if success:
            await status.edit_text(
                f"✅ متصل شد!\n\n"
                f"👤 <b>{collector.me.first_name}</b>\n"
                f"🆔 <code>{collector.me.id}</code>\n\n"
                "🔑 <b>رمز عبور برای رمزنگاری فایل</b> را وارد کنید\n"
                "(حداقل 8 کاراکتر، برای دانلود امن):",
                parse_mode=ParseMode.HTML
            )
            return ENTER_ENC_PASSWORD
        elif msg == "awaiting_code":
            await status.edit_text(
                f"📱 کد تأیید به تلگرام شما ارسال شد.\n\n"
                "🔑 کد 5 رقمی را وارد کنید:"
            )
            return ENTER_CODE
        else:
            await status.edit_text(f"❌ خطا: {msg}")
            await collector.disconnect()
            self.collectors.pop(uid, None)
            return ConversationHandler.END
    
    async def receive_code(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        code = update.message.text.strip()
        if not re.match(r'^\d{4,6}$', code):
            await update.message.reply_text("❌ کد باید 4-6 رقم باشد.")
            return ENTER_CODE
        
        uid = update.effective_user.id
        collector = self.collectors.get(uid)
        if not collector:
            await update.message.reply_text("❌ Session منقضی شد. دوباره /collect بزنید.")
            return ConversationHandler.END
        
        status = await update.message.reply_text("🔄 در حال تأیید...")
        success, msg = await collector.verify_code(code)
        
        if success:
            await status.edit_text(
                f"✅ ورود موفق!\n\n"
                f"👤 <b>{collector.me.first_name}</b>\n"
                f"🆔 <code>{collector.me.id}</code>\n\n"
                "🔑 <b>رمز عبور برای رمزنگاری فایل</b> را وارد کنید\n"
                "(حداقل 8 کاراکتر):",
                parse_mode=ParseMode.HTML
            )
            return ENTER_ENC_PASSWORD
        elif msg == "awaiting_2fa":
            await status.edit_text(
                "🔒 اکانت <b>تأیید دو مرحله‌ای</b> دارد.\n\n"
                "🔑 رمز دو مرحله‌ای را وارد کنید:",
                parse_mode=ParseMode.HTML
            )
            return ENTER_2FA
        else:
            await status.edit_text(f"❌ کد اشتباه: {msg}\n\nدوباره وارد کنید:")
            return ENTER_CODE
    
    async def receive_2fa(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        password = update.message.text.strip()
        uid = update.effective_user.id
        collector = self.collectors.get(uid)
        if not collector:
            await update.message.reply_text("❌ Session منقضی شد.")
            return ConversationHandler.END
        
        status = await update.message.reply_text("🔄 در حال تأیید...")
        success, msg = await collector.verify_2fa(password)
        
        if success:
            await status.edit_text(
                f"✅ ورود موفق!\n\n"
                "🔑 <b>رمز عبور برای رمزنگاری فایل</b> را وارد کنید\n"
                "(حداقل 8 کاراکتر):",
                parse_mode=ParseMode.HTML
            )
            return ENTER_ENC_PASSWORD
        else:
            await status.edit_text(f"❌ رمز اشتباه: {msg}\n\nدوباره:")
            return ENTER_2FA
    
    async def receive_enc_password(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        pw = update.message.text.strip()
        if len(pw) < 8:
            await update.message.reply_text("❌ حداقل 8 کاراکتر!")
            return ENTER_ENC_PASSWORD
        context.user_data['enc_password'] = pw
        await update.message.reply_text("🔑 رمز عبور را <b>دوباره</b> وارد کنید (برای تأیید):",
                                        parse_mode=ParseMode.HTML)
        return CONFIRM_ENC_PASSWORD
    
    async def confirm_enc_password(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        pw = update.message.text.strip()
        if pw != context.user_data.get('enc_password'):
            await update.message.reply_text("❌ مطابقت ندارند! دوباره:")
            return ENTER_ENC_PASSWORD
        
        uid = update.effective_user.id
        collector = self.collectors.get(uid)
        if not collector:
            await update.message.reply_text("❌ Session منقضی شد.")
            return ConversationHandler.END
        
        status = await update.message.reply_text(
            "🚀 <b>شروع جمع‌آوری...</b>\n\n"
            "⏳ ممکنه چند دقیقه طول بکشه.",
            parse_mode=ParseMode.HTML
        )
        
        async def progress(msg):
            try:
                await status.edit_text(f"🚀 <b>در حال جمع‌آوری...</b>\n\n{msg}",
                                       parse_mode=ParseMode.HTML)
            except:
                pass
        
        collector.progress_callback = progress
        
        try:
            data = await collector.collect_all()
            
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output = OUTPUT_DIR / f"intel_{uid}_{ts}.enc"
            
            await progress("💾 رمزنگاری...")
            size = collector.encrypt_and_save(data, pw, str(output))
            mb = size / (1024 * 1024)
            
            stats = data['_metadata']['stats']
            elapsed = data['_metadata']['elapsed']
            
            summary = (
                "✅ <b>جمع‌آوری کامل شد!</b>\n\n"
                f"👤 <b>{collector.me.first_name}</b>\n"
                f"🆔 <code>{collector.me.id}</code>\n"
                f"⏱️ زمان: {elapsed:.1f} ثانیه\n"
                f"✅ ماژول‌ها: {stats['executed']}/{stats['executed']+stats['failed']}\n"
                f"💾 حجم: {mb:.2f} MB\n\n"
                "📤 در حال ارسال..."
            )
            await status.edit_text(summary, parse_mode=ParseMode.HTML)
            
            caption = (
                f"🔐 Intel Report\n"
                f"👤 {collector.me.first_name}\n"
                f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
                f"🔑 AES-256-GCM + PBKDF2"
            )
            
            try:
                with open(output, 'rb') as f:
                    await update.message.reply_document(
                        document=f,
                        filename=f"intel_{ts}.enc",
                        caption=caption,
                    )
            except Exception as e:
                await update.message.reply_text(f"⚠️ خطای ارسال: {e}")
            
            try:
                output.unlink()
            except:
                pass
            
        except Exception as e:
            await status.edit_text(f"❌ خطا: {e}")
            logger.exception("Error in collection")
        
        return ConversationHandler.END
    
    async def decrypt_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self._auth(update.effective_user.id):
            await update.message.reply_text("⛔ مجاز نیستید.")
            return ConversationHandler.END
        
        await update.message.reply_text(
            "🔓 <b>حالت رمزگشایی</b>\n\n"
            "📎 فایل <code>.enc</code> رمزنگاری شده را ارسال کنید:",
            parse_mode=ParseMode.HTML
        )
        return DECRYPT_UPLOAD
    
    async def decrypt_file(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not update.message.document:
            await update.message.reply_text("❌ لطفاً فایل ارسال کنید.")
            return DECRYPT_UPLOAD
        
        doc = update.message.document
        if not doc.file_name.endswith('.enc'):
            await update.message.reply_text("❌ فقط فایل‌های .enc")
            return DECRYPT_UPLOAD
        
        f = await doc.get_file()
        path = OUTPUT_DIR / f"dec_{update.effective_user.id}_{int(time.time())}.enc"
        await f.download_to_drive(str(path))
        context.user_data['dec_file'] = str(path)
        
        await update.message.reply_text("🔑 رمز عبور را وارد کنید:")
        return DECRYPT_PASSWORD
    
    async def decrypt_password(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        pw = update.message.text.strip()
        path = context.user_data.get('dec_file')
        
        if not path or not Path(path).exists():
            await update.message.reply_text("❌ فایل گم شد. /decrypt")
            return ConversationHandler.END
        
        status = await update.message.reply_text("🔄 در حال رمزگشایی...")
        
        try:
            data = TelegramIntelCollector.decrypt(path, pw)
            
            json_path = Path(path).with_suffix('.json')
            json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
            
            await status.edit_text("✅ رمزگشایی موفق! در حال ارسال...")
            
            with open(json_path, 'rb') as f:
                await update.message.reply_document(
                    document=f, filename=json_path.name,
                    caption="🔓 فایل رمزگشایی شده (JSON)"
                )
            
            try:
                Path(path).unlink()
                json_path.unlink()
            except:
                pass
            
        except ValueError:
            await status.edit_text("❌ رمز اشتباه یا فایل خراب!")
        except Exception as e:
            await status.edit_text(f"❌ خطا: {e}")
        
        return ConversationHandler.END
    
    async def unknown_text(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(
            "❓ دستور نامفهوم.\n\n/start را بزنید."
        )


def main():
    if not TELETHON_AVAILABLE:
        print("❌ Telethon نصب نیست: pip install telethon")
        sys.exit(1)
    
    print("=" * 60)
    print("🤖 Telegram Intel Collector Bot v2.0")
    print(f"✅ API_ID: {API_ID} (از .env)")
    print(f"🔐 Authorized users: {len(AUTHORIZED_USERS) or 'ALL'}")
    print("=" * 60)
    
    bot = IntelBot()
    app = Application.builder().token(BOT_TOKEN).build()
    
    # ConversationHandler برای /collect
    collect_conv = ConversationHandler(
        entry_points=[CommandHandler("collect", bot.collect_start)],
        states={
            SELECT_LEVEL: [CallbackQueryHandler(bot.level_selected)],
            ENTER_PHONE: [MessageHandler(filters.TEXT & ~filters.COMMAND, bot.receive_phone)],
            ENTER_CODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, bot.receive_code)],
            ENTER_2FA: [MessageHandler(filters.TEXT & ~filters.COMMAND, bot.receive_2fa)],
            ENTER_ENC_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, bot.receive_enc_password)],
            CONFIRM_ENC_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, bot.confirm_enc_password)],
        },
        fallbacks=[CommandHandler("cancel", bot.cmd_cancel)],
    )
    
    # ConversationHandler برای /decrypt
    decrypt_conv = ConversationHandler(
        entry_points=[CommandHandler("decrypt", bot.decrypt_start)],
        states={
            DECRYPT_UPLOAD: [MessageHandler(filters.Document.ALL, bot.decrypt_file)],
            DECRYPT_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, bot.decrypt_password)],
        },
        fallbacks=[CommandHandler("cancel", bot.cmd_cancel)],
    )
    
    app.add_handler(CommandHandler("start", bot.cmd_start))
    app.add_handler(CommandHandler("help", bot.cmd_help))
    app.add_handler(CommandHandler("revoke", bot.cmd_revoke))
    app.add_handler(collect_conv)
    app.add_handler(decrypt_conv)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.unknown_text))
    
    print("\n🚀 ربات در حال اجرا...")
    print("   Ctrl+C برای توقف\n")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()

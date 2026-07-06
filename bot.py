#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telegram Export Analyzer Bot v2.0
ربات تحلیل forensics فایل Export تلگرام (بدون نیاز به api_id/api_hash)
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
import zipfile
import tarfile
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, asdict
from collections import Counter, defaultdict
from html.parser import HTMLParser

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
from telegram.constants import ParseMode, ChatAction

# ==================== بارگذاری .env ====================
load_dotenv()

# ==================== تنظیمات ====================
VERSION = "2.0"
PBKDF2_ITERATIONS = 600_000

BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
if not BOT_TOKEN:
    print("❌ متغیر TELEGRAM_BOT_TOKEN در .env تنظیم نشده!")
    sys.exit(1)

AUTHORIZED_USERS_STR = os.environ.get('AUTHORIZED_USERS', '')
AUTHORIZED_USERS: Set[int] = set()
if AUTHORIZED_USERS_STR.strip():
    try:
        AUTHORIZED_USERS = {int(uid.strip()) for uid in AUTHORIZED_USERS_STR.split(',') if uid.strip()}
    except ValueError:
        pass

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)
TEMP_DIR = Path("temp")
TEMP_DIR.mkdir(exist_ok=True)

# Conversation States
(AWAITING_EXPORT, AWAITING_PASSWORD, CONFIRM_PASSWORD) = range(3)

# ==================== لاگ ====================
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


# ==================== HTML Parser برای Export HTML ====================
class TelegramHTMLParser(HTMLParser):
    """پارسر فایل‌های HTML export تلگرام"""
    
    def __init__(self):
        super().__init__()
        self.messages = []
        self.current_message = {}
        self.current_text = ""
        self.in_message = False
        self.in_text = False
        self.in_from = False
        self.in_date = False
        
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        cls = attrs_dict.get('class', '')
        
        if 'message' in cls and tag == 'div':
            self.in_message = True
            self.current_message = {'text': '', 'media': [], 'links': []}
        
        if self.in_message:
            if tag == 'div' and 'from_name' in cls:
                self.in_from = True
                self.current_text = ""
            elif tag == 'div' and 'date' in cls:
                self.in_date = True
                self.current_text = ""
            elif tag == 'a' and 'media' in cls:
                self.current_message['media'].append(attrs_dict.get('href', ''))
            elif tag == 'a' and attrs_dict.get('href', '').startswith('http'):
                self.current_message['links'].append(attrs_dict.get('href', ''))
    
    def handle_endtag(self, tag):
        if self.in_message:
            if tag == 'div' and self.in_from:
                self.current_message['from'] = self.current_text.strip()
                self.in_from = False
            elif tag == 'div' and self.in_date:
                self.current_message['date'] = self.current_text.strip()
                self.in_date = False
            elif tag == 'div' and 'message' in self.current_message.get('raw_class', ''):
                self.messages.append(self.current_message)
                self.in_message = False
    
    def handle_data(self, data):
        if self.in_from or self.in_date:
            self.current_text += data
        elif self.in_message:
            self.current_message['text'] += data


# ==================== کلاس تحلیل‌گر ====================
@dataclass
class ExportAnalysisConfig:
    level: str = "full"
    include_sensitive: bool = True
    analyze_messages: bool = True
    analyze_contacts: bool = True
    analyze_media: bool = True
    osint_enabled: bool = True
    geo_enabled: bool = True
    pattern_detection: bool = True


class TelegramExportAnalyzer:
    """تحلیل‌گر فایل Export رسمی تلگرام"""
    
    def __init__(self, export_path: Path, config: ExportAnalysisConfig = None,
                 progress_callback=None):
        self.export_path = export_path
        self.config = config or ExportAnalysisConfig()
        self.progress_callback = progress_callback
        self.start_time = time.time()
        self.stats = {'modules_executed': 0, 'modules_failed': 0}
        self.extracted_dir: Optional[Path] = None
        self.data = {}
    
    async def _progress(self, msg: str):
        if self.progress_callback:
            try:
                await self.progress_callback(msg)
            except:
                pass
    
    async def extract_archive(self) -> bool:
        """استخراج فایل ZIP/TAR"""
        try:
            await self._progress("📦 در حال استخراج فایل...")
            self.extracted_dir = TEMP_DIR / f"export_{int(time.time())}"
            self.extracted_dir.mkdir(exist_ok=True)
            
            file_path = str(self.export_path)
            
            if file_path.lower().endswith('.zip'):
                with zipfile.ZipFile(file_path, 'r') as z:
                    z.extractall(self.extracted_dir)
            elif file_path.lower().endswith(('.tar', '.tar.gz', '.tgz')):
                with tarfile.open(file_path, 'r:*') as t:
                    t.extractall(self.extracted_dir)
            else:
                # شاید فقط یک فایل JSON یا HTML باشه
                shutil.copy(file_path, self.extracted_dir / Path(file_path).name)
            
            # پیدا کردن result.json یا پوشه‌های چت
            return True
        except Exception as e:
            logger.error(f"استخراج ناموفق: {e}")
            return False
    
    def _find_result_json(self) -> Optional[Path]:
        """پیدا کردن فایل result.json"""
        for p in self.extracted_dir.rglob('result.json'):
            return p
        return None
    
    def _find_chat_files(self) -> List[Path]:
        """پیدا کردن تمام فایل‌های چت (JSON یا HTML)"""
        files = []
        for p in self.extracted_dir.rglob('*.html'):
            if 'chat' in str(p).lower() or 'messages' in str(p).lower():
                files.append(p)
        for p in self.extracted_dir.rglob('*.json'):
            if p.name != 'result.json':
                files.append(p)
        return files
    
    async def analyze_all(self) -> Dict[str, Any]:
        """تحلیل کامل"""
        await self._progress("🔍 شروع تحلیل...")
        
        analysis = {
            '_metadata': {
                'version': VERSION,
                'timestamp': datetime.now().isoformat(),
                'analyzer': 'Telegram Export Analyzer v2.0',
                'export_file': self.export_path.name,
                'config': asdict(self.config),
            }
        }
        
        # استخراج
        if not await self.extract_archive():
            analysis['_error'] = 'Failed to extract archive'
            return analysis
        
        # پیدا کردن فایل‌ها
        result_json = self._find_result_json()
        chat_files = self._find_chat_files()
        
        await self._progress(f"📁 یافت شد: {len(chat_files)} فایل چت")
        
        # ماژول‌های تحلیل
        modules = [
            ('personal_info', self._analyze_personal_info, result_json),
            ('contacts', self._analyze_contacts, result_json),
            ('chats_overview', self._analyze_chats_overview, result_json),
            ('messages_analysis', self._analyze_messages, (result_json, chat_files)),
            ('media_analysis', self._analyze_media, result_json),
            ('links_analysis', self._analyze_links, chat_files),
            ('activity_patterns', self._analyze_activity, chat_files),
            ('geo_intelligence', self._analyze_geo, chat_files),
            ('osint_extraction', self._extract_osint, chat_files),
            ('sensitive_data', self._find_sensitive, chat_files),
            ('behavioral_analysis', self._analyze_behavior, chat_files),
        ]
        
        for i, (name, func, arg) in enumerate(modules):
            await self._progress(f"📊 [{i+1}/{len(modules)}] {name}...")
            try:
                if arg is None:
                    analysis[name] = await func() if asyncio.iscoroutinefunction(func) else func()
                elif isinstance(arg, tuple):
                    analysis[name] = func(*arg)
                else:
                    analysis[name] = func(arg)
                self.stats['modules_executed'] += 1
            except Exception as e:
                logger.error(f"خطا در {name}: {e}")
                analysis[name] = {'error': str(e)}
                self.stats['modules_failed'] += 1
        
        # خلاصه و متادیتا
        elapsed = time.time() - self.start_time
        analysis['_metadata']['elapsed_seconds'] = round(elapsed, 2)
        analysis['_metadata']['stats'] = self.stats
        analysis['_summary'] = self._generate_summary(analysis)
        
        # پاکسازی
        try:
            shutil.rmtree(self.extracted_dir)
        except:
            pass
        
        return analysis
    
    def _analyze_personal_info(self, result_json: Optional[Path]) -> Dict:
        """اطلاعات شخصی از result.json"""
        if not result_json or not result_json.exists():
            return {'error': 'No result.json'}
        
        try:
            with open(result_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            personal = data.get('personal_information', {})
            profile = data.get('profile', {})
            
            return {
                'user_id': data.get('user_id'),
                'first_name': profile.get('first_name'),
                'last_name': profile.get('last_name'),
                'phone_number': profile.get('phone_number') if self.config.include_sensitive else '[hidden]',
                'username': profile.get('username'),
                'bio': profile.get('bio'),
                'personal_info_keys': list(personal.keys()) if isinstance(personal, dict) else [],
                'data_export_date': data.get('export_date') or data.get('date'),
                'about': personal.get('About') if isinstance(personal, dict) else None,
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_contacts(self, result_json: Optional[Path]) -> Dict:
        """تحلیل مخاطبین"""
        if not result_json or not result_json.exists():
            return {'error': 'No result.json'}
        
        try:
            with open(result_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            contacts = data.get('contacts', {}).get('list', [])
            
            analyzed = []
            country_codes = Counter()
            
            for contact in contacts:
                phone = contact.get('phone_number', '')
                if phone and self.config.include_sensitive:
                    # استخراج کد کشور
                    code = re.match(r'^\+(\d{1,3})', phone)
                    if code:
                        country_codes[code.group(1)] += 1
                
                analyzed.append({
                    'first_name': contact.get('first_name'),
                    'last_name': contact.get('last_name'),
                    'phone': phone if self.config.include_sensitive else '[hidden]',
                    'date_added': contact.get('date'),
                })
            
            return {
                'total_contacts': len(contacts),
                'contacts_sample': analyzed[:100],
                'country_codes_distribution': dict(country_codes.most_common(20)),
                'has_date_info': any('date' in c for c in contacts),
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_chats_overview(self, result_json: Optional[Path]) -> Dict:
        """نمای کلی چت‌ها"""
        if not result_json or not result_json.exists():
            return {'error': 'No result.json'}
        
        try:
            with open(result_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            chats = data.get('chats', {})
            chat_list = chats.get('list', []) if isinstance(chats, dict) else []
            chat_types = Counter()
            msg_counts = []
            
            for chat in chat_list:
                chat_type = chat.get('type', 'unknown')
                chat_types[chat_type] += 1
                msg_counts.append({
                    'name': chat.get('name'),
                    'type': chat_type,
                    'messages_count': len(chat.get('messages', [])),
                })
            
            # مرتب‌سازی بر اساس تعداد پیام
            msg_counts.sort(key=lambda x: x['messages_count'], reverse=True)
            
            return {
                'total_chats': len(chat_list),
                'chat_types': dict(chat_types),
                'top_active_chats': msg_counts[:30],
                'total_messages_in_export': sum(c['messages_count'] for c in msg_counts),
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_messages(self, result_json: Optional[Path], chat_files: List[Path]) -> Dict:
        """تحلیل پیام‌ها"""
        messages = []
        word_counter = Counter()
        emoji_counter = Counter()
        msg_types = Counter()
        
        # الگوی emoji
        emoji_pattern = re.compile(
            "["
            "\U0001F600-\U0001F64F"  # emoticons
            "\U0001F300-\U0001F5FF"  # symbols & pictographs
            "\U0001F680-\U0001F6FF"  # transport & map
            "\U0001F1E0-\U0001F1FF"  # flags
            "\U00002702-\U000027B0"
            "\U0001F900-\U0001F9FF"  # supplemental
            "]+",
            flags=re.UNICODE
        )
        
        # خواندن result.json
        if result_json and result_json.exists():
            try:
                with open(result_json, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                chats = data.get('chats', {}).get('list', []) if isinstance(data.get('chats'), dict) else []
                for chat in chats[:200]:  # محدود به 200 چت
                    for msg in chat.get('messages', [])[:200]:
                        msg_text = msg.get('text', '')
                        if isinstance(msg_text, list):
                            msg_text = ''.join(
                                p if isinstance(p, str) else p.get('text', '')
                                for p in msg_text
                            )
                        
                        msg_types[msg.get('type', 'message')] += 1
                        
                        if msg_text:
                            messages.append({
                                'from': msg.get('from'),
                                'date': msg.get('date'),
                                'text_length': len(msg_text),
                                'text_preview': msg_text[:200] if self.config.include_sensitive else '[hidden]',
                                'type': msg.get('type'),
                                'media_type': msg.get('media_type'),
                            })
                            
                            # کلمات
                            words = re.findall(r'\b\w+\b', msg_text.lower())
                            word_counter.update(words)
                            
                            # ایموجی‌ها
                            emojis = emoji_pattern.findall(msg_text)
                            for e in emojis:
                                emoji_counter[e] += 1
            
            except Exception as e:
                return {'error': str(e)}
        
        # کلمات رایج (حذف stop words فارسی و انگلیسی)
        stop_words = {'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been',
                      'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will',
                      'would', 'could', 'should', 'may', 'might', 'can', 'to', 'of',
                      'in', 'for', 'on', 'with', 'at', 'by', 'from', 'as', 'into',
                      'and', 'or', 'but', 'if', 'then', 'than', 'so', 'that',
                      'این', 'که', 'را', 'از', 'به', 'با', 'و', 'یا', 'اما', 'پس',
                      'تا', 'هم', 'یک', 'دو', 'سه', 'بود', 'شد', 'است', 'هست'}
        
        filtered_words = Counter({w: c for w, c in word_counter.items() 
                                 if w not in stop_words and len(w) > 2})
        
        return {
            'total_messages_analyzed': len(messages),
            'message_types': dict(msg_types),
            'top_words': filtered_words.most_common(50),
            'top_emojis': emoji_counter.most_common(30),
            'messages_sample': messages[:500],
            'avg_message_length': sum(m['text_length'] for m in messages) / len(messages) if messages else 0,
        }
    
    def _analyze_media(self, result_json: Optional[Path]) -> Dict:
        """تحلیل رسانه‌ها"""
        if not result_json or not result_json.exists():
            return {'error': 'No result.json'}
        
        try:
            with open(result_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            media_types = Counter()
            media_files = []
            
            chats = data.get('chats', {}).get('list', []) if isinstance(data.get('chats'), dict) else []
            for chat in chats:
                for msg in chat.get('messages', []):
                    if msg.get('type') == 'media':
                        media_type = msg.get('media_type', 'unknown')
                        media_types[media_type] += 1
                        if msg.get('file'):
                            media_files.append({
                                'file': msg.get('file'),
                                'type': media_type,
                                'from': msg.get('from'),
                                'date': msg.get('date'),
                                'mime_type': msg.get('mime_type'),
                                'file_size': msg.get('file_size'),
                            })
            
            # شمارش فایل‌های واقعی
            actual_files = {
                'photos': len(list(self.extracted_dir.rglob('*.jpg'))) + len(list(self.extracted_dir.rglob('*.png'))) + len(list(self.extracted_dir.rglob('*.webp'))),
                'videos': len(list(self.extracted_dir.rglob('*.mp4'))) + len(list(self.extracted_dir.rglob('*.mov'))),
                'audios': len(list(self.extracted_dir.rglob('*.mp3'))) + len(list(self.extracted_dir.rglob('*.ogg'))) + len(list(self.extracted_dir.rglob('*.m4a'))),
                'documents': len(list(self.extracted_dir.rglob('*.pdf'))) + len(list(self.extracted_dir.rglob('*.doc*'))) + len(list(self.extracted_dir.rglob('*.zip'))),
            }
            
            return {
                'media_types': dict(media_types),
                'media_sample': media_files[:100],
                'actual_files_count': actual_files,
                'total_media_references': len(media_files),
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_links(self, chat_files: List[Path]) -> Dict:
        """تحلیل لینک‌ها"""
        urls = []
        domains = Counter()
        tlds = Counter()
        
        url_pattern = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
        
        for file in chat_files[:100]:
            try:
                if file.suffix.lower() == '.html':
                    content = file.read_text(encoding='utf-8', errors='ignore')
                elif file.suffix.lower() == '.json':
                    content = file.read_text(encoding='utf-8', errors='ignore')
                else:
                    continue
                
                found_urls = url_pattern.findall(content)
                for url in found_urls[:1000]:
                    urls.append(url)
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        domain = parsed.netloc.lower()
                        if domain:
                            domains[domain] += 1
                            parts = domain.split('.')
                            if len(parts) >= 2:
                                tlds[parts[-1]] += 1
                    except:
                        pass
            except:
                pass
        
        # دسته‌بندی دامنه‌ها
        categories = {
            'social_media': ['instagram.com', 'twitter.com', 'x.com', 'facebook.com', 'tiktok.com', 'youtube.com'],
            'messaging': ['t.me', 'telegram.org', 'wa.me', 'whatsapp.com'],
            'news': ['bbc.com', 'cnn.com', 'reuters.com', 'aljazeera.com'],
            'iranian': ['.ir'],
        }
        
        categorized = {}
        for cat, sites in categories.items():
            count = sum(domains.get(s, 0) for s in sites if not s.startswith('.'))
            if cat == 'iranian':
                count = sum(c for d, c in domains.items() if d.endswith('.ir'))
            if count:
                categorized[cat] = count
        
        return {
            'total_urls': len(urls),
            'unique_urls': len(set(urls)),
            'top_domains': domains.most_common(30),
            'top_tlds': tlds.most_common(15),
            'categories': categorized,
            'url_sample': list(set(urls))[:100],
        }
    
    def _analyze_activity(self, chat_files: List[Path]) -> Dict:
        """الگوهای فعالیت"""
        hours = Counter()
        days = Counter()
        dates = Counter()
        
        date_pattern = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')
        
        # از result.json استفاده می‌کنیم
        result_json = self._find_result_json()
        if not result_json:
            return {'error': 'No result.json'}
        
        try:
            with open(result_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            chats = data.get('chats', {}).get('list', []) if isinstance(data.get('chats'), dict) else []
            for chat in chats:
                for msg in chat.get('messages', []):
                    date_str = msg.get('date', '')
                    if date_str:
                        match = date_pattern.search(date_str)
                        if match:
                            try:
                                dt = datetime.fromisoformat(match.group(0).replace('Z', '+00:00'))
                                hours[dt.hour] += 1
                                days[dt.strftime('%A')] += 1
                                dates[dt.strftime('%Y-%m-%d')] += 1
                            except:
                                pass
            
            # پیدا کردن فعال‌ترین ساعت و روز
            peak_hour = hours.most_common(1)[0] if hours else None
            peak_day = days.most_common(1)[0] if days else None
            
            return {
                'hourly_distribution': dict(sorted(hours.items())),
                'daily_distribution': dict(days),
                'date_range': {
                    'first': min(dates.keys()) if dates else None,
                    'last': max(dates.keys()) if dates else None,
                    'total_days': len(dates),
                },
                'peak_activity': {
                    'hour': peak_hour,
                    'day': peak_day,
                },
                'most_active_dates': sorted(dates.items(), key=lambda x: -x[1])[:10],
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_geo(self, chat_files: List[Path]) -> Dict:
        """اطلاعات جغرافیایی"""
        locations = []
        venues = []
        
        result_json = self._find_result_json()
        if not result_json:
            return {'error': 'No result.json'}
        
        try:
            with open(result_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            chats = data.get('chats', {}).get('list', []) if isinstance(data.get('chats'), dict) else []
            for chat in chats:
                for msg in chat.get('messages', []):
                    if msg.get('media_type') == 'location' or msg.get('location'):
                        loc = msg.get('location', {})
                        if 'latitude' in loc and 'longitude' in loc:
                            locations.append({
                                'lat': loc['latitude'],
                                'long': loc['longitude'],
                                'date': msg.get('date'),
                                'from': msg.get('from'),
                            })
                    
                    if msg.get('media_type') == 'venue' or msg.get('venue'):
                        venue = msg.get('venue', {})
                        if venue:
                            venues.append({
                                'title': venue.get('title'),
                                'address': venue.get('address'),
                                'lat': venue.get('latitude'),
                                'long': venue.get('longitude'),
                                'date': msg.get('date'),
                            })
            
            return {
                'locations': locations[:100],
                'locations_count': len(locations),
                'venues': venues[:100],
                'venues_count': len(venues),
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_osint(self, chat_files: List[Path]) -> Dict:
        """استخراج OSINT"""
        emails = set()
        phones = set()
        usernames = set()
        ips = set()
        crypto_addresses = set()
        api_keys = []
        
        # الگوها
        patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
            'phone_ir': r'(?:\+98|0)9\d{9}',
            'phone_int': r'\+\d{10,15}',
            'username': r'@([A-Za-z0-9_]{4,32})',
            'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'btc': r'\b(1[A-HJ-NP-Za-km-z1-9]{25,39}|3[A-HJ-NP-Za-km-z1-9]{25,39}|bc1[a-z0-9]{11,71})\b',
            'eth': r'\b0x[a-fA-F0-9]{40}\b',
            'api_key': r'(?:api[_-]?key|token|secret)["\s:=]+["\']?([A-Za-z0-9_\-]{20,})["\']?',
            'telegram_bot_token': r'(\d{8,10}:[A-Za-z0-9_\-]{35})',
        }
        
        # خواندن تمام چت‌ها
        result_json = self._find_result_json()
        text_content = ""
        
        if result_json and result_json.exists():
            try:
                text_content = result_json.read_text(encoding='utf-8', errors='ignore')[:20_000_000]
            except:
                pass
        
        if text_content:
            emails.update(re.findall(patterns['email'], text_content))
            phones.update(re.findall(patterns['phone_ir'], text_content))
            phones.update(re.findall(patterns['phone_int'], text_content))
            usernames.update(re.findall(patterns['username'], text_content))
            ips.update(re.findall(patterns['ipv4'], text_content))
            crypto_addresses.update(re.findall(patterns['btc'], text_content))
            crypto_addresses.update(re.findall(patterns['eth'], text_content))
            
            # API keys
            for match in re.finditer(patterns['api_key'], text_content, re.IGNORECASE):
                if self.config.include_sensitive:
                    api_keys.append({'key': match.group(1)[:10] + '...', 'length': len(match.group(1))})
            
            # Bot tokens
            for match in re.finditer(patterns['telegram_bot_token'], text_content):
                api_keys.append({'type': 'bot_token', 'preview': match.group(1)[:20] + '...'})
        
        # حذف IP های private
        public_ips = [ip for ip in ips if not (
            ip.startswith('192.168.') or ip.startswith('10.') or 
            ip.startswith('172.') or ip.startswith('127.') or
            ip == '0.0.0.0'
        )]
        
        return {
            'emails': list(emails)[:500],
            'phones': list(phones)[:500] if self.config.include_sensitive else [f'[{len(phones)} found]'],
            'usernames': list(usernames)[:500],
            'public_ips': public_ips[:50],
            'crypto_addresses': list(crypto_addresses)[:100],
            'api_keys_count': len(api_keys),
            'api_keys_sample': api_keys[:10],
            'statistics': {
                'emails_found': len(emails),
                'phones_found': len(phones),
                'usernames_found': len(usernames),
                'ips_found': len(public_ips),
                'crypto_found': len(crypto_addresses),
            }
        }
    
    def _find_sensitive(self, chat_files: List[Path]) -> Dict:
        """یافتن اطلاعات حساس"""
        sensitive_patterns = {
            'national_id_ir': r'\b\d{10}\b',  # کد ملی ایران
            'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            'cvv': r'\bCVV[:\s]*\d{3,4}\b',
            'password': r'(?:password|pass|pwd|رمز)["\s:=]+["\']?([^\s"\']{6,})["\']?',
            'bank_info': r'(?:sheba|شبا|IBAN|account)[\s:=]+([A-Z0-9]{20,})',
            'passport': r'(?:passport|پاسپورت)[\s:]+([A-Z0-9]{6,12})',
        }
        
        findings = defaultdict(list)
        
        result_json = self._find_result_json()
        if result_json and result_json.exists():
            try:
                text = result_json.read_text(encoding='utf-8', errors='ignore')[:10_000_000]
                
                for name, pattern in sensitive_patterns.items():
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    if matches:
                        findings[name] = [
                            f"[{len(m)} chars]" if self.config.include_sensitive else '[REDACTED]'
                            for m in matches[:10]
                        ]
            except:
                pass
        
        return {
            'sensitive_data_types': dict(findings),
            'has_sensitive_data': len(findings) > 0,
            'risk_level': 'high' if len(findings) >= 3 else 'medium' if findings else 'low',
        }
    
    def _analyze_behavior(self, chat_files: List[Path]) -> Dict:
        """تحلیل رفتاری"""
        chat_partners = Counter()
        group_activity = Counter()
        time_response = []
        languages = Counter()
        
        result_json = self._find_result_json()
        if not result_json:
            return {'error': 'No result.json'}
        
        try:
            with open(result_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            chats = data.get('chats', {}).get('list', []) if isinstance(data.get('chats'), dict) else []
            
            for chat in chats:
                chat_type = chat.get('type', '')
                chat_name = chat.get('name', 'Unknown')
                msg_count = len(chat.get('messages', []))
                
                if chat_type in ('personal_chat', 'private'):
                    chat_partners[chat_name] += msg_count
                elif chat_type in ('group', 'supergroup', 'public_supergroup'):
                    group_activity[chat_name] += msg_count
                
                # تشخیص زبان (ساده - بر اساس کاراکترها)
                for msg in chat.get('messages', [])[:50]:
                    text = msg.get('text', '')
                    if isinstance(text, list):
                        text = ''.join(p if isinstance(p, str) else p.get('text', '') for p in text)
                    
                    if text:
                        # تشخیص فارسی
                        if re.search(r'[\u0600-\u06FF]', text):
                            languages['Persian'] += 1
                        elif re.search(r'[a-zA-Z]', text):
                            languages['English'] += 1
                        elif re.search(r'[\u0627-\u064A]', text):
                            languages['Arabic'] += 1
            
            return {
                'top_chat_partners': chat_partners.most_common(20),
                'top_groups': group_activity.most_common(20),
                'languages_detected': dict(languages.most_common(5)),
                'total_unique_chats': len(chat_partners) + len(group_activity),
                'communication_pattern': {
                    'private_chats': len(chat_partners),
                    'group_chats': len(group_activity),
                    'most_active_partner': chat_partners.most_common(1)[0] if chat_partners else None,
                }
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _generate_summary(self, analysis: Dict) -> Dict:
        """تولید خلاصه"""
        personal = analysis.get('personal_info', {})
        contacts = analysis.get('contacts', {})
        chats = analysis.get('chats_overview', {})
        messages = analysis.get('messages_analysis', {})
        osint = analysis.get('osint_extraction', {})
        geo = analysis.get('geo_intelligence', {})
        sensitive = analysis.get('sensitive_data', {})
        activity = analysis.get('activity_patterns', {})
        
        return {
            'user': personal.get('first_name', 'Unknown'),
            'username': personal.get('username'),
            'export_date': personal.get('data_export_date'),
            'total_contacts': contacts.get('total_contacts', 0),
            'total_chats': chats.get('total_chats', 0),
            'total_messages': chats.get('total_messages_in_export', 0),
            'emails_found': osint.get('statistics', {}).get('emails_found', 0),
            'phones_found': osint.get('statistics', {}).get('phones_found', 0),
            'urls_found': analysis.get('links_analysis', {}).get('total_urls', 0),
            'locations_found': geo.get('locations_count', 0),
            'media_files': sum(analysis.get('media_analysis', {}).get('actual_files_count', {}).values()),
            'risk_level': sensitive.get('risk_level', 'unknown'),
            'active_hours': activity.get('peak_activity', {}).get('hour'),
            'analysis_time': analysis['_metadata'].get('elapsed_seconds'),
        }
    
    def encrypt_and_save(self, data: Dict, password: str, output_path: str) -> int:
        """رمزنگاری و ذخیره"""
        json_data = json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8')
        compressed = gzip.compress(json_data, compresslevel=9)
        salt = get_random_bytes(16)
        key = PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=PBKDF2_ITERATIONS, prf=hmac_sha256)
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(compressed)
        blob = salt + nonce + tag + ciphertext
        encoded = base64.b64encode(blob).decode('utf-8')
        Path(output_path).write_text(encoded, encoding='utf-8')
        return len(encoded)
    
    @staticmethod
    def decrypt(encrypted_path: str, password: str) -> Dict:
        blob = base64.b64decode(Path(encrypted_path).read_text(encoding='utf-8'))
        salt, nonce, tag = blob[:16], blob[16:28], blob[28:44]
        ciphertext = blob[44:]
        key = PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=PBKDF2_ITERATIONS, prf=hmac_sha256)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        compressed = cipher.decrypt_and_verify(ciphertext, tag)
        return json.loads(gzip.decompress(compressed).decode('utf-8'))


# ==================== کلاس ربات ====================

class ExportBot:
    def __init__(self):
        self.user_states: Dict[int, Dict] = {}
    
    def _check_auth(self, user_id: int) -> bool:
        if not AUTHORIZED_USERS:
            return True
        return user_id in AUTHORIZED_USERS
    
    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = update.effective_user
        if not self._check_auth(user.id):
            await update.message.reply_text("⛔ شما مجاز به استفاده از این ربات نیستید.")
            return
        
        await update.message.reply_text(
            f"👋 سلام {user.first_name}!\n\n"
            "🤖 <b>Telegram Export Analyzer Bot v2.0</b>\n\n"
            "🔒 <b>این ربات نیازی به api_id یا api_hash نداره!</b>\n\n"
            "📋 <b>نحوه کار:</b>\n"
            "1️⃣ از تلگرام دسکتاپ خود Export می‌گیرید\n"
            "2️⃣ فایل ZIP رو به ربات ارسال می‌کنید\n"
            "3️⃣ ربات forensics کامل انجام می‌ده\n"
            "4️⃣ گزارش رمزنگاری شده دریافت می‌کنید\n\n"
            "📝 <b>راهنمای Export گرفتن:</b>\n"
            "1. Telegram Desktop رو باز کنید\n"
            "2. به Settings → Advanced برید\n"
            "3. روی \"Export Telegram data\" کلیک کنید\n"
            "4. گزینه‌ها رو انتخاب کنید (همه موارد)\n"
            "5. Format رو روی \"Machine-readable JSON\" بذارید\n"
            "6. Export رو شروع کنید (ZIP)\n"
            "7. فایل ZIP رو برای ربات ارسال کنید\n\n"
            "📋 <b>دستورات:</b>\n"
            "/analyze - شروع تحلیل\n"
            "/decrypt - رمزگشایی فایل\n"
            "/help - راهنما\n"
            "/cancel - لغو\n\n"
            "برای شروع /analyze رو بزن 👇",
            parse_mode=ParseMode.HTML
        )
    
    async def analyze_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = update.effective_user
        if not self._check_auth(user.id):
            await update.message.reply_text("⛔ شما مجاز نیستید.")
            return ConversationHandler.END
        
        await update.message.reply_text(
            "📦 <b>فایل Export تلگرام رو ارسال کنید</b>\n\n"
            "💾 پشتیبانی از:\n"
            "• ZIP (توصیه می‌شه)\n"
            "• TAR / TAR.GZ\n"
            "• فایل JSON تکی\n"
            "• پوشه HTML\n\n"
            "⚠️ حداکثر حجم: 50 MB",
            parse_mode=ParseMode.HTML
        )
        return AWAITING_EXPORT
    
    async def receive_export(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        doc = update.message.document
        
        if not doc:
            await update.message.reply_text("❌ لطفاً یک فایل ارسال کنید.")
            return AWAITING_EXPORT
        
        # بررسی اندازه
        if doc.file_size and doc.file_size > 50 * 1024 * 1024:
            await update.message.reply_text("❌ فایل بزرگتر از 50 MB است.")
            return AWAITING_EXPORT
        
        status_msg = await update.message.reply_text("📥 در حال دانلود فایل...")
        
        try:
            file = await doc.get_file()
            ext = Path(doc.file_name).suffix.lower() if doc.file_name else '.zip'
            temp_path = TEMP_DIR / f"export_{update.effective_user.id}_{int(time.time())}{ext}"
            await file.download_to_drive(str(temp_path))
            
            context.user_data['export_file'] = str(temp_path)
            
            await status_msg.edit_text(
                "✅ فایل دریافت شد!\n\n"
                "🔑 <b>رمز عبور برای رمزنگاری گزارش رو وارد کنید:</b>\n"
                "(حداقل 8 کاراکتر)"
            )
            return AWAITING_PASSWORD
        
        except Exception as e:
            await status_msg.edit_text(f"❌ خطا در دانلود: {e}")
            return ConversationHandler.END
    
    async def receive_password(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        password = update.message.text.strip()
        
        if len(password) < 8:
            await update.message.reply_text(
                "❌ رمز عبور باید حداقل 8 کاراکتر باشد. دوباره وارد کنید:"
            )
            return AWAITING_PASSWORD
        
        # حذف پیام رمز
        try:
            await update.message.delete()
        except:
            pass
        
        context.user_data['password'] = password
        await update.message.reply_text(
            "🔑 رمز عبور را برای تأیید دوباره وارد کنید:"
        )
        return CONFIRM_PASSWORD
    
    async def confirm_password(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        password = update.message.text.strip()
        
        if password != context.user_data.get('password'):
            await update.message.reply_text("❌ رمزها مطابقت ندارند. دوباره وارد کنید:")
            return AWAITING_PASSWORD
        
        # حذف پیام رمز
        try:
            await update.message.delete()
        except:
            pass
        
        export_path = Path(context.user_data['export_file'])
        password = context.user_data['password']
        user_id = update.effective_user.id
        
        status_msg = await update.message.reply_text(
            "🚀 <b>شروع تحلیل forensics...</b>\n\n"
            "⏳ این عملیات ممکنه چند دقیقه طول بکشه."
        )
        
        async def progress(msg):
            try:
                await status_msg.edit_text(f"🚀 <b>در حال تحلیل...</b>\n\n{msg}", parse_mode=ParseMode.HTML)
            except:
                pass
        
        try:
            config = ExportAnalysisConfig(level='full', include_sensitive=True)
            analyzer = TelegramExportAnalyzer(export_path, config, progress_callback=progress)
            
            analysis = await analyzer.analyze_all()
            
            # ذخیره و رمزنگاری
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = OUTPUT_DIR / f"analysis_{user_id}_{timestamp}.enc"
            
            await progress("💾 رمزنگاری گزارش...")
            size = analyzer.encrypt_and_save(analysis, password, str(output_file))
            size_mb = size / (1024 * 1024)
            
            # خلاصه
            summary = analysis.get('_summary', {})
            stats = analysis.get('_metadata', {}).get('stats', {})
            
            summary_text = (
                "✅ <b>تحلیل کامل شد!</b>\n\n"
                f"👤 کاربر: {summary.get('user', 'Unknown')}\n"
                f"📛 Username: @{summary.get('username', 'N/A')}\n"
                f"📊 مخاطبین: {summary.get('total_contacts', 0)}\n"
                f"💬 چت‌ها: {summary.get('total_chats', 0)}\n"
                f"📨 پیام‌ها: {summary.get('total_messages', 0):,}\n"
                f"🔗 لینک‌ها: {summary.get('urls_found', 0)}\n"
                f"📍 موقعیت‌ها: {summary.get('locations_found', 0)}\n"
                f"📧 ایمیل‌ها: {summary.get('emails_found', 0)}\n"
                f"📱 شماره‌ها: {summary.get('phones_found', 0)}\n"
                f"⚠️ سطح ریسک: {summary.get('risk_level', 'N/A')}\n"
                f"⏱️ زمان تحلیل: {summary.get('analysis_time', 0):.2f} ثانیه\n"
                f"💾 حجم: {size_mb:.2f} MB\n\n"
                "📤 ارسال فایل..."
            )
            
            await status_msg.edit_text(summary_text, parse_mode=ParseMode.HTML)
            
            # ارسال فایل
            try:
                caption = (
                    f"🔐 گزارش تحلیل رمزنگاری شده\n"
                    f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
                    f"🔑 AES-256-GCM + PBKDF2\n"
                    f"📊 شامل: {stats.get('modules_executed', 0)} ماژول موفق"
                )
                with open(output_file, 'rb') as f:
                    await update.message.reply_document(
                        document=f,
                        filename=f"telegram_forensics_{timestamp}.enc",
                        caption=caption[:1024],
                    )
            except Exception as e:
                await update.message.reply_text(f"⚠️ خطا در ارسال: {e}")
            
            # پاکسازی
            try:
                export_path.unlink()
                output_file.unlink()
            except:
                pass
            
        except Exception as e:
            logger.error(f"خطا: {e}", exc_info=True)
            await status_msg.edit_text(f"❌ خطا در تحلیل: {e}")
        
        finally:
            for key in ['export_file', 'password']:
                context.user_data.pop(key, None)
        
        return ConversationHandler.END
    
    async def decrypt_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = update.effective_user
        if not self._check_auth(user.id):
            await update.message.reply_text("⛔ شما مجاز نیستید.")
            return ConversationHandler.END
        
        await update.message.reply_text(
            "🔓 <b>حالت رمزگشایی</b>\n\n"
            "📎 فایل رمزنگاری شده (.enc) را ارسال کنید:"
        )
        context.user_data['mode'] = 'decrypt_file'
        return AWAITING_EXPORT
    
    async def handle_any(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """مدیریت پیام‌های عمومی"""
        mode = context.user_data.get('mode')
        
        if mode == 'decrypt_file' and update.message.document:
            file = await update.message.document.get_file()
            temp_path = OUTPUT_DIR / f"temp_{update.effective_user.id}_{int(time.time())}.enc"
            await file.download_to_drive(str(temp_path))
            context.user_data['decrypt_file'] = str(temp_path)
            
            await update.message.reply_text("🔑 رمز عبور را وارد کنید:")
            context.user_data['mode'] = 'decrypt_password'
            return AWAITING_PASSWORD
        
        elif mode == 'decrypt_password':
            password = update.message.text.strip()
            file_path = context.user_data.get('decrypt_file')
            
            if not file_path or not Path(file_path).exists():
                await update.message.reply_text("❌ فایل یافت نشد.")
                return ConversationHandler.END
            
            try:
                await update.message.delete()
            except:
                pass
            
            status = await update.message.reply_text("🔄 در حال رمزگشایی...")
            
            try:
                data = TelegramExportAnalyzer.decrypt(file_path, password)
                output_json = Path(file_path).with_suffix('.json')
                output_json.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
                
                await status.edit_text("✅ رمزگشایی موفق!")
                
                with open(output_json, 'rb') as f:
                    await update.message.reply_document(
                        document=f,
                        filename=output_json.name,
                        caption="🔓 فایل رمزگشایی شده",
                    )
                
                try:
                    Path(file_path).unlink()
                    output_json.unlink()
                except:
                    pass
            
            except ValueError:
                await status.edit_text("❌ رمز اشتباه یا فایل دستکاری شده!")
            except Exception as e:
                await status.edit_text(f"❌ خطا: {e}")
            
            context.user_data.pop('decrypt_file', None)
            context.user_data.pop('mode', None)
            return ConversationHandler.END
        
        return ConversationHandler.END
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(
            "📖 <b>راهنما</b>\n\n"
            "🔹 <b>/start</b> - شروع\n"
            "🔹 <b>/analyze</b> - تحلیل فایل Export\n"
            "🔹 <b>/decrypt</b> - رمزگشایی\n"
            "🔹 <b>/cancel</b> - لغو\n"
            "🔹 <b>/help</b> - این راهنما\n\n"
            "📦 <b>نحوه Export گرفتن:</b>\n"
            "Telegram Desktop → Settings → Advanced → Export Telegram data\n\n"
            "📊 <b>ماژول‌های تحلیل:</b>\n"
            "• 👤 اطلاعات شخصی\n"
            "• 📞 مخاطبین (13 مورد)\n"
            "• 💬 چت‌ها و پیام‌ها\n"
            "• 🖼️ رسانه‌ها\n"
            "• 🔗 لینک‌ها و دامنه‌ها\n"
            "• 📅 الگوهای فعالیت\n"
            "• 📍 اطلاعات جغرافیایی\n"
            "• 🧠 OSINT (ایمیل، شماره، IP، رمز ارز)\n"
            "• ⚠️ اطلاعات حساس\n"
            "• 🎭 تحلیل رفتاری\n\n"
            "🔐 <b>امنیت:</b> AES-256-GCM + PBKDF2",
            parse_mode=ParseMode.HTML
        )
    
    async def cancel(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        for key in ['export_file', 'password', 'mode']:
            context.user_data.pop(key, None)
        await update.message.reply_text("❌ عملیات لغو شد.")
        return ConversationHandler.END
    
    async def error_handler(self, update: object, context: ContextTypes.DEFAULT_TYPE):
        logger.error(f"خطا: {context.error}", exc_info=context.error)


# ==================== اجرای اصلی ====================

def main():
    if not TELETHON_AVAILABLE and False:
        pass  # Telethon دیگر نیاز نیست
    
    app = Application.builder().token(BOT_TOKEN).build()
    bot = ExportBot()
    
    # Conversation Handler
    conv_handler = ConversationHandler(
        entry_points=[
            CommandHandler("analyze", bot.analyze_start),
            CommandHandler("decrypt", bot.decrypt_start),
        ],
        states={
            AWAITING_EXPORT: [
                MessageHandler(filters.Document.ALL, bot.receive_export),
                MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_any),
            ],
            AWAITING_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, bot.receive_password),
                MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_any),
            ],
            CONFIRM_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, bot.confirm_password),
            ],
        },
        fallbacks=[CommandHandler("cancel", bot.cancel)],
    )
    
    app.add_handler(CommandHandler("start", bot.start))
    app.add_handler(CommandHandler("help", bot.help_command))
    app.add_handler(conv_handler)
    app.add_error_handler(bot.error_handler)
    
    print("=" * 60)
    print("🤖 Telegram Export Analyzer Bot v2.0")
    print("=" * 60)
    print("✅ ربات در حال اجرا...")
    print("🔒 نیازی به api_id/api_hash نیست")
    print("📦 فقط فایل Export تلگرام لازمه")
    print("=" * 60)
    
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()

# Flask Privacy-Focused Image and Video Uploader - Security Hardened
# Enhanced with NSFW detection, optimized memory usage, and strengthened anonymization
#
# --- CRITICAL SETUP INSTRUCTIONS ---
# 1. Install necessary Python libraries:
#    pip install Flask Pillow pycryptodome captcha opencv-python rembg easyocr torch torchvision numba timm
#
# 2. Install system-level dependencies:
#    - FFmpeg: Must be installed and accessible in your system's PATH (for video compression).
#
# 3. Download the Haar Cascade model for face detection:
#    - Download 'haarcascade_frontalface_default.xml' from the official OpenCV GitHub repository.
#    - Place this XML file in the same directory as this script.
#
# 4. Create directories:
#    - Create a directory named 'uploads' and 'static' in the same directory as this script.
#
# 5. NSFW Detection Model:
#    - On first startup, the Marqo/nsfw-image-detection-384 model will be downloaded automatically (~5.6MB).
#    - Ensure internet connection for initial model download only.
#    - Model provides 98.56% accuracy for NSFW detection with fallback to simple heuristics.
#
# 6. Run for production using a WSGI server (do not use debug mode):
#    gunicorn --workers 4 --bind 0.0.0.0:8000 app:app

# © 2025 Bario — Licensed under AGPLv3
# Educational Use Only — No Warranty — See LICENSE

import os
import shutil
import hashlib
import random
import string
import time
import threading
import logging
import mimetypes
import gc
import sqlite3
import socket
import subprocess
import secrets
import hmac
import re
from datetime import datetime, timedelta, timezone
from io import BytesIO
from urllib.parse import quote
from pathlib import Path

# --- Third-party imports ---
from flask import Flask, request, redirect, url_for, render_template_string, make_response, session, jsonify, abort
from PIL import Image, ImageFilter
from PIL.ExifTags import TAGS
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from captcha.image import ImageCaptcha
import cv2
import numpy as np
from rembg import remove
import easyocr
from numba import jit, uint8
import numba as nb
import timm
import torch

# --- Configuration ---
UPLOAD_FOLDER = 'uploads'
STATIC_FOLDER = 'static'
MAX_CONTENT_LENGTH = 300 * 1024 * 1024  # 300 MB
MAX_STORAGE_GB = 1
DELETION_TIME_HOURS = 3
JURISDICTION = "Vanuatu"  # Legal jurisdiction for the service
REPORTS_DB_FILE = 'reports.db'
CONFIGURATION_FILE = 'CONFIGURATION'

# --- Security Configuration ---
CSRF_SECRET_KEY = secrets.token_bytes(32)
SESSION_COOKIE_SECURE = True  # Set to False for development over HTTP
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
MAX_UPLOAD_FILES = 10
MAX_SINGLE_FILE_SIZE = 100 * 1024 * 1024  # 100MB per file

# --- Rate Limiting Configuration ---
RATE_LIMIT_WINDOW = 600  # 10 minutes
MAX_UPLOADS_PER_WINDOW = 5
MAX_REPORTS_PER_WINDOW = 3
MAX_CAPTCHA_ATTEMPTS = 10

# --- Secure filename validation ---
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.webp', '.mp4', '.mov', '.avi', '.webm'}
DANGEROUS_FILENAMES = {'con', 'prn', 'aux', 'nul', 'com1', 'com2', 'com3', 'com4', 'com5', 
                      'com6', 'com7', 'com8', 'com9', 'lpt1', 'lpt2', 'lpt3', 'lpt4', 
                      'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9'}

# --- Report Categories ---
REPORT_CATEGORIES = [
    "CHILD EXPLOITATION & SEXUAL OFFENSES",
    "CYBERCRIME & DIGITAL OFFENSES", 
    "INTELLECTUAL PROPERTY & COPYRIGHT",
    "TERRORISM & NATIONAL SECURITY",
    "PUBLIC ORDER & SEDITIOUS CONTENT",
    "DEFAMATION & REPUTATION",
    "OBSCENITY & MORAL OFFENSES",
    "FINANCIAL & COMMERCIAL CRIMES",
    "JUSTICE ADMINISTRATION & EVIDENCE",
    "OTHER"
]

# --- File Erasure & Plausible Deniability ---
GUTMANN_PASSES = [
    (b'\x55',), (b'\xAA',), (b'\x92\x49\x24',), (b'\x49\x24\x92',), (b'\x24\x92\x49',),
    (b'\x00',), (b'\x11',), (b'\x22',), (b'\x33',), (b'\x44',), (b'\x55',), (b'\x66',),
    (b'\x77',), (b'\x88',), (b'\x99',), (b'\xAA',), (b'\xBB',), (b'\xCC',), (b'\xDD',),
    (b'\xEE',), (b'\xFF',), (b'\x92\x49\x24',), (b'\x49\x24\x92',), (b'\x24\x92\x49',),
    (b'\x6D\xB6\xDB',), (b'\xB6\xDB\x6D',), (b'\xDB\x6D\xB6',)]

# --- Flask App Initialization ---
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['STATIC_FOLDER'] = STATIC_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.secret_key = secrets.token_bytes(32)

# --- Security Headers ---
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'unsafe-inline'; script-src 'none'"
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# --- CSRF Protection ---
def generate_csrf_token():
    """Generate a secure CSRF token"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token using constant-time comparison"""
    if 'csrf_token' not in session:
        return False
    return hmac.compare_digest(session['csrf_token'], token or '')

# --- Input Validation & Sanitization ---
def sanitize_filename(filename):
    """Safely sanitize filename to prevent path traversal"""
    if not filename:
        return None
    
    # Remove path components and normalize
    filename = os.path.basename(filename)
    filename = os.path.normpath(filename)
    
    # Check for dangerous filenames
    name_part = os.path.splitext(filename)[0].lower()
    if name_part in DANGEROUS_FILENAMES:
        return None
    
    # Remove dangerous characters
    filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '', filename)
    
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255-len(ext)] + ext
    
    return filename if filename else None

def validate_file_extension(filename):
    """Validate file extension against allowlist"""
    if not filename:
        return False
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS

def validate_file_content(file_path, expected_type):
    """Validate file content matches expected type"""
    try:
        if expected_type == 'image':
            with Image.open(file_path) as img:
                img.verify()
            return True
        elif expected_type == 'video':
            # Basic video validation - check if FFmpeg can read it
            result = subprocess.run(['ffprobe', '-v', 'quiet', file_path], 
                                  capture_output=True, timeout=5)
            return result.returncode == 0
    except Exception:
        return False
    return False

def sanitize_user_input(user_input, max_length=1000):
    """Sanitize user input to prevent injection attacks"""
    if not user_input:
        return ""
    
    # Remove null bytes and control characters
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', str(user_input))
    
    # Truncate to max length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized.strip()

# --- Rate Limiting ---
class RateLimiter:
    def __init__(self):
        self.attempts = {}
        self.lock = threading.Lock()
    
    def get_client_id(self, request):
        """Generate client identifier based on multiple factors"""
        factors = [
            request.environ.get('REMOTE_ADDR', ''),
            request.headers.get('User-Agent', ''),
            request.headers.get('Accept-Language', ''),
            str(session.get('csrf_token', ''))
        ]
        client_hash = hashlib.sha256('|'.join(factors).encode()).hexdigest()[:16]
        return client_hash
    
    def is_allowed(self, request, action_type):
        """Check if action is allowed based on rate limits"""
        client_id = self.get_client_id(request)
        current_time = time.time()
        
        with self.lock:
            if client_id not in self.attempts:
                self.attempts[client_id] = {}
            
            client_attempts = self.attempts[client_id]
            
            # Clean old attempts
            cutoff_time = current_time - RATE_LIMIT_WINDOW
            client_attempts[action_type] = [
                timestamp for timestamp in client_attempts.get(action_type, [])
                if timestamp > cutoff_time
            ]
            
            # Check limits
            max_attempts = {
                'upload': MAX_UPLOADS_PER_WINDOW,
                'report': MAX_REPORTS_PER_WINDOW,
                'captcha': MAX_CAPTCHA_ATTEMPTS
            }.get(action_type, 5)
            
            if len(client_attempts[action_type]) >= max_attempts:
                return False
            
            # Record this attempt
            client_attempts[action_type].append(current_time)
            return True

rate_limiter = RateLimiter()

# --- Configuration Management ---
def load_configuration():
    """Load configuration from CONFIGURATION file"""
    config = {
        'smart_anonymity_enabled': True  # Default value
    }
    
    try:
        if os.path.exists(CONFIGURATION_FILE):
            with open(CONFIGURATION_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line == 'smart_anonymity: false':
                        config['smart_anonymity_enabled'] = False
                        break
    except Exception as e:
        logging.warning(f"Could not read configuration file: {e}")
    
    return config

# Load configuration at startup
APP_CONFIG = load_configuration()

# --- Secure Password Hashing ---
def get_password_hash(password):
    """Generate secure password hash using PBKDF2"""
    salt = secrets.token_bytes(32)
    key = PBKDF2(password, salt, 32, count=100000, hmac_hash_module=SHA256)
    return salt.hex() + ':' + key.hex()

def verify_password_hash(password, hash_string):
    """Verify password against stored hash"""
    try:
        salt_hex, key_hex = hash_string.split(':')
        salt = bytes.fromhex(salt_hex)
        stored_key = bytes.fromhex(key_hex)
        new_key = PBKDF2(password, salt, 32, count=100000, hmac_hash_module=SHA256)
        return hmac.compare_digest(stored_key, new_key)
    except Exception:
        return False

# --- Database Functions ---
def init_reports_database():
    """Initialize reports database with proper security"""
    if os.path.exists(REPORTS_DB_FILE):
        try:
            os.remove(REPORTS_DB_FILE)
        except OSError:
            pass
    
    conn = sqlite3.connect(REPORTS_DB_FILE)
    cursor = conn.cursor()
    
    # Enable WAL mode for better concurrency
    cursor.execute('PRAGMA journal_mode=WAL')
    cursor.execute('PRAGMA synchronous=FULL')
    cursor.execute('PRAGMA foreign_keys=ON')
    
    cursor.execute('''
        CREATE TABLE reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            file_id TEXT NOT NULL,
            session_hash TEXT,
            created_at REAL NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()
    
    # Set secure file permissions
    os.chmod(REPORTS_DB_FILE, 0o600)

def store_report(category, description, file_id, session_hash=None):
    """Store a report in the database with proper sanitization"""
    try:
        # Sanitize inputs
        category = sanitize_user_input(category, 100)
        description = sanitize_user_input(description, 10000)
        file_id = sanitize_user_input(file_id, 50)
        
        if category not in REPORT_CATEGORIES:
            return False
        
        conn = sqlite3.connect(REPORTS_DB_FILE, timeout=10.0)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO reports (timestamp, category, description, file_id, session_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now(timezone.utc).isoformat(),
            category,
            description,
            file_id,
            session_hash,
            time.time()
        ))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logging.error(f"Error storing report: {e}")
        return False

# --- OCR and NSFW Model Initialization ---
try:
    EASYOCR_READER = easyocr.Reader(['en'], gpu=False)
except Exception as e:
    EASYOCR_READER = None
    logging.warning(f"Could not initialize EasyOCR: {e}")

# Initialize NSFW Detection Model
NSFW_MODEL = None
NSFW_TRANSFORMS = None
try:
    test_model = timm.create_model("hf_hub:Marqo/nsfw-image-detection-384", pretrained=True)
    test_model = None
    
    NSFW_MODEL = timm.create_model("hf_hub:Marqo/nsfw-image-detection-384", pretrained=True)
    NSFW_MODEL = NSFW_MODEL.eval()
    
    data_config = timm.data.resolve_model_data_config(NSFW_MODEL)
    NSFW_TRANSFORMS = timm.data.create_transform(**data_config, is_training=False)
    
    logging.info("NSFW detection model loaded successfully")
except Exception as e:
    logging.warning(f"Could not initialize NSFW detection model: {e}")
    NSFW_MODEL = None
    NSFW_TRANSFORMS = None

# --- Disable logging for privacy ---
logging.getLogger('werkzeug').setLevel(logging.ERROR)
app.logger.setLevel(logging.ERROR)

# --- In-memory Volatile State ---
file_db = {}
db_lock = threading.Lock()
last_upload_time = time.time()
view_tracking = {}
view_tracking_lock = threading.Lock()

# --- Secure Random Generation ---
def generate_random_filename(extension):
    """Generate cryptographically secure random filename"""
    return secrets.token_urlsafe(32) + extension.lower()

def generate_file_id():
    """Generate cryptographically secure file ID"""
    return secrets.token_urlsafe(16)

# --- Optimized Processing Functions with Numba ---
@jit(nopython=True)
def optimized_color_quantization(pixels, k=256):
    """Fast color quantization using optimized k-means alternative"""
    quantized = pixels.copy()
    step = np.uint8(256 // k)
    if step > 1:
        quantized = (quantized // step) * step
    return quantized

@jit(nopython=True)  
def add_selective_noise_jit(img_array, variance_threshold=50, seed=42):
    """Add noise only to high-variance areas using Numba optimization"""
    np.random.seed(seed)
    height, width, channels = img_array.shape
    result = img_array.copy()
    
    for y in range(1, height-1):
        for x in range(1, width-1):
            center = img_array[y, x]
            neighbors = [
                img_array[y-1, x], img_array[y+1, x],
                img_array[y, x-1], img_array[y, x+1]
            ]
            
            variance = 0
            for neighbor in neighbors:
                for c in range(channels):
                    variance += abs(int(center[c]) - int(neighbor[c]))
            
            if variance > variance_threshold:
                for c in range(channels):
                    noise = np.random.randint(-5, 6)
                    new_val = int(result[y, x, c]) + noise
                    result[y, x, c] = max(0, min(255, new_val))
    
    return result

# --- EXIF Data Stripping ---
def strip_exif_data(image_path):
    """Strip all EXIF data from an image file"""
    try:
        with Image.open(image_path) as img:
            if img.mode not in ('RGB', 'L'):
                if img.mode == 'RGBA':
                    background = Image.new('RGB', img.size, (255, 255, 255))
                    background.paste(img, mask=img.split()[-1] if 'A' in img.mode else None)
                    img = background
                else:
                    img = img.convert('RGB')
            
            data = list(img.getdata())
            image_without_exif = Image.new(img.mode, img.size)
            image_without_exif.putdata(data)
            
            image_without_exif.save(image_path, quality=95, optimize=True)
            
        return True
    except Exception as e:
        logging.warning(f"Could not strip EXIF data from {image_path}: {e}")
        return False

# --- NSFW Detection Functions ---
def advanced_nsfw_detector(img_array):
    """High-accuracy NSFW detection using Marqo model"""
    if NSFW_MODEL is None or NSFW_TRANSFORMS is None:
        return simple_nsfw_detector_fallback(img_array)
    
    try:
        img_rgb = cv2.cvtColor(img_array, cv2.COLOR_BGR2RGB)
        pil_img = Image.fromarray(img_rgb)
        
        transformed_img = NSFW_TRANSFORMS(pil_img).unsqueeze(0)
        
        with torch.no_grad():
            raw_output = NSFW_MODEL(transformed_img)
            probabilities = raw_output.softmax(dim=-1).cpu()
            nsfw_probability = float(probabilities[0][0])
            
            del transformed_img, raw_output, probabilities
            torch.cuda.empty_cache() if torch.cuda.is_available() else None
            
            return nsfw_probability
            
    except Exception:
        return simple_nsfw_detector_fallback(img_array)

def simple_nsfw_detector_fallback(img_array):
    """Lightweight NSFW detection fallback"""
    try:
        hsv = cv2.cvtColor(img_array, cv2.COLOR_BGR2HSV)
        
        skin_lower1 = np.array([0, 20, 70])
        skin_upper1 = np.array([20, 255, 255])
        skin_lower2 = np.array([160, 20, 70])
        skin_upper2 = np.array([180, 255, 255])
        
        skin_mask1 = cv2.inRange(hsv, skin_lower1, skin_upper1)
        skin_mask2 = cv2.inRange(hsv, skin_lower2, skin_upper2)
        skin_mask = cv2.bitwise_or(skin_mask1, skin_mask2)
        
        skin_pixels = cv2.countNonZero(skin_mask)
        total_pixels = img_array.shape[0] * img_array.shape[1]
        skin_ratio = skin_pixels / total_pixels
        
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY)
        blurred = cv2.GaussianBlur(gray, (15, 15), 0)
        smooth_regions = cv2.absdiff(gray, blurred)
        smooth_ratio = np.count_nonzero(smooth_regions < 10) / total_pixels
        
        nsfw_score = (skin_ratio * 0.4) + (smooth_ratio * 0.2)
        
        return min(1.0, nsfw_score)
        
    except Exception:
        return 0.0

# --- Utility Functions ---
def secure_delete(path):
    """Securely delete file using Gutmann method"""
    try:
        if not os.path.exists(path):
            return
        
        file_size = os.path.getsize(path)
        with open(path, "wb") as f:
            for pattern in GUTMANN_PASSES:
                f.seek(0)
                f.write(pattern[0] * file_size)
            f.seek(0)
            f.write(secrets.token_bytes(file_size))
        
        os.remove(path)
    except Exception:
        if os.path.exists(path):
            os.remove(path)

def schedule_cleanup():
    """Background cleanup thread"""
    while True:
        with db_lock:
            now = datetime.now(timezone.utc)
            expired_ids = [fid for fid, meta in file_db.items() 
                          if meta['delete_at'] <= now]
            for fid in expired_ids:
                meta = file_db.get(fid)
                if meta and meta.get('path') and os.path.exists(meta['path']):
                    secure_delete(meta['path'])
                    file_db.pop(fid, None)
        
        with view_tracking_lock:
            current_time = time.time()
            for file_id in list(view_tracking.keys()):
                if file_id not in file_db:
                    view_tracking.pop(file_id, None)
                else:
                    file_views = view_tracking[file_id]
                    old_ips = [ip_hash for ip_hash, last_time in file_views.items() 
                              if current_time - last_time > 3600]
                    for ip_hash in old_ips:
                        file_views.pop(ip_hash, None)
        
        gc.collect()
        time.sleep(60)

def manage_storage():
    """Manage storage limits"""
    max_storage_bytes = MAX_STORAGE_GB * 1024 * 1024 * 1024
    with db_lock:
        current_files = {fid: meta for fid, meta in file_db.items() 
                        if os.path.exists(meta.get('path', ''))}
        total_size = sum(os.path.getsize(meta['path']) for meta in current_files.values())
        
        if total_size > max_storage_bytes:
            sorted_files = sorted(current_files.items(), 
                                key=lambda item: item[1]['delete_at'])
            while total_size > max_storage_bytes and sorted_files:
                fid, meta_to_delete = sorted_files.pop(0)
                if os.path.exists(meta_to_delete['path']):
                    file_size = os.path.getsize(meta_to_delete['path'])
                    secure_delete(meta_to_delete['path'])
                    total_size -= file_size
                    file_db.pop(fid, None)

def mask_password(password):
    """Mask password for display"""
    if len(password) <= 3:
        return '*' * len(password)
    return f"{password[0]}{'*' * (len(password) - 3)}{password[-2:]}"

# --- View Tracking Functions ---
def hash_session_info(request):
    """Create secure hash of session information"""
    factors = [
        request.environ.get('REMOTE_ADDR', ''),
        request.headers.get('User-Agent', ''),
        str(session.get('csrf_token', ''))
    ]
    return hashlib.sha256('|'.join(factors).encode()).hexdigest()[:16]

def should_count_view(file_id, request, cookie_value):
    """Determine if view should be counted based on session factors"""
    current_time = time.time()
    session_hash = hash_session_info(request)
    
    with view_tracking_lock:
        if file_id not in view_tracking:
            view_tracking[file_id] = {}
        
        file_views = view_tracking[file_id]
        
        if session_hash in file_views:
            last_view_time = file_views[session_hash]
            if current_time - last_view_time < 45:
                return False, cookie_value
        
        expected_cookie = f"{file_id}_{session_hash}"
        if cookie_value == expected_cookie:
            if session_hash in file_views and current_time - file_views[session_hash] < 45:
                return False, cookie_value
        
        file_views[session_hash] = current_time
        return True, expected_cookie

# --- Image and Video Processing ---
def radical_image_compression(input_path, output_path, smart_anonymity_enabled=False):
    """Secure image compression with anonymization"""
    try:
        strip_exif_data(input_path)
        
        img = cv2.imread(input_path)
        if img is None:
            raise ValueError("Could not read image")

        h, w, _ = img.shape
        max_dim = 1080
        if h > max_dim or w > max_dim:
            if h > w:
                new_h, new_w = max_dim, int(w * max_dim / h)
            else:
                new_w, new_h = max_dim, int(h * max_dim / w)
            img = cv2.resize(img, (new_w, new_h), interpolation=cv2.INTER_AREA)

        nsfw_score = advanced_nsfw_detector(img)
        is_nsfw = nsfw_score > 0.5

        img_flat = img.reshape((-1, 3)).astype(np.uint8)
        quantized_flat = optimized_color_quantization(img_flat, k=256)
        img = quantized_flat.reshape(img.shape)

        if smart_anonymity_enabled and APP_CONFIG['smart_anonymity_enabled']:
            # Face blurring
            if os.path.exists('haarcascade_frontalface_default.xml'):
                face_cascade = cv2.CascadeClassifier('haarcascade_frontalface_default.xml')
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                faces = face_cascade.detectMultiScale(gray, 1.1, 4)
                for (x, y, w, h) in faces:
                    if w > 0 and h > 0:
                        roi = img[y:y+h, x:x+w]
                        kernel_size = max(w, h)
                        if kernel_size % 2 == 0:
                            kernel_size += 1
                        roi = cv2.GaussianBlur(roi, (kernel_size, kernel_size), 0)
                        img[y:y+roi.shape[0], x:x+roi.shape[1]] = roi

            # Text blurring
            if EASYOCR_READER:
                try:
                    ocr_data = EASYOCR_READER.readtext(img)
                    for (bbox, text, prob) in ocr_data:
                        (tl, tr, br, bl) = bbox
                        x, y, w, h = int(tl[0]), int(tl[1]), int(br[0] - tl[0]), int(br[1] - tl[1])
                        if (w > 0 and h > 0 and x >= 0 and y >= 0 and 
                            (x+w) <= img.shape[1] and (y+h) <= img.shape[0]):
                            roi = img[y:y+h, x:x+w]
                            kernel_size = max(w, h)
                            if kernel_size % 2 == 0:
                                kernel_size += 1
                            roi = cv2.GaussianBlur(roi, (kernel_size, kernel_size), 0)
                            img[y:y+h, x:x+w] = roi
                except Exception:
                    pass

            # Enhanced background blurring
            try:
                pil_img = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
                foreground = remove(pil_img, alpha_matting=True, 
                                  alpha_matting_foreground_threshold=50, 
                                  alpha_matting_background_threshold=50)
                fg_cv2 = cv2.cvtColor(np.array(foreground), cv2.COLOR_RGBA_BGRA)
                mask = fg_cv2[:, :, 3]
                
                blurred_bg = cv2.GaussianBlur(img, (101, 101), 0)
                blurred_bg = cv2.GaussianBlur(blurred_bg, (101, 101), 0)
                
                mask_inv = cv2.bitwise_not(mask)
                fg = cv2.bitwise_and(img, img, mask=mask)
                bg = cv2.bitwise_and(blurred_bg, blurred_bg, mask=mask_inv)
                img = cv2.add(bg, fg)
            except Exception:
                pass

        # Standard anonymity features
        h, w, _ = img.shape
        if h > 10 and w > 10:
            crop_h = int(h * random.uniform(0.97, 1.0))
            crop_w = int(w * random.uniform(0.97, 1.0))
            x_start = random.randint(0, w - crop_w)
            y_start = random.randint(0, h - crop_h)
            img = img[y_start:y_start+crop_h, x_start:x_start+crop_w]

        noise_seed = int(time.time()) % 2**31
        img = add_selective_noise_jit(img, seed=noise_seed)

        cv2.imwrite(output_path, img, [cv2.IMWRITE_JPEG_QUALITY, random.randint(15, 40)])

        del img
        gc.collect()
        
        return is_nsfw

    except Exception as e:
        logging.error(f"Error during image processing: {e}")
        shutil.copy(input_path, output_path)
        strip_exif_data(output_path)
        return False

def radical_video_compression(input_path, output_path):
    """Secure video compression using subprocess"""
    try:
        # Use subprocess.run for security instead of os.system
        cmd = [
            'ffmpeg', '-i', input_path, '-y',
            '-vf', 'scale=iw/2.5:ih/2.5',
            '-crf', '40',
            '-preset', 'veryfast',
            '-an',
            output_path
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=300,  # 5 minute timeout
            check=False
        )
        
        if result.returncode != 0:
            # FFmpeg failed, fall back to copy
            shutil.copy(input_path, output_path)
            
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        # Fallback to simple copy if ffmpeg fails
        shutil.copy(input_path, output_path)

# --- HTML Templates (inline for no external dependencies) ---
LEGAL_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Legal Notice &amp; Terms of Service</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
            background-color: #121212; 
            color: #e0e0e0; 
            line-height: 1.6; 
            margin: 0; 
            padding: 0;
        }
        .container { 
            background-color: #1e1e1e; 
            padding: 2rem; 
            border-radius: 8px; 
            max-width: 800px; 
            margin: 2rem auto; 
        }
        h1, h2 { 
            color: #cf6679; 
            border-bottom: 1px solid #444; 
            padding-bottom: 0.5rem; 
        }
        p, li { color: #ccc; }
        strong { color: #fff; }
        .warning { 
            background-color: #b00020; 
            padding: 1rem; 
            border-radius: 4px; 
            text-align: center; 
            font-weight: bold; 
            margin-bottom: 2rem; 
        }
        a { color: #bb86fc; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="warning">THIS IS A BINDING LEGAL AGREEMENT. READ CAREFULLY.</div>
        <h1>Terms of Service &amp; Legal Notice</h1>
        <p><strong>Effective Date:</strong> January 1, 2024</p>

        <h2>1. Jurisdiction and Governing Law</h2>
        <p>This service is offered exclusively within the sovereign jurisdiction of <strong>{{ JURISDICTION }}</strong>. By accessing or using this service, you irrevocably agree that any and all disputes, claims, or controversies arising out of or relating to your use of this service shall be governed by and construed in accordance with the laws of {{ JURISDICTION }}, without regard to its conflict of law provisions.</p>

        <h2>2. Nature of the Service &amp; Disclaimer of Responsibility</h2>
        <p>This is an automated, ephemeral, and privacy-preserving data transformation service. We, the operators, have <strong>NO ABILITY</strong> to view, access, recover, or provide any information about the data processed. All files are subjected to irreversible, destructive transformations and are permanently deleted after a short, predefined period.</p>

        <h2>3. Absolute Waiver of Rights</h2>
        <p>By uploading a file, you knowingly and voluntarily <strong>WAIVE ALL RIGHTS</strong> to make any claim against the service, its operators, owners, affiliates, or hosts for any reason whatsoever.</p>
        
        <h2>4. NO WARRANTY</h2>
        <p>The service is provided <strong>WITHOUT ANY WARRANTY OF ANY KIND, EXPRESS OR IMPLIED</strong>.</p>
        
        <h2>5. Extreme Limitation of Liability</h2>
        <p>In the unlikely event that any part of this agreement is found to be unenforceable by a competent court in {{ JURISDICTION }}, you agree that the total aggregate liability of the service, its operators, and affiliates, for any and all claims, shall be strictly limited to a symbolic sum of <strong>TEN UNITED STATES DOLLARS ($10.00 USD)</strong>.</p>

        <h2>6. Agreement</h2>
        <p>Your use of the upload functionality constitutes your full and unconditional agreement to these terms. If you do not agree to these terms, do not use the service.</p>
        <p><a href="/">Return to Upload Page</a></p>
    </div>
</body>
</html>
"""

UPLOAD_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privacy Uploader</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
            background-color: #121212; 
            color: #e0e0e0; 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            min-height: 100vh; 
            margin: 0; 
        }
        .container { 
            background-color: #1e1e1e; 
            padding: 2rem; 
            border-radius: 8px; 
            box-shadow: 0 4px 15px rgba(0,0,0,0.5); 
            width: 90%; 
            max-width: 600px; 
        }
        h1 { text-align: center; color: #bb86fc; }
        .jurisdiction-note { 
            text-align: center; 
            color: #888; 
            font-size: 0.9rem; 
            margin-top: -1rem; 
            margin-bottom: 1rem; 
        }
        .terms-note { 
            text-align: center; 
            font-size: 0.8rem; 
            color: #aaa; 
            margin-top: 1.5rem; 
        }
        .terms-note a { color: #bb86fc; text-decoration: none; }
        .terms-note a:hover { text-decoration: underline; }
        .form-group { margin-bottom: 1.5rem; }
        label { 
            display: block; 
            margin-bottom: 0.5rem; 
            font-weight: bold; 
        }
        input[type="file"], input[type="password"], input[type="text"], input[type="number"] { 
            width: calc(100% - 22px); 
            padding: 10px; 
            background-color: #333; 
            border: 1px solid #444; 
            border-radius: 4px; 
            color: #e0e0e0; 
        }
        .btn { 
            background-color: #6200ee; 
            color: white; 
            padding: 12px 20px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer; 
            font-size: 1rem; 
            width: 100%; 
        }
        .btn:hover { background-color: #7c4dff; }
        .info { 
            font-size: 0.8rem; 
            color: #888; 
            margin-top: 5px; 
        }
        .error { 
            color: #cf6679; 
            text-align: center; 
            margin-bottom: 1rem; 
            background-color: #3e1e1e;
            padding: 1rem;
            border-radius: 4px;
        }
        .delete-box { 
            position: fixed; 
            bottom: 20px; 
            right: 20px; 
            background-color: #1e1e1e; 
            padding: 1rem; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.5); 
            z-index: 10; 
        }
        .checkbox-group { margin: 1rem 0; }
        .checkbox-group label { 
            display: flex; 
            align-items: center; 
            margin-bottom: 0.5rem; 
            cursor: pointer; 
            font-weight: normal;
        }
        .checkbox-group input[type="checkbox"] { 
            margin-right: 10px; 
            width: auto;
        }
        .speed-warning { 
            background-color: #b00020; 
            color: #fff; 
            padding: 1rem; 
            border-radius: 4px; 
            text-align: center; 
            font-weight: bold; 
            margin-bottom: 1rem; 
        }
        .local-warning { 
            background-color: #555; 
            color: #ccc; 
            padding: 1rem; 
            border-radius: 4px; 
            text-align: center; 
            margin-bottom: 1rem; 
        }
        #captcha-container img { 
            border-radius: 4px; 
            margin-top: 10px; 
            cursor: pointer;
        }
        .tooltip { 
            position: relative; 
            display: inline-block; 
            cursor: help; 
            color: #bb86fc;
            margin-left: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        {% if show_speed_warning %}
        <div class="speed-warning">
            ⚠️ WARNING: The infrastructure of this website is very fast. This may be a sign that this is hosted by a malicious entity.
        </div>
        {% endif %}
        
        {% if show_local_warning %}
        <div class="local-warning">
            This is a testing application. http://{{ server_info }}
        </div>
        {% endif %}
        
        <h1>Anonymous File Uploader</h1>
        <p class="jurisdiction-note">Note: This service is only for use within the jurisdiction of <strong>{{ JURISDICTION }}</strong>.</p>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <form action="/" method="post" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            
            <div class="form-group">
                <label for="files">Select files</label>
                <input type="file" name="files" id="files" multiple required accept=".jpg,.jpeg,.png,.webp,.mp4,.mov,.avi,.webm">
                <p class="info">Max {{ max_files }} files or 100s of video. Each file &lt; {{ max_file_size_mb }}MB. Total size &lt; 300MB.</p>
            </div>
            
            <div class="form-group">
                <label for="password">Deletion Password (8-16 chars)</label>
                <input type="password" name="password" id="password" minlength="8" maxlength="16" required>
            </div>
            
            <div class="form-group">
                <label for="max_views">Delete after views:</label>
                <input type="number" name="max_views" id="max_views" min="5" max="150" value="30" style="width: 80px;">
            </div>
            
            <div class="checkbox-group">
                <label>
                    <input type="checkbox" name="ignore_duplicate_views" id="ignore_duplicate_views">
                    Ignore views by the same person
                    <span class="tooltip">ℹ</span>
                </label>
            </div>
            
            {% if smart_anonymity_enabled %}
            <div class="checkbox-group">
                <label>
                    <input type="checkbox" name="smart_anonymity" id="smart_anonymity">
                    Smart Anonymity?
                    <span class="tooltip">ℹ</span>
                </label>
            </div>
            {% endif %}
            
            <div class="checkbox-group">
                <label>
                    <input type="checkbox" name="aes_encrypt" id="aes_encrypt">
                    AES-256 Encrypt?
                    <span class="tooltip">ℹ</span>
                </label>
            </div>
            
            <div class="form-group" id="aes_password_group" style="display: none;">
                <label for="aes_password">AES Encryption Password</label>
                <input type="password" name="aes_password" id="aes_password">
            </div>
            
            <div class="form-group" id="captcha-container">
                <label for="captcha">Enter Captcha Text</label>
                <img id="captcha-img" src="{{ url_for('captcha_image') }}" alt="captcha" onclick="this.src='{{ url_for('captcha_image') }}?' + new Date().getTime()">
                <input type="text" name="captcha" id="captcha" required autocomplete="off">
                <p class="info">Click image to refresh</p>
            </div>
            
            <button type="submit" class="btn">Upload Securely</button>
            <p class="terms-note">By clicking "Upload Securely", you agree to our <a href="/legal" target="_blank">Terms of Service</a>.</p>
        </form>
    </div>
    
    <div class="delete-box">
        <form action="/delete" method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <label for="delete_password">Enter Password to Delete</label>
            <input type="password" name="delete_password" id="delete_password" required>
            <button type="submit" class="btn" style="margin-top:5px;width:100%;">Delete</button>
            {% if deletion_feedback %}
            <p style="font-size:0.8rem;color:#bb86fc;margin-top:5px;">{{ deletion_feedback }}</p>
            {% endif %}
        </form>
    </div>
</body>
</html>
"""

NSFW_VIEW_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Content Warning</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
            background-color: #121212; 
            color: #e0e0e0; 
            padding: 2rem; 
            text-align: center; 
        }
        .container { 
            background-color: #1e1e1e; 
            padding: 2rem; 
            border-radius: 8px; 
            max-width: 600px; 
            margin: auto; 
        }
        .warning { 
            background-color: #b00020; 
            padding: 1rem; 
            border-radius: 4px; 
            font-weight: bold; 
            margin-bottom: 2rem; 
        }
        .image-container { 
            position: relative; 
            display: inline-block; 
            margin: 2rem 0; 
        }
        .blurred-image { 
            filter: blur(20px); 
            transition: filter 0.3s ease; 
            max-width: 100%; 
            border-radius: 8px; 
        }
        .image-container:hover .blurred-image { filter: blur(0px); }
        .hover-instruction { 
            position: absolute; 
            top: 50%; 
            left: 50%; 
            transform: translate(-50%, -50%); 
            background-color: rgba(0,0,0,0.8); 
            color: white; 
            padding: 1rem; 
            border-radius: 4px; 
            font-weight: bold; 
            pointer-events: none; 
        }
        .image-container:hover .hover-instruction { display: none; }
        .report-btn { 
            background-color: #cf6679; 
            color: white; 
            padding: 10px 20px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer; 
            margin: 1rem; 
            text-decoration: none;
            display: inline-block;
        }
        .report-btn:hover { background-color: #e57373; }
        .back-link { 
            color: #bb86fc; 
            text-decoration: none;
        }
        .back-link:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="warning">⚠️ CONTENT WARNING ⚠️<br>This content may contain adult material</div>
        
        <div class="image-container">
            <img src="data:{{ mimetype }};base64,{{ image_data }}" alt="Content" class="blurred-image">
            <div class="hover-instruction">HOVER TO DISPLAY</div>
        </div>
        
        <div>
            <a href="/report/{{ file_id }}" class="report-btn">Report Content</a>
        </div>
        
        <p><a href="/" class="back-link">← Back to Upload</a></p>
    </div>
</body>
</html>
"""

RESULT_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload Successful</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
            background-color: #121212; 
            color: #e0e0e0; 
            padding: 2rem; 
        }
        .container { 
            background-color: #1e1e1e; 
            padding: 2rem; 
            border-radius: 8px; 
            max-width: 800px; 
            margin: auto; 
        }
        h1 { color: #03dac6; text-align: center; }
        .file-card { 
            background-color: #2c2c2c; 
            border: 1px solid #444; 
            border-radius: 8px; 
            margin-bottom: 2rem; 
            padding: 1.5rem; 
        }
        h2 { 
            margin-top: 0; 
            color: #bb86fc; 
            word-wrap: break-word;
        }
        .file-card img, .file-card video { 
            max-width: 100%; 
            border-radius: 4px; 
            margin-top: 1rem; 
        }
        .file-card video {
            background-color: #000;
        }
        .details { 
            list-style-type: none; 
            padding: 0; 
        }
        .details li { 
            margin-bottom: 0.5rem; 
            word-wrap: break-word; 
        }
        .details strong { color: #03dac6; }
        a { 
            color: #bb86fc; 
            text-decoration: none;
        }
        a:hover { text-decoration: underline; }
        .delete-btn { 
            background-color: #cf6679; 
            color: white; 
            text-decoration: none; 
            padding: 10px 15px; 
            border-radius: 4px; 
            display: inline-block; 
            margin-top: 1rem; 
        }
        .delete-btn:hover { 
            background-color: #e57373; 
            text-decoration: none;
        }
        .password-warning { 
            background-color: #b00020; 
            padding: 1rem; 
            border-radius: 4px; 
            text-align: center; 
            font-weight: bold; 
        }
        .nsfw-warning { 
            background-color: #ff6f00; 
            color: #000; 
            padding: 1rem; 
            border-radius: 4px; 
            text-align: center; 
            font-weight: bold; 
            margin-bottom: 1rem; 
        }
        .center-link {
            text-align: center;
            margin-top: 2rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Upload Complete</h1>
        <div class="password-warning">
            <p>CRITICAL: You must save the password you entered. It will NOT be shown again.</p>
            <p>For confirmation, your password looks like this: <strong style="color: #fff; font-family: monospace;">{{ masked_password }}</strong></p>
        </div>
        
        {% for file in files %}
        <div class="file-card">
            <h2>{{ file.original_name }}</h2>
            {% if file.is_nsfw %}
            <div class="nsfw-warning">⚠️ This content has been flagged as potentially adult material</div>
            {% endif %}
            
            {% if file.is_video %}
            <video controls preload="none">
                <source src="{{ url_for('view_file', file_id=file.id) }}" type="video/mp4">
                Your browser does not support the video tag.
            </video>
            {% else %}
            <img src="{{ url_for('view_file', file_id=file.id) }}" alt="Processed and Compressed Image">
            {% endif %}
            
            <ul class="details">
                <li><strong>File URL:</strong> <a href="{{ url_for('view_file', file_id=file.id, _external=True) }}" target="_blank">{{ url_for('view_file', file_id=file.id, _external=True) }}</a></li>
                <li><strong>Compressed Size:</strong> {{ "%.2f"|format(file.size_mb) }} MB</li>
                <li><strong>Deletes At (UTC):</strong> {{ file.delete_at.strftime('%Y-%m-%d %H:%M:%S') }}</li>
                <li><strong>Views Remaining:</strong> {{ file.views_left }} / {{ file.max_views }}</li>
                {% if file.ignore_duplicate_views %}
                <li><strong>Duplicate View Protection:</strong> Enabled</li>
                {% endif %}
                {% if file.is_encrypted %}
                <li><strong style="color: #cf6679;">AES-256 Password:</strong> {{ file.aes_password }} (Save this too!)</li>
                {% endif %}
            </ul>
            <a href="{{ url_for('delete_file_get', file_id=file.id) }}" class="delete-btn">Delete Now</a>
        </div>
        {% endfor %}
        
        <div class="center-link">
            <a href="/">Upload more files</a>
        </div>
    </div>
</body>
</html>
"""

REPORT_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Report Content</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
            background-color: #121212; 
            color: #e0e0e0; 
            padding: 2rem; 
        }
        .container { 
            background-color: #1e1e1e; 
            padding: 2rem; 
            border-radius: 8px; 
            max-width: 600px; 
            margin: auto; 
        }
        h1 { color: #cf6679; text-align: center; }
        .form-group { margin-bottom: 1.5rem; }
        label { 
            display: block; 
            margin-bottom: 0.5rem; 
            font-weight: bold; 
        }
        select, textarea, input[type="text"] { 
            width: calc(100% - 22px); 
            padding: 10px; 
            background-color: #333; 
            border: 1px solid #444; 
            border-radius: 4px; 
            color: #e0e0e0; 
            font-family: inherit;
        }
        textarea { 
            resize: vertical; 
            min-height: 100px; 
        }
        .btn { 
            background-color: #6200ee; 
            color: white; 
            padding: 12px 20px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer; 
            font-size: 1rem; 
            margin-right: 10px;
        }
        .btn:hover { background-color: #7c4dff; }
        .btn-secondary { 
            background-color: #444; 
            color: white; 
        }
        .btn-secondary:hover { background-color: #555; }
        .error { 
            color: #cf6679; 
            text-align: center; 
            margin-bottom: 1rem; 
            background-color: #3e1e1e;
            padding: 1rem;
            border-radius: 4px;
        }
        .success { 
            color: #03dac6; 
            text-align: center; 
            margin-bottom: 1rem; 
            background-color: #1e3e3e;
            padding: 1rem;
            border-radius: 4px;
        }
        .char-counter { 
            font-size: 0.8rem; 
            color: #888; 
            margin-top: 5px; 
        }
        .checkbox-group { margin: 1rem 0; }
        .checkbox-group label { 
            display: flex; 
            align-items: center; 
            margin-bottom: 0.5rem; 
            cursor: pointer; 
            font-weight: normal;
        }
        .checkbox-group input[type="checkbox"] { 
            margin-right: 10px; 
            width: auto;
        }
        #captcha-container img { 
            border-radius: 4px; 
            margin: 10px 0; 
            cursor: pointer;
        }
        .back-link { 
            color: #bb86fc; 
            text-decoration: none;
            display: block;
            text-align: center;
            margin-top: 2rem;
        }
        .back-link:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Report Illegal Content ({{ JURISDICTION }})</h1>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        {% if success %}
        <div class="success">{{ success }}</div>
        {% else %}
        <form action="/report/{{ file_id }}" method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            
            <div class="form-group">
                <label for="category">Select the category that best describes the illegal content:</label>
                <select name="category" id="category" required>
                    <option value="">-- Select Category --</option>
                    {% for cat in categories %}
                    <option value="{{ cat }}">{{ cat }}</option>
                    {% endfor %}
                </select>
            </div>
            
            <div class="form-group">
                <label for="description">Describe the issue more specifically:</label>
                <textarea name="description" id="description" placeholder="Describe the issue more specifically" maxlength="10000" required></textarea>
                <div class="char-counter">0 / 10000 characters</div>
            </div>
            
            <div class="checkbox-group">
                <label>
                    <input type="checkbox" name="consent1" required>
                    This content <strong>is illegal</strong> in {{ JURISDICTION }}
                </label>
                <label>
                    <input type="checkbox" name="consent2" required>
                    I confirm that I am a legal resident of <strong>{{ JURISDICTION }}</strong> 🇻🇺
                </label>
                <label>
                    <input type="checkbox" name="consent3" required>
                    I understand that this report may be logged permanently
                </label>
            </div>
            
            <div class="form-group" id="captcha-container">
                <label for="captcha">Enter Captcha Text:</label>
                <img src="{{ url_for('report_captcha_image') }}" alt="captcha" onclick="this.src='{{ url_for('report_captcha_image') }}?' + new Date().getTime()">
                <input type="text" name="captcha" id="captcha" required autocomplete="off">
            </div>
            
            <button type="submit" class="btn">Consent &amp; Submit</button>
            <a href="/" class="btn btn-secondary">Cancel</a>
        </form>
        {% endif %}
        
        <a href="/" class="back-link">← Back to Upload</a>
    </div>
</body>
</html>
"""

DELETED_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Deleted</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #121212;
            color: #e0e0e0;
            text-align: center;
            padding: 2rem;
            margin: 0;
        }
        .container {
            background-color: #1e1e1e;
            padding: 2rem;
            border-radius: 8px;
            max-width: 400px;
            margin: 2rem auto;
        }
        h1 { color: #03dac6; }
        a { 
            color: #bb86fc; 
            text-decoration: none;
        }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{ message }}</h1>
        <a href="/">Go back</a>
    </div>
</body>
</html>
"""

# --- Connection Speed Detection ---
def detect_local_hosting():
    """Detect if the application is running locally"""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return (local_ip.startswith('127.') or 
                local_ip.startswith('192.168.') or 
                local_ip.startswith('10.') or 
                hostname == 'localhost')
    except Exception:
        return False

def get_server_info():
    """Get server information for local hosting detection"""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        port = request.environ.get('SERVER_PORT', '5000')
        return f"{local_ip}:{port}"
    except Exception:
        return "localhost:5000"

# --- Flask Routes ---
@app.route('/legal')
def legal_page():
    """Legal notice page"""
    return render_template_string(LEGAL_PAGE_TEMPLATE, JURISDICTION=JURISDICTION)

@app.route('/captcha-image')
def captcha_image():
    """Generate CAPTCHA image"""
    if not rate_limiter.is_allowed(request, 'captcha'):
        abort(429)
    
    image_captcha = ImageCaptcha()
    captcha_text = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
    session['captcha'] = captcha_text
    image_data = image_captcha.generate(captcha_text)
    
    response = make_response(image_data.getvalue())
    response.headers['Content-Type'] = 'image/png'
    return response

@app.route('/report-captcha')
def report_captcha_image():
    """Generate report CAPTCHA image"""
    if not rate_limiter.is_allowed(request, 'captcha'):
        abort(429)
    
    image_captcha = ImageCaptcha()
    captcha_text = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
    session['report_captcha'] = captcha_text
    image_data = image_captcha.generate(captcha_text)
    
    response = make_response(image_data.getvalue())
    response.headers['Content-Type'] = 'image/png'
    return response

@app.route('/report/<file_id>', methods=['GET', 'POST'])
def report_content(file_id):
    """Content reporting page and handler"""
    # Validate and sanitize file_id
    file_id = sanitize_user_input(file_id, 50)
    
    # Check if file exists
    with db_lock:
        if file_id not in file_db:
            abort(404)
    
    if request.method == 'GET':
        return render_template_string(
            REPORT_PAGE_TEMPLATE,
            file_id=file_id,
            categories=REPORT_CATEGORIES,
            csrf_token=generate_csrf_token(),
            JURISDICTION=JURISDICTION
        )
    
    # Handle POST request
    if not rate_limiter.is_allowed(request, 'report'):
        return render_template_string(
            REPORT_PAGE_TEMPLATE,
            file_id=file_id,
            categories=REPORT_CATEGORIES,
            csrf_token=generate_csrf_token(),
            JURISDICTION=JURISDICTION,
            error="Too many reports. Please wait before submitting another."
        )
    
    # Validate CSRF token
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)
    
    # Validate CAPTCHA
    if ('report_captcha' not in session or 
        request.form.get('captcha', '').upper() != session['report_captcha'].upper()):
        session.pop('report_captcha', None)
        return render_template_string(
            REPORT_PAGE_TEMPLATE,
            file_id=file_id,
            categories=REPORT_CATEGORIES,
            csrf_token=generate_csrf_token(),
            JURISDICTION=JURISDICTION,
            error="Invalid captcha."
        )
    
    session.pop('report_captcha', None)
    
    # Validate form inputs
    category = sanitize_user_input(request.form.get('category', ''), 100)
    description = sanitize_user_input(request.form.get('description', ''), 10000)
    
    # Validate required checkboxes
    required_checkboxes = ['consent1', 'consent2', 'consent3']
    for checkbox in required_checkboxes:
        if not request.form.get(checkbox):
            return render_template_string(
                REPORT_PAGE_TEMPLATE,
                file_id=file_id,
                categories=REPORT_CATEGORIES,
                csrf_token=generate_csrf_token(),
                JURISDICTION=JURISDICTION,
                error="All consent checkboxes must be checked."
            )
    
    # Validate category
    if category not in REPORT_CATEGORIES:
        return render_template_string(
            REPORT_PAGE_TEMPLATE,
            file_id=file_id,
            categories=REPORT_CATEGORIES,
            csrf_token=generate_csrf_token(),
            JURISDICTION=JURISDICTION,
            error="Invalid category."
        )
    
    # Validate description
    if category == 'OTHER' and len(description) < 3:
        return render_template_string(
            REPORT_PAGE_TEMPLATE,
            file_id=file_id,
            categories=REPORT_CATEGORIES,
            csrf_token=generate_csrf_token(),
            JURISDICTION=JURISDICTION,
            error="Description must be at least 3 characters for OTHER category."
        )
    
    if category != 'OTHER' and len(description) == 0:
        return render_template_string(
            REPORT_PAGE_TEMPLATE,
            file_id=file_id,
            categories=REPORT_CATEGORIES,
            csrf_token=generate_csrf_token(),
            JURISDICTION=JURISDICTION,
            error="Description is required."
        )
    
    # Store the report
    session_hash = hash_session_info(request)
    if store_report(category, description, file_id, session_hash):
        return render_template_string(
            REPORT_PAGE_TEMPLATE,
            file_id=file_id,
            categories=REPORT_CATEGORIES,
            csrf_token=generate_csrf_token(),
            JURISDICTION=JURISDICTION,
            success="Your report has been submitted successfully."
        )
    else:
        return render_template_string(
            REPORT_PAGE_TEMPLATE,
            file_id=file_id,
            categories=REPORT_CATEGORIES,
            csrf_token=generate_csrf_token(),
            JURISDICTION=JURISDICTION,
            error="Failed to store report. Please try again."
        )

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    """Main upload page and handler"""
    global last_upload_time
    
    if request.method == 'GET':
        is_local = detect_local_hosting()
        server_info = get_server_info() if is_local else None
        show_speed_warning = not is_local
        
        return render_template_string(
            UPLOAD_PAGE_TEMPLATE,
            JURISDICTION=JURISDICTION,
            smart_anonymity_enabled=APP_CONFIG['smart_anonymity_enabled'],
            show_speed_warning=show_speed_warning,
            show_local_warning=is_local,
            server_info=server_info,
            csrf_token=generate_csrf_token(),
            max_files=MAX_UPLOAD_FILES,
            max_file_size_mb=MAX_SINGLE_FILE_SIZE // (1024*1024)
        )
    
    # Handle POST request
    if not rate_limiter.is_allowed(request, 'upload'):
        return render_template_string(
            UPLOAD_PAGE_TEMPLATE,
            error="Upload rate limit exceeded. Please wait before uploading again.",
            JURISDICTION=JURISDICTION,
            smart_anonymity_enabled=APP_CONFIG['smart_anonymity_enabled'],
            show_speed_warning=False,
            show_local_warning=detect_local_hosting(),
            server_info=get_server_info() if detect_local_hosting() else None,
            csrf_token=generate_csrf_token(),
            max_files=MAX_UPLOAD_FILES,
            max_file_size_mb=MAX_SINGLE_FILE_SIZE // (1024*1024)
        )
    
    # Validate CSRF token
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)
    
    # Validate CAPTCHA
    if ('captcha' not in session or 
        request.form.get('captcha', '').upper() != session['captcha'].upper()):
        session.pop('captcha', None)
        return render_template_string(
            UPLOAD_PAGE_TEMPLATE,
            error="Incorrect captcha.",
            JURISDICTION=JURISDICTION,
            smart_anonymity_enabled=APP_CONFIG['smart_anonymity_enabled'],
            show_speed_warning=False,
            show_local_warning=detect_local_hosting(),
            server_info=get_server_info() if detect_local_hosting() else None,
            csrf_token=generate_csrf_token(),
            max_files=MAX_UPLOAD_FILES,
            max_file_size_mb=MAX_SINGLE_FILE_SIZE // (1024*1024)
        )
    
    session.pop('captcha', None)
    
    # Get and validate form data
    files = request.files.getlist('files')
    password = sanitize_user_input(request.form.get('password', ''), 16)
    aes_encrypt = 'aes_encrypt' in request.form
    smart_anonymity = ('smart_anonymity' in request.form and 
                      APP_CONFIG['smart_anonymity_enabled'])
    ignore_duplicate_views = 'ignore_duplicate_views' in request.form
    aes_password = sanitize_user_input(request.form.get('aes_password', ''), 256)
    max_views = int(request.form.get('max_views', 30))
    
    # Validate inputs
    error = None
    if not files or not files[0].filename:
        error = 'No files selected.'
    elif len(files) > MAX_UPLOAD_FILES:
        error = f'Maximum {MAX_UPLOAD_FILES} files allowed.'
    elif not (password and 8 <= len(password) <= 16):
        error = 'Deletion password must be 8-16 characters.'
    elif aes_encrypt and not aes_password:
        error = 'AES encryption requires its own password.'
    elif max_views < 5 or max_views > 150:
        error = 'Max views must be between 5 and 150.'
    
    # Validate file names and extensions
    if not error:
        for file in files:
            if file.filename:
                sanitized_name = sanitize_filename(file.filename)
                if not sanitized_name:
                    error = f'Invalid filename: {file.filename}'
                    break
                if not validate_file_extension(sanitized_name):
                    error = f'File type not allowed: {file.filename}'
                    break
    
    if error:
        return render_template_string(
            UPLOAD_PAGE_TEMPLATE,
            error=error,
            JURISDICTION=JURISDICTION,
            smart_anonymity_enabled=APP_CONFIG['smart_anonymity_enabled'],
            show_speed_warning=False,
            show_local_warning=detect_local_hosting(),
            server_info=get_server_info() if detect_local_hosting() else None,
            csrf_token=generate_csrf_token(),
            max_files=MAX_UPLOAD_FILES,
            max_file_size_mb=MAX_SINGLE_FILE_SIZE // (1024*1024)
        )
    
    last_upload_time = time.time()
    processed_files = []
    password_hash = get_password_hash(password)
    
    for file in files:
        if file and file.filename:
            # Validate file size
            file.seek(0, 2)  # Seek to end
            file_size = file.tell()
            file.seek(0)  # Reset to beginning
            
            if file_size > MAX_SINGLE_FILE_SIZE:
                error = f"File {file.filename} is too large (max {MAX_SINGLE_FILE_SIZE // (1024*1024)}MB)"
                break
            
            if file_size == 0:
                continue  # Skip empty files
            
            original_filename = sanitize_filename(file.filename)
            ext = os.path.splitext(original_filename)[1].lower()
            obfuscated_name = generate_random_filename(ext)
            
            # Ensure upload directory exists
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_' + obfuscated_name)
            final_path = os.path.join(app.config['UPLOAD_FOLDER'], obfuscated_name)
            
            try:
                file.save(temp_path)
                
                # Validate file content
                is_img = ext in ['.jpg', '.jpeg', '.png', '.webp']
                is_video = ext in ['.mp4', '.mov', '.avi', '.webm']
                
                if is_img and not validate_file_content(temp_path, 'image'):
                    secure_delete(temp_path)
                    error = f"Invalid image file: {original_filename}"
                    break
                elif is_video and not validate_file_content(temp_path, 'video'):
                    secure_delete(temp_path)
                    error = f"Invalid video file: {original_filename}"
                    break
                
                is_nsfw = False
                
                if aes_encrypt:
                    if file_size > 25 * 1024 * 1024:
                        error = "AES encrypted files cannot exceed 25MB."
                        secure_delete(temp_path)
                        break
                    
                    # Strip EXIF before encryption for images
                    if is_img:
                        strip_exif_data(temp_path)
                    
                    # Improved AES encryption
                    salt = secrets.token_bytes(32)
                    key = PBKDF2(aes_password, salt, 32, count=100000, hmac_hash_module=SHA256)
                    cipher = AES.new(key, AES.MODE_EAX)
                    
                    with open(temp_path, 'rb') as f_in:
                        plaintext = f_in.read()
                    
                    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
                    
                    with open(final_path, 'wb') as f_out:
                        f_out.write(salt)
                        f_out.write(cipher.nonce)
                        f_out.write(tag)
                        f_out.write(ciphertext)
                    
                    delete_hours = 1
                elif is_img:
                    is_nsfw = radical_image_compression(temp_path, final_path, 
                                                      smart_anonymity_enabled=smart_anonymity)
                    delete_hours = DELETION_TIME_HOURS
                elif is_video:
                    radical_video_compression(temp_path, final_path)
                    delete_hours = DELETION_TIME_HOURS
                else:
                    secure_delete(temp_path)
                    continue
                
                if os.path.exists(temp_path):
                    secure_delete(temp_path)
                
                # Generate file ID and store metadata
                file_id = generate_file_id()
                with db_lock:
                    file_db[file_id] = {
                        'path': final_path,
                        'password_hash': password_hash,
                        'delete_at': datetime.now(timezone.utc) + timedelta(hours=delete_hours),
                        'size_mb': os.path.getsize(final_path) / (1024*1024),
                        'original_name': original_filename,
                        'views': 0,
                        'max_views': max(5, min(150, max_views)),
                        'is_encrypted': aes_encrypt,
                        'is_video': is_video,
                        'aes_password': aes_password if aes_encrypt else None,
                        'uploaded_at': datetime.now(timezone.utc),
                        'is_nsfw': is_nsfw,
                        'ignore_duplicate_views': ignore_duplicate_views
                    }
                
                processed_files.append({
                    'id': file_id,
                    'original_name': original_filename,
                    'size_mb': file_db[file_id]['size_mb'],
                    'is_video': is_video,
                    'delete_at': file_db[file_id]['delete_at'],
                    'views_left': file_db[file_id]['max_views'],
                    'max_views': file_db[file_id]['max_views'],
                    'is_encrypted': aes_encrypt,
                    'aes_password': aes_password if aes_encrypt else None,
                    'is_nsfw': is_nsfw,
                    'ignore_duplicate_views': ignore_duplicate_views
                })
                
            except Exception as e:
                if os.path.exists(temp_path):
                    secure_delete(temp_path)
                if os.path.exists(final_path):
                    secure_delete(final_path)
                logging.error(f"Error processing file {original_filename}: {e}")
                error = "File processing error occurred."
                break
    
    if error:
        return render_template_string(
            UPLOAD_PAGE_TEMPLATE,
            error=error,
            JURISDICTION=JURISDICTION,
            smart_anonymity_enabled=APP_CONFIG['smart_anonymity_enabled'],
            show_speed_warning=False,
            show_local_warning=detect_local_hosting(),
            server_info=get_server_info() if detect_local_hosting() else None,
            csrf_token=generate_csrf_token(),
            max_files=MAX_UPLOAD_FILES,
            max_file_size_mb=MAX_SINGLE_FILE_SIZE // (1024*1024)
        )
    
    manage_storage()
    return render_template_string(
        RESULT_PAGE_TEMPLATE,
        files=processed_files,
        masked_password=mask_password(password)
    )

@app.route('/view/<file_id>')
def view_file(file_id):
    """View file endpoint"""
    # Sanitize file_id
    file_id = sanitize_user_input(file_id, 50)
    
    with db_lock:
        meta = file_db.get(file_id)
        if not meta or not os.path.exists(meta.get('path', '')):
            abort(404)
        
        # Check for immediate deletion conditions
        is_expired = meta['delete_at'] <= datetime.now(timezone.utc)
        is_max_views = meta['views'] >= meta['max_views']
        
        if is_expired or is_max_views:
            secure_delete(meta['path'])
            file_db.pop(file_id, None)
            abort(404)
        
        # Handle view counting
        should_count = True
        view_cookie_name = f"viewed_{file_id}"
        existing_cookie = request.cookies.get(view_cookie_name, '')
        
        if meta.get('ignore_duplicate_views', False):
            should_count, new_cookie_value = should_count_view(file_id, request, existing_cookie)
        else:
            new_cookie_value = f"{file_id}_{hash_session_info(request)}"
        
        if should_count:
            meta['views'] += 1
    
    if meta['is_encrypted']:
        return "This file is AES-256 encrypted. Download and decrypt it.", 403
    
    # Handle NSFW content
    if meta.get('is_nsfw', False) and not meta.get('is_video', False):
        import base64
        with open(meta['path'], 'rb') as f:
            image_data = base64.b64encode(f.read()).decode()
        mimetype, _ = mimetypes.guess_type(meta['path'])
        response = make_response(render_template_string(
            NSFW_VIEW_TEMPLATE,
            image_data=image_data,
            mimetype=mimetype or 'image/jpeg',
            file_id=file_id,
            JURISDICTION=JURISDICTION
        ))
    else:
        mimetype, _ = mimetypes.guess_type(meta['path'])
        with open(meta['path'], 'rb') as f:
            response = make_response(f.read())
        response.headers['Content-Type'] = mimetype or 'application/octet-stream'
        safe_filename = quote(meta.get('original_name', file_id))
        response.headers['Content-Disposition'] = f'inline; filename="{safe_filename}"'
    
    # Set view tracking cookie if needed
    if meta.get('ignore_duplicate_views', False):
        response.set_cookie(
            view_cookie_name, 
            new_cookie_value, 
            max_age=3600, 
            httponly=True, 
            secure=request.is_secure,
            samesite='Strict'
        )
    
    return response

@app.route('/delete', methods=['POST'])
def delete_file_post():
    """Delete files by password"""
    # Validate CSRF token
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)
    
    password = sanitize_user_input(request.form.get('delete_password', ''), 16)
    if not password:
        return redirect(url_for('upload_file'))
    
    deleted_count = 0
    feedback = "Incorrect password or no files to delete."
    
    with db_lock:
        ids_to_delete = []
        for fid, meta in file_db.items():
            if verify_password_hash(password, meta.get('password_hash', '')):
                ids_to_delete.append(fid)
        
        if ids_to_delete:
            for fid in ids_to_delete:
                if fid in file_db and os.path.exists(file_db[fid].get('path', '')):
                    secure_delete(file_db[fid]['path'])
                    file_db.pop(fid, None)
                    deleted_count += 1
            
            if deleted_count > 0:
                feedback = f"Successfully deleted {deleted_count} file(s)."
    
    is_local = detect_local_hosting()
    return render_template_string(
        UPLOAD_PAGE_TEMPLATE,
        deletion_feedback=feedback,
        JURISDICTION=JURISDICTION,
        smart_anonymity_enabled=APP_CONFIG['smart_anonymity_enabled'],
        show_speed_warning=False,
        show_local_warning=is_local,
        server_info=get_server_info() if is_local else None,
        csrf_token=generate_csrf_token(),
        max_files=MAX_UPLOAD_FILES,
        max_file_size_mb=MAX_SINGLE_FILE_SIZE // (1024*1024)
    )

@app.route('/delete/<file_id>')
def delete_file_get(file_id):
    """Delete specific file by ID"""
    file_id = sanitize_user_input(file_id, 50)
    
    with db_lock:
        if file_id in file_db and os.path.exists(file_db[file_id].get('path', '')):
            secure_delete(file_db[file_id]['path'])
            file_db.pop(file_id, None)
            return render_template_string(
                DELETED_PAGE_TEMPLATE,
                message="File has been securely deleted."
            )
    
    return render_template_string(
        DELETED_PAGE_TEMPLATE,
        message="File not found or already deleted."
    )

# --- Error Handlers ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template_string(
        DELETED_PAGE_TEMPLATE,
        message="Page not found."
    ), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template_string(
        DELETED_PAGE_TEMPLATE,
        message="Access forbidden."
    ), 403

@app.errorhandler(413)
def payload_too_large_error(error):
    return render_template_string(
        DELETED_PAGE_TEMPLATE,
        message="File too large."
    ), 413

@app.errorhandler(429)
def rate_limit_error(error):
    return render_template_string(
        DELETED_PAGE_TEMPLATE,
        message="Rate limit exceeded. Please try again later."
    ), 429

@app.errorhandler(500)
def internal_error(error):
    return render_template_string(
        DELETED_PAGE_TEMPLATE,
        message="Internal server error."
    ), 500

# --- Main Execution ---
if __name__ == '__main__':
    # Initialize directories with secure permissions
    for folder in [UPLOAD_FOLDER, STATIC_FOLDER]:
        if not os.path.exists(folder):
            os.makedirs(folder, mode=0o700)
        else:
            os.chmod(folder, 0o700)
    
    # Initialize reports database (wipes existing data)
    init_reports_database()
    
    # Start background threads
    cleanup_thread = threading.Thread(target=schedule_cleanup, daemon=True)
    cleanup_thread.start()
    
    # Configure secure session cookies
    app.config.update(
        SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
        SESSION_COOKIE_HTTPONLY=SESSION_COOKIE_HTTPONLY,
        SESSION_COOKIE_SAMESITE=SESSION_COOKIE_SAMESITE,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
    )
    
    # Start the Flask application
    print("🔒 Security-hardened Privacy Uploader starting...")
    print("⚠️  For production use: gunicorn --workers 4 --bind 0.0.0.0:8000 app:app")
    app.run(host='0.0.0.0', port=5000, debug=False)

# Flask Privacy-Focused Image and Video Uploader
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
from datetime import datetime, timedelta, timezone
from io import BytesIO

# --- Third-party imports ---
from flask import Flask, request, redirect, url_for, render_template_string, make_response, session, jsonify
from PIL import Image, ImageFilter
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
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
PASSWORD_SALT = get_random_bytes(16).hex()
HAAR_CASCADE_PATH = 'haarcascade_frontalface_default.xml'
JURISDICTION = "Vanuatu" # Legal jurisdiction for the service
REPORTS_DB_FILE = 'reports.db'

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
DECOY_FILES = [
    "C:\\Put\\Your\\Decoy\\Files\\Here",
]

# --- Flask App Initialization ---
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['STATIC_FOLDER'] = STATIC_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.secret_key = get_random_bytes(32)

# --- Database Functions ---
def init_reports_database():
    """Initialize reports database, wiping any existing data"""
    # Remove existing database file if it exists
    if os.path.exists(REPORTS_DB_FILE):
        try:
            os.remove(REPORTS_DB_FILE)
        except OSError:
            pass
    
    # Create new database with schema
    conn = sqlite3.connect(REPORTS_DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            file_id TEXT NOT NULL,
            session_id TEXT,
            created_at REAL NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()

def store_report(category, description, file_id, session_id=None):
    """Store a report in the database"""
    try:
        conn = sqlite3.connect(REPORTS_DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO reports (timestamp, category, description, file_id, session_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now(timezone.utc).isoformat(),
            category,
            description,
            file_id,
            session_id,
            time.time()
        ))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error storing report: {e}")
        return False

# --- OCR and NSFW Model Initialization (runs once on startup) ---
try:
    EASYOCR_READER = easyocr.Reader(['en'], gpu=False)
except Exception as e:
    EASYOCR_READER = None
    print(f"Warning: Could not initialize EasyOCR. Text blurring will be disabled. Error: {e}")

# Initialize NSFW Detection Model
NSFW_MODEL = None
NSFW_TRANSFORMS = None
try:
    # Check if model is already cached
    model_already_cached = False
    try:
        # Try to create model without printing anything first
        test_model = timm.create_model("hf_hub:Marqo/nsfw-image-detection-384", pretrained=True)
        test_model = None  # Clean up test model
        model_already_cached = True
    except:
        model_already_cached = False
    
    if not model_already_cached:
        print("Loading NSFW detection model (one-time download)...")
    
    NSFW_MODEL = timm.create_model("hf_hub:Marqo/nsfw-image-detection-384", pretrained=True)
    NSFW_MODEL = NSFW_MODEL.eval()
    
    data_config = timm.data.resolve_model_data_config(NSFW_MODEL)
    NSFW_TRANSFORMS = timm.data.create_transform(**data_config, is_training=False)
    
    if not model_already_cached:
        print("✓ NSFW detection model loaded successfully")
except Exception as e:
    print(f"Warning: Could not initialize NSFW detection model. Falling back to simple detector. Error: {e}")
    NSFW_MODEL = None
    NSFW_TRANSFORMS = None

# --- Disable all logging for production privacy ---
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
app.logger.setLevel(logging.ERROR)

# --- In-memory Volatile State ---
file_db = {}
db_lock = threading.Lock()
last_upload_time = time.time()
report_timestamps = {}  # Simple rate limiting for reports

# --- Optimized Processing Functions with Numba ---
@jit(nopython=True)
def optimized_color_quantization(pixels, k=256):
    """Fast color quantization using optimized k-means alternative"""
    # Simple uniform quantization - much faster than k-means
    quantized = pixels.copy()
    step = np.uint8(256 // k)  # Ensure step matches array dtype
    if step > 1:
        quantized = (quantized // step) * step
    return quantized

@jit(nopython=True)  
def add_selective_noise_jit(img_array, variance_threshold=50, seed=42):
    """Add noise only to high-variance areas using Numba optimization"""
    np.random.seed(seed)  # Use NumPy random for Numba compatibility
    height, width, channels = img_array.shape
    result = img_array.copy()
    
    # Simple variance approximation using neighboring pixels
    for y in range(1, height-1):
        for x in range(1, width-1):
            # Calculate simple variance using surrounding pixels
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
                    noise = np.random.randint(-5, 6)  # Use NumPy random
                    new_val = int(result[y, x, c]) + noise
                    result[y, x, c] = max(0, min(255, new_val))
    
    return result

# --- NSFW Detection Functions ---
def advanced_nsfw_detector(img_array):
    """
    High-accuracy NSFW detection using Marqo/nsfw-image-detection-384 model
    Returns probability score (0-1) where >0.5 suggests NSFW content
    """
    if NSFW_MODEL is None or NSFW_TRANSFORMS is None:
        return simple_nsfw_detector_fallback(img_array)
    
    try:
        # Convert OpenCV BGR to PIL RGB
        img_rgb = cv2.cvtColor(img_array, cv2.COLOR_BGR2RGB)
        pil_img = Image.fromarray(img_rgb)
        
        # Apply model transforms (resize to 384x384, normalize, etc.)
        transformed_img = NSFW_TRANSFORMS(pil_img).unsqueeze(0)
        
        # Inference with memory optimization
        with torch.no_grad():
            raw_output = NSFW_MODEL(transformed_img)
            
            # Apply softmax to get probabilities
            probabilities = raw_output.softmax(dim=-1).cpu()
            
            # Extract probabilities for both classes
            nsfw_probability = float(probabilities[0][0])  # Class 0 = NSFW
            sfw_probability = float(probabilities[0][1])   # Class 1 = SFW
            
            # Clean up tensors
            del transformed_img, raw_output, probabilities
            torch.cuda.empty_cache() if torch.cuda.is_available() else None
            
            return nsfw_probability
            
    except Exception as e:
        return simple_nsfw_detector_fallback(img_array)

def simple_nsfw_detector_fallback(img_array):
    """
    Lightweight NSFW detection fallback using color and texture analysis
    Returns probability score (0-1) where >0.6 suggests NSFW content
    """
    try:
        # Convert to HSV for better skin tone detection
        hsv = cv2.cvtColor(img_array, cv2.COLOR_BGR2HSV)
        
        # Skin tone detection ranges
        skin_lower1 = np.array([0, 20, 70])
        skin_upper1 = np.array([20, 255, 255])
        skin_lower2 = np.array([160, 20, 70])
        skin_upper2 = np.array([180, 255, 255])
        
        # Create skin mask
        skin_mask1 = cv2.inRange(hsv, skin_lower1, skin_upper1)
        skin_mask2 = cv2.inRange(hsv, skin_lower2, skin_upper2)
        skin_mask = cv2.bitwise_or(skin_mask1, skin_mask2)
        
        # Calculate skin percentage
        skin_pixels = cv2.countNonZero(skin_mask)
        total_pixels = img_array.shape[0] * img_array.shape[1]
        skin_ratio = skin_pixels / total_pixels
        
        # Texture analysis - look for smooth regions (typical in inappropriate content)
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY)
        blurred = cv2.GaussianBlur(gray, (15, 15), 0)
        smooth_regions = cv2.absdiff(gray, blurred)
        smooth_ratio = np.count_nonzero(smooth_regions < 10) / total_pixels
        
        # Conservative scoring algorithm for fallback
        nsfw_score = (skin_ratio * 0.4) + (smooth_ratio * 0.2)  # Much less aggressive
        
        return min(1.0, nsfw_score)  # No amplification for fallback
        
    except Exception:
        return 0.0  # Default to safe if detection fails

# --- Utility Functions ---
def secure_delete(path):
    try:
        if not os.path.exists(path): return
        file_size = os.path.getsize(path)
        with open(path, "wb") as f:
            for pattern in GUTMANN_PASSES: f.seek(0); f.write(pattern * (file_size // len(pattern) + 1))
            f.seek(0); f.write(get_random_bytes(file_size))
        decoy_source = random.choice(DECOY_FILES)
        if os.path.exists(decoy_source): shutil.copyfile(decoy_source, path)
        else: os.remove(path)
    except Exception:
        if os.path.exists(path): os.remove(path)

def schedule_cleanup():
    while True:
        with db_lock:
            now = datetime.now(timezone.utc)
            expired_ids = [fid for fid, meta in file_db.items() if meta['delete_at'] <= now]
            for fid in expired_ids:
                meta = file_db.get(fid)
                if meta and meta.get('path') and os.path.exists(meta['path']):
                    secure_delete(meta['path'])
                    file_db.pop(fid, None)
        gc.collect()  # Force garbage collection
        time.sleep(60)

def manage_storage():
    max_storage_bytes = MAX_STORAGE_GB * 1024 * 1024 * 1024
    with db_lock:
        current_files = {fid: meta for fid, meta in file_db.items() if os.path.exists(meta.get('path', ''))}
        total_size = sum(os.path.getsize(meta['path']) for meta in current_files.values())
        if total_size > max_storage_bytes:
            sorted_files = sorted(current_files.items(), key=lambda item: item[1]['delete_at'])
            while total_size > max_storage_bytes and sorted_files:
                fid, meta_to_delete = sorted_files.pop(0)
                if os.path.exists(meta_to_delete['path']):
                    file_size = os.path.getsize(meta_to_delete['path'])
                    secure_delete(meta_to_delete['path'])
                    total_size -= file_size
                    file_db.pop(fid, None)

def plausible_deniability_engine():
    global last_upload_time
    while True:
        time_since_last_upload = time.time() - last_upload_time
        if random.random() < (1 / (1 + (time_since_last_upload / 60))):
            decoy_source = random.choice(DECOY_FILES)
            if os.path.exists(decoy_source):
                with db_lock:
                    ext = os.path.splitext(decoy_source)[1].lower()
                    obfuscated_name = generate_random_filename(ext)
                    final_path = os.path.join(app.config['UPLOAD_FOLDER'], obfuscated_name)
                    radical_image_compression(decoy_source, final_path, smart_anonymity_enabled=False)
                    if os.path.exists(final_path):
                        file_id = ''.join(random.choices(string.ascii_letters+string.digits, k=12))
                        file_db[file_id] = {'path': final_path,'password_hash': get_password_hash(''.join(random.choices(string.ascii_letters + string.digits, k=10))),'delete_at': datetime.now(timezone.utc) + timedelta(hours=random.uniform(1, 5)),'size_mb': os.path.getsize(final_path) / (1024*1024),'original_name': os.path.basename(decoy_source),'views': 0, 'max_views': random.randint(5, 50), 'is_encrypted': False,'is_video': False, 'aes_password': None, 'uploaded_at': datetime.now(timezone.utc),'deletion_reason': None, 'is_nsfw': False}
        time.sleep(random.randint(54, 68) * 60)

def get_password_hash(password): return hashlib.sha3_512((password + PASSWORD_SALT).encode()).hexdigest()
def generate_random_filename(extension): return ''.join(random.choices(string.ascii_lowercase + string.digits, k=32)) + extension
def mask_password(password):
    if len(password) <= 3: return '*' * len(password)
    return f"{password[0]}{'*' * (len(password) - 3)}{password[-2:]}"

def check_report_rate_limit():
    """Simple rate limiting for reports - max 3 reports per 10 minutes per session"""
    current_time = time.time()
    session_id = session.get('session_id', str(random.randint(100000, 999999)))
    session['session_id'] = session_id
    
    if session_id not in report_timestamps:
        report_timestamps[session_id] = []
    
    # Clean old timestamps
    report_timestamps[session_id] = [ts for ts in report_timestamps[session_id] if current_time - ts < 600]
    
    if len(report_timestamps[session_id]) >= 3:
        return False
    
    report_timestamps[session_id].append(current_time)
    return True

# --- Image and Video Processing ---
def radical_image_compression(input_path, output_path, smart_anonymity_enabled=False):
    try:
        img = cv2.imread(input_path)
        if img is None: raise ValueError("Could not read image")

        # --- 1. Memory-efficient downscaling ---
        h, w, _ = img.shape
        max_dim = 1080
        if h > max_dim or w > max_dim:
            if h > w: new_h, new_w = max_dim, int(w * max_dim / h)
            else: new_w, new_h = max_dim, int(h * max_dim / w)
            img = cv2.resize(img, (new_w, new_h), interpolation=cv2.INTER_AREA)

        # --- 2. Advanced NSFW Detection ---
        nsfw_score = advanced_nsfw_detector(img)
        is_nsfw = nsfw_score > 0.5  # Advanced model uses 0.5 threshold

        # --- 3. Optimized Color Quantization ---
        img_flat = img.reshape((-1, 3)).astype(np.uint8)
        quantized_flat = optimized_color_quantization(img_flat, k=256)
        img = quantized_flat.reshape(img.shape)

        # --- 4. Enhanced Smart Anonymity Features ---
        if smart_anonymity_enabled:
            # Face blurring
            if os.path.exists(HAAR_CASCADE_PATH):
                face_cascade = cv2.CascadeClassifier(HAAR_CASCADE_PATH)
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                faces = face_cascade.detectMultiScale(gray, 1.1, 4)
                for (x, y, w, h) in faces:
                    if w > 0 and h > 0:
                        roi = img[y:y+h, x:x+w]
                        kernel_size = max(w, h)
                        if kernel_size % 2 == 0: kernel_size += 1
                        roi = cv2.GaussianBlur(roi, (kernel_size, kernel_size), 0)
                        img[y:y+roi.shape[0], x:x+roi.shape[1]] = roi

            # Text blurring (EasyOCR)
            if EASYOCR_READER:
                try:
                    ocr_data = EASYOCR_READER.readtext(img)
                    for (bbox, text, prob) in ocr_data:
                        (tl, tr, br, bl) = bbox
                        x, y, w, h = int(tl[0]), int(tl[1]), int(br[0] - tl[0]), int(br[1] - tl[1])
                        if w > 0 and h > 0 and x >= 0 and y >= 0 and (x+w) <= img.shape[1] and (y+h) <= img.shape[0]:
                            roi = img[y:y+h, x:x+w]
                            kernel_size = max(w, h)
                            if kernel_size % 2 == 0: kernel_size += 1
                            roi = cv2.GaussianBlur(roi, (kernel_size, kernel_size), 0)
                            img[y:y+h, x:x+w] = roi
                except Exception: pass

            # Enhanced Background blurring - STRENGTHENED
            try:
                pil_img = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
                foreground = remove(pil_img, alpha_matting=True, alpha_matting_foreground_threshold=50, alpha_matting_background_threshold=50)
                fg_cv2 = cv2.cvtColor(np.array(foreground), cv2.COLOR_RGBA_BGRA)
                mask = fg_cv2[:, :, 3]
                
                # STRENGTHENED: Multiple blur passes and larger kernel
                blurred_bg = cv2.GaussianBlur(img, (101, 101), 0)  # Increased from (51, 51)
                blurred_bg = cv2.GaussianBlur(blurred_bg, (101, 101), 0)  # Second pass for stronger blur
                
                mask_inv = cv2.bitwise_not(mask)
                fg = cv2.bitwise_and(img, img, mask=mask)
                bg = cv2.bitwise_and(blurred_bg, blurred_bg, mask=mask_inv)
                img = cv2.add(bg, fg)
            except Exception: pass

        # --- 5. Standard Anonymity & Final Compression ---
        # Subtle random crop
        h, w, _ = img.shape
        if h > 10 and w > 10:
            crop_h, crop_w = int(h * random.uniform(0.97, 1.0)), int(w * random.uniform(0.97, 1.0))
            x_start, y_start = random.randint(0, w - crop_w), random.randint(0, h - crop_h)
            img = img[y_start:y_start+crop_h, x_start:x_start+crop_w]

        # Optimized selective noise addition
        noise_seed = int(time.time()) % 2**31  # Generate seed from current time
        img = add_selective_noise_jit(img, seed=noise_seed)

        # --- 6. Final Save with reduced bitrate ---
        cv2.imwrite(output_path, img, [cv2.IMWRITE_JPEG_QUALITY, random.randint(15, 40)])

        # Clean up memory
        del img
        gc.collect()
        
        return is_nsfw

    except Exception as e:
        print(f"Error during image processing: {e}")
        shutil.copy(input_path, output_path)
        return False

def radical_video_compression(input_path, output_path):
    try:
        # Reduced resolution, very high CRF for max compression, remove audio, veryfast preset
        command = f"ffmpeg -i '{input_path}' -y -vf 'scale=iw/2.5:ih/2.5' -crf 40 -preset veryfast -an '{output_path}'"
        os.system(command)
    except Exception:
        shutil.copy(input_path, output_path)

# --- HTML Templates ---
LEGAL_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Legal Notice & Terms of Service</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #121212; color: #e0e0e0; line-height: 1.6; }
        .container { background-color: #1e1e1e; padding: 2rem; border-radius: 8px; max-width: 800px; margin: 2rem auto; }
        h1, h2 { color: #cf6679; border-bottom: 1px solid #444; padding-bottom: 0.5rem; }
        p, li { color: #ccc; }
        strong { color: #fff; }
        .warning { background-color: #b00020; padding: 1rem; border-radius: 4px; text-align: center; font-weight: bold; margin-bottom: 2rem; }
        a { color: #bb86fc; }
    </style>
</head>
<body>
    <div class="container">
        <div class="warning">THIS IS A BINDING LEGAL AGREEMENT. READ CAREFULLY.</div>
        <h1>Terms of Service & Legal Notice</h1>
        <p><strong>Effective Date:</strong> January 1, 2024</p>

        <h2>1. Jurisdiction and Governing Law</h2>
        <p>This service is offered exclusively within the sovereign jurisdiction of <strong>Vanuatu</strong>. By accessing or using this service, you irrevocably agree that any and all disputes, claims, or controversies arising out of or relating to your use of this service shall be governed by and construed in accordance with the laws of Vanuatu, without regard to its conflict of law provisions. You further consent to the exclusive jurisdiction of the courts located in Vanuatu for the resolution of any such disputes. If you are accessing this service from outside Vanuatu, you are doing so at your own risk and are solely responsible for compliance with your local laws.</p>

        <h2>2. Nature of the Service & Disclaimer of Responsibility</h2>
        <p>This is an automated, ephemeral, and privacy-preserving data transformation service. We, the operators, have <strong>NO ABILITY</strong> to view, access, recover, or provide any information about the data processed. All files are subjected to irreversible, destructive transformations and are permanently deleted after a short, predefined period. <strong>We hold no logs, no user data, and no plaintext files.</strong> Accordingly, we are technically incapable of complying with data requests from any entity, government or private.</p>
        <p>You, the user, are <strong>SOLELY AND EXCLUSIVELY RESPONSIBLE</strong> for the content you upload. By using this service, you affirm that you have the legal right to use and process the content you upload and that it does not violate any laws within your jurisdiction or the jurisdiction of Vanuatu.</p>

        <h2>3. Absolute Waiver of Rights</h2>
        <p>By uploading a file, you knowingly and voluntarily <strong>WAIVE ALL RIGHTS</strong> to make any claim against the service, its operators, owners, affiliates, or hosts for any reason whatsoever. This includes, but is not limited to, claims of data loss, corruption, emotional distress, financial loss, or any other tangible or intangible damage. You acknowledge that the service is provided "AS IS" and you use it at your own absolute risk.</p>
        
        <h2>4. NO WARRANTY</h2>
        <p>The service is provided <strong>WITHOUT ANY WARRANTY OF ANY KIND, EXPRESS OR IMPLIED</strong>. This includes, but is not limited to, the implied warranties of merchantability, fitness for a particular purpose, and non-infringement. We do not warrant that the service will be error-free, uninterrupted, or secure.</p>
        
        <h2>5. Extreme Limitation of Liability</h2>
        <p>In the unlikely event that any part of this agreement is found to be unenforceable by a competent court in Vanuatu, you agree that the total aggregate liability of the service, its operators, and affiliates, for any and all claims, shall be strictly limited to a symbolic sum of <strong>TEN UNITED STATES DOLLARS ($10.00 USD)</strong>. This limitation is a fundamental part of the agreement to provide this service.</p>

        <h2>6. Agreement</h2>
        <p>Your use of the upload functionality constitutes your full and unconditional agreement to these terms. If you do not agree to these terms, do not use the service.
        <br><br><a href="/">Return to Upload Page</a>
        </p>
    </div>
</body>
</html>
"""

UPLOAD_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Privacy Uploader</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #121212; color: #e0e0e0; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .container { background-color: #1e1e1e; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); width: 90%; max-width: 600px; }
        h1 { text-align: center; color: #bb86fc; }
        .jurisdiction-note { text-align: center; color: #888; font-size: 0.9rem; margin-top: -1rem; margin-bottom: 1rem; }
        .terms-note { text-align: center; font-size: 0.8rem; color: #aaa; margin-top: 1.5rem; }
        .terms-note a { color: #bb86fc; }
        .form-group { margin-bottom: 1.5rem; }
        label { display: block; margin-bottom: 0.5rem; font-weight: bold; }
        input[type="file"], input[type="password"], input[type="text"], input[type="number"] { width: calc(100% - 22px); padding: 10px; background-color: #333; border: 1px solid #444; border-radius: 4px; color: #e0e0e0; }
        .btn { background-color: #6200ee; color: white; padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; width: 100%; }
        .info { font-size: 0.8rem; color: #888; margin-top: 5px; }
        .tooltip { position: relative; display: inline-block; cursor: help; }
        .tooltip .tooltiptext { visibility: hidden; width: 220px; background-color: #555; color: #fff; text-align: center; border-radius: 6px; padding: 5px; position: absolute; z-index: 1; bottom: 125%; left: 50%; margin-left: -110px; opacity: 0; transition: opacity 0.3s; }
        .tooltip:hover .tooltiptext { visibility: visible; opacity: 1; }
        .error { color: #cf6679; text-align: center; margin-bottom: 1rem; }
        .delete-box { position: fixed; bottom: 20px; right: 20px; background-color: #1e1e1e; padding: 1rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.5); z-index: 10; }
        #aes_password_group { display: none; }
        #aes_encrypt:checked ~ #aes_password_group { display: block; }
        #captcha-container img { border-radius: 4px; margin-top: 10px; }
        .js-warning { background-color: #ff6f00; color: #000; padding: 1rem; border-radius: 4px; text-align: center; font-weight: bold; margin-bottom: 1rem; display: none; }
    </style>
    <noscript>
        <style>
            .js-warning { display: none !important; }
        </style>
    </noscript>
</head>
<body>
    <div class="container">
        <div class="js-warning" id="js-warning">
            ⚠️ WARNING: JavaScript is enabled in your browser. For maximum privacy and security, it is recommended to disable JavaScript by clicking the shield icon → Settings → Safest in your browser.
        </div>
        <h1>Anonymous File Uploader</h1>
        <p class="jurisdiction-note">Note: This service is only for use within the jurisdiction of <strong>{{ JURISDICTION }}</strong>.</p>
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
        <form action="/" method="post" enctype="multipart/form-data">
            <div class="form-group"><label for="files">Select files</label><input type="file" name="files" id="files" multiple required><p class="info">Max 10 files or 100s of video. Total size < 300MB.</p></div>
            <div class="form-group"><label for="password">Deletion Password (8-16 chars)</label><input type="password" name="password" id="password" minlength="8" maxlength="16" required></div>
            <div class="form-group"><label for="max_views">Delete after views:</label><input type="number" name="max_views" id="max_views" min="5" max="50" value="30" style="width: 60px;"></div>
            <div class="form-group">
                <input type="checkbox" name="smart_anonymity" id="smart_anonymity">
                <label for="smart_anonymity" style="display: inline;">Smart Anonymity? <span class="tooltip">i<span class="tooltiptext">For images only. Applies advanced, processor-intensive privacy filters including strengthened background blur.</span></span></label>
            </div>
            <div class="form-group">
                <input type="checkbox" name="aes_encrypt" id="aes_encrypt">
                <label for="aes_encrypt" style="display: inline;">AES-256 Encrypt? <span class="tooltip">i<span class="tooltiptext">File won't be compressed or filtered. Max 25MB, 1 hour expiry.</span></span></label>
                <div id="aes_password_group"><label for="aes_password" style="margin-top:1rem;">AES Encryption Password</label><input type="password" name="aes_password" id="aes_password"></div>
            </div>
            <div class="form-group" id="captcha-container">
                <label for="captcha">Enter Captcha Text</label>
                <a href="/" title="Click to refresh site. This will clear all inputs."><img id="captcha-img" src="{{ url_for('captcha_image') }}" alt="captcha"></a>
                <input type="text" name="captcha" id="captcha" required>
            </div>
            <button type="submit" class="btn">Upload Securely</button>
            <p class="terms-note">By clicking "Upload Securely", you agree to our <a href="/legal" target="_blank">Terms of Service</a>.</p>
        </form>
    </div>
    <div class="delete-box">
        <form action="/delete" method="post"><label for="delete_password">Enter Password to Delete</label><input type="password" name="delete_password" id="delete_password" required><button type="submit" class="btn" style="margin-top:5px;width:100%;">Delete</button>
        {% if deletion_feedback %}<p style="font-size:0.8rem;color:#bb86fc;margin-top:5px;">{{ deletion_feedback }}</p>{% endif %}
        </form>
    </div>

    <script>
        // Show JavaScript warning
        document.getElementById('js-warning').style.display = 'block';
    </script>
</body>
</html>
"""

NSFW_VIEW_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Content Warning</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #121212; color: #e0e0e0; padding: 2rem; text-align: center; }
        .container { background-color: #1e1e1e; padding: 2rem; border-radius: 8px; max-width: 600px; margin: auto; }
        .warning { background-color: #b00020; padding: 1rem; border-radius: 4px; font-weight: bold; margin-bottom: 2rem; }
        .image-container { position: relative; display: inline-block; margin: 2rem 0; }
        .blurred-image { filter: blur(20px); transition: filter 0.3s ease; max-width: 100%; border-radius: 8px; }
        .image-container:hover .blurred-image { filter: blur(0px); }
        .hover-instruction { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); background-color: rgba(0,0,0,0.8); color: white; padding: 1rem; border-radius: 4px; font-weight: bold; pointer-events: none; }
        .image-container:hover .hover-instruction { display: none; }
        .report-btn { background-color: #cf6679; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin: 1rem; }
        .back-link { color: #bb86fc; }
        
        /* Modal styles */
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.8); }
        .modal-content { background-color: #1e1e1e; margin: 5% auto; padding: 2rem; border: 1px solid #444; border-radius: 8px; width: 90%; max-width: 600px; color: #e0e0e0; max-height: 80vh; overflow-y: auto; }
        .close { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
        .close:hover { color: #fff; }
        .step { display: none; }
        .step.active { display: block; }
        .category-grid { display: grid; grid-template-columns: 1fr; gap: 10px; margin: 1rem 0; }
        .category-btn { background-color: #333; border: 1px solid #555; color: #e0e0e0; padding: 1rem; border-radius: 4px; cursor: pointer; transition: all 0.3s; }
        .category-btn:hover { background-color: #444; }
        .category-btn.selected { background-color: #6200ee; border-color: #bb86fc; }
        .form-group { margin: 1rem 0; }
        .form-group label { display: block; margin-bottom: 0.5rem; font-weight: bold; }
        .form-group input, .form-group textarea { width: calc(100% - 22px); padding: 10px; background-color: #333; border: 1px solid #444; border-radius: 4px; color: #e0e0e0; font-family: inherit; }
        .form-group textarea { resize: vertical; min-height: 100px; }
        .checkbox-group { margin: 1rem 0; }
        .checkbox-group label { display: flex; align-items: center; margin-bottom: 0.5rem; cursor: pointer; }
        .checkbox-group input[type="checkbox"] { margin-right: 10px; }
        .btn { background-color: #6200ee; color: white; padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; margin: 0.5rem; }
        .btn:disabled { background-color: #555; cursor: not-allowed; }
        .btn-secondary { background-color: #444; }
        .char-counter { font-size: 0.8rem; color: #888; margin-top: 5px; }
        .captcha-container { text-align: center; margin: 1rem 0; }
        .captcha-container img { border-radius: 4px; margin: 10px 0; }
        .noscript-msg { background-color: #b00020; padding: 1rem; border-radius: 4px; text-align: center; font-weight: bold; margin: 1rem 0; }
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
            <button class="report-btn" onclick="openReportModal()">Report Content</button>
            <noscript>
                <div class="noscript-msg">
                    JavaScript must be enabled to report content. Please enable JavaScript in your browser to use the reporting feature.
                </div>
            </noscript>
        </div>
        
        <p><a href="/" class="back-link">← Back to Upload</a></p>
    </div>

    <!-- Report Modal -->
    <div id="reportModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeReportModal()">&times;</span>
            
            <!-- Step 1: Category Selection -->
            <div id="step1" class="step active">
                <h2>Report Illegal Content ({{ JURISDICTION }})</h2>
                <p>Select the category that best describes the illegal content:</p>
                <div class="category-grid">
                    <div class="category-btn" onclick="selectCategory(this, 'CHILD EXPLOITATION & SEXUAL OFFENSES')">
                        <strong>CHILD EXPLOITATION & SEXUAL OFFENSES</strong>
                    </div>
                    <div class="category-btn" onclick="selectCategory(this, 'CYBERCRIME & DIGITAL OFFENSES')">
                        <strong>CYBERCRIME & DIGITAL OFFENSES</strong>
                    </div>
                    <div class="category-btn" onclick="selectCategory(this, 'INTELLECTUAL PROPERTY & COPYRIGHT')">
                        <strong>INTELLECTUAL PROPERTY & COPYRIGHT</strong>
                    </div>
                    <div class="category-btn" onclick="selectCategory(this, 'TERRORISM & NATIONAL SECURITY')">
                        <strong>TERRORISM & NATIONAL SECURITY</strong>
                    </div>
                    <div class="category-btn" onclick="selectCategory(this, 'PUBLIC ORDER & SEDITIOUS CONTENT')">
                        <strong>PUBLIC ORDER & SEDITIOUS CONTENT</strong>
                    </div>
                    <div class="category-btn" onclick="selectCategory(this, 'DEFAMATION & REPUTATION')">
                        <strong>DEFAMATION & REPUTATION</strong>
                    </div>
                    <div class="category-btn" onclick="selectCategory(this, 'OBSCENITY & MORAL OFFENSES')">
                        <strong>OBSCENITY & MORAL OFFENSES</strong>
                    </div>
                    <div class="category-btn" onclick="selectCategory(this, 'FINANCIAL & COMMERCIAL CRIMES')">
                        <strong>FINANCIAL & COMMERCIAL CRIMES</strong>
                    </div>
                    <div class="category-btn" onclick="selectCategory(this, 'JUSTICE ADMINISTRATION & EVIDENCE')">
                        <strong>JUSTICE ADMINISTRATION & EVIDENCE</strong>
                    </div>
                    <div class="category-btn" onclick="selectCategory(this, 'OTHER')">
                        <strong>OTHER</strong>
                    </div>
                </div>
                <button class="btn" onclick="nextStep()" id="nextBtn" disabled>Next</button>
                <button class="btn btn-secondary" onclick="closeReportModal()">Cancel</button>
            </div>
            
            <!-- Step 2: Description -->
            <div id="step2" class="step">
                <h2>Describe the Issue</h2>
                <div class="form-group">
                    <label for="description">Describe the issue more specifically:</label>
                    <textarea id="description" placeholder="Describe the issue more specifically" maxlength="10000" oninput="updateCharCount()"></textarea>
                    <div class="char-counter" id="charCounter">0 / 10000 characters</div>
                </div>
                <button class="btn" onclick="nextStep()" id="nextBtn2" disabled>Next</button>
                <button class="btn btn-secondary" onclick="prevStep()">Back</button>
            </div>
            
            <!-- Step 3: Legal Consent -->
            <div id="step3" class="step">
                <h2>Legal Consent</h2>
                <div class="checkbox-group">
                    <label>
                        <input type="checkbox" id="consent1" onchange="checkConsents()">
                        This content <strong>is illegal</strong> in {{ JURISDICTION }}
                    </label>
                    <label>
                        <input type="checkbox" id="consent2" onchange="checkConsents()">
                        I confirm that I am a legal resident of <strong>{{ JURISDICTION }}</strong> 🇻🇺
                    </label>
                    <label>
                        <input type="checkbox" id="consent3" onchange="checkConsents()">
                        I understand that this report may be logged permanently
                    </label>
                </div>
                
                <div class="captcha-container">
                    <label for="reportCaptcha">Enter Captcha Text:</label>
                    <img id="reportCaptchaImg" src="/report-captcha" alt="captcha">
                    <input type="text" id="reportCaptcha" placeholder="Enter captcha" oninput="checkConsents()">
                </div>
                
                <button class="btn" onclick="submitReport()" id="submitBtn" disabled>Consent & Submit</button>
                <button class="btn btn-secondary" onclick="prevStep()">Back</button>
            </div>
            
            <!-- Step 4: Success -->
            <div id="step4" class="step">
                <h2>Success</h2>
                <p style="color: #03dac6; text-align: center; font-size: 1.2rem; margin: 2rem 0;">
                    ✓ Your report has been submitted.
                </p>
                <button class="btn" onclick="closeReportModal()">Close</button>
            </div>
        </div>
    </div>

    <script>
        let selectedCategory = '';
        let currentStep = 1;
        
        function openReportModal() {
            document.getElementById('reportModal').style.display = 'block';
            // Refresh captcha
            document.getElementById('reportCaptchaImg').src = '/report-captcha?' + new Date().getTime();
        }
        
        function closeReportModal() {
            document.getElementById('reportModal').style.display = 'none';
            resetModal();
        }
        
        function resetModal() {
            currentStep = 1;
            selectedCategory = '';
            document.querySelectorAll('.step').forEach(step => step.classList.remove('active'));
            document.getElementById('step1').classList.add('active');
            document.querySelectorAll('.category-btn').forEach(btn => btn.classList.remove('selected'));
            document.getElementById('description').value = '';
            document.getElementById('reportCaptcha').value = '';
            document.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
            updateCharCount();
            checkConsents();
        }
        
        function selectCategory(btn, category) {
            document.querySelectorAll('.category-btn').forEach(b => b.classList.remove('selected'));
            btn.classList.add('selected');
            selectedCategory = category;
            document.getElementById('nextBtn').disabled = false;
        }
        
        function nextStep() {
            if (currentStep === 1 && !selectedCategory) return;
            if (currentStep === 2) {
                const desc = document.getElementById('description').value.trim();
                if (selectedCategory === 'OTHER' && desc.length < 3) return;
                if (selectedCategory !== 'OTHER' && desc.length === 0) return;
            }
            
            document.getElementById('step' + currentStep).classList.remove('active');
            currentStep++;
            document.getElementById('step' + currentStep).classList.add('active');
            
            // Skip description step if category is OTHER and go directly to consent
            if (currentStep === 2 && selectedCategory === 'OTHER') {
                // For OTHER, make description required with min 3 chars
                document.getElementById('description').placeholder = 'Describe the issue more specifically (minimum 3 characters)';
            }
            
            if (currentStep === 2) {
                updateDescriptionValidation();
            }
        }
        
        function prevStep() {
            document.getElementById('step' + currentStep).classList.remove('active');
            currentStep--;
            document.getElementById('step' + currentStep).classList.add('active');
        }
        
        function updateCharCount() {
            const desc = document.getElementById('description');
            const counter = document.getElementById('charCounter');
            counter.textContent = desc.value.length + ' / 10000 characters';
            updateDescriptionValidation();
        }
        
        function updateDescriptionValidation() {
            const desc = document.getElementById('description').value.trim();
            const btn = document.getElementById('nextBtn2');
            
            if (selectedCategory === 'OTHER') {
                btn.disabled = desc.length < 3;
            } else {
                btn.disabled = desc.length === 0;
            }
        }
        
        function checkConsents() {
            const consent1 = document.getElementById('consent1').checked;
            const consent2 = document.getElementById('consent2').checked;
            const consent3 = document.getElementById('consent3').checked;
            const captcha = document.getElementById('reportCaptcha').value.trim();
            
            document.getElementById('submitBtn').disabled = !(consent1 && consent2 && consent3 && captcha.length > 0);
        }
        
        async function submitReport() {
            const formData = new FormData();
            formData.append('category', selectedCategory);
            formData.append('description', document.getElementById('description').value);
            formData.append('captcha', document.getElementById('reportCaptcha').value);
            formData.append('file_id', '{{ file_id }}');
            
            try {
                const response = await fetch('/submit-report', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    document.getElementById('step3').classList.remove('active');
                    document.getElementById('step4').classList.add('active');
                    currentStep = 4;
                } else {
                    alert('Error: ' + (result.error || 'Failed to submit report'));
                    // Refresh captcha on error
                    document.getElementById('reportCaptchaImg').src = '/report-captcha?' + new Date().getTime();
                    document.getElementById('reportCaptcha').value = '';
                    checkConsents();
                }
            } catch (error) {
                alert('Network error. Please try again.');
            }
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('reportModal');
            if (event.target === modal) {
                closeReportModal();
            }
        }
    </script>
</body>
</html>
"""

RESULT_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Upload Successful</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #121212; color: #e0e0e0; padding: 2rem; }
        .container { background-color: #1e1e1e; padding: 2rem; border-radius: 8px; max-width: 800px; margin: auto; }
        h1 { color: #03dac6; text-align: center; }
        .file-card { background-color: #2c2c2c; border: 1px solid #444; border-radius: 8px; margin-bottom: 2rem; padding: 1.5rem; }
        h2 { margin-top: 0; color: #bb86fc; word-wrap: break-word;}
        .file-card img, .file-card video { max-width: 100%; border-radius: 4px; margin-top: 1rem; }
        .details { list-style-type: none; padding: 0; }
        .details li { margin-bottom: 0.5rem; word-wrap: break-word; }
        .details strong { color: #03dac6; }
        a { color: #bb86fc; }
        .delete-btn { background-color: #cf6679; color: white; text-decoration: none; padding: 10px 15px; border-radius: 4px; display: inline-block; margin-top: 1rem; }
        .password-warning { background-color: #b00020; padding: 1rem; border-radius: 4px; text-align: center; font-weight: bold; }
        .nsfw-warning { background-color: #ff6f00; color: #000; padding: 1rem; border-radius: 4px; text-align: center; font-weight: bold; margin-bottom: 1rem; }
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
            {% if file.is_nsfw %}<div class="nsfw-warning">⚠️ This content has been flagged as potentially adult material</div>{% endif %}
            {% if file.is_video %}<video controls><source src="{{ url_for('view_file', file_id=file.id) }}" type="video/mp4"></video>
            {% else %}<img src="{{ url_for('view_file', file_id=file.id) }}" alt="Processed and Compressed Image">{% endif %}
            <ul class="details">
                <li><strong>File URL:</strong> <a href="{{ url_for('view_file', file_id=file.id, _external=True) }}" target="_blank">{{ url_for('view_file', file_id=file.id, _external=True) }}</a></li>
                <li><strong>Compressed Size:</strong> {{ "%.2f"|format(file.size_mb) }} MB</li>
                <li><strong>Deletes At (UTC):</strong> {{ file.delete_at.strftime('%Y-%m-%d %H:%M:%S') }}</li>
                <li><strong>Views Remaining:</strong> {{ file.views_left }} / {{ file.max_views }}</li>
                {% if file.is_encrypted %}<li><strong style="color: #cf6679;">AES-256 Password:</strong> {{ file.aes_password }} (Save this too!)</li>{% endif %}
            </ul>
            <a href="{{ url_for('delete_file_get', file_id=file.id) }}" class="delete-btn">Delete Now</a>
        </div>
        {% endfor %}
         <p style="text-align:center;"><a href="/">Upload more files</a></p>
    </div>
</body>
</html>
"""
DELETED_PAGE_TEMPLATE = "<!DOCTYPE html><html><head><title>File Deleted</title></head><body style='background-color:#121212;color:#e0e0e0;text-align:center;padding-top:50px;'><h1>{{ message }}</h1><a href='/' style='color:#bb86fc;'>Go back</a></body></html>"

# --- Flask Routes ---
@app.route('/legal')
def legal_page():
    return render_template_string(LEGAL_PAGE_TEMPLATE)

@app.route('/captcha-image')
def captcha_image():
    image_captcha = ImageCaptcha()
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session['captcha'] = captcha_text
    image_data = image_captcha.generate(captcha_text)
    response = make_response(image_data.getvalue())
    response.headers['Content-Type'] = 'image/png'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

@app.route('/report-captcha')
def report_captcha_image():
    image_captcha = ImageCaptcha()
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session['report_captcha'] = captcha_text
    image_data = image_captcha.generate(captcha_text)
    response = make_response(image_data.getvalue())
    response.headers['Content-Type'] = 'image/png'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

@app.route('/submit-report', methods=['POST'])
def submit_report():
    try:
        # Rate limiting
        if not check_report_rate_limit():
            return jsonify({'success': False, 'error': 'Too many reports. Please wait before submitting another.'})
        
        # Validate captcha
        if 'report_captcha' not in session or request.form.get('captcha', '').lower() != session['report_captcha'].lower():
            return jsonify({'success': False, 'error': 'Invalid captcha.'})
        
        session.pop('report_captcha', None)
        
        # Validate inputs
        category = request.form.get('category', '').strip()
        description = request.form.get('description', '').strip()
        file_id = request.form.get('file_id', '').strip()
        
        if category not in REPORT_CATEGORIES:
            return jsonify({'success': False, 'error': 'Invalid category.'})
        
        if category == 'OTHER' and len(description) < 3:
            return jsonify({'success': False, 'error': 'Description must be at least 3 characters for OTHER category.'})
        
        if category != 'OTHER' and len(description) == 0:
            return jsonify({'success': False, 'error': 'Description is required.'})
        
        if len(description) > 10000:
            return jsonify({'success': False, 'error': 'Description too long.'})
        
        # Verify file exists
        with db_lock:
            if file_id not in file_db:
                return jsonify({'success': False, 'error': 'File not found.'})
        
        # Store the report in database
        session_id = session.get('session_id', 'anonymous')
        if store_report(category, description, file_id, session_id):
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to store report. Please try again.'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': 'Server error. Please try again.'})

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    global last_upload_time
    if request.method == 'POST':
        if 'captcha' not in session or request.form.get('captcha','').lower() != session['captcha'].lower():
            return render_template_string(UPLOAD_PAGE_TEMPLATE, error="Incorrect captcha.", JURISDICTION=JURISDICTION)
        session.pop('captcha', None)

        files, password = request.files.getlist('files'), request.form.get('password')
        aes_encrypt, smart_anonymity = 'aes_encrypt' in request.form, 'smart_anonymity' in request.form
        aes_password, max_views = request.form.get('aes_password'), int(request.form.get('max_views', 30))

        error = None
        if not files or files[0].filename == '': error = 'No files selected.'
        elif not (password and 8 <= len(password) <= 16): error = 'Deletion password must be 8-16 characters.'
        elif aes_encrypt and not aes_password: error = 'AES encryption requires its own password.'
        if error: return render_template_string(UPLOAD_PAGE_TEMPLATE, error=error, JURISDICTION=JURISDICTION)
        
        last_upload_time, processed_files = time.time(), []
        password_hash = get_password_hash(password)

        for file in files:
            if file and file.filename:
                original_filename, ext = file.filename, os.path.splitext(file.filename)[1].lower()
                obfuscated_name = generate_random_filename(ext)
                temp_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_' + obfuscated_name)
                final_path = os.path.join(app.config['UPLOAD_FOLDER'], obfuscated_name)
                file.save(temp_path)
                
                is_img = ext in ['.jpg', '.jpeg', '.png', '.webp']
                is_video = ext in ['.mp4', '.mov', '.avi', '.webm']
                is_nsfw = False
                
                if aes_encrypt:
                    if os.path.getsize(temp_path) > 25 * 1024 * 1024:
                        error = "AES encrypted files cannot exceed 25MB."; os.remove(temp_path); break
                    cipher = AES.new(hashlib.sha256(aes_password.encode()).digest(), AES.MODE_EAX)
                    with open(temp_path, 'rb') as f_in: ciphertext, tag = cipher.encrypt_and_digest(f_in.read())
                    with open(final_path, 'wb') as f_out: [f_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
                    delete_hours = 1
                elif is_img:
                    is_nsfw = radical_image_compression(temp_path, final_path, smart_anonymity_enabled=smart_anonymity)
                    delete_hours = DELETION_TIME_HOURS
                elif is_video:
                    radical_video_compression(temp_path, final_path)
                    delete_hours = DELETION_TIME_HOURS
                else: # Unsupported file type
                    os.remove(temp_path)
                    continue

                if os.path.exists(temp_path): os.remove(temp_path)
                
                file_id = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
                with db_lock:
                    file_db[file_id] = {'path': final_path, 'password_hash': password_hash, 'delete_at': datetime.now(timezone.utc) + timedelta(hours=delete_hours),'size_mb': os.path.getsize(final_path)/(1024*1024),'original_name': original_filename, 'views': 0,'max_views': max(5, min(50, max_views)),'is_encrypted': aes_encrypt,'is_video': is_video,'aes_password': aes_password if aes_encrypt else None,'uploaded_at': datetime.now(timezone.utc), 'is_nsfw': is_nsfw}
                processed_files.append({'id': file_id, 'original_name': original_filename, 'size_mb': file_db[file_id]['size_mb'], 'is_video': is_video, 'delete_at': file_db[file_id]['delete_at'], 'views_left': file_db[file_id]['max_views'], 'max_views': file_db[file_id]['max_views'], 'is_encrypted': aes_encrypt, 'aes_password': aes_password if aes_encrypt else None, 'is_nsfw': is_nsfw})

        if error: return render_template_string(UPLOAD_PAGE_TEMPLATE, error=error, JURISDICTION=JURISDICTION)
        manage_storage()
        return render_template_string(RESULT_PAGE_TEMPLATE, files=processed_files, masked_password=mask_password(password))
    return render_template_string(UPLOAD_PAGE_TEMPLATE, JURISDICTION=JURISDICTION)

@app.route('/view/<file_id>')
def view_file(file_id):
    with db_lock:
        meta = file_db.get(file_id)
        if not meta or not os.path.exists(meta.get('path','')): return "File not found or has been deleted.", 404
        
        # Check for immediate deletion conditions
        is_expired = meta['delete_at'] <= datetime.now(timezone.utc)
        is_max_views = meta['views'] >= meta['max_views']

        if is_expired or is_max_views:
            secure_delete(meta['path'])
            file_db.pop(file_id, None)
            return "File not found or has been deleted.", 404

        meta['views'] += 1
    
    if meta['is_encrypted']: return "This file is AES-256 encrypted. Download and decrypt it.", 403

    # Handle NSFW content
    if meta.get('is_nsfw', False) and not meta.get('is_video', False):
        import base64
        with open(meta['path'], 'rb') as f:
            image_data = base64.b64encode(f.read()).decode()
        mimetype, _ = mimetypes.guess_type(meta['path'])
        return render_template_string(NSFW_VIEW_TEMPLATE, 
                                    image_data=image_data, 
                                    mimetype=mimetype or 'image/jpeg',
                                    file_id=file_id,
                                    JURISDICTION=JURISDICTION)

    mimetype, _ = mimetypes.guess_type(meta['path'])
    with open(meta['path'], 'rb') as f:
        response = make_response(f.read())
    response.headers['Content-Type'] = mimetype or 'application/octet-stream'
    response.headers['Content-Disposition'] = f'inline; filename="{meta.get("original_name", file_id)}"'
    return response

@app.route('/delete', methods=['POST'])
def delete_file_post():
    password = request.form.get('delete_password')
    if not password: return redirect(url_for('upload_file'))
    password_hash, deleted_count = get_password_hash(password), 0
    feedback = "Incorrect password or no files to delete."
    with db_lock:
        ids_to_delete = [fid for fid, meta in file_db.items() if meta.get('password_hash') == password_hash]
        if ids_to_delete:
            for fid in ids_to_delete:
                if fid in file_db and os.path.exists(file_db[fid].get('path','')):
                    secure_delete(file_db[fid]['path']); file_db.pop(fid, None); deleted_count += 1
            if deleted_count > 0: feedback = f"Successfully deleted {deleted_count} file(s)."
    return render_template_string(UPLOAD_PAGE_TEMPLATE, deletion_feedback=feedback, JURISDICTION=JURISDICTION)

@app.route('/delete/<file_id>')
def delete_file_get(file_id):
    with db_lock:
        if file_id in file_db and os.path.exists(file_db[file_id].get('path','')):
            secure_delete(file_db[file_id]['path']); file_db.pop(file_id, None)
            return render_template_string(DELETED_PAGE_TEMPLATE, message="File has been securely deleted.")
    return render_template_string(DELETED_PAGE_TEMPLATE, message="File not found or already deleted.")

# --- Main Execution ---
if __name__ == '__main__':
    # Initialize directories
    for folder in [UPLOAD_FOLDER, STATIC_FOLDER]:
        if not os.path.exists(folder): os.makedirs(folder)
    
    # Initialize reports database (wipes existing data)
    init_reports_database()
    
    # Start background threads
    threading.Thread(target=schedule_cleanup, daemon=True).start()
    threading.Thread(target=plausible_deniability_engine, daemon=True).start()
    
    # Start the Flask application
    app.run(host='0.0.0.0', port=5000, debug=False)
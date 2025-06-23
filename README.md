# Privacy-Preserving File Transformer

## A Tool for Anonymously Reducing Storage of Files in Vanuatu

0. [DEMO](#demo)
1. [Project Goal](#1-project-goal)
2. [Features](#2-features)
3. ![Setup & Installation](#3-setup--installation)

## DEMO
![A screenshot of the home page](https://i.ibb.co/hRyJ2nBs/image-2025-06-23-143425108.png)
![Before vs After comparison](https://i.ibb.co/tpMFvB4n/2.gif)

---

### **CRITICAL NOTICE: EDUCATIONAL PURPOSES ONLY**

This project is a **proof-of-concept** developed for **educational and research purposes only**. It demonstrates advanced techniques in file processing, anonymization, and security within a theoretical legal framework.

**DO NOT RUN THIS IN A PRODUCTION ENVIRONMENT.**

The author and contributors of this project assume **NO LIABILITY** for any misuse of this code. By downloading, cloning, or using this software, you agree that you are solely responsible for your actions and for complying with all applicable laws in your jurisdiction. This tool is not intended to facilitate illegal activity.

---

## 1. Project Goal

This application is an exploration into building a highly ephemeral, privacy-centric file transformation service. The primary goal is to accept user-uploaded files (images and videos), apply a series of destructive and anonymizing transformations to them, and drastically reduce their file size before providing a temporary access link. The entire process is designed to leave a minimal-to-zero data footprint.

## 2. Features
* 🎬 **Image and video upload**: Upload your images and videos. 
* 🪓 **EXIF data stripping**: Remove all silently added information of your files.
* 🚮 **File deletion**: Allows uploaders to remove files using a password.
* 👁️ **Deleting by views**: Automatically delete media after a certain amount of views.
* 🕛 **Ephemeral**: All files are deleted after three hours, a certain amount of views, or to recycle host storage.
* ❌ **Smart Anonymity**: Intelligent measures to anonymize more, e.g. by blurring faces, background, and text.
* 🤖 **CAPTCHA**: Requires the user to do a captcha before upload.
* 🪖 **Gutmann deletion**: US Military file shredding using the Gutmann method. Plausible deniability with background fake data generation.
* 🪖 **AES-256 password protection**: Encrypt files by password. Makes it impossible for the host to see your files. Used by the US military.
* 🅾️ **Zero-Log Policy**: The Flask server is configured to suppress all access and error logs.
* 🧠 **In-Memory Database**: File metadata is stored in a volatile Python dictionary, which is lost on application restart.
* 🚤 **Aggressive Compression**: Videos and images are heavily compressed with low bitrates and reduced resolutions to optimize speed.
* 🩶 **Color Quantization**: Images are reduced to 256 colors. This merges flat areas, enhances anonymity, and cuts down on loading time.
* 🤫 **Selective Noise**: Digital noise on high-detail area, further breaking analysis without unnecessarily slowing down loading.
* 🔈 **Audio Stripping**: All audio tracks are removed from video files.
* 🛜 **NoJS**: Supports running without JavaScript
* 🍪 **NoCookie**: Supports running without cookie
* 🫥 **No IP leakage**: We don't know your IP nor do we use it.
* 🧅 **Onion**: Works very well with minimal speed and data.

## 3. Setup & Installation

1.  **Clone the repository:**

2.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *Note: Installing `torch` and `torchvision` can be complex. Follow the official PyTorch instructions for your specific system (CPU/GPU).*

3.  **Install System Dependencies:**
    * **FFmpeg**: Required for video processing. Install it via your system's package manager (e.g., `sudo apt-get install ffmpeg`).

6.  **Run the Application (for testing only):**
    ```bash
    python3 app.py
    ```
or
    ```bash
    gunicorn --workers 4 --bind 0.0.0.0:8000 app:app
    ```

## License
This project is licensed under the **GNU AGPLv3 License**.  
See the [LICENSE](./LICENSE) file for details. Educational use only. No warranty.

# Privacy-Preserving File Transformer

## A Tool for Anonymously Reducing Storage of Files in Vanuatu

---

### **CRITICAL NOTICE: EDUCATIONAL PURPOSES ONLY**

This project is a **proof-of-concept** developed for **educational and research purposes only**. It demonstrates advanced techniques in file processing, anonymization, and security within a theoretical legal framework.

**DO NOT RUN THIS IN A PRODUCTION ENVIRONMENT.**

The author and contributors of this project assume **NO LIABILITY** for any misuse of this code. By downloading, cloning, or using this software, you agree that you are solely responsible for your actions and for complying with all applicable laws in your jurisdiction. This tool is not intended to facilitate illegal activity.

---

## 1. Project Goal

This application is an exploration into building a highly ephemeral, privacy-centric file transformation service. The primary goal is to accept user-uploaded files (images and videos), apply a series of destructive and anonymizing transformations to them, and drastically reduce their file size before providing a temporary access link. The entire process is designed to leave a minimal-to-zero data footprint.

## 2. Core Features

### Anonymization & Privacy
* **Jurisdictional Shield**: The service is theoretically bound to the laws of **Vanuatu**, chosen for its privacy-forward legal landscape.
* **Face Blurring**: Automatically detects faces in images using a Haar Cascade classifier and applies an unidentifiable, proportional Gaussian blur.
* **Text Blurring**: Utilizes the `EasyOCR` engine to find and blur any discernible text within an image.
* **Background Removal/Blurring**: Isolates the main subject of an image (using `rembg`) and heavily blurs the background to remove contextual information.
* **Ephemeral by Design**: All files are automatically and securely deleted after a set time (`3 hours`) or a maximum view count (`5-50 views`).
* **Secure Deletion**: Files are overwritten using a multi-pass algorithm (inspired by Gutmann) before being deleted from the filesystem, making recovery computationally infeasible.
* **Zero-Log Policy**: The Flask server is configured to suppress all access and error logs.
* **In-Memory Database**: File metadata is stored in a volatile Python dictionary, which is lost on application restart.

### Storage & Data Reduction
* **Aggressive Compression**: Videos and images are heavily compressed with low bitrates and reduced resolutions to minimize storage.
* **Color Quantization**: Images are posterized, reducing the color palette to just 16 colors. This merges flat areas, enhances anonymity, and significantly cuts down on file size.
* **Selective Noise**: A small amount of digital noise is added only to high-detail areas of an image, further breaking forensic analysis without unnecessarily increasing file size.
* **Audio Stripping**: All audio tracks are removed from video files.

### Security
* **Client-Side Encryption Option**: Users can choose to encrypt files with AES-256 using a password they provide. Encrypted files are not processed or compressed, ensuring end-to-end privacy.
* **Password Protection**: All uploads are tied to a user-provided password, which is required to delete the associated files manually before they expire.
* **Plausible Deniability Engine**: A background thread periodically generates and processes fake "decoy" uploads, making it difficult to distinguish real user activity from system noise.

## 3. Technology Stack

* **Backend**: Python 3, Flask
* **Image Processing**: OpenCV, Pillow, EasyOCR, rembg
* **Cryptography**: PyCryptodome
* **WSGI Server (recommended)**: Gunicorn

## 4. Setup & Installation

1.  **Clone the repository:**
    ```bash
    git clone [your-repository-url]
    cd [repository-directory]
    ```

2.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    # Or manually:
    # pip install Flask Pillow pycryptodome captcha opencv-python rembg easyocr torch torchvision
    ```
    *Note: Installing `torch` and `torchvision` can be complex. Follow the official PyTorch instructions for your specific system (CPU/GPU).*

3.  **Install System Dependencies:**
    * **FFmpeg**: Required for video processing. Install it via your system's package manager (e.g., `sudo apt-get install ffmpeg`).

4.  **Download Haar Cascade Model:**
    * Download the `haarcascade_frontalface_default.xml` file from the [OpenCV GitHub repository](https://github.com/opencv/opencv/tree/master/data/haarcascades).
    * Place it in the root directory of the project.

5.  **Create Directories:**
    ```bash
    mkdir uploads
    mkdir static
    ```

6.  **Run the Application (for testing only):**
    ```bash
    python3 app.py
    ```

7.  **Run with a Production Server (Theoretical):**
    ```bash
    gunicorn --workers 4 --bind 0.0.0.0:8000 app:app
    ```

## License
This project is licensed under the **GNU AGPLv3 License**.  
See the [LICENSE](./LICENSE) file for details. Educational use only. No warranty.

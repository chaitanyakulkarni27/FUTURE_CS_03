# Secure File Sharing System

A secure file upload/download portal with AES-256 encryption for files at rest and in transit.

## Features

- **AES-256 Encryption**: Military-grade encryption for files at rest
- **PBKDF2 Key Derivation**: Secure password-based key derivation
- **CBC Mode with Random IV**: Unique initialization vector for each file
- **Secure File Upload/Download**: End-to-end encrypted file sharing
- **Modern Web Interface**: Clean, responsive design with real-time feedback
- **Password Strength Indicator**: Visual password strength meter
- **Share Code System**: Unique codes for file sharing
- **HTTPS Ready**: Built for secure communication

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd secure-file-sharing
```

2. Create a virtual environment:
```bash
python -m venv venv  # If this is not working then use this: python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
3. Install dependencies:
```bash
pip install -r requirements.txt   # If this is not working then use this: pip3 install -r requirements.txt
```
4. Run the application:
```bash
python app.py
```
5.Open your browser and navigate to:
```bash
https://localhost:5000
```

## Usage
 **Uploading a File**
1. Click on "Upload & Encrypt" tab
2. Select a file (max 16MB)
3. Enter a strong password
4. Click "Encrypt & Upload"
5. Share the generated code with the recipient

**Downloading a File**
1. Click on "Download & Decrypt" tab
2. Enter the share code
3. Enter the decryption password
4. Click "Decrypt & Download"

**Security Notes**
- Password Security: The system relies on password strength. Always use strong, unique passwords.
- Share Codes: Share codes and passwords should be transmitted through separate channels.
- Temporary Files: The system automatically cleans up temporary decrypted files.
- HTTPS: Always deploy with HTTPS in production for secure communication.

**Limitations**
- Maximum file size: 16MB (configurable)
- Supported file types: txt, pdf, png, jpg, jpeg, gif, doc, docx, zip
- Files are stored on the server (consider cloud storage for production)
 
**License*
- MIT License
 
 @Project By Chaitanya.R.Kulkarni

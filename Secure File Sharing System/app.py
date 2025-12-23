import os
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, request, send_file, jsonify
from werkzeug.utils import secure_filename
from urllib.parse import quote, unquote
import pyaes
import pbkdf2
import secrets
import hashlib

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ENCRYPTED_FOLDER'] = 'encrypted_files'
app.config['METADATA_FILE'] = 'file_metadata.json'
app.config['ALLOWED_EXTENSIONS'] = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 
    'doc', 'docx', 'zip', 'mp4', 'mp3', 'pptx', 'xlsx'
}

# Create directories if they don't exist
for folder in [app.config['UPLOAD_FOLDER'], app.config['ENCRYPTED_FOLDER']]:
    os.makedirs(folder, exist_ok=True)

class AESFileEncryptor:
    """Handles AES-256 encryption/decryption of files"""
    
    def __init__(self, password):
        self.password = password.encode('utf-8')
    
    def _derive_key_and_iv(self, salt):
        """Derive AES key and IV from password using PBKDF2"""
        derived_key = pbkdf2.PBKDF2(
            self.password, 
            salt, 
            iterations=100000,
            digestmodule=hashlib.sha256
        ).read(48)  # 32 bytes for key + 16 bytes for IV
        
        key = derived_key[:32]   # AES-256 key
        iv = derived_key[32:48]  # IV for CBC mode
        return key, iv
    
    def encrypt_file(self, input_path, output_path):
        """Encrypt file using AES-256 CBC mode"""
        # Generate random salt
        salt = secrets.token_bytes(16)
        
        # Derive key and IV
        key, iv = self._derive_key_and_iv(salt)
        
        # Read file
        with open(input_path, 'rb') as f:
            plaintext = f.read()
        
        # PKCS7 padding
        padding_length = 16 - (len(plaintext) % 16)
        plaintext += bytes([padding_length]) * padding_length
        
        # Encrypt in 16-byte blocks
        aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
        ciphertext = b''
        
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            ciphertext += aes.encrypt(block)
        
        # Write salt + ciphertext
        with open(output_path, 'wb') as f:
            f.write(salt + ciphertext)
        
        # Clean up original
        if os.path.exists(input_path):
            os.remove(input_path)
        
        return output_path
    
    def decrypt_file(self, input_path, output_path):
        """Decrypt file using AES-256 CBC mode"""
        # Read encrypted file
        with open(input_path, 'rb') as f:
            data = f.read()
        
        # Extract salt and ciphertext
        salt = data[:16]
        ciphertext = data[16:]
        
        # Derive key and IV
        key, iv = self._derive_key_and_iv(salt)
        
        # Decrypt in 16-byte blocks
        aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
        plaintext = b''
        
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            plaintext += aes.decrypt(block)
        
        # Remove PKCS7 padding
        padding_length = plaintext[-1]
        if 1 <= padding_length <= 16:
            plaintext = plaintext[:-padding_length]
        
        # Write decrypted file
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        return output_path

# Helper Functions
def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_share_code():
    """Generate a unique share code"""
    return secrets.token_urlsafe(12)

def generate_link_token():
    """Generate secure token for share links"""
    return secrets.token_urlsafe(32)

def load_metadata():
    """Load metadata from JSON file"""
    metadata_file = app.config['METADATA_FILE']
    if os.path.exists(metadata_file):
        try:
            with open(metadata_file, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_metadata(metadata):
    """Save metadata to JSON file"""
    with open(app.config['METADATA_FILE'], 'w') as f:
        json.dump(metadata, f, indent=2)

def add_file_metadata(share_code, filename, file_size, upload_time, password_hash, expires_days=7):
    """Add new file metadata"""
    metadata = load_metadata()
    
    metadata[share_code] = {
        'filename': filename,
        'file_size': file_size,
        'upload_time': upload_time,
        'password_hash': password_hash,
        'download_count': 0,
        'last_download': None,
        'share_links': [],
        'expires_at': (datetime.now() + timedelta(days=expires_days)).isoformat(),
        'created_at': datetime.now().isoformat()
    }
    
    save_metadata(metadata)
    return metadata[share_code]

def update_download_metadata(share_code):
    """Update download statistics"""
    metadata = load_metadata()
    if share_code in metadata:
        metadata[share_code]['download_count'] += 1
        metadata[share_code]['last_download'] = datetime.now().isoformat()
        save_metadata(metadata)

def add_share_link(share_code, token, expires_hours=168):
    """Add a share link to file metadata"""
    metadata = load_metadata()
    if share_code in metadata:
        link_data = {
            'token': token,
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(hours=expires_hours)).isoformat(),
            'downloads': 0
        }
        
        if 'share_links' not in metadata[share_code]:
            metadata[share_code]['share_links'] = []
        
        metadata[share_code]['share_links'].append(link_data)
        save_metadata(metadata)

def get_all_files():
    """Get list of all uploaded files"""
    metadata = load_metadata()
    files = []
    
    for share_code, file_info in metadata.items():
        # Add share code to info
        file_info['share_code'] = share_code
        
        # Check if encrypted file exists
        encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], f"{share_code}.enc")
        file_info['encrypted_path'] = encrypted_path
        file_info['exists'] = os.path.exists(encrypted_path)
        
        # Check expiration
        if 'expires_at' in file_info:
            expires_at = datetime.fromisoformat(file_info['expires_at'])
            file_info['expired'] = datetime.now() > expires_at
        else:
            file_info['expired'] = False
        
        files.append(file_info)
    
    return files

def create_download_link(share_code, filename, expires_hours=168):
    """Create secure download link"""
    token = generate_link_token()
    expires_at = datetime.now() + timedelta(hours=expires_hours)
    
    # Store token in metadata
    add_share_link(share_code, token, expires_hours)
    
    # Create the link
    base_url = request.host_url.rstrip('/') if request.host_url else 'http://localhost:5000'
    encoded_filename = quote(filename)
    
    return f"{base_url}/download/{share_code}/{token}/{encoded_filename}", expires_at

def format_file_size(bytes_size):
    """Format file size to human readable format"""
    if bytes_size == 0:
        return "0 Bytes"
    
    units = ['Bytes', 'KB', 'MB', 'GB']
    i = 0
    while bytes_size >= 1024 and i < len(units) - 1:
        bytes_size /= 1024.0
        i += 1
    
    return f"{bytes_size:.2f} {units[i]}"

# Routes
@app.route('/')
def index():
    """Home page"""
    files = get_all_files()
    return render_template('index.html', files=files)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and encryption"""
    # Check if file was uploaded
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    file = request.files['file']
    password = request.form.get('password', '')
    custom_name = request.form.get('file_name', '')
    expires_days = request.form.get('expires_days', '7')
    
    # Validate inputs
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if not password:
        return jsonify({'success': False, 'error': 'Password is required'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'File type not allowed'}), 400
    
    try:
        # Parse expiration days
        expires_days = int(expires_days)
        if expires_days < 1 or expires_days > 365:
            expires_days = 7
    except ValueError:
        expires_days = 7
    
    try:
        # Get file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        # Check file size limit
        if file_size > app.config['MAX_CONTENT_LENGTH']:
            return jsonify({'success': False, 'error': 'File too large (max 16MB)'}), 400
        
        # Determine filename
        if custom_name:
            original_filename = secure_filename(custom_name)
            # Add extension if missing
            if '.' not in original_filename:
                ext = file.filename.rsplit('.', 1)[1].lower()
                original_filename = f"{original_filename}.{ext}"
        else:
            original_filename = secure_filename(file.filename)
        
        # Generate unique temp filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_filename = f"{timestamp}_{original_filename}"
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
        
        # Save uploaded file temporarily
        file.save(temp_path)
        
        # Generate share code and metadata
        share_code = generate_share_code()
        upload_time = datetime.now().isoformat()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Encrypt the file
        encryptor = AESFileEncryptor(password)
        encrypted_filename = f"{share_code}.enc"
        encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], encrypted_filename)
        
        encryptor.encrypt_file(temp_path, encrypted_path)
        
        # Save metadata
        file_info = add_file_metadata(share_code, original_filename, file_size, 
                                     upload_time, password_hash, expires_days)
        
        # Create share link
        share_link, expires_at = create_download_link(share_code, original_filename, expires_days * 24)
        
        return jsonify({
            'success': True,
            'share_code': share_code,
            'filename': original_filename,
            'file_size': file_size,
            'upload_time': upload_time,
            'expires_at': expires_at.isoformat(),
            'share_link': share_link,
            'message': 'File uploaded and encrypted successfully!'
        })
        
    except Exception as e:
        app.logger.error(f"Upload error: {str(e)}")
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'}), 500

@app.route('/download', methods=['POST'])
def download_file():
    """Download file with password (traditional method)"""
    try:
        share_code = request.form.get('share_code', '').strip()
        password = request.form.get('password', '')
        
        if not share_code or not password:
            return jsonify({'success': False, 'error': 'Share code and password are required'}), 400
        
        # Check if file exists
        encrypted_file = os.path.join(app.config['ENCRYPTED_FOLDER'], f"{share_code}.enc")
        if not os.path.exists(encrypted_file):
            return jsonify({'success': False, 'error': 'File not found or invalid share code'}), 404
        
        # Get file info from metadata
        metadata = load_metadata()
        if share_code not in metadata:
            original_filename = f"file_{share_code}"
        else:
            original_filename = metadata[share_code]['filename']
            
            # Check if password matches
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if password_hash != metadata[share_code].get('password_hash'):
                return jsonify({'success': False, 'error': 'Incorrect password'}), 401
        
        # Decrypt file
        encryptor = AESFileEncryptor(password)
        temp_filename = f"temp_{share_code}.dec"
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
        
        try:
            encryptor.decrypt_file(encrypted_file, temp_path)
        except Exception as e:
            return jsonify({'success': False, 'error': 'Decryption failed. Wrong password or corrupted file.'}), 400
        
        # Update download stats
        update_download_metadata(share_code)
        
        # Send file
        response = send_file(
            temp_path,
            as_attachment=True,
            download_name=original_filename,
            mimetype='application/octet-stream'
        )
        
        # Clean up temp file after download
        @response.call_on_close
        def cleanup():
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except:
                pass
        
        return response
        
    except Exception as e:
        app.logger.error(f"Download error: {str(e)}")
        return jsonify({'success': False, 'error': 'Download failed. Please try again.'}), 500

@app.route('/download/<share_code>/<token>/<filename>', methods=['GET', 'POST'])
def download_via_link(share_code, token, filename):
    """Download via share link"""
    try:
        # Get file metadata
        metadata = load_metadata()
        if share_code not in metadata:
            return render_template('error.html', error='File not found'), 404
        
        file_info = metadata[share_code]
        original_filename = unquote(filename)
        
        # Check if file has expired
        expires_at = datetime.fromisoformat(file_info['expires_at'])
        if datetime.now() > expires_at:
            return render_template('error.html', error='This file has expired'), 410
        
        # Verify token
        token_valid = False
        token_info = None
        
        for link in file_info.get('share_links', []):
            if link['token'] == token:
                token_expires = datetime.fromisoformat(link['expires_at'])
                if datetime.now() > token_expires:
                    return render_template('error.html', error='This download link has expired'), 410
                token_valid = True
                token_info = link
                break
        
        if not token_valid:
            return render_template('error.html', error='Invalid download link'), 403
        
        if request.method == 'GET':
            # Show password entry page
            return render_template('download_link.html',
                                 share_code=share_code,
                                 token=token,
                                 filename=original_filename)
        
        elif request.method == 'POST':
            # Process download
            password = request.form.get('password', '')
            if not password:
                return render_template('download_link.html',
                                     share_code=share_code,
                                     token=token,
                                     filename=original_filename,
                                     error='Password is required')
            
            # Verify password
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if password_hash != file_info.get('password_hash'):
                return render_template('download_link.html',
                                     share_code=share_code,
                                     token=token,
                                     filename=original_filename,
                                     error='Incorrect password')
            
            # Decrypt file
            encrypted_file = os.path.join(app.config['ENCRYPTED_FOLDER'], f"{share_code}.enc")
            temp_filename = f"temp_{share_code}_{token}.dec"
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
            
            encryptor = AESFileEncryptor(password)
            encryptor.decrypt_file(encrypted_file, temp_path)
            
            # Update download stats
            update_download_metadata(share_code)
            if token_info:
                token_info['downloads'] = token_info.get('downloads', 0) + 1
                save_metadata(metadata)
            
            # Send file
            response = send_file(
                temp_path,
                as_attachment=True,
                download_name=original_filename,
                mimetype='application/octet-stream'
            )
            
            # Clean up temp file
            @response.call_on_close
            def cleanup():
                try:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                except:
                    pass
            
            return response
            
    except Exception as e:
        app.logger.error(f"Link download error: {str(e)}")
        return render_template('error.html', error='Download failed. Please try again.'), 500

@app.route('/api/files', methods=['GET'])
def get_files_api():
    """API to get all files"""
    files = get_all_files()
    return jsonify({'success': True, 'files': files})

@app.route('/api/create-link', methods=['POST'])
def create_share_link_api():
    """API to create a new share link"""
    try:
        data = request.get_json()
        share_code = data.get('share_code', '').strip()
        expires_hours = data.get('expires_hours', 168)  # Default 7 days
        
        metadata = load_metadata()
        if share_code not in metadata:
            return jsonify({'success': False, 'error': 'File not found'}), 404
        
        file_info = metadata[share_code]
        share_link, expires_at = create_download_link(share_code, file_info['filename'], expires_hours)
        
        return jsonify({
            'success': True,
            'share_link': share_link,
            'expires_at': expires_at.isoformat(),
            'message': 'Share link created successfully'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/delete/<share_code>', methods=['DELETE'])
def delete_file_api(share_code):
    """API to delete a file"""
    try:
        # Delete encrypted file
        encrypted_file = os.path.join(app.config['ENCRYPTED_FOLDER'], f"{share_code}.enc")
        if os.path.exists(encrypted_file):
            os.remove(encrypted_file)
        
        # Remove from metadata
        metadata = load_metadata()
        if share_code in metadata:
            del metadata[share_code]
            save_metadata(metadata)
        
        return jsonify({'success': True, 'message': 'File deleted successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/cleanup', methods=['POST'])
def cleanup():
    """Clean up expired files and temp files"""
    try:
        cleaned_temp = 0
        cleaned_expired = 0
        
        # Clean temp files
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            if filename.startswith('temp_') or filename.endswith('.dec'):
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                if os.path.isfile(file_path):
                    os.remove(file_path)
                    cleaned_temp += 1
        
        # Clean expired files
        metadata = load_metadata()
        expired_files = []
        
        for share_code, file_info in metadata.items():
            expires_at = datetime.fromisoformat(file_info['expires_at'])
            if datetime.now() > expires_at:
                # Delete encrypted file
                encrypted_file = os.path.join(app.config['ENCRYPTED_FOLDER'], f"{share_code}.enc")
                if os.path.exists(encrypted_file):
                    os.remove(encrypted_file)
                expired_files.append(share_code)
                cleaned_expired += 1
        
        # Remove from metadata
        for share_code in expired_files:
            del metadata[share_code]
        
        if expired_files:
            save_metadata(metadata)
        
        return jsonify({
            'success': True,
            'message': f'Cleaned {cleaned_temp} temp files and {cleaned_expired} expired files'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.errorhandler(413)
def too_large(e):
    return jsonify({'success': False, 'error': 'File too large (max 16MB)'}), 413

@app.errorhandler(404)
def not_found(e):
    return jsonify({'success': False, 'error': 'Page not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

# Application entry point
if __name__ == '__main__':
    print("=" * 50)
    print("Secure File Sharing System")
    print("=" * 50)
    print(f"Upload folder: {app.config['UPLOAD_FOLDER']}")
    print(f"Encrypted files folder: {app.config['ENCRYPTED_FOLDER']}")
    print(f"Server running on: http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)
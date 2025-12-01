"""
Integrated Cloud Platform - Main Application
Merges CloudSim distributed storage with CloudTemplate authentication
"""

import os
import sys
import json
import time
import hashlib
import tempfile
import threading
import smtplib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_socketio import SocketIO, emit
import jwt
import bcrypt
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Import CloudSim components
sys.path.append(os.path.join(os.path.dirname(__file__), 'CloudSim'))
from virtual_node import VirtualNode
from network_manager import NetworkManager
from virtual_disk import VirtualDisk

# Flask App Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key_here_change_in_production'
socketio = SocketIO(app, cors_allowed_origins="*")

# Constants
JWT_SECRET = 'your_jwt_secret_key_here_change_in_production'
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24
USERS_FILE = 'integrated_users.json'
SYSTEM_CONFIG_FILE = 'system_config.json'
EMAIL_CONFIG_FILE = 'email_config.json'
FILE_SHARES_FILE = 'file_shares.json'

# Global System State
system_network = None
user_nodes = {}  # {user_id: {node_id: VirtualNode}}
user_sessions = {}  # {session_id: user_data}
system_metrics = {
    'total_users': 0,
    'active_users': 0,
    'total_nodes': 0,
    'total_storage_gb': 0,
    'active_transfers': 0,
    'system_uptime': time.time()
}

@dataclass
class FileShare:
    share_id: str
    owner_id: str
    file_id: str
    file_name: str
    shared_with: str  # username or 'public'
    permissions: List[str]  # ['read', 'write', 'delete']
    created_at: str
    expires_at: Optional[str] = None

class EmailService:
    def __init__(self):
        self.config = self.load_email_config()
    
    def load_email_config(self):
        if os.path.exists(EMAIL_CONFIG_FILE):
            with open(EMAIL_CONFIG_FILE, 'r') as f:
                return json.load(f)
        return {
            'from_email': 'your_email@gmail.com',
            'app_password': 'your_app_password',
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587
        }
    
    def send_email(self, to_email: str, subject: str, body: str) -> bool:
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config['from_email']
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port']) as server:
                server.starttls()
                server.login(self.config['from_email'], self.config['app_password'])
                server.send_message(msg)
            return True
        except Exception as e:
            print(f"Email failed: {e}")
            return False

class UserService:
    def __init__(self):
        self.users = self.load_users()
        self.email_service = EmailService()
        self.active_otps = {}
        self.file_shares = self.load_file_shares()
    
    def load_users(self) -> Dict[str, Dict]:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        return {}
    
    def save_users(self):
        with open(USERS_FILE, 'w') as f:
            json.dump(self.users, f, indent=2)
    
    def load_file_shares(self) -> List[Dict]:
        if os.path.exists(FILE_SHARES_FILE):
            with open(FILE_SHARES_FILE, 'r') as f:
                return json.load(f)
        return []
    
    def save_file_shares(self):
        with open(FILE_SHARES_FILE, 'w') as f:
            json.dump(self.file_shares, f, indent=2)
    
    def generate_otp(self) -> str:
        return str(hashlib.md5(f"{time.time()}{os.urandom(4)}".encode()).hexdigest())[:6].upper()
    
    def hash_password(self, password: str) -> str:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def create_user(self, username: str, email: str, password: str, full_name: str) -> Dict:
        if username in self.users:
            return {'success': False, 'message': 'Username already exists'}
        
        user_data = {
            'user_id': hashlib.md5(f"{username}{time.time()}".encode()).hexdigest(),
            'username': username,
            'email': email,
            'full_name': full_name,
            'password_hash': self.hash_password(password),
            'is_active': False,
            'is_admin': len(self.users) == 0,  # First user is admin
            'storage_quota_gb': 10.0,  # Default 10GB quota
            'created_at': datetime.utcnow().isoformat(),
            'last_login': None,
            'phone': None,
            'profile_settings': {
                'theme': 'light',
                'notifications': True,
                'language': 'en'
            }
        }
        
        self.users[username] = user_data
        self.save_users()
        
        # Send activation OTP
        otp = self.generate_otp()
        self.active_otps[username] = {
            'otp': otp,
            'expires_at': (datetime.utcnow() + timedelta(minutes=10)).isoformat(),
            'purpose': 'activation'
        }
        
        # Send email
        subject = "Activate Your Cloud Account"
        body = f"""
        Hello {full_name},
        
        Welcome to our Cloud Platform! Your account has been created.
        
        Your activation code is: {otp}
        
        This code will expire in 10 minutes.
        
        Best regards,
        Cloud Platform Team
        """
        
        self.email_service.send_email(email, subject, body)
        
        return {'success': True, 'message': 'Account created. Please check your email for activation code.'}
    
    def authenticate_user(self, username: str, password: str) -> Dict:
        if username not in self.users:
            return {'success': False, 'message': 'Invalid username or password'}
        
        user = self.users[username]
        if not user['is_active']:
            return {'success': False, 'message': 'Account not activated'}
        
        if not self.verify_password(password, user['password_hash']):
            return {'success': False, 'message': 'Invalid username or password'}
        
        # Update last login
        self.users[username]['last_login'] = datetime.utcnow().isoformat()
        self.save_users()
        
        # Create JWT token
        token = jwt.encode({
            'sub': username,
            'user_id': user['user_id'],
            'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
        }, JWT_SECRET, algorithm=JWT_ALGORITHM)
        
        return {'success': True, 'token': token, 'user': user}
    
    def verify_otp(self, username: str, otp: str) -> Dict:
        if username not in self.active_otps:
            return {'success': False, 'message': 'No active OTP found'}
        
        otp_data = self.active_otps[username]
        
        # Check expiration
        expiry_time = datetime.fromisoformat(otp_data['expires_at'])
        if datetime.utcnow() > expiry_time:
            del self.active_otps[username]
            return {'success': False, 'message': 'OTP has expired'}
        
        if otp_data['otp'] != otp:
            return {'success': False, 'message': 'Invalid OTP'}
        
        # Handle different purposes
        if otp_data.get('purpose') == 'activation':
            self.users[username]['is_active'] = True
            self.save_users()
            message = 'Account activated successfully!'
        else:
            message = 'OTP verified successfully!'
        
        del self.active_otps[username]
        return {'success': True, 'message': message}
    
    def get_user_by_token(self, token: str) -> Optional[Dict]:
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            username = payload['sub']
            if username in self.users:
                return self.users[username]
        except:
            pass
        return None
    
    def get_all_users(self) -> List[Dict]:
        return list(self.users.values())
    
    def update_user_quota(self, username: str, new_quota_gb: float) -> bool:
        if username in self.users:
            self.users[username]['storage_quota_gb'] = new_quota_gb
            self.save_users()
            return True
        return False
    
    def update_user_profile(self, username: str, profile_data: Dict) -> bool:
        if username in self.users:
            self.users[username].update(profile_data)
            self.save_users()
            return True
        return False
    
    def create_file_share(self, owner_id: str, file_id: str, file_name: str, shared_with: str, permissions: List[str]) -> str:
        share_id = hashlib.md5(f"{owner_id}{file_id}{shared_with}{time.time()}".encode()).hexdigest()
        
        share = FileShare(
            share_id=share_id,
            owner_id=owner_id,
            file_id=file_id,
            file_name=file_name,
            shared_with=shared_with,
            permissions=permissions,
            created_at=datetime.utcnow().isoformat()
        )
        
        self.file_shares.append(asdict(share))
        self.save_file_shares()
        
        # Send notification email
        if shared_with != 'public':
            shared_user = next((u for u in self.users.values() if u['username'] == shared_with), None)
            if shared_user:
                subject = f"File Shared With You: {file_name}"
                body = f"""
                Hello {shared_user['full_name']},
                
                A file has been shared with you on the Cloud Platform.
                
                File: {file_name}
                Permissions: {', '.join(permissions)}
                
                Login to your dashboard to access the file.
                
                Best regards,
                Cloud Platform Team
                """
                self.email_service.send_email(shared_user['email'], subject, body)
        
        return share_id
    
    def get_user_file_shares(self, user_id: str) -> List[Dict]:
        user_shares = []
        for share in self.file_shares:
            if share['owner_id'] == user_id or share['shared_with'] == user_id or share['shared_with'] == 'public':
                user_shares.append(share)
        return user_shares

class CloudNodeManager:
    def __init__(self):
        self.user_nodes = {}  # {user_id: {node_id: VirtualNode}}
        self.shared_network = NetworkManager(use_localhost=True)
        self.user_files = {}  # {user_id: {file_id: file_info}}
    
    def create_user_node(self, user_id: str, username: str, capacity_gb: float = 2) -> str:
        node_id = f"{username}_node_{len(self.user_nodes.get(user_id, {}))}"
        
        node = VirtualNode(
            node_id=node_id,
            capacity_gb=int(capacity_gb),
            port=8000 + len(self.user_nodes.get(user_id, {})),
            use_localhost=True,
            shared_network_manager=self.shared_network
        )
        
        if user_id not in self.user_nodes:
            self.user_nodes[user_id] = {}
        
        self.user_nodes[user_id][node_id] = node
        return node_id
    
    def get_user_nodes(self, user_id: str) -> Dict[str, VirtualNode]:
        return self.user_nodes.get(user_id, {})
    
    def get_node_stats(self, user_id: str) -> Dict:
        user_nodes = self.get_user_nodes(user_id)
        stats = {
            'total_nodes': len(user_nodes),
            'total_storage_gb': 0,
            'used_storage_gb': 0,
            'files_stored': 0,
            'active_transfers': 0
        }
        
        for node in user_nodes.values():
            try:
                node_stats = node.get_node_stats()
                stats['total_storage_gb'] += node_stats['storage']['capacity_gb']
                stats['used_storage_gb'] += (node_stats['storage']['allocated_blocks'] / 
                                           node_stats['storage']['total_blocks']) * node_stats['storage']['capacity_gb']
                stats['files_stored'] += node_stats['storage']['files_stored']
                stats['active_transfers'] += node_stats['performance']['active_transfers']
            except:
                pass
        
        return stats
    
    def distribute_user_file(self, user_id: str, username: str, file_path: str, replication_factor: int = 2) -> Dict:
        user_nodes = self.get_user_nodes(user_id)
        if not user_nodes:
            return {'success': False, 'message': 'No nodes available. Create a node first.'}
        
        # Use the first node for distribution
        primary_node = list(user_nodes.values())[0]
        
        try:
            result = primary_node.distribute_file(file_path, replication_factor)
            
            if result.get('success'):
                # Store file metadata
                if user_id not in self.user_files:
                    self.user_files[user_id] = {}
                
                self.user_files[user_id][result['file_id']] = {
                    'filename': result['filename'],
                    'file_size': result['file_size'],
                    'chunk_count': result['chunk_count'],
                    'chunk_distribution': result['chunk_distribution'],
                    'created_at': datetime.utcnow().isoformat()
                }
                
                # Send notification email
                user = user_service.get_user_by_token(request.headers.get('Authorization', '').replace('Bearer ', '')) or {}
                if user:
                    subject = f"File Uploaded Successfully: {result['filename']}"
                    body = f"""
                    Hello {user['full_name']},
                    
                    Your file has been successfully uploaded to the cloud platform.
                    
                    File: {result['filename']}
                    Size: {result['file_size']} bytes
                    Chunks: {result['chunk_count']}
                    Distributed across {result['chunks_distributed']} nodes
                    
                    Best regards,
                    Cloud Platform Team
                    """
                    user_service.email_service.send_email(user['email'], subject, body)
            
            return result
            
        except Exception as e:
            return {'success': False, 'message': f'File distribution failed: {str(e)}'}
    
    def shutdown_user_nodes(self, user_id: str):
        if user_id in self.user_nodes:
            for node in self.user_nodes[user_id].values():
                try:
                    node.shutdown()
                except:
                    pass
            del self.user_nodes[user_id]

# Global Services
user_service = UserService()
node_manager = CloudNodeManager()

# Initialize system
def initialize_system():
    global system_network
    system_network = NetworkManager(use_localhost=True)
    
    # Load system config
    if os.path.exists(SYSTEM_CONFIG_FILE):
        with open(SYSTEM_CONFIG_FILE, 'r') as f:
            config = json.load(f)
    else:
        config = {
            'system_name': 'Integrated Cloud Platform',
            'default_user_quota_gb': 10,
            'max_nodes_per_user': 5,
            'admin_email': 'admin@cloudplatform.com'
        }
        with open(SYSTEM_CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    
    # Update system metrics
    system_metrics['total_users'] = len(user_service.users)
    system_metrics['active_users'] = len([u for u in user_service.users.values() if u['is_active']])

# Authentication Decorator
def require_auth(f):
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization') or session.get('token')
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        user = user_service.get_user_by_token(token.replace('Bearer ', '') if token.startswith('Bearer ') else token)
        if not user:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(user, *args, **kwargs)
    return decorated

def require_admin(f):
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization') or session.get('token')
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        user = user_service.get_user_by_token(token.replace('Bearer ', '') if token.startswith('Bearer ') else token)
        if not user or not user.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        return f(user, *args, **kwargs)
    return decorated

# API Routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    result = user_service.create_user(
        data['username'], 
        data['email'], 
        data['password'], 
        data['full_name']
    )
    return jsonify(result)

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    result = user_service.authenticate_user(data['username'], data['password'])
    
    if result['success']:
        session['token'] = result['token']
        session['user'] = result['user']
    
    return jsonify(result)

@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    result = user_service.verify_otp(data['username'], data['otp'])
    return jsonify(result)

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/user/profile', methods=['GET'])
@require_auth
def get_profile(user):
    return jsonify({'user': user})

@app.route('/api/user/profile', methods=['PUT'], endpoint='update_user_profile')
@require_auth
def update_user_profile(user):
    data = request.get_json()
    success = user_service.update_user_profile(user['username'], data)
    return jsonify({'success': success})

@app.route('/api/user/nodes', methods=['GET'], endpoint='get_user_nodes')
@require_auth
def get_user_nodes(user):
    nodes = node_manager.get_user_nodes(user['user_id'])
    node_list = []
    
    for node_id, node in nodes.items():
        try:
            stats = node.get_node_stats()
            node_list.append({
                'node_id': node_id,
                'ip': stats['ip'],
                'port': stats['port'],
                'uptime': stats['uptime'],
                'storage': stats['storage'],
                'performance': stats['performance']
            })
        except:
            pass
    
    return jsonify({'nodes': node_list})

@app.route('/api/user/nodes', methods=['POST'], endpoint='create_user_node')
@require_auth
def create_user_node(user):
    data = request.get_json()
    capacity_gb = data.get('capacity_gb', 2)
    
    # Check user quota
    current_nodes = len(node_manager.get_user_nodes(user['user_id']))
    if current_nodes >= 5:  # Max nodes per user
        return jsonify({'success': False, 'message': 'Maximum nodes limit reached'})
    
    node_id = node_manager.create_user_node(user['user_id'], user['username'], capacity_gb)
    return jsonify({'success': True, 'node_id': node_id})

@app.route('/api/user/storage/stats', endpoint='get_storage_stats')
@require_auth
def get_storage_stats(user):
    stats = node_manager.get_node_stats(user['user_id'])
    return jsonify(stats)

@app.route('/api/user/files/upload', methods=['POST'], endpoint='upload_file')
@require_auth
def upload_file(user):
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'})
    
    # Save file temporarily
    temp_path = tempfile.mktemp()
    file.save(temp_path)
    
    try:
        result = node_manager.distribute_user_file(user['user_id'], user['username'], temp_path)
        return jsonify(result)
    finally:
        os.unlink(temp_path)

@app.route('/api/user/files/shares', endpoint='get_file_shares')
@require_auth
def get_file_shares(user):
    shares = user_service.get_user_file_shares(user['user_id'])
    return jsonify({'shares': shares})

@app.route('/api/user/files/share', methods=['POST'], endpoint='create_file_share')
@require_auth
def create_file_share(user):
    data = request.get_json()
    share_id = user_service.create_file_share(
        user['user_id'],
        data['file_id'],
        data['file_name'],
        data['shared_with'],
        data['permissions']
    )
    return jsonify({'success': True, 'share_id': share_id})

@app.route('/api/admin/users', endpoint='get_admin_users')
@require_admin
def get_admin_users(admin_user):
    users = user_service.get_all_users()
    return jsonify({'users': users})

@app.route('/api/admin/users/<username>/quota', methods=['PUT'], endpoint='admin_update_user_quota')
@require_admin
def admin_update_user_quota(admin_user, username):
    data = request.get_json()
    success = user_service.update_user_quota(username, data['quota_gb'])
    return jsonify({'success': success})

@app.route('/api/admin/system/metrics', endpoint='get_system_metrics')
@require_admin
def get_system_metrics(admin_user):
    # Update metrics
    system_metrics['total_users'] = len(user_service.users)
    system_metrics['active_users'] = len([u for u in user_service.users.values() if u['is_active']])
    system_metrics['total_nodes'] = sum(len(nodes) for nodes in node_manager.user_nodes.values())
    
    return jsonify(system_metrics)

# Web Routes
@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('index'))
    # Ensure user data is clean for template
    user_data = {
        'username': session['user'].get('username', ''),
        'email': session['user'].get('email', ''),
        'full_name': session['user'].get('full_name', ''),
        'is_admin': session['user'].get('is_admin', False),
        'user_id': session['user'].get('user_id', ''),
        'storage_quota_gb': session['user'].get('storage_quota_gb', 10),
        'is_active': session['user'].get('is_active', True)
    }
    return render_template('dashboard.html', user=user_data)

@app.route('/admin')
def admin():
    if 'user' not in session or not session['user'].get('is_admin'):
        return redirect(url_for('index'))
    # Ensure user data is clean for template
    user_data = {
        'username': session['user'].get('username', ''),
        'email': session['user'].get('email', ''),
        'full_name': session['user'].get('full_name', ''),
        'is_admin': session['user'].get('is_admin', False),
        'user_id': session['user'].get('user_id', ''),
        'storage_quota_gb': session['user'].get('storage_quota_gb', 10),
        'is_active': session['user'].get('is_active', True)
    }
    return render_template('admin.html', user=user_data)

# WebSocket Events
@socketio.on('connect')
def handle_connect():
    emit('status', {'message': 'Connected to cloud platform'})

@socketio.on('join_user_room')
def handle_join_user_room(data):
    user_id = data.get('user_id')
    if user_id:
        from flask_socketio import join_room
        join_room(f"user_{user_id}")

# Background Tasks
def broadcast_system_metrics():
    while True:
        socketio.emit('system_metrics', {
            'timestamp': time.time(),
            'total_users': len(user_service.users),
            'active_users': len([u for u in user_service.users.values() if u['is_active']]),
            'total_nodes': sum(len(nodes) for nodes in node_manager.user_nodes.values())
        })
        time.sleep(30)  # Update every 30 seconds

# Start background thread
metrics_thread = threading.Thread(target=broadcast_system_metrics, daemon=True)
metrics_thread.start()

if __name__ == '__main__':
    initialize_system()
    print("🚀 Starting Integrated Cloud Platform...")
    print("📊 Dashboard: http://localhost:5000")
    print("🔧 Admin Panel: http://localhost:5000/admin")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

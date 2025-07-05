from flask import Flask, request, jsonify
import json, base64, hashlib, time, re, random, os
from datetime import datetime, timedelta
import requests
import nacl.signing
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.secret_key = "octra-wallet-secret-key-2025"

# Cấu hình session cho Vercel
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='None',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

# Global variables
b58 = re.compile(r"^oct[1-9A-HJ-NP-Za-km-z]{44}$")
μ = 1_000_000

# In-memory storage để thay thế session (tạm thời)
wallet_storage = {}

def get_serializer():
    return URLSafeTimedSerializer(app.secret_key)

def generate_session_id():
    """Tạo session ID unique cho mỗi request"""
    return hashlib.sha256(f"{time.time()}{random.random()}".encode()).hexdigest()[:32]

def get_wallet_data(session_id=None):
    """Lấy wallet data từ storage"""
    if not session_id:
        return None
    
    try:
        wallet_data = wallet_storage.get(session_id)
        if not wallet_data:
            return None
            
        # Kiểm tra expiry
        if time.time() - wallet_data.get('timestamp', 0) > 3600:  # 1 hour
            del wallet_storage[session_id]
            return None
            
        # Add runtime data if not exists
        if 'cb' not in wallet_data:
            wallet_data.update({
                'cb': None,
                'cn': None,
                'lu': 0,
                'h': [],
                'lh': 0
            })
        return wallet_data
    except Exception as e:
        print(f"Error getting wallet data: {e}")
        return None

def set_wallet_data(session_id, priv_key, addr, rpc_url):
    """Lưu wallet data vào storage"""
    try:
        sk = nacl.signing.SigningKey(base64.b64decode(priv_key))
        pub = base64.b64encode(sk.verify_key.encode()).decode()
        
        wallet_data = {
            'priv': priv_key,
            'addr': addr,
            'rpc': rpc_url,
            'sk_encoded': base64.b64encode(sk.encode()).decode(),
            'pub': pub,
            'cb': None,
            'cn': None,
            'lu': 0,
            'h': [],
            'lh': 0,
            'timestamp': time.time()
        }
        
        wallet_storage[session_id] = wallet_data
        return True
    except Exception as e:
        print(f"Error setting wallet data: {e}")
        return False

def get_signing_key(wallet_data):
    """Lấy signing key từ wallet data"""
    try:
        return nacl.signing.SigningKey(base64.b64decode(wallet_data['sk_encoded']))
    except Exception as e:
        print(f"Error getting signing key: {e}")
        return None

def req(method, path, data=None, timeout=10, wallet_data=None):
    """Thực hiện HTTP request"""
    if not wallet_data:
        return 0, "No wallet loaded", None
    
    try:
        url = f"{wallet_data['rpc']}{path}"
        if method.upper() == 'POST':
            resp = requests.post(url, json=data, timeout=timeout)
        else:
            resp = requests.get(url, timeout=timeout)
        
        try:
            j = resp.json() if resp.text else None
        except:
            j = None
        return resp.status_code, resp.text, j
    except Exception as e:
        return 0, str(e), None

def get_status(session_id):
    """Lấy status của wallet"""
    wallet_data = get_wallet_data(session_id)
    if not wallet_data:
        return None, None
    
    now = time.time()
    if wallet_data['cb'] is not None and (now - wallet_data['lu']) < 30:
        return wallet_data['cn'], wallet_data['cb']
    
    try:
        s, t, j = req('GET', f'/balance/{wallet_data["addr"]}', wallet_data=wallet_data)
        if s == 200 and j:
            wallet_data['cn'] = int(j.get('nonce', 0))
            wallet_data['cb'] = float(j.get('balance', 0))
            wallet_data['lu'] = now
            wallet_storage[session_id] = wallet_data
        elif s == 404:
            wallet_data['cn'], wallet_data['cb'], wallet_data['lu'] = 0, 0.0, now
            wallet_storage[session_id] = wallet_data
        elif s == 200 and t and not j:
            try:
                parts = t.strip().split()
                if len(parts) >= 2:
                    wallet_data['cb'] = float(parts[0]) if parts[0].replace('.', '').isdigit() else 0.0
                    wallet_data['cn'] = int(parts[1]) if parts[1].isdigit() else 0
                    wallet_data['lu'] = now
                    wallet_storage[session_id] = wallet_data
                else:
                    wallet_data['cn'], wallet_data['cb'] = 0, 0.0
            except:
                wallet_data['cn'], wallet_data['cb'] = 0, 0.0
        else:
            wallet_data['cn'], wallet_data['cb'] = 0, 0.0
        
        return wallet_data['cn'], wallet_data['cb']
    except Exception as e:
        print(f"Error getting status: {e}")
        return 0, 0.0

def get_history(session_id):
    """Lấy lịch sử giao dịch"""
    wallet_data = get_wallet_data(session_id)
    if not wallet_data:
        return []
    
    now = time.time()
    if now - wallet_data['lh'] < 60 and wallet_data['h']:
        return wallet_data['h']
    
    try:
        s, t, j = req('GET', f'/address/{wallet_data["addr"]}?limit=20', wallet_data=wallet_data)
        if s != 200:
            wallet_data['lh'] = now
            wallet_storage[session_id] = wallet_data
            return wallet_data['h']
        
        if j and 'recent_transactions' in j:
            existing_hashes = {tx['hash'] for tx in wallet_data['h']}
            nh = []
            
            for ref in j.get('recent_transactions', [])[:10]:
                tx_hash = ref['hash']
                if tx_hash in existing_hashes:
                    continue
                
                s2, _, j2 = req('GET', f'/tx/{tx_hash}', None, 5, wallet_data)
                if s2 == 200 and j2 and 'parsed_tx' in j2:
                    p = j2['parsed_tx']
                    is_incoming = p.get('to') == wallet_data['addr']
                    amount_raw = p.get('amount_raw', p.get('amount', '0'))
                    amount = float(amount_raw) if '.' in str(amount_raw) else int(amount_raw) / μ
                    
                    msg = None
                    if 'data' in j2:
                        try:
                            data = json.loads(j2['data'])
                            msg = data.get('message')
                        except:
                            pass
                    
                    nh.append({
                        'time': datetime.fromtimestamp(p.get('timestamp', 0)).isoformat(),
                        'hash': tx_hash,
                        'amount': amount,
                        'address': p.get('to') if not is_incoming else p.get('from'),
                        'type': 'in' if is_incoming else 'out',
                        'confirmed': True,
                        'nonce': p.get('nonce', 0),
                        'epoch': ref.get('epoch', 0),
                        'message': msg
                    })
            
            wallet_data['h'] = sorted(nh + wallet_data['h'], key=lambda x: x['time'], reverse=True)[:20]
            wallet_data['lh'] = now
            wallet_storage[session_id] = wallet_data
        
        return wallet_data['h']
    except Exception as e:
        print(f"Error getting history: {e}")
        wallet_data['lh'] = now
        wallet_storage[session_id] = wallet_data
        return wallet_data['h']

def make_transaction(session_id, to, amount, nonce, message=None):
    """Tạo giao dịch"""
    wallet_data = get_wallet_data(session_id)
    if not wallet_data:
        return None, None
    
    sk = get_signing_key(wallet_data)
    if not sk:
        return None, None
    
    tx = {
        "from": wallet_data['addr'],
        "to_": to,
        "amount": str(int(amount * μ)),
        "nonce": int(nonce),
        "ou": "1" if amount < 1000 else "3",
        "timestamp": time.time() + random.random() * 0.01
    }
    
    if message:
        tx["message"] = message
    
    base_line = json.dumps({k: v for k, v in tx.items() if k != "message"}, separators=(",", ":"))
    signature = base64.b64encode(sk.sign(base_line.encode()).signature).decode()
    tx.update(signature=signature, public_key=wallet_data['pub'])
    
    return tx, hashlib.sha256(base_line.encode()).hexdigest()

def send_transaction(tx, wallet_data):
    """Gửi giao dịch"""
    start_time = time.time()
    status, text, json_resp = req('POST', '/send-tx', tx, wallet_data=wallet_data)
    duration = time.time() - start_time
    
    if status == 200:
        if json_resp and json_resp.get('status') == 'accepted':
            return True, json_resp.get('tx_hash', ''), duration, json_resp
        elif text and text.lower().startswith('ok'):
            return True, text.split()[-1] if ' ' in text else text, duration, None
    
    return False, json.dumps(json_resp) if json_resp else text, duration, json_resp

# API Routes
@app.route('/')
def index():
    return jsonify({'message': 'Octra Wallet API is running', 'status': 'ok'})

@app.route('/api')
@app.route('/api/')
def api_root():
    return jsonify({'message': 'Octra Wallet API', 'status': 'running', 'version': '1.0'})

@app.route('/api/wallet/login', methods=['POST'])
def wallet_login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Không có dữ liệu JSON'}), 400
        
        private_key = data.get('private_key', '').strip()
        address = data.get('address', '').strip()
        rpc_url = data.get('rpc_url', 'https://octra.network').strip()
        
        if not private_key or not address:
            return jsonify({'error': 'Vui lòng nhập đầy đủ Private Key và Address'}), 400
        
        if not b58.match(address):
            return jsonify({'error': 'Định dạng address không hợp lệ'}), 400
        
        session_id = generate_session_id()
        if set_wallet_data(session_id, private_key, address, rpc_url):
            return jsonify({
                'success': True, 
                'message': 'Đăng nhập ví thành công!',
                'session_id': session_id
            })
        else:
            return jsonify({'error': 'Private Key không hợp lệ'}), 400
    
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': f'Lỗi server: {str(e)}'}), 500

@app.route('/api/wallet/logout', methods=['POST'])
def wallet_logout():
    try:
        data = request.get_json() or {}
        session_id = data.get('session_id')
        
        if session_id and session_id in wallet_storage:
            del wallet_storage[session_id]
        
        return jsonify({'success': True, 'message': 'Đăng xuất thành công!'})
    except Exception as e:
        return jsonify({'error': f'Lỗi đăng xuất: {str(e)}'}), 500

@app.route('/api/wallet/status', methods=['GET', 'POST'])
def wallet_status():
    try:
        if request.method == 'POST':
            data = request.get_json() or {}
            session_id = data.get('session_id')
        else:
            session_id = request.args.get('session_id')
        
        if not session_id:
            return jsonify({'error': 'Session ID không được cung cấp'}), 400
        
        wallet_data = get_wallet_data(session_id)
        if not wallet_data:
            return jsonify({'error': 'Chưa đăng nhập ví'}), 401
        
        nonce, balance = get_status(session_id)
        return jsonify({
            'address': wallet_data['addr'],
            'balance': balance or 0.0,
            'nonce': nonce or 0,
            'public_key': wallet_data['pub'],
            'staging_count': 0
        })
    except Exception as e:
        print(f"Status error: {e}")
        return jsonify({'error': f'Lỗi lấy trạng thái: {str(e)}'}), 500

@app.route('/api/wallet/history', methods=['GET', 'POST'])
def wallet_history():
    try:
        if request.method == 'POST':
            data = request.get_json() or {}
            session_id = data.get('session_id')
        else:
            session_id = request.args.get('session_id')
        
        if not session_id:
            return jsonify({'error': 'Session ID không được cung cấp'}), 400
        
        wallet_data = get_wallet_data(session_id)
        if not wallet_data:
            return jsonify({'error': 'Chưa đăng nhập ví'}), 401
        
        history = get_history(session_id)
        return jsonify({'transactions': history})
    except Exception as e:
        print(f"History error: {e}")
        return jsonify({'error': f'Lỗi lấy lịch sử: {str(e)}'}), 500

@app.route('/api/wallet/send', methods=['POST'])
def send_tx():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Không có dữ liệu JSON'}), 400
        
        session_id = data.get('session_id')
        if not session_id:
            return jsonify({'error': 'Session ID không được cung cấp'}), 400
        
        wallet_data = get_wallet_data(session_id)
        if not wallet_data:
            return jsonify({'error': 'Chưa đăng nhập ví'}), 401
        
        to_address = data.get('to', '').strip()
        amount = float(data.get('amount', 0))
        message = data.get('message', '').strip() or None
        
        if not b58.match(to_address):
            return jsonify({'error': 'Định dạng address không hợp lệ'}), 400
        
        if amount <= 0:
            return jsonify({'error': 'Số tiền không hợp lệ'}), 400
        
        nonce, balance = get_status(session_id)
        if nonce is None:
            return jsonify({'error': 'Không thể lấy nonce'}), 500
        
        if not balance or balance < amount:
            return jsonify({'error': f'Số dư không đủ ({balance:.6f} < {amount})'}), 400
        
        tx, tx_hash = make_transaction(session_id, to_address, amount, nonce + 1, message)
        if not tx:
            return jsonify({'error': 'Không thể tạo giao dịch'}), 500
        
        success, result, duration, response = send_transaction(tx, wallet_data)
        
        if success:
            # Update history
            wallet_data = get_wallet_data(session_id)
            wallet_data['h'].insert(0, {
                'time': datetime.now().isoformat(),
                'hash': result,
                'amount': amount,
                'address': to_address,
                'type': 'out',
                'confirmed': True,
                'message': message,
                'nonce': nonce + 1,
                'epoch': 0
            })
            wallet_data['lu'] = 0  # Force refresh on next status check
            wallet_storage[session_id] = wallet_data
            
            return jsonify({
                'success': True,
                'tx_hash': result,
                'duration': duration,
                'pool_info': response.get('pool_info') if response else None
            })
        else:
            return jsonify({'error': result}), 400
    
    except Exception as e:
        print(f"Send transaction error: {e}")
        return jsonify({'error': f'Lỗi gửi giao dịch: {str(e)}'}), 500

@app.route('/api/wallet/export', methods=['GET', 'POST'])
def export_wallet():
    try:
        if request.method == 'POST':
            data = request.get_json() or {}
            session_id = data.get('session_id')
        else:
            session_id = request.args.get('session_id')
        
        if not session_id:
            return jsonify({'error': 'Session ID không được cung cấp'}), 400
        
        wallet_data = get_wallet_data(session_id)
        if not wallet_data:
            return jsonify({'error': 'Chưa đăng nhập ví'}), 401
        
        return jsonify({
            'private_key': wallet_data['priv'],
            'public_key': wallet_data['pub'],
            'address': wallet_data['addr'],
            'rpc': wallet_data['rpc']
        })
    except Exception as e:
        print(f"Export error: {e}")
        return jsonify({'error': f'Lỗi xuất ví: {str(e)}'}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'API endpoint không tìm thấy', 'path': request.path}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Lỗi server nội bộ'}), 500

# Export app for Vercel
app = app
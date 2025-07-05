from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json, base64, hashlib, time, re, random, os, logging, traceback
from datetime import datetime, timedelta
import requests
import nacl.signing
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException

# Cấu hình logging chi tiết
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, origins=["*"], supports_credentials=True)

# Cấu hình bảo mật
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'octra-wallet-secret-key-2025-' + os.urandom(16).hex()),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024  # 16MB max file size
)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Constants
B58_PATTERN = re.compile(r"^oct[1-9A-HJ-NP-Za-km-z]{44}$")
MICRO_UNITS = 1_000_000
SESSION_TIMEOUT = 7200  # 2 hours

# In-memory storage với TTL
wallet_storage = {}
session_cleanup_last = time.time()

class WalletError(Exception):
    """Custom exception for wallet operations"""
    pass

# ============= ERROR HANDLERS - SỬA LỖI CHÍNH =============

@app.errorhandler(400)
def bad_request_error(error):
    logger.error(f"Bad request error: {str(error)}")
    return jsonify({
        'success': False,
        'error': 'Bad Request',
        'message': 'Yêu cầu không hợp lệ hoặc thiếu thông tin bắt buộc',
        'status': 400
    }), 400

@app.errorhandler(401)
def unauthorized_error(error):
    logger.error(f"Unauthorized error: {str(error)}")
    return jsonify({
        'success': False,
        'error': 'Unauthorized',
        'message': 'Không có quyền truy cập, vui lòng đăng nhập lại',
        'status': 401
    }), 401

@app.errorhandler(404)
def not_found_error(error):
    logger.error(f"Not found error: {str(error)}")
    return jsonify({
        'success': False,
        'error': 'Not Found',
        'message': 'API endpoint không tồn tại',
        'status': 404
    }), 404

@app.errorhandler(405)
def method_not_allowed_error(error):
    logger.error(f"Method not allowed error: {str(error)}")
    return jsonify({
        'success': False,
        'error': 'Method Not Allowed',
        'message': 'Phương thức HTTP không được hỗ trợ',
        'status': 405
    }), 405

@app.errorhandler(429)
def ratelimit_handler(error):
    logger.error(f"Rate limit error: {str(error)}")
    return jsonify({
        'success': False,
        'error': 'Rate Limit Exceeded',
        'message': 'Quá nhiều yêu cầu, vui lòng thử lại sau',
        'status': 429
    }), 429

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    logger.error(f"Traceback: {traceback.format_exc()}")
    return jsonify({
        'success': False,
        'error': 'Internal Server Error',
        'message': 'Đã xảy ra lỗi server, vui lòng thử lại sau',
        'status': 500
    }), 500

@app.errorhandler(Exception)
def handle_exception(error):
    """Handle all unhandled exceptions"""
    logger.error(f"Unhandled exception: {str(error)}")
    logger.error(f"Traceback: {traceback.format_exc()}")
    
    # Return 500 for non-HTTP exceptions
    if isinstance(error, HTTPException):
        return jsonify({
            'success': False,
            'error': error.name,
            'message': error.description,
            'status': error.code
        }), error.code
    
    return jsonify({
        'success': False,
        'error': 'Internal Server Error',
        'message': 'Đã xảy ra lỗi không mong muốn',
        'status': 500
    }), 500

# ============= UTILITY FUNCTIONS =============

def cleanup_expired_sessions():
    """Dọn dẹp session hết hạn"""
    global session_cleanup_last
    current_time = time.time()
    if current_time - session_cleanup_last > 300:  # Cleanup every 5 minutes
        expired_sessions = [
            sid for sid, data in wallet_storage.items()
            if current_time - data.get('timestamp', 0) > SESSION_TIMEOUT
        ]
        for sid in expired_sessions:
            del wallet_storage[sid]
        session_cleanup_last = current_time

def get_serializer():
    """Tạo serializer cho session"""
    return URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_session_id():
    """Tạo session ID an toàn"""
    return hashlib.sha256(f"{time.time()}{random.random()}{os.urandom(8).hex()}".encode()).hexdigest()[:32]

def validate_address(address):
    """Validate Octra address format"""
    if not address or not isinstance(address, str):
        return False
    return bool(B58_PATTERN.match(address.strip()))

def validate_amount(amount):
    """Validate transaction amount"""
    try:
        amount = float(amount)
        return amount > 0 and amount <= 1000000  # Max 1M tokens
    except (ValueError, TypeError):
        return False

def get_wallet_data(session_id):
    """Lấy dữ liệu ví từ storage"""
    try:
        cleanup_expired_sessions()
        if not session_id or session_id not in wallet_storage:
            return None

        wallet_data = wallet_storage[session_id]
        current_time = time.time()

        # Kiểm tra session timeout
        if current_time - wallet_data.get('timestamp', 0) > SESSION_TIMEOUT:
            del wallet_storage[session_id]
            return None

        # Cập nhật timestamp
        wallet_data['last_access'] = current_time

        # Khởi tạo runtime data nếu chưa có
        if 'balance' not in wallet_data:
            wallet_data.update({
                'balance': None,
                'nonce': None,
                'last_update': 0,
                'transaction_history': [],
                'last_history_update': 0
            })

        return wallet_data
    except Exception as e:
        logger.error(f"Error getting wallet data: {str(e)}")
        return None

def set_wallet_data(session_id, private_key, address, rpc_url):
    """Lưu dữ liệu ví vào storage"""
    try:
        # Validate inputs
        if not all([session_id, private_key, address, rpc_url]):
            raise WalletError("Missing required parameters")

        if not validate_address(address):
            raise WalletError("Invalid address format")

        # Validate private key
        try:
            sk = nacl.signing.SigningKey(base64.b64decode(private_key))
            public_key = base64.b64encode(sk.verify_key.encode()).decode()
        except Exception as e:
            raise WalletError(f"Invalid private key: {str(e)}")

        # Validate RPC URL
        if not rpc_url.startswith(('http://', 'https://')):
            raise WalletError("Invalid RPC URL format")

        wallet_data = {
            'private_key': private_key,
            'address': address,
            'rpc_url': rpc_url.rstrip('/'),
            'signing_key': base64.b64encode(sk.encode()).decode(),
            'public_key': public_key,
            'balance': None,
            'nonce': None,
            'last_update': 0,
            'transaction_history': [],
            'last_history_update': 0,
            'timestamp': time.time(),
            'last_access': time.time()
        }

        wallet_storage[session_id] = wallet_data
        logger.info(f"Wallet data set for session: {session_id[:8]}...")
        return True

    except Exception as e:
        logger.error(f"Error setting wallet data: {str(e)}")
        raise WalletError(f"Failed to set wallet data: {str(e)}")

def get_signing_key(wallet_data):
    """Lấy signing key từ wallet data"""
    try:
        return nacl.signing.SigningKey(base64.b64decode(wallet_data['signing_key']))
    except Exception as e:
        logger.error(f"Error getting signing key: {str(e)}")
        return None

def make_request(method, path, data=None, timeout=15, wallet_data=None):
    """Thực hiện HTTP request với error handling"""
    if not wallet_data:
        return 0, "No wallet loaded", None

    try:
        url = f"{wallet_data['rpc_url']}{path}"
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Octra-Wallet/1.0'
        }

        if method.upper() == 'POST':
            response = requests.post(url, json=data, headers=headers, timeout=timeout)
        else:
            response = requests.get(url, headers=headers, timeout=timeout)

        # Parse JSON response
        try:
            json_data = response.json() if response.text else None
        except json.JSONDecodeError:
            json_data = None

        return response.status_code, response.text, json_data

    except requests.exceptions.Timeout:
        return 0, "Request timeout", None
    except requests.exceptions.ConnectionError:
        return 0, "Connection error", None
    except Exception as e:
        return 0, str(e), None

def get_wallet_status(session_id):
    """Lấy trạng thái ví (balance và nonce)"""
    try:
        wallet_data = get_wallet_data(session_id)
        if not wallet_data:
            return None, None

        current_time = time.time()

        # Cache for 30 seconds
        if (wallet_data['balance'] is not None and
            wallet_data['nonce'] is not None and
            (current_time - wallet_data['last_update']) < 30):
            return wallet_data['nonce'], wallet_data['balance']

        status_code, response_text, json_data = make_request(
            'GET', f'/balance/{wallet_data["address"]}', wallet_data=wallet_data
        )

        if status_code == 200:
            if json_data:
                wallet_data['nonce'] = int(json_data.get('nonce', 0))
                wallet_data['balance'] = float(json_data.get('balance', 0))
            elif response_text:
                # Parse plain text response
                parts = response_text.strip().split()
                if len(parts) >= 2:
                    wallet_data['balance'] = float(parts[0]) if parts[0].replace('.', '').replace('-', '').isdigit() else 0.0
                    wallet_data['nonce'] = int(parts[1]) if parts[1].isdigit() else 0
                else:
                    wallet_data['nonce'], wallet_data['balance'] = 0, 0.0
            else:
                wallet_data['nonce'], wallet_data['balance'] = 0, 0.0
        elif status_code == 404:
            wallet_data['nonce'], wallet_data['balance'] = 0, 0.0
        else:
            logger.warning(f"Unexpected status code: {status_code}")
            wallet_data['nonce'], wallet_data['balance'] = 0, 0.0

        wallet_data['last_update'] = current_time
        wallet_storage[session_id] = wallet_data

        return wallet_data['nonce'], wallet_data['balance']

    except Exception as e:
        logger.error(f"Error getting wallet status: {str(e)}")
        return 0, 0.0

def get_transaction_history(session_id, limit=20):
    """Lấy lịch sử giao dịch"""
    try:
        wallet_data = get_wallet_data(session_id)
        if not wallet_data:
            return []

        current_time = time.time()

        # Cache for 60 seconds
        if (wallet_data['transaction_history'] and
            (current_time - wallet_data['last_history_update']) < 60):
            return wallet_data['transaction_history']

        status_code, _, json_data = make_request(
            'GET', f'/address/{wallet_data["address"]}?limit={limit}', wallet_data=wallet_data
        )

        if status_code != 200 or not json_data:
            wallet_data['last_history_update'] = current_time
            return wallet_data['transaction_history']

        transactions = []
        existing_hashes = {tx['hash'] for tx in wallet_data['transaction_history']}

        for tx_ref in json_data.get('recent_transactions', [])[:limit]:
            tx_hash = tx_ref.get('hash')
            if not tx_hash or tx_hash in existing_hashes:
                continue

            # Get transaction details
            tx_status, _, tx_json = make_request(
                'GET', f'/tx/{tx_hash}', None, 10, wallet_data
            )

            if tx_status == 200 and tx_json and 'parsed_tx' in tx_json:
                parsed_tx = tx_json['parsed_tx']
                is_incoming = parsed_tx.get('to') == wallet_data['address']
                amount_raw = parsed_tx.get('amount_raw', parsed_tx.get('amount', '0'))

                try:
                    amount = float(amount_raw) if '.' in str(amount_raw) else int(amount_raw) / MICRO_UNITS
                except (ValueError, TypeError):
                    amount = 0.0

                # Extract message if exists
                message = None
                if 'data' in tx_json:
                    try:
                        data = json.loads(tx_json['data'])
                        message = data.get('message')
                    except (json.JSONDecodeError, TypeError):
                        pass

                transaction = {
                    'time': datetime.fromtimestamp(parsed_tx.get('timestamp', 0)).isoformat(),
                    'hash': tx_hash,
                    'amount': amount,
                    'address': parsed_tx.get('to') if not is_incoming else parsed_tx.get('from'),
                    'type': 'incoming' if is_incoming else 'outgoing',
                    'confirmed': True,
                    'nonce': parsed_tx.get('nonce', 0),
                    'epoch': tx_ref.get('epoch', 0),
                    'message': message,
                    'status': 'confirmed'
                }

                transactions.append(transaction)

        # Merge with existing transactions and sort
        all_transactions = transactions + wallet_data['transaction_history']
        unique_transactions = {tx['hash']: tx for tx in all_transactions}.values()
        sorted_transactions = sorted(unique_transactions, key=lambda x: x['time'], reverse=True)

        wallet_data['transaction_history'] = sorted_transactions[:limit]
        wallet_data['last_history_update'] = current_time
        wallet_storage[session_id] = wallet_data

        return wallet_data['transaction_history']

    except Exception as e:
        logger.error(f"Error getting transaction history: {str(e)}")
        return []

def create_transaction(session_id, to_address, amount, nonce, message=None):
    """Tạo giao dịch"""
    try:
        wallet_data = get_wallet_data(session_id)
        if not wallet_data:
            raise WalletError("Wallet not loaded")

        signing_key = get_signing_key(wallet_data)
        if not signing_key:
            raise WalletError("Invalid signing key")

        transaction = {
            "from": wallet_data['address'],
            "to_": to_address,
            "amount": str(int(amount * MICRO_UNITS)),
            "nonce": int(nonce),
            "ou": "1" if amount < 1000 else "3",
            "timestamp": time.time() + random.random() * 0.01
        }

        if message:
            transaction["message"] = message[:200]  # Limit message length

        # Create signature
        base_data = json.dumps(
            {k: v for k, v in transaction.items() if k != "message"},
            separators=(",", ":"),
            sort_keys=True
        )

        signature = base64.b64encode(signing_key.sign(base_data.encode()).signature).decode()

        transaction.update({
            "signature": signature,
            "public_key": wallet_data['public_key']
        })

        tx_hash = hashlib.sha256(base_data.encode()).hexdigest()

        return transaction, tx_hash

    except Exception as e:
        logger.error(f"Error creating transaction: {str(e)}")
        raise WalletError(f"Failed to create transaction: {str(e)}")

def send_transaction(transaction, wallet_data):
    """Gửi giao dịch"""
    start_time = time.time()
    try:
        status_code, response_text, json_data = make_request(
            'POST', '/send-tx', transaction, wallet_data=wallet_data
        )

        duration = time.time() - start_time

        if status_code == 200:
            if json_data and json_data.get('status') == 'accepted':
                return True, json_data.get('tx_hash', ''), duration, json_data
            elif response_text and response_text.lower().startswith('ok'):
                tx_hash = response_text.split()[-1] if ' ' in response_text else response_text
                return True, tx_hash, duration, None

        error_msg = json.dumps(json_data) if json_data else response_text
        return False, error_msg, duration, json_data

    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"Error sending transaction: {str(e)}")
        return False, str(e), duration, None

# ============= API ROUTES =============

@app.before_request
def log_request_info():
    """Log request information for debugging"""
    logger.debug('Request: %s %s', request.method, request.url)
    logger.debug('Headers: %s', dict(request.headers))
    if request.get_json(silent=True):
        logger.debug('JSON: %s', request.get_json())

@app.after_request
def log_response_info(response):
    """Log response information for debugging"""
    logger.debug('Response: %s', response.status)
    return response

@app.route('/')
def index():
    return jsonify({
        'success': True,
        'message': 'Octra Wallet API v2.0',
        'status': 'running',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/health')
def health_check():
    return jsonify({
        'success': True,
        'status': 'healthy',
        'active_sessions': len(wallet_storage),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/wallet/login', methods=['POST'])
@limiter.limit("10 per minute")
def wallet_login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400

        private_key = data.get('private_key', '').strip()
        address = data.get('address', '').strip()
        rpc_url = data.get('rpc_url', 'https://octra.network').strip()

        if not private_key or not address:
            return jsonify({
                'success': False,
                'error': 'Private key and address are required'
            }), 400

        if not validate_address(address):
            return jsonify({
                'success': False,
                'error': 'Invalid address format'
            }), 400

        session_id = generate_session_id()

        try:
            set_wallet_data(session_id, private_key, address, rpc_url)
            return jsonify({
                'success': True,
                'message': 'Wallet login successful',
                'session_id': session_id,
                'address': address
            }), 200

        except WalletError as e:
            logger.error(f"Wallet error: {str(e)}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 400

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@app.route('/api/wallet/logout', methods=['POST'])
def wallet_logout():
    try:
        data = request.get_json() or {}
        session_id = data.get('session_id')

        if session_id and session_id in wallet_storage:
            del wallet_storage[session_id]

        return jsonify({
            'success': True,
            'message': 'Logout successful'
        }), 200

    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Logout failed'
        }), 500

@app.route('/api/wallet/status', methods=['GET', 'POST'])
@limiter.limit("30 per minute")
def wallet_status():
    try:
        if request.method == 'POST':
            data = request.get_json() or {}
            session_id = data.get('session_id')
        else:
            session_id = request.args.get('session_id')

        if not session_id:
            return jsonify({
                'success': False,
                'error': 'Session ID required'
            }), 400

        wallet_data = get_wallet_data(session_id)
        if not wallet_data:
            return jsonify({
                'success': False,
                'error': 'Wallet not logged in'
            }), 401

        nonce, balance = get_wallet_status(session_id)

        return jsonify({
            'success': True,
            'address': wallet_data['address'],
            'balance': balance or 0.0,
            'nonce': nonce or 0,
            'public_key': wallet_data['public_key'],
            'last_update': wallet_data.get('last_update', 0)
        }), 200

    except Exception as e:
        logger.error(f"Status error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to get wallet status'
        }), 500

@app.route('/api/wallet/history', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def wallet_history():
    try:
        if request.method == 'POST':
            data = request.get_json() or {}
            session_id = data.get('session_id')
            limit = data.get('limit', 20)
        else:
            session_id = request.args.get('session_id')
            limit = int(request.args.get('limit', 20))

        if not session_id:
            return jsonify({
                'success': False,
                'error': 'Session ID required'
            }), 400

        wallet_data = get_wallet_data(session_id)
        if not wallet_data:
            return jsonify({
                'success': False,
                'error': 'Wallet not logged in'
            }), 401

        limit = min(max(1, limit), 100)  # Limit between 1-100
        history = get_transaction_history(session_id, limit)

        return jsonify({
            'success': True,
            'transactions': history,
            'count': len(history)
        }), 200

    except Exception as e:
        logger.error(f"History error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to get transaction history'
        }), 500

@app.route('/api/wallet/send', methods=['POST'])
@limiter.limit("5 per minute")
def send_transaction_api():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400

        session_id = data.get('session_id')
        if not session_id:
            return jsonify({
                'success': False,
                'error': 'Session ID required'
            }), 400

        wallet_data = get_wallet_data(session_id)
        if not wallet_data:
            return jsonify({
                'success': False,
                'error': 'Wallet not logged in'
            }), 401

        to_address = data.get('to', '').strip()
        amount = data.get('amount', 0)
        message = data.get('message', '').strip() or None

        # Validate inputs
        if not validate_address(to_address):
            return jsonify({
                'success': False,
                'error': 'Invalid recipient address'
            }), 400

        if not validate_amount(amount):
            return jsonify({
                'success': False,
                'error': 'Invalid amount'
            }), 400

        amount = float(amount)

        # Get current status
        nonce, balance = get_wallet_status(session_id)
        if nonce is None or balance is None:
            return jsonify({
                'success': False,
                'error': 'Unable to get wallet status'
            }), 500

        if balance < amount:
            return jsonify({
                'success': False,
                'error': f'Insufficient balance ({balance:.6f} < {amount})'
            }), 400

        # Create and send transaction
        try:
            transaction, tx_hash = create_transaction(session_id, to_address, amount, nonce + 1, message)
            success, result, duration, response = send_transaction(transaction, wallet_data)

            if success:
                # Add to transaction history
                new_transaction = {
                    'time': datetime.now().isoformat(),
                    'hash': result,
                    'amount': amount,
                    'address': to_address,
                    'type': 'outgoing',
                    'confirmed': False,
                    'message': message,
                    'nonce': nonce + 1,
                    'epoch': 0,
                    'status': 'pending'
                }

                wallet_data['transaction_history'].insert(0, new_transaction)
                wallet_data['last_update'] = 0  # Force refresh
                wallet_storage[session_id] = wallet_data

                return jsonify({
                    'success': True,
                    'tx_hash': result,
                    'duration': duration,
                    'message': 'Transaction sent successfully'
                }), 200
            else:
                return jsonify({
                    'success': False,
                    'error': f'Transaction failed: {result}'
                }), 400

        except WalletError as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 400

    except Exception as e:
        logger.error(f"Send transaction error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to send transaction'
        }), 500

@app.route('/api/wallet/export', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def export_wallet():
    try:
        if request.method == 'POST':
            data = request.get_json() or {}
            session_id = data.get('session_id')
        else:
            session_id = request.args.get('session_id')

        if not session_id:
            return jsonify({
                'success': False,
                'error': 'Session ID required'
            }), 400

        wallet_data = get_wallet_data(session_id)
        if not wallet_data:
            return jsonify({
                'success': False,
                'error': 'Wallet not logged in'
            }), 401

        return jsonify({
            'success': True,
            'private_key': wallet_data['private_key'],
            'public_key': wallet_data['public_key'],
            'address': wallet_data['address'],
            'rpc_url': wallet_data['rpc_url']
        }), 200

    except Exception as e:
        logger.error(f"Export error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to export wallet'
        }), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

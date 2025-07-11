from flask import Flask, render_template, request, jsonify, session
import os
import time
from api.wallet import wallet_api

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')

class WalletManager:
    def __init__(self):
        self.wallets = []
        self.load_wallets()
    
    def load_wallets(self):
        """Load wallets from session"""
        self.wallets = session.get('wallets', [])
    
    def save_wallets(self):
        """Save wallets to session"""
        session['wallets'] = self.wallets
        session.permanent = True
    
    def add_wallet(self, wallet_data):
        """Add new wallet to collection"""
        self.wallets.append(wallet_data)
        self.save_wallets()
    
    def find_wallet_by_address(self, address):
        """Find wallet by address"""
        for wallet in self.wallets:
            if wallet['addr'] == address:
                return wallet
        return None
    
    def wallet_exists(self, address):
        """Check if wallet already exists"""
        return self.find_wallet_by_address(address) is not None

wallet_manager = WalletManager()

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/api/create_wallet', methods=['POST'])
def create_wallet():
    """Create new wallet with mnemonic"""
    try:
        data = request.json
        wallet_name = data.get('name', f'Wallet {len(wallet_manager.wallets) + 1}')
        
        # Generate new wallet using API
        result = wallet_api.generate_mnemonic_wallet()
        if not result['success']:
            return jsonify({'success': False, 'error': result['error']})
        
        new_wallet_data = result['data']
        
        # Check if wallet already exists
        if wallet_manager.wallet_exists(new_wallet_data['address']):
            return jsonify({'success': False, 'error': 'Wallet already exists'})
        
        # Prepare wallet info for storage
        wallet_info = {
            'name': wallet_name,
            'addr': new_wallet_data['address'],
            'priv': new_wallet_data['private_key'],
            'pub': new_wallet_data['public_key'],
            'mnemonic': new_wallet_data['mnemonic'],
            'priv_b64': new_wallet_data['priv_b64'],
            'pub_b64': new_wallet_data['pub_b64'],
            'created_at': time.time()
        }
        
        # Add to wallet collection
        wallet_manager.add_wallet(wallet_info)
        
        return jsonify({
            'success': True,
            'wallet': {
                'name': wallet_name,
                'address': new_wallet_data['address'],
                'mnemonic': new_wallet_data['mnemonic'],
                'private_key': new_wallet_data['private_key'],
                'public_key': new_wallet_data['public_key']
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/import_wallet', methods=['POST'])
def import_wallet():
    """Import wallet from private key"""
    try:
        data = request.json
        private_key = data.get('private_key', '').strip()
        wallet_name = data.get('name', f'Imported Wallet {int(time.time())}')
        
        if not private_key:
            return jsonify({'success': False, 'error': 'Private key is required'})
        
        # Import wallet using API
        result = wallet_api.import_from_private_key(private_key)
        if not result['success']:
            return jsonify({'success': False, 'error': result['error']})
        
        wallet_data = result['data']
        
        # Check if wallet already exists
        if wallet_manager.wallet_exists(wallet_data['address']):
            return jsonify({'success': False, 'error': 'Wallet already exists'})
        
        # Prepare wallet info for storage
        wallet_info = {
            'name': wallet_name,
            'addr': wallet_data['address'],
            'priv': wallet_data['private_key'],
            'pub': wallet_data['public_key'],
            'mnemonic': None,  # Imported wallets don't have mnemonic
            'priv_b64': wallet_data['priv_b64'],
            'pub_b64': wallet_data['pub_b64'],
            'created_at': time.time(),
            'imported': True
        }
        
        # Add to wallet collection
        wallet_manager.add_wallet(wallet_info)
        
        return jsonify({
            'success': True,
            'wallet': {
                'name': wallet_name,
                'address': wallet_data['address']
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/get_wallets', methods=['GET'])
def get_wallets():
    """Get all wallets"""
    try:
        wallet_manager.load_wallets()  # Refresh from session
        
        wallets = []
        for wallet in wallet_manager.wallets:
            wallets.append({
                'name': wallet['name'],
                'address': wallet['addr'],
                'has_mnemonic': wallet.get('mnemonic') is not None,
                'imported': wallet.get('imported', False),
                'created_at': wallet.get('created_at', 0)
            })
        
        # Sort by creation time (newest first)
        wallets.sort(key=lambda x: x['created_at'], reverse=True)
        
        return jsonify({'success': True, 'wallets': wallets})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/get_balance', methods=['POST'])
def get_balance():
    """Get wallet balance and encrypted balance"""
    try:
        data = request.json
        address = data.get('address', '').strip()
        
        if not address:
            return jsonify({'success': False, 'error': 'Address is required'})
        
        # Validate address format
        if not wallet_api.validate_address(address):
            return jsonify({'success': False, 'error': 'Invalid address format'})
        
        # Find wallet info
        wallet_info = wallet_manager.find_wallet_by_address(address)
        if not wallet_info:
            return jsonify({'success': False, 'error': 'Wallet not found'})
        
        # Get wallet overview using API
        result = wallet_api.get_wallet_overview(address, wallet_info['priv_b64'])
        if not result['success']:
            return jsonify({'success': False, 'error': result['error']})
        
        overview_data = result['data']
        
        return jsonify({
            'success': True,
            'balance': overview_data['public_balance'],
            'encrypted_balance': overview_data['encrypted_balance'],
            'nonce': overview_data['nonce'],
            'total_balance': overview_data['total_balance'],
            'pending_transfers': len(overview_data['pending_transfers'])
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/send_transaction', methods=['POST'])
def send_transaction():
    """Send OCT transaction"""
    try:
        data = request.json
        from_address = data.get('from_address', '').strip()
        to_address = data.get('to_address', '').strip()
        amount = float(data.get('amount', 0))
        
        # Validation
        if not from_address or not to_address:
            return jsonify({'success': False, 'error': 'From and to addresses are required'})
        
        if amount <= 0:
            return jsonify({'success': False, 'error': 'Amount must be greater than 0'})
        
        if not wallet_api.validate_address(to_address):
            return jsonify({'success': False, 'error': 'Invalid recipient address format'})
        
        # Find sender wallet
        wallet_info = wallet_manager.find_wallet_by_address(from_address)
        if not wallet_info:
            return jsonify({'success': False, 'error': 'Sender wallet not found'})
        
        # Get current balance and nonce
        balance_result = wallet_api.get_wallet_balance(from_address)
        if not balance_result['success']:
            return jsonify({'success': False, 'error': 'Cannot get wallet balance'})
        
        current_balance = balance_result['balance']
        current_nonce = balance_result['nonce']
        
        # Check sufficient balance
        if amount > current_balance:
            return jsonify({
                'success': False, 
                'error': f'Insufficient balance. Available: {current_balance} OCT, Required: {amount} OCT'
            })
        
        # Send transaction using API
        result = wallet_api.send_transaction(wallet_info, to_address, amount, current_nonce + 1)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': 'Transaction sent successfully',
                'data': result['data']
            })
        else:
            return jsonify({'success': False, 'error': result['error']})
            
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid amount format'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/encrypt_balance', methods=['POST'])
def encrypt_balance():
    """Encrypt wallet balance"""
    try:
        data = request.json
        address = data.get('address', '').strip()
        amount = float(data.get('amount', 0))
        
        if not address:
            return jsonify({'success': False, 'error': 'Address is required'})
        
        if amount <= 0:
            return jsonify({'success': False, 'error': 'Amount must be greater than 0'})
        
        # Find wallet
        wallet_info = wallet_manager.find_wallet_by_address(address)
        if not wallet_info:
            return jsonify({'success': False, 'error': 'Wallet not found'})
        
        # Check if user has enough public balance
        balance_result = wallet_api.get_wallet_balance(address)
        if not balance_result['success']:
            return jsonify({'success': False, 'error': 'Cannot get wallet balance'})
        
        if amount > balance_result['balance']:
            return jsonify({
                'success': False, 
                'error': f'Insufficient public balance. Available: {balance_result["balance"]} OCT'
            })
        
        # Encrypt balance using API
        result = wallet_api.encrypt_balance(address, amount, wallet_info['priv_b64'])
        
        return jsonify(result)
        
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid amount format'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/decrypt_balance', methods=['POST'])
def decrypt_balance():
    """Decrypt wallet balance"""
    try:
        data = request.json
        address = data.get('address', '').strip()
        amount = float(data.get('amount', 0))
        
        if not address:
            return jsonify({'success': False, 'error': 'Address is required'})
        
        if amount <= 0:
            return jsonify({'success': False, 'error': 'Amount must be greater than 0'})
        
        # Find wallet
        wallet_info = wallet_manager.find_wallet_by_address(address)
        if not wallet_info:
            return jsonify({'success': False, 'error': 'Wallet not found'})
        
        # Decrypt balance using API
        result = wallet_api.decrypt_balance(address, amount, wallet_info['priv_b64'])
        
        return jsonify(result)
        
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid amount format'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/private_transfer', methods=['POST'])
def private_transfer():
    """Send private transfer"""
    try:
        data = request.json
        from_address = data.get('from_address', '').strip()
        to_address = data.get('to_address', '').strip()
        amount = float(data.get('amount', 0))
        
        # Validation
        if not from_address or not to_address:
            return jsonify({'success': False, 'error': 'From and to addresses are required'})
        
        if amount <= 0:
            return jsonify({'success': False, 'error': 'Amount must be greater than 0'})
        
        if not wallet_api.validate_address(to_address):
            return jsonify({'success': False, 'error': 'Invalid recipient address format'})
        
        # Find sender wallet
        wallet_info = wallet_manager.find_wallet_by_address(from_address)
        if not wallet_info:
            return jsonify({'success': False, 'error': 'Sender wallet not found'})
        
        # Check encrypted balance
        enc_result = wallet_api.get_encrypted_balance(from_address, wallet_info['priv_b64'])
        if not enc_result['success']:
            return jsonify({'success': False, 'error': 'Cannot get encrypted balance'})
        
        if amount > enc_result['encrypted_balance']:
            return jsonify({
                'success': False, 
                'error': f'Insufficient encrypted balance. Available: {enc_result["encrypted_balance"]} OCT'
            })
        
        # Send private transfer using API
        result = wallet_api.send_private_transfer(
            from_address, to_address, amount, wallet_info['priv_b64']
        )
        
        return jsonify(result)
        
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid amount format'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/get_pending_transfers', methods=['POST'])
def get_pending_transfers():
    """Get pending private transfers"""
    try:
        data = request.json
        address = data.get('address', '').strip()
        
        if not address:
            return jsonify({'success': False, 'error': 'Address is required'})
        
        # Find wallet
        wallet_info = wallet_manager.find_wallet_by_address(address)
        if not wallet_info:
            return jsonify({'success': False, 'error': 'Wallet not found'})
        
        # Get pending transfers using API
        result = wallet_api.get_pending_private_transfers(address, wallet_info['priv_b64'])
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/claim_transfer', methods=['POST'])
def claim_transfer():
    """Claim private transfer"""
    try:
        data = request.json
        address = data.get('address', '').strip()
        transfer_id = data.get('transfer_id', '').strip()
        
        if not address or not transfer_id:
            return jsonify({'success': False, 'error': 'Address and transfer ID are required'})
        
        # Find wallet
        wallet_info = wallet_manager.find_wallet_by_address(address)
        if not wallet_info:
            return jsonify({'success': False, 'error': 'Wallet not found'})
        
        # Claim transfer using API
        result = wallet_api.claim_private_transfer(address, wallet_info['priv_b64'], transfer_id)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/export_wallet', methods=['POST'])
def export_wallet():
    """Export wallet information"""
    try:
        data = request.json
        address = data.get('address', '').strip()
        
        if not address:
            return jsonify({'success': False, 'error': 'Address is required'})
        
        # Find wallet
        wallet_info = wallet_manager.find_wallet_by_address(address)
        if not wallet_info:
            return jsonify({'success': False, 'error': 'Wallet not found'})
        
        # Prepare export data
        export_data = {
            'name': wallet_info['name'],
            'address': wallet_info['addr'],
            'private_key': wallet_info['priv'],
            'public_key': wallet_info['pub'],
            'mnemonic': wallet_info.get('mnemonic'),
            'imported': wallet_info.get('imported', False),
            'created_at': wallet_info.get('created_at', 0)
        }
        
        return jsonify({
            'success': True,
            'wallet_data': export_data
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/delete_wallet', methods=['POST'])
def delete_wallet():
    """Delete wallet from session"""
    try:
        data = request.json
        address = data.get('address', '').strip()
        
        if not address:
            return jsonify({'success': False, 'error': 'Address is required'})
        
        # Find and remove wallet
        wallet_manager.load_wallets()
        original_count = len(wallet_manager.wallets)
        
        wallet_manager.wallets = [
            wallet for wallet in wallet_manager.wallets 
            if wallet['addr'] != address
        ]
        
        if len(wallet_manager.wallets) == original_count:
            return jsonify({'success': False, 'error': 'Wallet not found'})
        
        wallet_manager.save_wallets()
        
        return jsonify({
            'success': True,
            'message': 'Wallet deleted successfully'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/wallet_overview', methods=['POST'])
def wallet_overview():
    """Get complete wallet overview"""
    try:
        data = request.json
        address = data.get('address', '').strip()
        
        if not address:
            return jsonify({'success': False, 'error': 'Address is required'})
        
        # Find wallet
        wallet_info = wallet_manager.find_wallet_by_address(address)
        if not wallet_info:
            return jsonify({'success': False, 'error': 'Wallet not found'})
        
        # Get overview using API
        result = wallet_api.get_wallet_overview(address, wallet_info['priv_b64'])
        
        if result['success']:
            # Add wallet metadata
            result['data']['wallet_name'] = wallet_info['name']
            result['data']['has_mnemonic'] = wallet_info.get('mnemonic') is not None
            result['data']['imported'] = wallet_info.get('imported', False)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'success': False, 'error': 'Bad request'}), 400

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'success': True,
        'status': 'healthy',
        'timestamp': time.time()
    })

# Session configuration
@app.before_first_request
def configure_session():
    """Configure session settings"""
    session.permanent = True
    app.permanent_session_lifetime = 86400 * 7  # 7 days
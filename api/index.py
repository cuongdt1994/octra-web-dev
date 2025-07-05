from flask import Flask, render_template, request, jsonify, session
import json, base64, hashlib, time, re, random, asyncio, aiohttp
from datetime import datetime, timedelta
import nacl.signing
import os
from functools import wraps
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Global variables
? = 1_000_000
b58 = re.compile(r"^oct[1-9A-HJ-NP-Za-km-z]{44}$")

class OctraWallet:
    def __init__(self):
        self.session = None
        self.cache = {}
        self.cache_timeout = 30
        
    async def get_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            )
        return self.session
    
    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None
    
    async def req(self, method, path, data=None, timeout=10):
        try:
            session = await self.get_session()
            rpc = session.get('rpc', 'https://octra.network')
            url = f"{rpc}{path}"
            
            async with getattr(session, method.lower())(
                url, json=data if method == 'POST' else None
            ) as resp:
                text = await resp.text()
                try:
                    json_data = json.loads(text) if text else None
                except:
                    json_data = None
                return resp.status, text, json_data
        except asyncio.TimeoutError:
            return 0, "timeout", None
        except Exception as e:
            return 0, str(e), None
    
    async def get_status(self, addr):
        cache_key = f"status_{addr}"
        now = time.time()
        
        if cache_key in self.cache:
            cached_data, cached_time = self.cache[cache_key]
            if now - cached_time < self.cache_timeout:
                return cached_data
        
        try:
            # Get balance and nonce
            status, text, json_data = await self.req('GET', f'/balance/{addr}')
            
            if status == 200 and json_data:
                nonce = int(json_data.get('nonce', 0))
                balance = float(json_data.get('balance', 0))
                
                # Check staging transactions
                staging_status, _, staging_json = await self.req('GET', '/staging', 5)
                if staging_status == 200 and staging_json:
                    our_txs = [
                        tx for tx in staging_json.get('staged_transactions', [])
                        if tx.get('from') == addr
                    ]
                    if our_txs:
                        nonce = max(nonce, max(int(tx.get('nonce', 0)) for tx in our_txs))
                
                result = {'nonce': nonce, 'balance': balance}
                self.cache[cache_key] = (result, now)
                return result
                
            elif status == 404:
                result = {'nonce': 0, 'balance': 0.0}
                self.cache[cache_key] = (result, now)
                return result
                
            elif status == 200 and text and not json_data:
                # Handle plain text response
                parts = text.strip().split()
                if len(parts) >= 2:
                    balance = float(parts[0]) if parts[0].replace('.', '').isdigit() else 0.0
                    nonce = int(parts[1]) if parts[1].isdigit() else 0
                    result = {'nonce': nonce, 'balance': balance}
                    self.cache[cache_key] = (result, now)
                    return result
                    
        except Exception as e:
            print(f"Error getting status: {e}")
        
        return {'nonce': None, 'balance': None}
    
    async def get_history(self, addr, limit=20):
        cache_key = f"history_{addr}"
        now = time.time()
        
        if cache_key in self.cache:
            cached_data, cached_time = self.cache[cache_key]
            if now - cached_time < 60:  # Cache for 1 minute
                return cached_data
        
        try:
            status, text, json_data = await self.req('GET', f'/address/{addr}?limit={limit}')
            
            if status != 200:
                return []
            
            if json_data and 'recent_transactions' in json_data:
                tx_refs = json_data.get('recent_transactions', [])
                transactions = []
                
                for ref in tx_refs:
                    tx_hash = ref['hash']
                    tx_status, _, tx_json = await self.req('GET', f'/tx/{tx_hash}', timeout=5)
                    
                    if tx_status == 200 and tx_json and 'parsed_tx' in tx_json:
                        parsed = tx_json['parsed_tx']
                        is_incoming = parsed.get('to') == addr
                        
                        amount_raw = parsed.get('amount_raw', parsed.get('amount', '0'))
                        amount = float(amount_raw) if '.' in str(amount_raw) else int(amount_raw) / ?
                        
                        # Extract message if exists
                        message = None
                        if 'data' in tx_json:
                            try:
                                data = json.loads(tx_json['data'])
                                message = data.get('message')
                            except:
                                pass
                        
                        transactions.append({
                            'time': datetime.fromtimestamp(parsed.get('timestamp', 0)),
                            'hash': tx_hash,
                            'amount': amount,
                            'address': parsed.get('to') if not is_incoming else parsed.get('from'),
                            'type': 'in' if is_incoming else 'out',
                            'nonce': parsed.get('nonce', 0),
                            'epoch': ref.get('epoch', 0),
                            'message': message,
                            'confirmed': bool(ref.get('epoch'))
                        })
                
                # Sort by time, newest first
                transactions.sort(key=lambda x: x['time'], reverse=True)
                self.cache[cache_key] = (transactions, now)
                return transactions
                
        except Exception as e:
            print(f"Error getting history: {e}")
        
        return []
    
    def create_transaction(self, from_addr, to_addr, amount, nonce, private_key, message=None):
        try:
            tx = {
                "from": from_addr,
                "to_": to_addr,
                "amount": str(int(amount * ?)),
                "nonce": int(nonce),
                "ou": "1" if amount < 1000 else "3",
                "timestamp": time.time() + random.random() * 0.01
            }
            
            if message:
                tx["message"] = message
            
            # Create signature
            base_tx = {k: v for k, v in tx.items() if k != "message"}
            tx_string = json.dumps(base_tx, separators=(",", ":"))
            
            sk = nacl.signing.SigningKey(base64.b64decode(private_key))
            signature = base64.b64encode(sk.sign(tx_string.encode()).signature).decode()
            public_key = base64.b64encode(sk.verify_key.encode()).decode()
            
            tx.update({
                "signature": signature,
                "public_key": public_key
            })
            
            tx_hash = hashlib.sha256(tx_string.encode()).hexdigest()
            return tx, tx_hash
            
        except Exception as e:
            raise Exception(f"Failed to create transaction: {str(e)}")
    
    async def send_transaction(self, tx):
        try:
            start_time = time.time()
            status, text, json_data = await self.req('POST', '/send-tx', tx)
            duration = time.time() - start_time
            
            if status == 200:
                if json_data and json_data.get('status') == 'accepted':
                    return {
                        'success': True,
                        'hash': json_data.get('tx_hash', ''),
                        'duration': duration,
                        'response': json_data
                    }
                elif text.lower().startswith('ok'):
                    return {
                        'success': True,
                        'hash': text.split()[-1],
                        'duration': duration,
                        'response': None
                    }
            
            return {
                'success': False,
                'error': json.dumps(json_data) if json_data else text,
                'duration': duration
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'duration': 0
            }

# Global wallet instance
wallet = OctraWallet()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/load_wallet', methods=['POST'])
def load_wallet():
    try:
        data = request.json
        private_key = data.get('private_key')
        rpc_url = data.get('rpc_url', 'https://octra.network')
        
        if not private_key:
            return jsonify({'success': False, 'error': 'Private key is required'})
        
        # Validate and create wallet
        sk = nacl.signing.SigningKey(base64.b64decode(private_key))
        public_key = base64.b64encode(sk.verify_key.encode()).decode()
        
        # Generate address (simplified - you may need to adjust based on Octra's address format)
        address_hash = hashlib.sha256(sk.verify_key.encode()).digest()
        address = 'oct' + base64.b32encode(address_hash).decode().lower()[:44]
        
        session['private_key'] = private_key
        session['public_key'] = public_key
        session['address'] = address
        session['rpc'] = rpc_url
        
        return jsonify({
            'success': True,
            'address': address,
            'public_key': public_key
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/generate_wallet', methods=['POST'])
def generate_wallet():
    try:
        # Generate new wallet
        sk = nacl.signing.SigningKey.generate()
        private_key = base64.b64encode(sk.encode()).decode()
        public_key = base64.b64encode(sk.verify_key.encode()).decode()
        
        # Generate address
        address_hash = hashlib.sha256(sk.verify_key.encode()).digest()
        address = 'oct' + base64.b32encode(address_hash).decode().lower()[:44]
        
        return jsonify({
            'success': True,
            'private_key': private_key,
            'public_key': public_key,
            'address': address
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/status')
async def get_status():
    try:
        if 'address' not in session:
            return jsonify({'success': False, 'error': 'Wallet not loaded'})
        
        address = session['address']
        status = await wallet.get_status(address)
        
        return jsonify({
            'success': True,
            'nonce': status['nonce'],
            'balance': status['balance'],
            'address': address
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/history')
async def get_history():
    try:
        if 'address' not in session:
            return jsonify({'success': False, 'error': 'Wallet not loaded'})
        
        address = session['address']
        limit = request.args.get('limit', 20, type=int)
        
        history = await wallet.get_history(address, limit)
        
        # Convert datetime objects to strings for JSON serialization
        for tx in history:
            tx['time'] = tx['time'].isoformat()
        
        return jsonify({
            'success': True,
            'transactions': history
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/send', methods=['POST'])
async def send_transaction():
    try:
        if 'address' not in session or 'private_key' not in session:
            return jsonify({'success': False, 'error': 'Wallet not loaded'})
        
        data = request.json
        to_address = data.get('to')
        amount = float(data.get('amount', 0))
        message = data.get('message')
        
        # Validate inputs
        if not b58.match(to_address):
            return jsonify({'success': False, 'error': 'Invalid recipient address'})
        
        if amount <= 0:
            return jsonify({'success': False, 'error': 'Amount must be positive'})
        
        # Get current status
        from_address = session['address']
        private_key = session['private_key']
        
        status = await wallet.get_status(from_address)
        if status['nonce'] is None:
            return jsonify({'success': False, 'error': 'Failed to get wallet status'})
        
        if status['balance'] < amount:
            return jsonify({'success': False, 'error': 'Insufficient balance'})
        
        # Create and send transaction
        tx, tx_hash = wallet.create_transaction(
            from_address, to_address, amount, status['nonce'] + 1, private_key, message
        )
        
        result = await wallet.send_transaction(tx)
        
        if result['success']:
            # Clear cache to force refresh
            wallet.cache.clear()
            
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/multi_send', methods=['POST'])
async def multi_send():
    try:
        if 'address' not in session or 'private_key' not in session:
            return jsonify({'success': False, 'error': 'Wallet not loaded'})
        
        data = request.json
        recipients = data.get('recipients', [])
        
        if not recipients:
            return jsonify({'success': False, 'error': 'No recipients provided'})
        
        # Validate recipients
        total_amount = 0
        for recipient in recipients:
            if not b58.match(recipient['address']):
                return jsonify({'success': False, 'error': f'Invalid address: {recipient["address"]}'})
            
            amount = float(recipient['amount'])
            if amount <= 0:
                return jsonify({'success': False, 'error': 'All amounts must be positive'})
            
            total_amount += amount
        
        # Get current status
        from_address = session['address']
        private_key = session['private_key']
        
        status = await wallet.get_status(from_address)
        if status['nonce'] is None:
            return jsonify({'success': False, 'error': 'Failed to get wallet status'})
        
        if status['balance'] < total_amount:
            return jsonify({'success': False, 'error': 'Insufficient balance'})
        
        # Send transactions
        results = []
        current_nonce = status['nonce']
        
        for i, recipient in enumerate(recipients):
            try:
                tx, tx_hash = wallet.create_transaction(
                    from_address, recipient['address'], float(recipient['amount']),
                    current_nonce + i + 1, private_key, recipient.get('message')
                )
                
                result = await wallet.send_transaction(tx)
                results.append({
                    'address': recipient['address'],
                    'amount': recipient['amount'],
                    'success': result['success'],
                    'hash': result.get('hash', ''),
                    'error': result.get('error', '')
                })
                
            except Exception as e:
                results.append({
                    'address': recipient['address'],
                    'amount': recipient['amount'],
                    'success': False,
                    'error': str(e)
                })
        
        # Clear cache
        wallet.cache.clear()
        
        success_count = sum(1 for r in results if r['success'])
        
        return jsonify({
            'success': True,
            'results': results,
            'summary': {
                'total': len(recipients),
                'successful': success_count,
                'failed': len(recipients) - success_count
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/export', methods=['POST'])
def export_wallet():
    try:
        if 'address' not in session:
            return jsonify({'success': False, 'error': 'Wallet not loaded'})
        
        data = request.json
        export_type = data.get('type', 'address')
        
        if export_type == 'private_key':
            return jsonify({
                'success': True,
                'private_key': session.get('private_key', ''),
                'public_key': session.get('public_key', '')
            })
        elif export_type == 'wallet_file':
            wallet_data = {
                'priv': session.get('private_key', ''),
                'addr': session.get('address', ''),
                'rpc': session.get('rpc', 'https://octra.network')
            }
            return jsonify({
                'success': True,
                'wallet_data': wallet_data
            })
        else:  # address
            return jsonify({
                'success': True,
                'address': session.get('address', '')
            })
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/clear_cache', methods=['POST'])
def clear_cache():
    wallet.cache.clear()
    return jsonify({'success': True})

# Template for the main HTML page
@app.route('/templates/index.html')
def get_template():
    return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Octra Web Wallet</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Courier New', monospace; 
            background: #1a1a1a; 
            color: #fff; 
            line-height: 1.6; 
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; }
        .wallet-section { 
            background: #2a2a2a; 
            border: 1px solid #444; 
            border-radius: 8px; 
            padding: 20px; 
            margin-bottom: 20px; 
        }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; color: #ccc; }
        input, textarea, select { 
            width: 100%; 
            padding: 10px; 
            background: #333; 
            border: 1px solid #555; 
            border-radius: 4px; 
            color: #fff; 
        }
        button { 
            background: #007acc; 
            color: white; 
            padding: 10px 20px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer; 
            margin-right: 10px; 
        }
        button:hover { background: #005a9e; }
        .success { color: #4caf50; }
        .error { color: #f44336; }
        .tx-list { max-height: 400px; overflow-y: auto; }
        .tx-item { 
            border-bottom: 1px solid #444; 
            padding: 10px 0; 
            display: flex; 
            justify-content: space-between; 
        }
        .hidden { display: none; }
        .loading { color: #ffa500; }
        .tabs { display: flex; margin-bottom: 20px; }
        .tab { 
            padding: 10px 20px; 
            background: #333; 
            border: 1px solid #555; 
            cursor: pointer; 
            margin-right: 5px; 
        }
        .tab.active { background: #007acc; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>?? Octra Web Wallet</h1>
            <p>Testnet Environment - v1.0.0</p>
        </div>

        <!-- Wallet Setup -->
        <div id="wallet-setup" class="wallet-section">
            <h2>Wallet Setup</h2>
            <div class="tabs">
                <div class="tab active" onclick="showTab('load')">Load Wallet</div>
                <div class="tab" onclick="showTab('generate')">Generate New</div>
            </div>
            
            <div id="load-tab">
                <div class="form-group">
                    <label>Private Key:</label>
                    <input type="password" id="private-key" placeholder="Enter your private key">
                </div>
                <div class="form-group">
                    <label>RPC URL:</label>
                    <input type="text" id="rpc-url" value="https://octra.network" placeholder="RPC endpoint">
                </div>
                <button onclick="loadWallet()">Load Wallet</button>
            </div>
            
            <div id="generate-tab" class="hidden">
                <p>Generate a new wallet with a random private key.</p>
                <button onclick="generateWallet()">Generate New Wallet</button>
            </div>
            
            <div id="wallet-result"></div>
        </div>

        <!-- Wallet Info -->
        <div id="wallet-info" class="wallet-section hidden">
            <h2>Wallet Information</h2>
            <div id="wallet-details"></div>
            <button onclick="refreshWallet()">Refresh</button>
            <button onclick="exportWallet()">Export</button>
        </div>

        <!-- Send Transaction -->
        <div id="send-section" class="wallet-section hidden">
            <h2>Send Transaction</h2>
            <div class="form-group">
                <label>To Address:</label>
                <input type="text" id="send-to" placeholder="oct...">
            </div>
            <div class="form-group">
                <label>Amount (OCT):</label>
                <input type="number" id="send-amount" step="0.000001" placeholder="0.000000">
            </div>
            <div class="form-group">
                <label>Message (optional):</label>
                <textarea id="send-message" placeholder="Optional message" maxlength="1024"></textarea>
            </div>
            <button onclick="sendTransaction()">Send Transaction</button>
            <div id="send-result"></div>
        </div>

        <!-- Multi Send -->
        <div id="multi-send-section" class="wallet-section hidden">
            <h2>Multi Send</h2>
            <div id="recipients-list">
                <div class="recipient-item">
                    <div class="form-group">
                        <label>Address:</label>
                        <input type="text" class="recipient-address" placeholder="oct...">
                    </div>
                    <div class="form-group">
                        <label>Amount:</label>
                        <input type="number" class="recipient-amount" step="0.000001" placeholder="0.000000">
                    </div>
                </div>
            </div>
            <button onclick="addRecipient()">Add Recipient</button>
            <button onclick="multiSend()">Send All</button>
            <div id="multi-send-result"></div>
        </div>

        <!-- Transaction History -->
        <div id="history-section" class="wallet-section hidden">
            <h2>Transaction History</h2>
            <div id="transaction-list" class="tx-list"></div>
        </div>
    </div>

    <script>
        let walletLoaded = false;

        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('[id$="-tab"]').forEach(t => t.classList.add('hidden'));
            
            event.target.classList.add('active');
            document.getElementById(tab + '-tab').classList.remove('hidden');
        }

        async function loadWallet() {
            const privateKey = document.getElementById('private-key').value;
            const rpcUrl = document.getElementById('rpc-url').value;
            
            if (!privateKey) {
                showResult('wallet-result', 'Private key is required', 'error');
                return;
            }
            
            try {
                const response = await fetch('/api/load_wallet', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({private_key: privateKey, rpc_url: rpcUrl})
                });
                
                const data = await response.json();
                
                if (data.success) {
                    walletLoaded = true;
                    showResult('wallet-result', 'Wallet loaded successfully!', 'success');
                    showWalletSections();
                    refreshWallet();
                } else {
                    showResult('wallet-result', data.error, 'error');
                }
            } catch (error) {
                showResult('wallet-result', 'Network error: ' + error.message, 'error');
            }
        }

        async function generateWallet() {
            try {
                const response = await fetch('/api/generate_wallet', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'}
                });
                
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('private-key').value = data.private_key;
                    showResult('wallet-result', 
                        `New wallet generated!<br>
                        Address: ${data.address}<br>
                        <strong>Save your private key safely!</strong>`, 'success');
                } else {
                    showResult('wallet-result', data.error, 'error');
                }
            } catch (error) {
                showResult('wallet-result', 'Network error: ' + error.message, 'error');
            }
        }

        async function refreshWallet() {
            if (!walletLoaded) return;
            
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('wallet-details').innerHTML = `
                        <p><strong>Address:</strong> ${data.address}</p>
                        <p><strong>Balance:</strong> ${data.balance ? data.balance.toFixed(6) : '---'} OCT</p>
                        <p><strong>Nonce:</strong> ${data.nonce !== null ? data.nonce : '---'}</p>
                    `;
                    
                    loadHistory();
                } else {
                    showResult('wallet-details', data.error, 'error');
                }
            } catch (error) {
                showResult('wallet-details', 'Network error: ' + error.message, 'error');
            }
        }

        async function loadHistory() {
            try {
                const response = await fetch('/api/history');
                const data = await response.json();
                
                if (data.success) {
                    const historyHtml = data.transactions.map(tx => `
                        <div class="tx-item">
                            <div>
                                <strong>${tx.type.toUpperCase()}</strong> 
                                ${tx.amount.toFixed(6)} OCT
                                ${tx.message ? '<br><small>?? ' + tx.message + '</small>' : ''}
                            </div>
                            <div>
                                <small>${new Date(tx.time).toLocaleString()}</small><br>
                                <small>${tx.address.substring(0, 20)}...</small><br>
                                <small>${tx.confirmed ? '? Confirmed' : '? Pending'}</small>
                            </div>
                        </div>
                    `).join('');
                    
                    document.getElementById('transaction-list').innerHTML = 
                        historyHtml || '<p>No transactions yet</p>';
                }
            } catch (error) {
                console.error('Error loading history:', error);
            }
        }

        async function sendTransaction() {
            const to = document.getElementById('send-to').value;
            const amount = document.getElementById('send-amount').value;
            const message = document.getElementById('send-message').value;
            
            if (!to || !amount) {
                showResult('send-result', 'Address and amount are required', 'error');
                return;
            }
            
            showResult('send-result', 'Sending transaction...', 'loading');
            
            try {
                const response = await fetch('/api/send', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({to, amount, message})
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showResult('send-result', 
                        `Transaction sent successfully!<br>Hash: ${data.hash}`, 'success');
                    document.getElementById('send-to').value = '';
                    document.getElementById('send-amount').value = '';
                    document.getElementById('send-message').value = '';
                    setTimeout(refreshWallet, 2000);
                } else {
                    showResult('send-result', data.error, 'error');
                }
            } catch (error) {
                showResult('send-result', 'Network error: ' + error.message, 'error');
            }
        }

        function addRecipient() {
            const recipientHtml = `
                <div class="recipient-item">
                    <div class="form-group">
                        <label>Address:</label>
                        <input type="text" class="recipient-address" placeholder="oct...">
                    </div>
                    <div class="form-group">
                        <label>Amount:</label>
                        <input type="number" class="recipient-amount" step="0.000001" placeholder="0.000000">
                    </div>
                    <button onclick="this.parentElement.remove()">Remove</button>
                </div>
            `;
            document.getElementById('recipients-list').insertAdjacentHTML('beforeend', recipientHtml);
        }

        async function multiSend() {
            const recipients = [];
            document.querySelectorAll('.recipient-item').forEach(item => {
                const address = item.querySelector('.recipient-address').value;
                const amount = item.querySelector('.recipient-amount').value;
                if (address && amount) {
                    recipients.push({address, amount});
                }
            });
            
            if (recipients.length === 0) {
                showResult('multi-send-result', 'No recipients specified', 'error');
                return;
            }
            
            showResult('multi-send-result', 'Sending transactions...', 'loading');
            
            try {
                const response = await fetch('/api/multi_send', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({recipients})
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showResult('multi-send-result', 
                        `Multi-send completed!<br>
                        Successful: ${data.summary.successful}<br>
                        Failed: ${data.summary.failed}`, 'success');
                    setTimeout(refreshWallet, 2000);
                } else {
                    showResult('multi-send-result', data.error, 'error');
                }
            } catch (error) {
                showResult('multi-send-result', 'Network error: ' + error.message, 'error');
            }
        }

        async function exportWallet() {
            const type = prompt('Export type: address, private_key, or wallet_file', 'address');
            if (!type) return;
            
            try {
                const response = await fetch('/api/export', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({type})
                });
                
                const data = await response.json();
                
                if (data.success) {
                    if (type === 'wallet_file') {
                        const blob = new Blob([JSON.stringify(data.wallet_data, null, 2)], 
                            {type: 'application/json'});
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `octra_wallet_${Date.now()}.json`;
                        a.click();
                    } else {
                        const text = type === 'private_key' ? 
                            `Private Key: ${data.private_key}\nPublic Key: ${data.public_key}` :
                            data.address;
                        navigator.clipboard.writeText(text);
                        alert('Copied to clipboard!');
                    }
                }
            } catch (error) {
                alert('Export failed: ' + error.message);
            }
        }

        function showWalletSections() {
            document.getElementById('wallet-setup').classList.add('hidden');
            document.getElementById('wallet-info').classList.remove('hidden');
            document.getElementById('send-section').classList.remove('hidden');
            document.getElementById('multi-send-section').classList.remove('hidden');
            document.getElementById('history-section').classList.remove('hidden');
        }

        function showResult(elementId, message, type) {
            const element = document.getElementById(elementId);
            element.innerHTML = `<div class="${type}">${message}</div>`;
        }

        // Auto-refresh every 30 seconds
        setInterval(() => {
            if (walletLoaded) {
                refreshWallet();
            }
        }, 30000);
    </script>
</body>
</html>
    '''

# Create templates directory if it doesn't exist
if not os.path.exists('templates'):
    os.makedirs('templates')

# Write the template file
with open('templates/index.html', 'w') as f:
    f.write(get_template().strip())

if __name__ == '__main__':
    app.run(debug=True)

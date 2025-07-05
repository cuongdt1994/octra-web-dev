from flask import Flask, request, jsonify, render_template_string, session
import json, base64, hashlib, time, re, random, os
from datetime import datetime, timedelta
import asyncio
import aiohttp
import nacl.signing

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Tạo secret key ngẫu nhiên cho session

# Global variables
b58 = re.compile(r"^oct[1-9A-HJ-NP-Za-km-z]{44}$")
μ = 1_000_000
sessions_data = {}  # Lưu trữ dữ liệu session

def get_wallet_data():
    """Lấy thông tin wallet từ session"""
    session_id = session.get('session_id')
    if not session_id or session_id not in sessions_data:
        return None
    return sessions_data[session_id]

def set_wallet_data(priv_key, addr, rpc_url):
    """Lưu thông tin wallet vào session"""
    session_id = session.get('session_id')
    if not session_id:
        session_id = os.urandom(16).hex()
        session['session_id'] = session_id
    
    try:
        sk = nacl.signing.SigningKey(base64.b64decode(priv_key))
        pub = base64.b64encode(sk.verify_key.encode()).decode()
        
        sessions_data[session_id] = {
            'priv': priv_key,
            'addr': addr,
            'rpc': rpc_url,
            'sk': sk,
            'pub': pub,
            'cb': None,
            'cn': None,
            'lu': 0,
            'h': [],
            'lh': 0,
            'session': None
        }
        return True
    except:
        return False

async def req(method, path, data=None, timeout=10):
    wallet_data = get_wallet_data()
    if not wallet_data:
        return 0, "No wallet loaded", None
        
    if not wallet_data['session']:
        wallet_data['session'] = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout))
    
    try:
        url = f"{wallet_data['rpc']}{path}"
        async with getattr(wallet_data['session'], method.lower())(url, json=data if method == 'POST' else None) as resp:
            text = await resp.text()
            try:
                j = json.loads(text) if text else None
            except:
                j = None
            return resp.status, text, j
    except Exception as e:
        return 0, str(e), None

async def get_status():
    wallet_data = get_wallet_data()
    if not wallet_data:
        return None, None
        
    now = time.time()
    if wallet_data['cb'] is not None and (now - wallet_data['lu']) < 30:
        return wallet_data['cn'], wallet_data['cb']
    
    try:
        results = await asyncio.gather(
            req('GET', f'/balance/{wallet_data["addr"]}'),
            req('GET', '/staging', 5),
            return_exceptions=True
        )
        
        s, t, j = results[0] if not isinstance(results[0], Exception) else (0, str(results[0]), None)
        s2, _, j2 = results[1] if not isinstance(results[1], Exception) else (0, None, None)
        
        if s == 200 and j:
            wallet_data['cn'] = int(j.get('nonce', 0))
            wallet_data['cb'] = float(j.get('balance', 0))
            wallet_data['lu'] = now
            if s2 == 200 and j2:
                our = [tx for tx in j2.get('staged_transactions', []) if tx.get('from') == wallet_data['addr']]
                if our:
                    wallet_data['cn'] = max(wallet_data['cn'], max(int(tx.get('nonce', 0)) for tx in our))
        elif s == 404:
            wallet_data['cn'], wallet_data['cb'], wallet_data['lu'] = 0, 0.0, now
        elif s == 200 and t and not j:
            try:
                parts = t.strip().split()
                if len(parts) >= 2:
                    wallet_data['cb'] = float(parts[0]) if parts[0].replace('.', '').isdigit() else 0.0
                    wallet_data['cn'] = int(parts[1]) if parts[1].isdigit() else 0
                    wallet_data['lu'] = now
                else:
                    wallet_data['cn'], wallet_data['cb'] = None, None
            except:
                wallet_data['cn'], wallet_data['cb'] = None, None
        return wallet_data['cn'], wallet_data['cb']
    except:
        return None, None

async def get_history():
    wallet_data = get_wallet_data()
    if not wallet_data:
        return []
        
    now = time.time()
    if now - wallet_data['lh'] < 60 and wallet_data['h']:
        return wallet_data['h']
    
    try:
        s, t, j = await req('GET', f'/address/{wallet_data["addr"]}?limit=20')
        if s != 200 or (not j and not t):
            return wallet_data['h']
        
        if j and 'recent_transactions' in j:
            tx_hashes = [ref["hash"] for ref in j.get('recent_transactions', [])]
            tx_results = await asyncio.gather(*[req('GET', f'/tx/{hash}', 5) for hash in tx_hashes], return_exceptions=True)
            
            existing_hashes = {tx['hash'] for tx in wallet_data['h']}
            nh = []
            
            for i, (ref, result) in enumerate(zip(j.get('recent_transactions', []), tx_results)):
                if isinstance(result, Exception):
                    continue
                s2, _, j2 = result
                if s2 == 200 and j2 and 'parsed_tx' in j2:
                    p = j2['parsed_tx']
                    tx_hash = ref['hash']
                    
                    if tx_hash in existing_hashes:
                        continue
                    
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
            
            old_time = datetime.now() - timedelta(hours=1)
            wallet_data['h'][:] = sorted(nh + [tx for tx in wallet_data['h'] if datetime.fromisoformat(tx.get('time', datetime.now().isoformat())) > old_time], 
                         key=lambda x: x['time'], reverse=True)[:50]
            wallet_data['lh'] = now
        elif s == 404 or (s == 200 and t and 'no transactions' in t.lower()):
            wallet_data['h'].clear()
            wallet_data['lh'] = now
        return wallet_data['h']
    except:
        return wallet_data['h']

def make_transaction(to, amount, nonce, message=None):
    wallet_data = get_wallet_data()
    if not wallet_data:
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
    signature = base64.b64encode(wallet_data['sk'].sign(base_line.encode()).signature).decode()
    tx.update(signature=signature, public_key=wallet_data['pub'])
    return tx, hashlib.sha256(base_line.encode()).hexdigest()

async def send_transaction(tx):
    start_time = time.time()
    status, text, json_resp = await req('POST', '/send-tx', tx)
    duration = time.time() - start_time
    
    if status == 200:
        if json_resp and json_resp.get('status') == 'accepted':
            return True, json_resp.get('tx_hash', ''), duration, json_resp
        elif text.lower().startswith('ok'):
            return True, text.split()[-1], duration, None
    return False, json.dumps(json_resp) if json_resp else text, duration, json_resp

@app.route('/')
def index():
    return render_template_string(open('index.html', 'r', encoding='utf-8').read())

@app.route('/api/wallet/login', methods=['POST'])
def wallet_login():
    data = request.json
    private_key = data.get('private_key', '').strip()
    address = data.get('address', '').strip()
    rpc_url = data.get('rpc_url', 'https://octra.network').strip()
    
    if not private_key or not address:
        return jsonify({'error': 'Vui lòng nhập đầy đủ Private Key và Address'}), 400
    
    if not b58.match(address):
        return jsonify({'error': 'Định dạng address không hợp lệ'}), 400
    
    if set_wallet_data(private_key, address, rpc_url):
        return jsonify({'success': True, 'message': 'Đăng nhập ví thành công!'})
    else:
        return jsonify({'error': 'Private Key không hợp lệ'}), 400

@app.route('/api/wallet/logout', methods=['POST'])
def wallet_logout():
    session_id = session.get('session_id')
    if session_id and session_id in sessions_data:
        # Đóng session aiohttp nếu có
        if sessions_data[session_id]['session']:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(sessions_data[session_id]['session'].close())
            finally:
                loop.close()
        del sessions_data[session_id]
    session.clear()
    return jsonify({'success': True, 'message': 'Đăng xuất thành công!'})

@app.route('/api/wallet/status')
def wallet_status():
    wallet_data = get_wallet_data()
    if not wallet_data:
        return jsonify({'error': 'Chưa đăng nhập ví'}), 401
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        nonce, balance = loop.run_until_complete(get_status())
        staging_status, _, staging_json = loop.run_until_complete(req('GET', '/staging', None, 2))
        staging_count = len([tx for tx in staging_json.get('staged_transactions', []) if tx.get('from') == wallet_data['addr']]) if staging_json else 0
        
        return jsonify({
            'address': wallet_data['addr'],
            'balance': balance,
            'nonce': nonce,
            'public_key': wallet_data['pub'],
            'staging_count': staging_count
        })
    finally:
        loop.close()

@app.route('/api/wallet/history')
def wallet_history():
    wallet_data = get_wallet_data()
    if not wallet_data:
        return jsonify({'error': 'Chưa đăng nhập ví'}), 401
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        history = loop.run_until_complete(get_history())
        return jsonify({'transactions': history})
    finally:
        loop.close()

@app.route('/api/wallet/send', methods=['POST'])
def send_tx():
    wallet_data = get_wallet_data()
    if not wallet_data:
        return jsonify({'error': 'Chưa đăng nhập ví'}), 401
    
    data = request.json
    to_address = data.get('to')
    amount = float(data.get('amount', 0))
    message = data.get('message')
    
    if not b58.match(to_address):
        return jsonify({'error': 'Định dạng address không hợp lệ'}), 400
    
    if amount <= 0:
        return jsonify({'error': 'Số tiền không hợp lệ'}), 400
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        nonce, balance = loop.run_until_complete(get_status())
        
        if nonce is None:
            return jsonify({'error': 'Không thể lấy nonce'}), 500
        
        if not balance or balance < amount:
            return jsonify({'error': f'Số dư không đủ ({balance:.6f} < {amount})'}), 400
        
        tx, tx_hash = make_transaction(to_address, amount, nonce + 1, message)
        success, result, duration, response = loop.run_until_complete(send_transaction(tx))
        
        if success:
            wallet_data['h'].append({
                'time': datetime.now().isoformat(),
                'hash': result,
                'amount': amount,
                'address': to_address,
                'type': 'out',
                'confirmed': True,
                'message': message
            })
            wallet_data['lu'] = 0
            
            return jsonify({
                'success': True,
                'tx_hash': result,
                'duration': duration,
                'pool_info': response.get('pool_info') if response else None
            })
        else:
            return jsonify({'error': result}), 400
    finally:
        loop.close()

@app.route('/api/wallet/export')
def export_wallet():
    wallet_data = get_wallet_data()
    if not wallet_data:
        return jsonify({'error': 'Chưa đăng nhập ví'}), 401
    
    return jsonify({
        'private_key': wallet_data['priv'],
        'public_key': wallet_data['pub'],
        'address': wallet_data['addr'],
        'rpc': wallet_data['rpc']
    })

if __name__ == '__main__':
    app.run(debug=True)

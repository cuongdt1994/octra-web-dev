from flask import Flask, request, jsonify, render_template_string
import json, base64, hashlib, time, re, random, os
from datetime import datetime, timedelta
import asyncio
import aiohttp
import nacl.signing

app = Flask(__name__)

# Global variables
priv, addr, rpc = None, None, None
sk, pub = None, None
b58 = re.compile(r"^oct[1-9A-HJ-NP-Za-km-z]{44}$")
? = 1_000_000
h = []
cb, cn, lu, lh = None, None, 0, 0
session = None

def load_wallet():
    global priv, addr, rpc, sk, pub
    try:
        wallet_data = {
            'priv': os.environ.get('WALLET_PRIVATE_KEY'),
            'addr': os.environ.get('WALLET_ADDRESS'),
            'rpc': os.environ.get('RPC_URL', 'https://octra.network')
        }
        
        if not wallet_data['priv'] or not wallet_data['addr']:
            return False
            
        priv = wallet_data['priv']
        addr = wallet_data['addr']
        rpc = wallet_data['rpc']
        sk = nacl.signing.SigningKey(base64.b64decode(priv))
        pub = base64.b64encode(sk.verify_key.encode()).decode()
        return True
    except:
        return False

async def req(method, path, data=None, timeout=10):
    global session
    if not session:
        session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout))
    try:
        url = f"{rpc}{path}"
        async with getattr(session, method.lower())(url, json=data if method == 'POST' else None) as resp:
            text = await resp.text()
            try:
                j = json.loads(text) if text else None
            except:
                j = None
            return resp.status, text, j
    except Exception as e:
        return 0, str(e), None

async def get_status():
    global cb, cn, lu
    now = time.time()
    if cb is not None and (now - lu) < 30:
        return cn, cb
    
    try:
        results = await asyncio.gather(
            req('GET', f'/balance/{addr}'),
            req('GET', '/staging', 5),
            return_exceptions=True
        )
        
        s, t, j = results[0] if not isinstance(results[0], Exception) else (0, str(results[0]), None)
        s2, _, j2 = results[1] if not isinstance(results[1], Exception) else (0, None, None)
        
        if s == 200 and j:
            cn = int(j.get('nonce', 0))
            cb = float(j.get('balance', 0))
            lu = now
            if s2 == 200 and j2:
                our = [tx for tx in j2.get('staged_transactions', []) if tx.get('from') == addr]
                if our:
                    cn = max(cn, max(int(tx.get('nonce', 0)) for tx in our))
        elif s == 404:
            cn, cb, lu = 0, 0.0, now
        elif s == 200 and t and not j:
            try:
                parts = t.strip().split()
                if len(parts) >= 2:
                    cb = float(parts[0]) if parts[0].replace('.', '').isdigit() else 0.0
                    cn = int(parts[1]) if parts[1].isdigit() else 0
                    lu = now
                else:
                    cn, cb = None, None
            except:
                cn, cb = None, None
        return cn, cb
    except:
        return None, None

async def get_history():
    global h, lh
    now = time.time()
    if now - lh < 60 and h:
        return h
    
    try:
        s, t, j = await req('GET', f'/address/{addr}?limit=20')
        if s != 200 or (not j and not t):
            return h
        
        if j and 'recent_transactions' in j:
            tx_hashes = [ref["hash"] for ref in j.get('recent_transactions', [])]
            tx_results = await asyncio.gather(*[req('GET', f'/tx/{hash}', 5) for hash in tx_hashes], return_exceptions=True)
            
            existing_hashes = {tx['hash'] for tx in h}
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
                    
                    is_incoming = p.get('to') == addr
                    amount_raw = p.get('amount_raw', p.get('amount', '0'))
                    amount = float(amount_raw) if '.' in str(amount_raw) else int(amount_raw) / ?
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
            h[:] = sorted(nh + [tx for tx in h if datetime.fromisoformat(tx.get('time', datetime.now().isoformat())) > old_time], 
                         key=lambda x: x['time'], reverse=True)[:50]
            lh = now
        elif s == 404 or (s == 200 and t and 'no transactions' in t.lower()):
            h.clear()
            lh = now
        return h
    except:
        return h

def make_transaction(to, amount, nonce, message=None):
    tx = {
        "from": addr,
        "to_": to,
        "amount": str(int(amount * ?)),
        "nonce": int(nonce),
        "ou": "1" if amount < 1000 else "3",
        "timestamp": time.time() + random.random() * 0.01
    }
    if message:
        tx["message"] = message
    
    base_line = json.dumps({k: v for k, v in tx.items() if k != "message"}, separators=(",", ":"))
    signature = base64.b64encode(sk.sign(base_line.encode()).signature).decode()
    tx.update(signature=signature, public_key=pub)
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
    return render_template_string(open('index.html').read())

@app.route('/api/wallet/status')
def wallet_status():
    if not load_wallet():
        return jsonify({'error': 'Wallet not configured'}), 400
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        nonce, balance = loop.run_until_complete(get_status())
        staging_status, _, staging_json = loop.run_until_complete(req('GET', '/staging', None, 2))
        staging_count = len([tx for tx in staging_json.get('staged_transactions', []) if tx.get('from') == addr]) if staging_json else 0
        
        return jsonify({
            'address': addr,
            'balance': balance,
            'nonce': nonce,
            'public_key': pub,
            'staging_count': staging_count
        })
    finally:
        loop.close()

@app.route('/api/wallet/history')
def wallet_history():
    if not load_wallet():
        return jsonify({'error': 'Wallet not configured'}), 400
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        history = loop.run_until_complete(get_history())
        return jsonify({'transactions': history})
    finally:
        loop.close()

@app.route('/api/wallet/send', methods=['POST'])
def send_tx():
    if not load_wallet():
        return jsonify({'error': 'Wallet not configured'}), 400
    
    data = request.json
    to_address = data.get('to')
    amount = float(data.get('amount', 0))
    message = data.get('message')
    
    if not b58.match(to_address):
        return jsonify({'error': 'Invalid address format'}), 400
    
    if amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        nonce, balance = loop.run_until_complete(get_status())
        
        if nonce is None:
            return jsonify({'error': 'Failed to get nonce'}), 500
        
        if not balance or balance < amount:
            return jsonify({'error': f'Insufficient balance ({balance:.6f} < {amount})'}), 400
        
        tx, tx_hash = make_transaction(to_address, amount, nonce + 1, message)
        success, result, duration, response = loop.run_until_complete(send_transaction(tx))
        
        if success:
            h.append({
                'time': datetime.now().isoformat(),
                'hash': result,
                'amount': amount,
                'address': to_address,
                'type': 'out',
                'confirmed': True,
                'message': message
            })
            global lu
            lu = 0
            
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
    if not load_wallet():
        return jsonify({'error': 'Wallet not configured'}), 400
    
    return jsonify({
        'private_key': priv,
        'public_key': pub,
        'address': addr,
        'rpc': rpc
    })

if __name__ == '__main__':
    app.run(debug=True)

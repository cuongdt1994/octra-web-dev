import json
import base64
import hashlib
import time
import re
import random
import aiohttp
import asyncio
import logging
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import nacl.signing
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from pydantic import BaseModel

# Cấu hình logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

# Configuration
μ = 1_000_000
b58 = re.compile(r"^oct[1-9A-HJ-NP-Za-km-z]{40,48}$")
priv, addr, rpc = None, None, None
sk, pub = None, None
cb, cn, lu, lh = None, None, 0, 0
h = []
executor = ThreadPoolExecutor(max_workers=1)

class TransactionRequest(BaseModel):
    to: str
    amount: float

class LoadWalletRequest(BaseModel):
    private_key: str

class AutoSendRequest(BaseModel):
    amount: float = 0.00001
    batch_delay: float = 0.1

def base58_encode(data):
    """Encode bytes to base58 (excluding 0, O, I, l)."""
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    x = int.from_bytes(data, 'big')
    result = ''
    while x > 0:
        x, r = divmod(x, 58)
        result = alphabet[r] + result
    result = result.rjust(44, alphabet[0])
    return result

def validate_private_key(base64_key):
    """Validate private key format and length."""
    try:
        decoded = base64.b64decode(base64_key, validate=True)
        return len(decoded) == 32
    except:
        return False

def load_wallet(base64_key=None):
    """Load wallet from base64 private key with improved error handling."""
    global priv, addr, rpc, sk, pub
    
    try:
        if not base64_key:
            raise ValueError("No private key provided")
            
        # Validate private key first
        if not validate_private_key(base64_key):
            raise ValueError("Invalid private key format or length")
            
        decoded_key = base64.b64decode(base64_key, validate=True)
        
        priv = base64_key
        sk = nacl.signing.SigningKey(decoded_key)
        pub = base64.b64encode(sk.verify_key.encode()).decode()
        pubkey_hash = hashlib.sha256(sk.verify_key.encode()).digest()
        addr = "oct" + base58_encode(pubkey_hash)[:45]
        rpc = "https://octra.network"
        
        if not b58.match(addr):
            logger.warning(f"Generated address {addr} does not match expected format")
            
        logger.info(f"Wallet loaded successfully: {addr}")
        return True
        
    except Exception as e:
        logger.error(f"Wallet load error: {str(e)}")
        return False

async def req(m, p, d=None, t=10):
    """HTTP request with improved error handling."""
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=t)) as session:
        try:
            url = f"{rpc}{p}"
            async with getattr(session, m.lower())(url, json=d if m == 'POST' else None) as resp:
                text = await resp.text()
                try:
                    j = json.loads(text) if text else None
                except:
                    j = None
                return resp.status, text, j
        except asyncio.TimeoutError:
            logger.error(f"Request timeout for {p}")
            return 0, "timeout", None
        except Exception as e:
            logger.error(f"Request error for {p}: {str(e)}")
            return 0, str(e), None

async def st():
    """Get status with improved nonce handling and retry logic."""
    global cb, cn, lu
    now = time.time()
    
    # Cache for 30 seconds
    if cb is not None and (now - lu) < 30:
        return cn, cb
    
    # Retry logic for failed requests
    for attempt in range(3):
        try:
            logger.info(f"Attempting to get status for {addr} (attempt {attempt + 1})")
            
            results = await asyncio.gather(
                req('GET', f'/balance/{addr}'),
                req('GET', '/staging', 5),
                return_exceptions=True
            )
            
            s, t, j = results[0] if not isinstance(results[0], Exception) else (0, str(results[0]), None)
            s2, _, j2 = results[1] if not isinstance(results[1], Exception) else (0, None, None)
            
            logger.info(f"Balance API response: status={s}, data={j}")
            
            if s == 200 and j:
                cn = int(j.get('nonce', 0))
                cb = float(j.get('balance', 0))
                lu = now
                
                # Check staging transactions for higher nonce
                if s2 == 200 and j2:
                    our = [tx for tx in j2.get('staged_transactions', []) if tx.get('from') == addr]
                    if our:
                        max_staged_nonce = max(int(tx.get('nonce', 0)) for tx in our)
                        cn = max(cn, max_staged_nonce)
                        logger.info(f"Updated nonce from staging: {cn}")
                
                logger.info(f"Status updated: balance={cb}, nonce={cn}")
                return cn, cb
                
            elif s == 404:
                # New wallet - initialize with default values
                cn, cb, lu = 0, 0.0, now
                logger.info("New wallet detected, initialized with nonce=0, balance=0")
                return cn, cb
                
            elif s == 200 and t and not j:
                # Try to parse plain text response
                try:
                    parts = t.strip().split()
                    if len(parts) >= 2:
                        cb = float(parts[0]) if parts[0].replace('.', '').isdigit() else 0.0
                        cn = int(parts[1]) if parts[1].isdigit() else 0
                        lu = now
                        logger.info(f"Parsed text response: balance={cb}, nonce={cn}")
                        return cn, cb
                except:
                    pass
            
            # If we reach here, the request failed
            logger.warning(f"Failed to get status (attempt {attempt + 1}): status={s}, response={t}")
            
            if attempt < 2:  # Don't sleep on last attempt
                await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"Status request error (attempt {attempt + 1}): {str(e)}")
            if attempt < 2:
                await asyncio.sleep(1)
    
    # All attempts failed
    logger.error("All attempts to get status failed")
    return None, None

async def gh():
    """Get transaction history."""
    global h, lh
    now = time.time()
    
    if now - lh < 60 and h:
        return
    
    s, t, j = await req('GET', f'/address/{addr}?limit=20')
    if s != 200 or (not j and not t):
        return
    
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
                
                ii = p.get('to') == addr
                ar = p.get('amount_raw', p.get('amount', '0'))
                a = float(ar) if '.' in str(ar) else int(ar) / μ
                
                nh.append({
                    'time': datetime.fromtimestamp(p.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S'),
                    'hash': tx_hash,
                    'amt': a,
                    'to': p.get('to') if not ii else p.get('from'),
                    'type': 'in' if ii else 'out',
                    'ok': True,
                    'nonce': p.get('nonce', 0),
                    'epoch': ref.get('epoch', 0)
                })
        
        # Keep only recent transactions (last hour)
        oh = datetime.now() - timedelta(hours=1)
        h[:] = sorted(nh + [tx for tx in h if datetime.strptime(tx.get('time', datetime.now().strftime('%Y-%m-%d %H:%M:%S')), '%Y-%m-%d %H:%M:%S') > oh], 
                     key=lambda x: datetime.strptime(x['time'], '%Y-%m-%d %H:%M:%S'), reverse=True)[:50]
        lh = now
        
    elif s == 404 or (s == 200 and t and 'no transactions' in t.lower()):
        h.clear()
        lh = now

def mk(to, a, n):
    """Create transaction."""
    tx = {
        "from": addr,
        "to_": to,
        "amount": str(int(a * μ)),
        "nonce": int(n),
        "ou": "1" if a < 1000 else "3",
        "timestamp": time.time() + random.random() * 0.01
    }
    
    bl = json.dumps(tx, separators=(",", ":"))
    sig = base64.b64encode(sk.sign(bl.encode()).signature).decode()
    tx.update(signature=sig, public_key=pub)
    
    return tx, hashlib.sha256(bl.encode()).hexdigest()

async def snd(tx):
    """Send transaction."""
    t0 = time.time()
    s, t, j = await req('POST', '/send-tx', tx)
    dt = time.time() - t0
    
    if s == 200:
        if j and j.get('status') == 'accepted':
            return True, j.get('tx_hash', ''), dt, j
        elif t.lower().startswith('ok'):
            return True, t.split()[-1], dt, None
    
    return False, json.dumps(j) if j else t, dt, j

@app.on_event("startup")
async def startup_event():
    global priv, addr, rpc, sk, pub, cb, cn, lu, lh, h
    priv, addr, rpc, sk, pub = None, None, None, None, None
    cb, cn, lu, lh = None, None, 0, 0
    h = []
    logger.info("Application started")

@app.on_event("shutdown")
async def shutdown_event():
    executor.shutdown(wait=False)
    logger.info("Application shutdown")

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    try:
        with open("static/index.html") as f:
            return HTMLResponse(content=f.read())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to serve index: {str(e)}")

@app.get("/api/wallet")
async def get_wallet():
    try:
        if not addr:
            raise HTTPException(status_code=400, detail="No wallet loaded")
        
        n, b = await st()
        await gh()
        
        s, _, j = await req('GET', '/staging', 2)
        sc = len([tx for tx in j.get('staged_transactions', []) if tx.get('from') == addr]) if j else 0
        
        return {
            "address": addr,
            "balance": f"{b:.6f} oct" if b is not None else "N/A",
            "nonce": n if n is not None else "N/A",
            "public_key": pub,
            "pending_txs": sc,
            "transactions": sorted(h, key=lambda x: datetime.strptime(x['time'], '%Y-%m-%d %H:%M:%S'), reverse=True)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get wallet: {str(e)}")

@app.post("/api/send")
async def send_transaction(tx: TransactionRequest):
    try:
        if not addr:
            raise HTTPException(status_code=400, detail="No wallet loaded")
            
        if not b58.match(tx.to):
            raise HTTPException(status_code=400, detail="Invalid address")
        
        if not re.match(r"^\d+(\.\d+)?$", str(tx.amount)) or tx.amount <= 0:
            raise HTTPException(status_code=400, detail="Invalid amount")
        
        n, b = await st()
        if n is None:
            raise HTTPException(status_code=500, detail="Failed to get nonce")
        
        if not b or b < tx.amount:
            raise HTTPException(status_code=400, detail=f"Insufficient balance ({b:.6f} < {tx.amount})")
        
        t, _ = mk(tx.to, tx.amount, n + 1)
        ok, hs, dt, r = await snd(t)
        
        if ok:
            h.append({
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'hash': hs,
                'amt': tx.amount,
                'to': tx.to,
                'type': 'out',
                'ok': True
            })
            
            global lu
            lu = 0  # Reset cache
            
            return {
                "status": "success",
                "tx_hash": hs,
                "time": f"{dt:.2f}s",
                "pool_size": r.get('pool_info', {}).get('total_pool_size', 0) if r else 0
            }
        
        raise HTTPException(status_code=400, detail=f"Transaction failed: {hs}")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Send transaction failed: {str(e)}")

@app.get("/api/load_wallet_addresses")
async def load_wallet_addresses():
    """Load all addresses from wallet.json"""
    try:
        with open("wallet.json", "r") as f:
            addresses = json.load(f)
        return {"addresses": addresses, "count": len(addresses)}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="wallet.json not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load wallet.json: {str(e)}")

@app.post("/api/auto_send")
async def auto_send_to_all(auto_send: AutoSendRequest):
    """Automatically send OCT to all addresses in wallet.json with improved error handling."""
    try:
        if not addr:
            raise HTTPException(status_code=400, detail="Wallet chưa được load")
        
        # Load addresses from wallet.json
        try:
            with open("wallet.json", "r") as f:
                addresses = json.load(f)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="wallet.json not found")
        
        # Validate addresses
        valid_addresses = [addr_item for addr_item in addresses if b58.match(addr_item)]
        if not valid_addresses:
            raise HTTPException(status_code=400, detail="No valid addresses found in wallet.json")
        
        # Calculate total amount needed
        total_amount = auto_send.amount * len(valid_addresses)
        
        # Get current status with retry logic
        n, b = await st()
        if n is None:
            # Try to initialize new wallet
            logger.warning("Failed to get nonce, attempting to initialize new wallet")
            n, b = 0, 0.0
        
        # Check balance
        if not b or b < total_amount:
            raise HTTPException(status_code=400, detail=f"Insufficient balance ({b:.6f} < {total_amount})")
        
        logger.info(f"Starting auto send to {len(valid_addresses)} addresses, total amount: {total_amount}")
        
        results = []
        current_nonce = n
        successful_txs = 0
        
        for i, to_addr in enumerate(valid_addresses):
            try:
                current_nonce += 1
                logger.info(f"Sending {auto_send.amount} OCT to {to_addr} (nonce: {current_nonce})")
                
                t, _ = mk(to_addr, auto_send.amount, current_nonce)
                ok, hs, dt, r = await snd(t)
                
                if ok:
                    successful_txs += 1
                    h.append({
                        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'hash': hs,
                        'amt': auto_send.amount,
                        'to': to_addr,
                        'type': 'out',
                        'ok': True
                    })
                    
                    results.append({
                        'index': i,
                        'status': 'success',
                        'tx_hash': hs,
                        'to': to_addr,
                        'amount': auto_send.amount,
                        'time': f"{dt:.2f}s"
                    })
                    logger.info(f"Successfully sent to {to_addr}: {hs}")
                else:
                    results.append({
                        'index': i,
                        'status': 'failed',
                        'error': hs,
                        'to': to_addr,
                        'amount': auto_send.amount
                    })
                    logger.error(f"Failed to send to {to_addr}: {hs}")
                
                # Add delay between transactions
                if i < len(valid_addresses) - 1 and auto_send.batch_delay > 0:
                    await asyncio.sleep(auto_send.batch_delay)
                    
            except Exception as e:
                results.append({
                    'index': i,
                    'status': 'error',
                    'error': str(e),
                    'to': to_addr,
                    'amount': auto_send.amount
                })
                logger.error(f"Error sending to {to_addr}: {str(e)}")
        
        # Reset cache to force refresh
        global lu
        lu = 0
        
        logger.info(f"Auto send completed: {successful_txs}/{len(valid_addresses)} successful")
        
        return {
            'status': 'completed',
            'total_addresses': len(valid_addresses),
            'successful_transactions': successful_txs,
            'failed_transactions': len(valid_addresses) - successful_txs,
            'total_amount': total_amount,
            'results': results
        }
        
    except Exception as e:
        logger.error(f"Auto send failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Auto send failed: {str(e)}")

@app.post("/api/load_wallet")
async def load_base64_wallet(data: LoadWalletRequest):
    try:
        if not load_wallet(base64_key=data.private_key):
            raise HTTPException(status_code=400, detail="Invalid base64 private key")
        
        # Test connection after loading wallet
        n, b = await st()
        if n is None:
            logger.warning("Wallet loaded but failed to get initial status")
        
        return {
            "status": "wallet loaded", 
            "address": addr,
            "balance": f"{b:.6f} oct" if b is not None else "N/A",
            "nonce": n if n is not None else "N/A"
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Load wallet failed: {str(e)}")

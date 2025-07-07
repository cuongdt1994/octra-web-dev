import json
import base64
import hashlib
import time
import re
import random
import aiohttp
import asyncio
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import nacl.signing
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import os

app = FastAPI(title="Octra Wallet", version="2.0.0")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Configuration
μ = 1_000_000
b58 = re.compile(r"^oct[1-9A-HJ-NP-Za-km-z]{40,48}$")
priv, addr, rpc = None, None, None
sk, pub = None, None
cb, cn, lu, lh = None, None, 0, 0
h = []
executor = ThreadPoolExecutor(max_workers=4)

# Pydantic Models
class TransactionRequest(BaseModel):
    to: str
    amount: float

class LoadWalletRequest(BaseModel):
    private_key: str

class AutoSendRequest(BaseModel):
    amount: float = 0.00001
    batch_delay: float = 1.0
    max_concurrent: int = 1

class AddAddressRequest(BaseModel):
    address: str

class WalletResponse(BaseModel):
    address: str
    balance: str
    nonce: Any
    public_key: str
    pending_txs: int
    transactions: List[Dict]

# Cache cho API responses
api_cache = {}
cache_ttl = 30

def get_cache_key(key: str) -> str:
    return f"{key}_{int(time.time() // cache_ttl)}"

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

def validate_private_key(base64_key: str) -> bool:
    """Validate private key format and length."""
    try:
        decoded = base64.b64decode(base64_key, validate=True)
        return len(decoded) == 32
    except Exception:
        return False

def validate_address(address: str) -> bool:
    """Validate OCT address format."""
    return bool(b58.match(address))

def load_wallet(base64_key: Optional[str] = None) -> bool:
    """Load wallet from base64 private key with improved error handling."""
    global priv, addr, rpc, sk, pub
    try:
        if not base64_key:
            raise ValueError("No private key provided")
        
        if not validate_private_key(base64_key):
            raise ValueError("Invalid private key format or length")
        
        decoded_key = base64.b64decode(base64_key, validate=True)
        priv = base64_key
        sk = nacl.signing.SigningKey(decoded_key)
        pub = base64.b64encode(sk.verify_key.encode()).decode()
        pubkey_hash = hashlib.sha256(sk.verify_key.encode()).digest()
        addr = "oct" + base58_encode(pubkey_hash)[:45]
        rpc = "https://octra.network"
        
        return True
    except Exception:
        return False

async def req(method: str, path: str, data: Optional[Dict] = None, timeout: int = 10) -> tuple:
    """HTTP request with improved error handling and caching."""
    cache_key = get_cache_key(f"{method}_{path}_{str(data)}")
    
    if method == 'GET' and cache_key in api_cache:
        return api_cache[cache_key]
    
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
        try:
            url = f"{rpc}{path}"
            async with getattr(session, method.lower())(url, json=data if method == 'POST' else None) as resp:
                text = await resp.text()
                try:
                    j = json.loads(text) if text else None
                except json.JSONDecodeError:
                    j = None
                
                result = (resp.status, text, j)
                
                if method == 'GET' and resp.status == 200:
                    api_cache[cache_key] = result
                
                return result
        except asyncio.TimeoutError:
            return 0, "timeout", None
        except Exception:
            return 0, "error", None

async def get_status() -> tuple:
    """Get wallet status with improved error handling."""
    global cb, cn, lu
    now = time.time()
    
    if cb is not None and (now - lu) < 30:
        return cn, cb
    
    for attempt in range(3):
        try:
            results = await asyncio.gather(
                req('GET', f'/balance/{addr}'),
                req('GET', '/staging', 5),
                return_exceptions=True
            )
            
            balance_result = results[0] if not isinstance(results[0], Exception) else (0, str(results[0]), None)
            staging_result = results[1] if not isinstance(results[1], Exception) else (0, None, None)
            
            s, t, j = balance_result
            s2, _, j2 = staging_result
            
            if s == 200 and j:
                cn = int(j.get('nonce', 0))
                cb = float(j.get('balance', 0))
                lu = now
                
                if s2 == 200 and j2:
                    our_txs = [tx for tx in j2.get('staged_transactions', []) if tx.get('from') == addr]
                    if our_txs:
                        max_staged_nonce = max(int(tx.get('nonce', 0)) for tx in our_txs)
                        cn = max(cn, max_staged_nonce)
                
                return cn, cb
            elif s == 404:
                cn, cb, lu = 0, 0.0, now
                return cn, cb
            elif s == 200 and t and not j:
                try:
                    parts = t.strip().split()
                    if len(parts) >= 2:
                        cb = float(parts[0]) if parts[0].replace('.', '').isdigit() else 0.0
                        cn = int(parts[1]) if parts[1].isdigit() else 0
                        lu = now
                        return cn, cb
                except Exception:
                    pass
            
            if attempt < 2:
                await asyncio.sleep(1)
        except Exception:
            if attempt < 2:
                await asyncio.sleep(1)
    
    return None, None

async def get_history():
    """Get transaction history with improved caching."""
    global h, lh
    now = time.time()
    
    if now - lh < 60 and h:
        return
    
    try:
        s, t, j = await req('GET', f'/address/{addr}?limit=20')
        
        if s != 200 or (not j and not t):
            return
        
        if j and 'recent_transactions' in j:
            tx_hashes = [ref["hash"] for ref in j.get('recent_transactions', [])]
            
            tx_results = await asyncio.gather(
                *[req('GET', f'/tx/{hash}', None, 5) for hash in tx_hashes],
                return_exceptions=True
            )
            
            existing_hashes = {tx['hash'] for tx in h}
            new_transactions = []
            
            for ref, result in zip(j.get('recent_transactions', []), tx_results):
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
                    amount = float(amount_raw) if '.' in str(amount_raw) else int(amount_raw) / μ
                    
                    new_transactions.append({
                        'time': datetime.fromtimestamp(p.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S'),
                        'hash': tx_hash,
                        'amt': amount,
                        'to': p.get('to') if not is_incoming else p.get('from'),
                        'type': 'in' if is_incoming else 'out',
                        'ok': True,
                        'nonce': p.get('nonce', 0),
                        'epoch': ref.get('epoch', 0)
                    })
            
            one_hour_ago = datetime.now() - timedelta(hours=1)
            h[:] = sorted(
                new_transactions + [
                    tx for tx in h
                    if datetime.strptime(tx.get('time', datetime.now().strftime('%Y-%m-%d %H:%M:%S')), '%Y-%m-%d %H:%M:%S') > one_hour_ago
                ],
                key=lambda x: datetime.strptime(x['time'], '%Y-%m-%d %H:%M:%S'),
                reverse=True
            )[:50]
        elif s == 404 or (s == 200 and t and 'no transactions' in t.lower()):
            h.clear()
        
        lh = now
    except Exception:
        pass

def create_transaction(to: str, amount: float, nonce: int) -> tuple:
    """Create transaction with improved error handling."""
    try:
        tx = {
            "from": addr,
            "to_": to,
            "amount": str(int(amount * μ)),
            "nonce": int(nonce),
            "ou": "1" if amount < 1000 else "3",
            "timestamp": time.time() + random.random() * 0.01
        }
        
        tx_bytes = json.dumps(tx, separators=(",", ":"))
        signature = base64.b64encode(sk.sign(tx_bytes.encode()).signature).decode()
        tx.update(signature=signature, public_key=pub)
        tx_hash = hashlib.sha256(tx_bytes.encode()).hexdigest()
        
        return tx, tx_hash
    except Exception as e:
        raise

async def send_transaction(tx: Dict) -> tuple:
    """Send transaction with improved error handling."""
    start_time = time.time()
    try:
        s, t, j = await req('POST', '/send-tx', tx)
        duration = time.time() - start_time
        
        if s == 200:
            if j and j.get('status') == 'accepted':
                return True, j.get('tx_hash', ''), duration, j
            elif t.lower().startswith('ok'):
                return True, t.split()[-1], duration, None
        
        return False, json.dumps(j) if j else t, duration, j
    except Exception as e:
        return False, str(e), time.time() - start_time, None

def load_wallet_addresses() -> List[str]:
    """Load addresses from wallet.json with validation."""
    try:
        if not os.path.exists("wallet.json"):
            return []
        
        with open("wallet.json", "r") as f:
            addresses = json.load(f)
        
        valid_addresses = [addr for addr in addresses if validate_address(addr)]
        return valid_addresses
    except Exception:
        return []

def save_wallet_addresses(addresses: List[str]) -> bool:
    """Save addresses to wallet.json."""
    try:
        with open("wallet.json", "w") as f:
            json.dump(addresses, f, indent=2)
        return True
    except Exception:
        return False

async def sequential_auto_send(addresses: List[str], amount: float, delay: float):
    """Send transactions sequentially to avoid network congestion."""
    global lu
    results = []
    successful_txs = 0
    
    try:
        current_nonce, balance = await get_status()
        if current_nonce is None:
            current_nonce = 0
        
        total_amount = amount * len(addresses)
        if balance < total_amount:
            return
        
        for i, to_addr in enumerate(addresses):
            try:
                current_nonce += 1
                tx, tx_hash = create_transaction(to_addr, amount, current_nonce)
                success, result, duration, response = await send_transaction(tx)
                
                if success:
                    successful_txs += 1
                    h.append({
                        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'hash': result,
                        'amt': amount,
                        'to': to_addr,
                        'type': 'out',
                        'ok': True
                    })
                    results.append({
                        'index': i,
                        'status': 'success',
                        'tx_hash': result,
                        'to': to_addr,
                        'amount': amount,
                        'time': f"{duration:.2f}s"
                    })
                else:
                    results.append({
                        'index': i,
                        'status': 'failed',
                        'error': result,
                        'to': to_addr,
                        'amount': amount
                    })
                
                if i < len(addresses) - 1 and delay > 0:
                    await asyncio.sleep(delay)
                    
            except Exception as e:
                results.append({
                    'index': i,
                    'status': 'error',
                    'error': str(e),
                    'to': to_addr,
                    'amount': amount
                })
        
        lu = 0
    except Exception:
        pass

# API Endpoints
@app.on_event("startup")
async def startup_event():
    """Initialize application."""
    global priv, addr, rpc, sk, pub, cb, cn, lu, lh, h
    priv, addr, rpc, sk, pub = None, None, None, None, None
    cb, cn, lu, lh = None, None, 0, 0
    h = []

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    executor.shutdown(wait=False)

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """Serve main HTML page."""
    try:
        with open("static/index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to serve index: {str(e)}")

@app.get("/api/wallet", response_model=WalletResponse)
async def get_wallet():
    """Get wallet information."""
    try:
        if not addr:
            raise HTTPException(status_code=400, detail="No wallet loaded")
        
        nonce, balance = await get_status()
        await get_history()
        
        s, _, j = await req('GET', '/staging', 2)
        pending_count = len([tx for tx in j.get('staged_transactions', []) if tx.get('from') == addr]) if j else 0
        
        return WalletResponse(
            address=addr,
            balance=f"{balance:.6f} oct" if balance is not None else "N/A",
            nonce=nonce if nonce is not None else "N/A",
            public_key=pub,
            pending_txs=pending_count,
            transactions=sorted(h, key=lambda x: datetime.strptime(x['time'], '%Y-%m-%d %H:%M:%S'), reverse=True)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get wallet: {str(e)}")

@app.post("/api/send")
async def send_single_transaction(tx: TransactionRequest):
    """Send a single transaction."""
    try:
        if not addr:
            raise HTTPException(status_code=400, detail="No wallet loaded")
        
        if not validate_address(tx.to):
            raise HTTPException(status_code=400, detail="Invalid address format")
        
        if not re.match(r"^\d+(\.\d+)?$", str(tx.amount)) or tx.amount <= 0:
            raise HTTPException(status_code=400, detail="Invalid amount")
        
        nonce, balance = await get_status()
        if nonce is None:
            raise HTTPException(status_code=500, detail="Failed to get nonce")
        
        if not balance or balance < tx.amount:
            raise HTTPException(status_code=400, detail=f"Insufficient balance ({balance:.6f} < {tx.amount})")
        
        transaction, tx_hash = create_transaction(tx.to, tx.amount, nonce + 1)
        success, result, duration, response = await send_transaction(transaction)
        
        if success:
            h.append({
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'hash': result,
                'amt': tx.amount,
                'to': tx.to,
                'type': 'out',
                'ok': True
            })
            
            global lu
            lu = 0
            
            return {
                "status": "success",
                "tx_hash": result,
                "time": f"{duration:.2f}s",
                "pool_size": response.get('pool_info', {}).get('total_pool_size', 0) if response else 0
            }
        
        raise HTTPException(status_code=400, detail=f"Transaction failed: {result}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Send transaction failed: {str(e)}")

@app.get("/api/load_wallet_addresses")
async def get_wallet_addresses():
    """Load all addresses from wallet.json."""
    try:
        addresses = load_wallet_addresses()
        return {"addresses": addresses, "count": len(addresses)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load wallet addresses: {str(e)}")

@app.post("/api/add_address")
async def add_wallet_address(request: AddAddressRequest):
    """Add a new address to wallet.json."""
    try:
        if not validate_address(request.address):
            raise HTTPException(status_code=400, detail="Invalid address format")
        
        addresses = load_wallet_addresses()
        if request.address in addresses:
            raise HTTPException(status_code=400, detail="Address already exists")
        
        addresses.append(request.address)
        if save_wallet_addresses(addresses):
            return {
                "status": "success",
                "message": "Address added successfully",
                "total_addresses": len(addresses)
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to save address")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add address: {str(e)}")

@app.delete("/api/remove_address/{address}")
async def remove_wallet_address(address: str):
    """Remove an address from wallet.json."""
    try:
        addresses = load_wallet_addresses()
        if address not in addresses:
            raise HTTPException(status_code=404, detail="Address not found")
        
        addresses.remove(address)
        if save_wallet_addresses(addresses):
            return {
                "status": "success",
                "message": "Address removed successfully",
                "total_addresses": len(addresses)
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to save addresses")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to remove address: {str(e)}")

@app.post("/api/auto_send")
async def auto_send_sequential(auto_send: AutoSendRequest, background_tasks: BackgroundTasks):
    """Send OCT sequentially to all addresses in wallet.json."""
    try:
        if not addr:
            raise HTTPException(status_code=400, detail="Wallet not loaded")
        
        addresses = load_wallet_addresses()
        if not addresses:
            raise HTTPException(status_code=400, detail="No addresses found in wallet.json")
        
        total_amount = auto_send.amount * len(addresses)
        nonce, balance = await get_status()
        
        if nonce is None:
            nonce, balance = 0, 0.0
        
        if not balance or balance < total_amount:
            raise HTTPException(status_code=400, detail=f"Insufficient balance ({balance:.6f} < {total_amount})")
        
        background_tasks.add_task(sequential_auto_send, addresses, auto_send.amount, auto_send.batch_delay)
        
        return {
            'status': 'started',
            'message': 'Sequential auto send started in background',
            'total_addresses': len(addresses),
            'total_amount': total_amount,
            'estimated_time': f"{len(addresses) * auto_send.batch_delay:.1f} seconds"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Auto send failed: {str(e)}")

@app.post("/api/load_wallet")
async def load_wallet_endpoint(data: LoadWalletRequest):
    """Load wallet from base64 private key."""
    try:
        if not load_wallet(base64_key=data.private_key):
            raise HTTPException(status_code=400, detail="Invalid base64 private key")
        
        nonce, balance = await get_status()
        
        return {
            "status": "wallet loaded",
            "address": addr,
            "balance": f"{balance:.6f} oct" if balance is not None else "N/A",
            "nonce": nonce if nonce is not None else "N/A"
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Load wallet failed: {str(e)}")

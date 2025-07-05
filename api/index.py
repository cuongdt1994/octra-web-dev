import json
import base64
import hashlib
import time
import re
import random
import aiohttp
import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import nacl.signing
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from pydantic import BaseModel
import uvicorn

# Initialize FastAPI app
app = FastAPI(title="Octra Wallet", description="Secure Cryptocurrency Management")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="."), name="static")

# Configuration
MICROOCTRA = 1_000_000
ADDRESS_REGEX = re.compile(r"^oct[1-9A-HJ-NP-Za-km-z]{40,48}$")

# Global variables
private_key, wallet_address, rpc_url = None, None, None
signing_key, public_key = None, None
cached_balance, cached_nonce, last_update, last_history_update = None, None, 0, 0
transaction_history = []
executor = ThreadPoolExecutor(max_workers=1)

# Pydantic models
class TransactionRequest(BaseModel):
    to: str
    amount: float

class LoadWalletRequest(BaseModel):
    private_key: str

# Utility functions
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

def load_wallet(base64_key=None):
    """Load wallet from base64 private key."""
    global private_key, wallet_address, rpc_url, signing_key, public_key
    
    try:
        if not base64_key:
            raise ValueError("No private key provided")
            
        # Decode and validate private key
        decoded_key = base64.b64decode(base64_key, validate=True)
        if len(decoded_key) != 32:
            raise ValueError(f"Invalid private key length: {len(decoded_key)} bytes (expected 32)")
        
        # Initialize wallet components
        private_key = base64_key
        signing_key = nacl.signing.SigningKey(decoded_key)
        public_key = base64.b64encode(signing_key.verify_key.encode()).decode()
        
        # Generate wallet address
        pubkey_hash = hashlib.sha256(signing_key.verify_key.encode()).digest()
        wallet_address = "oct" + base58_encode(pubkey_hash)[:45]
        rpc_url = "https://octra.network"
        
        # Validate generated address
        if not ADDRESS_REGEX.match(wallet_address):
            print(f"Warning: Generated address {wallet_address} does not match expected format")
        
        return True
        
    except Exception as e:
        print(f"Wallet load error: {str(e)}")
        return False

async def make_request(method, path, data=None, timeout=10):
    """Make HTTP request to RPC server."""
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
        try:
            url = f"{rpc_url}{path}"
            kwargs = {'json': data} if method.upper() == 'POST' and data else {}
            
            async with getattr(session, method.lower())(url, **kwargs) as response:
                text = await response.text()
                
                try:
                    json_data = json.loads(text) if text else None
                except json.JSONDecodeError:
                    json_data = None
                    
                return response.status, text, json_data
                
        except asyncio.TimeoutError:
            return 0, "Request timeout", None
        except Exception as e:
            return 0, str(e), None

async def get_wallet_status():
    """Get wallet balance and nonce."""
    global cached_balance, cached_nonce, last_update
    
    current_time = time.time()
    
    # Use cached data if recent (within 30 seconds)
    if cached_balance is not None and (current_time - last_update) < 30:
        return cached_nonce, cached_balance
    
    try:
        # Make parallel requests for balance and staging
        results = await asyncio.gather(
            make_request('GET', f'/balance/{wallet_address}'),
            make_request('GET', '/staging', 5),
            return_exceptions=True
        )
        
        # Process balance response
        balance_result = results[0] if not isinstance(results[0], Exception) else (0, str(results[0]), None)
        status, text, json_data = balance_result
        
        # Process staging response
        staging_result = results[1] if not isinstance(results[1], Exception) else (0, None, None)
        staging_status, _, staging_json = staging_result
        
        if status == 200 and json_data:
            cached_nonce = int(json_data.get('nonce', 0))
            cached_balance = float(json_data.get('balance', 0))
            last_update = current_time
            
            # Check for pending transactions in staging
            if staging_status == 200 and staging_json:
                our_txs = [tx for tx in staging_json.get('staged_transactions', []) 
                          if tx.get('from') == wallet_address]
                if our_txs:
                    cached_nonce = max(cached_nonce, max(int(tx.get('nonce', 0)) for tx in our_txs))
                    
        elif status == 404:
            # New wallet with no transactions
            cached_nonce, cached_balance, last_update = 0, 0.0, current_time
            
        elif status == 200 and text and not json_data:
            # Handle plain text response
            try:
                parts = text.strip().split()
                if len(parts) >= 2:
                    cached_balance = float(parts[0]) if parts[0].replace('.', '').replace('-', '').isdigit() else 0.0
                    cached_nonce = int(parts[1]) if parts[1].isdigit() else 0
                    last_update = current_time
                else:
                    cached_nonce, cached_balance = None, None
            except (ValueError, IndexError):
                cached_nonce, cached_balance = None, None
        else:
            cached_nonce, cached_balance = None, None
            
    except Exception as e:
        print(f"Error getting wallet status: {e}")
        cached_nonce, cached_balance = None, None
    
    return cached_nonce, cached_balance

async def get_transaction_history():
    """Get transaction history for the wallet."""
    global transaction_history, last_history_update
    
    current_time = time.time()
    
    # Use cached data if recent (within 60 seconds)
    if current_time - last_history_update < 60 and transaction_history:
        return
    
    try:
        status, text, json_data = await make_request('GET', f'/address/{wallet_address}?limit=20')
        
        if status != 200 or (not json_data and not text):
            return
        
        if json_data and 'recent_transactions' in json_data:
            tx_hashes = [ref["hash"] for ref in json_data.get('recent_transactions', [])]
            
            # Fetch transaction details in parallel
            tx_results = await asyncio.gather(
                *[make_request('GET', f'/tx/{hash}', timeout=5) for hash in tx_hashes], 
                return_exceptions=True
            )
            
            existing_hashes = {tx['hash'] for tx in transaction_history}
            new_transactions = []
            
            for ref, result in zip(json_data.get('recent_transactions', []), tx_results):
                if isinstance(result, Exception):
                    continue
                    
                tx_status, _, tx_json = result
                if tx_status == 200 and tx_json and 'parsed_tx' in tx_json:
                    parsed_tx = tx_json['parsed_tx']
                    tx_hash = ref['hash']
                    
                    if tx_hash in existing_hashes:
                        continue
                    
                    is_incoming = parsed_tx.get('to') == wallet_address
                    amount_raw = parsed_tx.get('amount_raw', parsed_tx.get('amount', '0'))
                    
                    # Convert amount to OCT
                    if '.' in str(amount_raw):
                        amount = float(amount_raw)
                    else:
                        amount = int(amount_raw) / MICROOCTRA
                    
                    new_transactions.append({
                        'time': datetime.fromtimestamp(parsed_tx.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S'),
                        'hash': tx_hash,
                        'amt': amount,
                        'to': parsed_tx.get('to') if not is_incoming else parsed_tx.get('from'),
                        'type': 'in' if is_incoming else 'out',
                        'ok': True,
                        'nonce': parsed_tx.get('nonce', 0),
                        'epoch': ref.get('epoch', 0)
                    })
            
            # Merge with existing transactions and sort
            one_hour_ago = datetime.now() - timedelta(hours=1)
            filtered_old_txs = [
                tx for tx in transaction_history 
                if datetime.strptime(tx.get('time', datetime.now().strftime('%Y-%m-%d %H:%M:%S')), '%Y-%m-%d %H:%M:%S') > one_hour_ago
            ]
            
            transaction_history[:] = sorted(
                new_transactions + filtered_old_txs, 
                key=lambda x: datetime.strptime(x['time'], '%Y-%m-%d %H:%M:%S'), 
                reverse=True
            )[:50]
            
            last_history_update = current_time
            
        elif status == 404 or (status == 200 and text and 'no transactions' in text.lower()):
            transaction_history.clear()
            last_history_update = current_time
            
    except Exception as e:
        print(f"Error getting transaction history: {e}")

def create_transaction(to_address, amount, nonce):
    """Create and sign a transaction."""
    transaction = {
        "from": wallet_address,
        "to_": to_address,
        "amount": str(int(amount * MICROOCTRA)),
        "nonce": int(nonce),
        "ou": "1" if amount < 1000 else "3",
        "timestamp": time.time() + random.random() * 0.01
    }
    
    # Create transaction blob and sign it
    transaction_blob = json.dumps(transaction, separators=(",", ":"))
    signature = base64.b64encode(signing_key.sign(transaction_blob.encode()).signature).decode()
    
    # Add signature and public key
    transaction.update({
        "signature": signature,
        "public_key": public_key
    })
    
    tx_hash = hashlib.sha256(transaction_blob.encode()).hexdigest()
    return transaction, tx_hash

async def send_transaction(transaction):
    """Send transaction to the network."""
    start_time = time.time()
    status, text, json_data = await make_request('POST', '/send-tx', transaction)
    duration = time.time() - start_time
    
    if status == 200:
        if json_data and json_data.get('status') == 'accepted':
            return True, json_data.get('tx_hash', ''), duration, json_data
        elif text and text.lower().startswith('ok'):
            return True, text.split()[-1], duration, None
    
    error_msg = json.dumps(json_data) if json_data else text
    return False, error_msg, duration, json_data

def validate_transaction(tx: TransactionRequest):
    """Validate transaction parameters."""
    if not ADDRESS_REGEX.match(tx.to):
        raise ValueError("Invalid recipient address format")
    
    if tx.amount <= 0:
        raise ValueError("Amount must be positive")
    
    if tx.amount > 1000000:  # Max transaction limit
        raise ValueError("Amount exceeds maximum limit")
    
    return True

# Event handlers
@app.on_event("startup")
async def startup_event():
    """Initialize application state."""
    global private_key, wallet_address, rpc_url, signing_key, public_key
    global cached_balance, cached_nonce, last_update, last_history_update, transaction_history
    
    private_key, wallet_address, rpc_url, signing_key, public_key = None, None, None, None, None
    cached_balance, cached_nonce, last_update, last_history_update = None, None, 0, 0
    transaction_history = []
    
    print("Octra Wallet started successfully!")

@app.on_event("shutdown")
async def shutdown_event():
    """Clean up resources."""
    executor.shutdown(wait=False)
    print("Octra Wallet shutdown complete!")

# Exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler."""
    print(f"Global exception: {str(exc)}")
    return {"detail": f"Internal server error: {str(exc)}"}

# API Routes
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """Serve the main HTML page."""
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to serve index: {str(e)}")

@app.get("/api/wallet")
async def get_wallet():
    """Get wallet information including balance, nonce, and transaction history."""
    try:
        if not wallet_address:
            raise HTTPException(status_code=400, detail="No wallet loaded")
        
        # Get wallet status and transaction history
        nonce, balance = await get_wallet_status()
        await get_transaction_history()
        
        # Get pending transaction count
        staging_status, _, staging_json = await make_request('GET', '/staging', timeout=2)
        pending_count = 0
        if staging_status == 200 and staging_json:
            pending_count = len([
                tx for tx in staging_json.get('staged_transactions', []) 
                if tx.get('from') == wallet_address
            ])
        
        return {
            "address": wallet_address,
            "balance": f"{balance:.6f} oct" if balance is not None else "N/A",
            "nonce": nonce if nonce is not None else "N/A",
            "public_key": public_key,
            "pending_txs": pending_count,
            "transactions": sorted(
                transaction_history, 
                key=lambda x: datetime.strptime(x['time'], '%Y-%m-%d %H:%M:%S'), 
                reverse=True
            )
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get wallet: {str(e)}")

@app.post("/api/send")
async def send_transaction_endpoint(tx: TransactionRequest):
    """Send a transaction."""
    try:
        if not wallet_address:
            raise HTTPException(status_code=400, detail="No wallet loaded")
        
        # Validate transaction
        validate_transaction(tx)
        
        # Get current wallet status
        nonce, balance = await get_wallet_status()
        if nonce is None:
            raise HTTPException(status_code=500, detail="Failed to get wallet nonce")
        
        if not balance or balance < tx.amount:
            raise HTTPException(
                status_code=400, 
                detail=f"Insufficient balance ({balance:.6f} < {tx.amount})"
            )
        
        # Create and send transaction
        transaction, tx_hash = create_transaction(tx.to, tx.amount, nonce + 1)
        success, result, duration, response = await send_transaction(transaction)
        
        if success:
            # Add to local transaction history
            transaction_history.append({
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'hash': result,
                'amt': tx.amount,
                'to': tx.to,
                'type': 'out',
                'ok': True,
                'nonce': nonce + 1,
                'epoch': None
            })
            
            # Reset cache to force refresh
            global last_update
            last_update = 0
            
            return {
                "status": "success",
                "tx_hash": result,
                "time": f"{duration:.2f}s",
                "pool_size": response.get('pool_info', {}).get('total_pool_size', 0) if response else 0
            }
        else:
            raise HTTPException(status_code=400, detail=f"Transaction failed: {result}")
            
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Send transaction failed: {str(e)}")

@app.post("/api/load_wallet")
async def load_wallet_endpoint(data: LoadWalletRequest):
    """Load wallet from base64 private key."""
    try:
        if not load_wallet(base64_key=data.private_key):
            raise HTTPException(status_code=400, detail="Invalid base64 private key")
        
        return {
            "status": "wallet loaded", 
            "address": wallet_address
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Load wallet failed: {str(e)}")

# Health check endpoint
@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "wallet_loaded": wallet_address is not None,
        "timestamp": datetime.now().isoformat()
    }

# Run the application
if __name__ == "__main__":
    uvicorn.run(
        "index:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )

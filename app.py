from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
import json
import base64
import hashlib
import time
import aiohttp
import asyncio
import random
import re
from datetime import datetime, timedelta
import nacl.signing
from typing import Optional, Tuple, List, Dict

app = FastAPI(title="Octra Wallet Web", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="templates")

# Wallet Manager Class
class WalletManager:
    def __init__(self):
        self.private_key = None
        self.address = None
        self.rpc_url = None
        self.signing_key = None
        self.public_key = None
        self.session = None
        self.balance = 0.0
        self.nonce = 0
        self.last_update = 0
        self.transaction_history = []
        self.last_history_update = 0
        
    async def init_wallet(self, private_key: str, rpc_url: str = "https://octra.network") -> bool:
        try:
            self.private_key = private_key
            self.rpc_url = rpc_url
            self.signing_key = nacl.signing.SigningKey(base64.b64decode(private_key))
            self.public_key = base64.b64encode(self.signing_key.verify_key.encode()).decode()
            self.address = self._generate_address()
            
            if not self.session:
                self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
            return True
        except Exception as e:
            print(f"Wallet initialization error: {e}")
            return False
    
    def _generate_address(self) -> str:
        pub_bytes = base64.b64decode(self.public_key)
        hash_obj = hashlib.sha256(pub_bytes)
        address_bytes = hash_obj.digest()[:25]
        checksum = hashlib.sha256(address_bytes).digest()[:4]
        full_address = address_bytes + checksum
        return "oct" + self._base58_encode(full_address)
    
    def _base58_encode(self, data: bytes) -> str:
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        num = int.from_bytes(data, 'big')
        encoded = ""
        while num > 0:
            num, remainder = divmod(num, 58)
            encoded = alphabet[remainder] + encoded
        for byte in data:
            if byte == 0:
                encoded = alphabet[0] + encoded
            else:
                break
        return encoded
    
    def is_initialized(self) -> bool:
        return self.private_key is not None and self.address is not None
    
    async def _make_request(self, method: str, endpoint: str, data: dict = None) -> Tuple[int, str, dict]:
        try:
            url = f"{self.rpc_url}{endpoint}"
            if method.upper() == "GET":
                async with self.session.get(url) as response:
                    text = await response.text()
                    try:
                        json_data = json.loads(text) if text else None
                    except:
                        json_data = None
                    return response.status, text, json_data
            elif method.upper() == "POST":
                async with self.session.post(url, json=data) as response:
                    text = await response.text()
                    try:
                        json_data = json.loads(text) if text else None
                    except:
                        json_data = None
                    return response.status, text, json_data
        except Exception as e:
            return 0, str(e), None
    
    async def get_balance_and_nonce(self) -> Tuple[Optional[float], Optional[int]]:
        now = time.time()
        if self.last_update and (now - self.last_update) < 30:
            return self.balance, self.nonce
        
        try:
            status, text, json_data = await self._make_request("GET", f"/balance/{self.address}")
            if status == 200 and json_data:
                self.balance = float(json_data.get('balance', 0))
                self.nonce = int(json_data.get('nonce', 0))
                self.last_update = now
            elif status == 404:
                self.balance, self.nonce = 0.0, 0
                self.last_update = now
            return self.balance, self.nonce
        except Exception as e:
            print(f"Error getting balance: {e}")
            return None, None
    
    async def get_staging_count(self) -> int:
        try:
            status, _, json_data = await self._make_request("GET", "/staging")
            if status == 200 and json_data:
                our_txs = [tx for tx in json_data.get('staged_transactions', []) 
                          if tx.get('from') == self.address]
                return len(our_txs)
            return 0
        except:
            return 0
    
    async def get_transaction_history(self) -> List[Dict]:
        now = time.time()
        if self.last_history_update and (now - self.last_history_update) < 60:
            return self.transaction_history
        
        try:
            status, text, json_data = await self._make_request("GET", f"/address/{self.address}?limit=20")
            if status != 200:
                return []
            
            if json_data and 'recent_transactions' in json_data:
                tx_hashes = [ref["hash"] for ref in json_data.get('recent_transactions', [])]
                tasks = [self._make_request("GET", f"/tx/{hash}") for hash in tx_hashes]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                new_history = []
                for ref, result in zip(json_data.get('recent_transactions', []), results):
                    if isinstance(result, Exception):
                        continue
                    
                    status2, _, json_data2 = result
                    if status2 == 200 and json_data2 and 'parsed_tx' in json_data2:
                        parsed_tx = json_data2['parsed_tx']
                        is_incoming = parsed_tx.get('to') == self.address
                        amount_raw = parsed_tx.get('amount_raw', parsed_tx.get('amount', '0'))
                        amount = float(amount_raw) if '.' in str(amount_raw) else int(amount_raw) / 1_000_000
                        
                        message = None
                        if 'data' in json_data2:
                            try:
                                data = json.loads(json_data2['data'])
                                message = data.get('message')
                            except:
                                pass
                        
                        new_history.append({
                            'time': datetime.fromtimestamp(parsed_tx.get('timestamp', 0)),
                            'hash': ref['hash'],
                            'amount': amount,
                            'address': parsed_tx.get('to') if not is_incoming else parsed_tx.get('from'),
                            'type': 'incoming' if is_incoming else 'outgoing',
                            'confirmed': True,
                            'nonce': parsed_tx.get('nonce', 0),
                            'epoch': ref.get('epoch', 0),
                            'message': message
                        })
                
                self.transaction_history = sorted(new_history, key=lambda x: x['time'], reverse=True)
                self.last_history_update = now
        except Exception as e:
            print(f"Error getting transaction history: {e}")
        
        return self.transaction_history
    
    async def refresh_data(self):
        self.last_update = 0
        self.last_history_update = 0
        await self.get_balance_and_nonce()
        await self.get_transaction_history()
    
    def export_wallet(self) -> Dict:
        return {
            "address": self.address,
            "public_key": self.public_key,
            "private_key": self.private_key,
            "rpc_url": self.rpc_url
        }

# Transaction Manager Class
class TransactionManager:
    def __init__(self, wallet: WalletManager):
        self.wallet = wallet
        self.μ = 1_000_000
    
    def _create_transaction(self, to_address: str, amount: float, nonce: int, message: str = None) -> Tuple[Dict, str]:
        tx = {
            "from": self.wallet.address,
            "to_": to_address,
            "amount": str(int(amount * self.μ)),
            "nonce": int(nonce),
            "ou": "1" if amount < 1000 else "3",
            "timestamp": time.time() + random.random() * 0.01
        }
        
        if message:
            tx["message"] = message
        
        blob = json.dumps({k: v for k, v in tx.items() if k != "message"}, separators=(",", ":"))
        signature = base64.b64encode(self.wallet.signing_key.sign(blob.encode()).signature).decode()
        
        tx.update({
            "signature": signature,
            "public_key": self.wallet.public_key
        })
        
        tx_hash = hashlib.sha256(blob.encode()).hexdigest()
        return tx, tx_hash
    
    async def send_transaction(self, to_address: str, amount: float, message: str = None) -> Dict:
        try:
            balance, nonce = await self.wallet.get_balance_and_nonce()
            
            if balance is None or nonce is None:
                return {"success": False, "error": "Failed to get wallet state"}
            
            if balance < amount:
                return {"success": False, "error": f"Insufficient balance ({balance:.6f} < {amount:.6f})"}
            
            tx, tx_hash = self._create_transaction(to_address, amount, nonce + 1, message)
            
            start_time = time.time()
            status, text, json_data = await self.wallet._make_request("POST", "/send-tx", tx)
            send_time = time.time() - start_time
            
            if status == 200:
                if json_data and json_data.get('status') == 'accepted':
                    return {
                        "success": True,
                        "tx_hash": json_data.get('tx_hash', tx_hash),
                        "send_time": send_time,
                        "pool_info": json_data.get('pool_info', {})
                    }
                elif text.lower().startswith('ok'):
                    return {
                        "success": True,
                        "tx_hash": text.split()[-1] if ' ' in text else tx_hash,
                        "send_time": send_time
                    }
            
            error_msg = json_data.get('error', text) if json_data else text
            return {"success": False, "error": error_msg}
            
        except Exception as e:
            return {"success": False, "error": str(e)}

# Utility functions
def validate_address(address: str) -> bool:
    if not address:
        return False
    pattern = r"^oct[1-9A-HJ-NP-Za-km-z]{44}$"
    return bool(re.match(pattern, address))

def validate_amount(amount) -> bool:
    if not amount:
        return False
    try:
        amount_float = float(amount)
        return amount_float > 0
    except (ValueError, TypeError):
        return False

# Global wallet manager
wallet_manager = None

def get_wallet_manager():
    global wallet_manager
    if not wallet_manager:
        wallet_manager = WalletManager()
    return wallet_manager

# Routes
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/init-wallet")
async def init_wallet(data: dict):
    try:
        private_key = data.get("private_key")
        rpc_url = data.get("rpc_url", "https://octra.network")
        
        if not private_key:
            raise HTTPException(status_code=400, detail="Private key is required")
        
        wallet = get_wallet_manager()
        success = await wallet.init_wallet(private_key, rpc_url)
        
        if not success:
            raise HTTPException(status_code=400, detail="Invalid private key")
        
        return {
            "success": True,
            "address": wallet.address,
            "public_key": wallet.public_key
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/wallet-info")
async def get_wallet_info():
    try:
        wallet = get_wallet_manager()
        if not wallet.is_initialized():
            raise HTTPException(status_code=400, detail="Wallet not initialized")
        
        balance, nonce = await wallet.get_balance_and_nonce()
        staging_count = await wallet.get_staging_count()
        
        return {
            "address": wallet.address,
            "balance": balance,
            "nonce": nonce,
            "public_key": wallet.public_key,
            "staging_count": staging_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/transactions")
async def get_transactions():
    try:
        wallet = get_wallet_manager()
        if not wallet.is_initialized():
            raise HTTPException(status_code=400, detail="Wallet not initialized")
        
        transactions = await wallet.get_transaction_history()
        return {"transactions": transactions}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/send-transaction")
async def send_transaction(data: dict):
    try:
        wallet = get_wallet_manager()
        if not wallet.is_initialized():
            raise HTTPException(status_code=400, detail="Wallet not initialized")
        
        to_address = data.get("to_address")
        amount = data.get("amount")
        message = data.get("message", "")
        
        if not validate_address(to_address):
            raise HTTPException(status_code=400, detail="Invalid address")
        
        if not validate_amount(amount):
            raise HTTPException(status_code=400, detail="Invalid amount")
        
        tx_manager = TransactionManager(wallet)
        result = await tx_manager.send_transaction(to_address, float(amount), message)
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/refresh")
async def refresh_wallet():
    try:
        wallet = get_wallet_manager()
        if not wallet.is_initialized():
            raise HTTPException(status_code=400, detail="Wallet not initialized")
        
        await wallet.refresh_data()
        return {"success": True, "message": "Wallet data refreshed"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/export-wallet")
async def export_wallet():
    try:
        wallet = get_wallet_manager()
        if not wallet.is_initialized():
            raise HTTPException(status_code=400, detail="Wallet not initialized")
        
        wallet_data = wallet.export_wallet()
        return wallet_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

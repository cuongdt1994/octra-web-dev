import json
import base64
import hashlib
import time
import aiohttp
import asyncio
from datetime import datetime, timedelta
import nacl.signing
from typing import Optional, Tuple, List, Dict

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
        """Initialize wallet with private key"""
        try:
            self.private_key = private_key
            self.rpc_url = rpc_url
            self.signing_key = nacl.signing.SigningKey(base64.b64decode(private_key))
            self.public_key = base64.b64encode(self.signing_key.verify_key.encode()).decode()
            
            # Generate address from public key
            self.address = self._generate_address()
            
            # Initialize HTTP session
            if not self.session:
                self.session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=10)
                )
            
            return True
        except Exception as e:
            print(f"Wallet initialization error: {e}")
            return False
    
    def _generate_address(self) -> str:
        """Generate address from public key"""
        # This is a simplified address generation
        # In real implementation, you'd follow Octra's address generation rules
        pub_bytes = base64.b64decode(self.public_key)
        hash_obj = hashlib.sha256(pub_bytes)
        address_bytes = hash_obj.digest()[:25]  # Take first 25 bytes
        
        # Add checksum
        checksum = hashlib.sha256(address_bytes).digest()[:4]
        full_address = address_bytes + checksum
        
        # Encode to base58 with 'oct' prefix
        return "oct" + self._base58_encode(full_address)
    
    def _base58_encode(self, data: bytes) -> str:
        """Simple base58 encoding"""
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        num = int.from_bytes(data, 'big')
        encoded = ""
        
        while num > 0:
            num, remainder = divmod(num, 58)
            encoded = alphabet[remainder] + encoded
        
        # Add leading zeros
        for byte in data:
            if byte == 0:
                encoded = alphabet[0] + encoded
            else:
                break
        
        return encoded
    
    def is_initialized(self) -> bool:
        """Check if wallet is initialized"""
        return self.private_key is not None and self.address is not None
    
    async def _make_request(self, method: str, endpoint: str, data: dict = None) -> Tuple[int, str, dict]:
        """Make HTTP request to RPC"""
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
        """Get current balance and nonce"""
        now = time.time()
        if self.last_update and (now - self.last_update) < 30:
            return self.balance, self.nonce
        
        try:
            # Get balance
            status, text, json_data = await self._make_request("GET", f"/balance/{self.address}")
            
            if status == 200 and json_data:
                self.balance = float(json_data.get('balance', 0))
                self.nonce = int(json_data.get('nonce', 0))
                self.last_update = now
                
                # Check staging transactions
                status2, _, json_data2 = await self._make_request("GET", "/staging")
                if status2 == 200 and json_data2:
                    our_txs = [tx for tx in json_data2.get('staged_transactions', []) 
                              if tx.get('from') == self.address]
                    if our_txs:
                        self.nonce = max(self.nonce, max(int(tx.get('nonce', 0)) for tx in our_txs))
                        
            elif status == 404:
                self.balance, self.nonce = 0.0, 0
                self.last_update = now
            
            return self.balance, self.nonce
            
        except Exception as e:
            print(f"Error getting balance: {e}")
            return None, None
    
    async def get_staging_count(self) -> int:
        """Get number of pending transactions"""
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
        """Get transaction history"""
        now = time.time()
        if self.last_history_update and (now - self.last_history_update) < 60:
            return self.transaction_history
        
        try:
            status, text, json_data = await self._make_request("GET", f"/address/{self.address}?limit=20")
            
            if status != 200:
                return []
            
            if json_data and 'recent_transactions' in json_data:
                tx_hashes = [ref["hash"] for ref in json_data.get('recent_transactions', [])]
                
                # Get detailed transaction info
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
                        
                        # Extract message if exists
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
                
                # Sort by time, newest first
                self.transaction_history = sorted(new_history, key=lambda x: x['time'], reverse=True)
                self.last_history_update = now
                
        except Exception as e:
            print(f"Error getting transaction history: {e}")
        
        return self.transaction_history
    
    async def refresh_data(self):
        """Force refresh all wallet data"""
        self.last_update = 0
        self.last_history_update = 0
        await self.get_balance_and_nonce()
        await self.get_transaction_history()
    
    def export_wallet(self) -> Dict:
        """Export wallet data"""
        return {
            "address": self.address,
            "public_key": self.public_key,
            "private_key": self.private_key,
            "rpc_url": self.rpc_url
        }
    
    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()

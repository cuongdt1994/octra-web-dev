import base64
import hashlib
import base58
import nacl.signing
import requests
import secrets
import time
import json
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mnemonic import Mnemonic

RPC_URL = "https://octra.network"
μ = 1_000_000

class WalletAPI:
    def __init__(self):
        self.rpc_url = RPC_URL
        self.micro = μ
    
    def generate_mnemonic_wallet(self):
        """Generate a new wallet with mnemonic"""
        try:
            mnemo = Mnemonic("english")
            mnemonic = mnemo.generate(strength=128)
            seed = mnemo.to_seed(mnemonic)

            master_key = hmac.new(b'Octra seed', seed, hashlib.sha512).digest()
            priv_key = master_key[:32]

            signing_key = nacl.signing.SigningKey(priv_key)
            verify_key = signing_key.verify_key
            pubkey_bytes = verify_key.encode()

            sha256_hash = hashlib.sha256(pubkey_bytes).digest()
            octra_addr = "oct" + base58.b58encode(sha256_hash).decode()

            return {
                'success': True,
                'data': {
                    'mnemonic': mnemonic,
                    'address': octra_addr,
                    'private_key': base64.b64encode(priv_key).decode(),
                    'public_key': pubkey_bytes.hex(),
                    'pub_b64': base64.b64encode(pubkey_bytes).decode(),
                    'priv_b64': base64.b64encode(signing_key.encode()).decode()
                }
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def import_from_private_key(self, private_key):
        """Import wallet from private key"""
        try:
            # Clean and decode private key
            priv_key_clean = private_key.strip()
            
            # Add padding if needed
            missing_padding = len(priv_key_clean) % 4
            if missing_padding:
                priv_key_clean += '=' * (4 - missing_padding)
            
            secret_key_bytes = base64.b64decode(priv_key_clean)
            
            # Handle different key lengths
            if len(secret_key_bytes) == 64:
                signing_key = nacl.signing.SigningKey(secret_key_bytes[:32])
            elif len(secret_key_bytes) == 32:
                signing_key = nacl.signing.SigningKey(secret_key_bytes)
            else:
                raise ValueError(f"Invalid private key length: {len(secret_key_bytes)} bytes")
            
            pubkey_bytes = signing_key.verify_key.encode()
            sha256_hash = hashlib.sha256(pubkey_bytes).digest()
            octra_addr = "oct" + base58.b58encode(sha256_hash).decode()
            
            return {
                'success': True,
                'data': {
                    'address': octra_addr,
                    'private_key': private_key,
                    'public_key': pubkey_bytes.hex(),
                    'pub_b64': base64.b64encode(pubkey_bytes).decode(),
                    'priv_b64': base64.b64encode(signing_key.encode()).decode(),
                    'signing_key': signing_key
                }
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_wallet_balance(self, address):
        """Get wallet balance and nonce"""
        try:
            response = requests.get(f"{self.rpc_url}/balance/{address}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'balance': float(data.get('balance', 0)),
                    'nonce': int(data.get('nonce', 0))
                }
            else:
                return {'success': False, 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_encrypted_balance(self, address, private_key_b64):
        """Get encrypted balance"""
        try:
            headers = {"X-Private-Key": private_key_b64}
            response = requests.get(
                f"{self.rpc_url}/view_encrypted_balance/{address}", 
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'encrypted_balance_raw': int(data.get("encrypted_balance_raw", 0)),
                    'encrypted_balance': int(data.get("encrypted_balance_raw", 0)) / self.micro
                }
            else:
                return {'success': False, 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def send_transaction(self, wallet_data, to_address, amount, nonce):
        """Send OCT transaction"""
        try:
            # Recreate signing key
            signing_key = nacl.signing.SigningKey(base64.b64decode(wallet_data['priv_b64'])[:32])
            
            tx = {
                "from": wallet_data['address'],
                "to_": to_address,
                "amount": str(int(amount * self.micro)),
                "nonce": nonce,
                "ou": "1" if amount < 1000 else "3",
                "timestamp": time.time()
            }
            
            # Create signature
            tx_string = '{' + f'"from":"{tx["from"]}","to_":"{tx["to_"]}","amount":"{tx["amount"]}","nonce":{tx["nonce"]},"ou":"{tx["ou"]}","timestamp":{tx["timestamp"]}' + '}'
            signature = base64.b64encode(signing_key.sign(tx_string.encode()).signature).decode()
            
            tx['signature'] = signature
            tx['public_key'] = wallet_data['pub_b64']
            
            response = requests.post(f"{self.rpc_url}/send-tx", json=tx, timeout=15)
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'data': response.json()
                }
            else:
                return {
                    'success': False,
                    'error': f'Transaction failed: {response.text}'
                }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def derive_encryption_key(self, private_key_b64):
        """Derive encryption key for balance encryption"""
        try:
            priv_bytes = base64.b64decode(private_key_b64)
            salt = b"octra_encrypted_balance_v2"
            return hashlib.sha256(salt + priv_bytes).digest()[:32]
        except Exception as e:
            raise Exception(f"Key derivation failed: {e}")
    
    def encrypt_balance_data(self, balance_raw, private_key_b64):
        """Encrypt balance data"""
        try:
            key = self.derive_encryption_key(private_key_b64)
            aesgcm = AESGCM(key)
            nonce = secrets.token_bytes(12)
            plaintext = str(balance_raw).encode()
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            return "v2|" + base64.b64encode(nonce + ciphertext).decode()
        except Exception as e:
            raise Exception(f"Encryption failed: {e}")
    
    def encrypt_balance(self, address, amount, private_key_b64):
        """Encrypt balance on blockchain"""
        try:
            # Get current encrypted balance
            enc_result = self.get_encrypted_balance(address, private_key_b64)
            if not enc_result['success']:
                return enc_result
            
            current_encrypted = enc_result['encrypted_balance_raw']
            new_encrypted = current_encrypted + int(amount * self.micro)
            
            # Create encrypted data
            encrypted_data = self.encrypt_balance_data(new_encrypted, private_key_b64)
            
            payload = {
                "address": address,
                "amount": str(int(amount * self.micro)),
                "private_key": private_key_b64,
                "encrypted_data": encrypted_data
            }
            
            response = requests.post(f"{self.rpc_url}/encrypt_balance", json=payload, timeout=15)
            
            if response.status_code == 200:
                return {'success': True, 'message': 'Balance encrypted successfully'}
            else:
                return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def decrypt_balance(self, address, amount, private_key_b64):
        """Decrypt balance on blockchain"""
        try:
            # Get current encrypted balance
            enc_result = self.get_encrypted_balance(address, private_key_b64)
            if not enc_result['success']:
                return enc_result
            
            current_encrypted = enc_result['encrypted_balance_raw']
            amount_micro = int(amount * self.micro)
            
            if amount_micro > current_encrypted:
                return {'success': False, 'error': 'Insufficient encrypted balance'}
            
            new_encrypted = current_encrypted - amount_micro
            
            # Create encrypted data
            encrypted_data = self.encrypt_balance_data(new_encrypted, private_key_b64)
            
            payload = {
                "address": address,
                "amount": str(amount_micro),
                "private_key": private_key_b64,
                "encrypted_data": encrypted_data
            }
            
            response = requests.post(f"{self.rpc_url}/decrypt_balance", json=payload, timeout=15)
            
            if response.status_code == 200:
                return {'success': True, 'message': 'Balance decrypted successfully'}
            else:
                return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_pending_private_transfers(self, address, private_key_b64):
        """Get pending private transfers"""
        try:
            headers = {"X-Private-Key": private_key_b64}
            response = requests.get(
                f"{self.rpc_url}/pending_private_transfers?address={address}",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'transfers': data.get("pending_transfers", [])
                }
            else:
                return {'success': False, 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def send_private_transfer(self, from_address, to_address, amount, from_private_key_b64):
        """Send private transfer"""
        try:
            # Get recipient's public key
            pub_key_response = requests.get(f"{self.rpc_url}/public_key/{to_address}", timeout=10)
            if pub_key_response.status_code != 200:
                return {'success': False, 'error': 'Cannot get recipient public key'}
            
            to_public_key = pub_key_response.json().get("public_key")
            
            payload = {
                "from": from_address,
                "to": to_address,
                "amount": str(int(amount * self.micro)),
                "from_private_key": from_private_key_b64,
                "to_public_key": to_public_key
            }
            
            response = requests.post(f"{self.rpc_url}/private_transfer", json=payload, timeout=15)
            
            if response.status_code == 200:
                return {'success': True, 'message': 'Private transfer sent successfully'}
            else:
                return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def claim_private_transfer(self, recipient_address, private_key_b64, transfer_id):
        """Claim private transfer"""
        try:
            payload = {
                "recipient_address": recipient_address,
                "private_key": private_key_b64,
                "transfer_id": transfer_id
            }
            
            response = requests.post(f"{self.rpc_url}/claim_private_transfer", json=payload, timeout=15)
            
            if response.status_code == 200:
                return {'success': True, 'message': 'Private transfer claimed successfully'}
            else:
                return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def validate_address(self, address):
        """Validate Octra address format"""
        try:
            if not address.startswith('oct'):
                return False
            
            # Try to decode the base58 part
            addr_part = address[3:]
            base58.b58decode(addr_part)
            return True
        except:
            return False
    
    def get_wallet_overview(self, address, private_key_b64):
        """Get complete wallet overview"""
        try:
            # Get public balance
            balance_result = self.get_wallet_balance(address)
            if not balance_result['success']:
                return balance_result
            
            # Get encrypted balance
            encrypted_result = self.get_encrypted_balance(address, private_key_b64)
            if not encrypted_result['success']:
                encrypted_balance = 0
            else:
                encrypted_balance = encrypted_result['encrypted_balance']
            
            # Get pending transfers
            transfers_result = self.get_pending_private_transfers(address, private_key_b64)
            if not transfers_result['success']:
                pending_transfers = []
            else:
                pending_transfers = transfers_result['transfers']
            
            return {
                'success': True,
                'data': {
                    'address': address,
                    'public_balance': balance_result['balance'],
                    'encrypted_balance': encrypted_balance,
                    'nonce': balance_result['nonce'],
                    'pending_transfers': pending_transfers,
                    'total_balance': balance_result['balance'] + encrypted_balance
                }
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

# Create global instance
wallet_api = WalletAPI()

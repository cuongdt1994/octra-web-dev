import json
import base64
import hashlib
import time
import random
import asyncio
from typing import List, Dict, Tuple
from .wallet import WalletManager

class TransactionManager:
    def __init__(self, wallet: WalletManager):
        self.wallet = wallet
        self.μ = 1_000_000  # Micro units
    
    def _create_transaction(self, to_address: str, amount: float, nonce: int, message: str = None) -> Tuple[Dict, str]:
        """Create and sign a transaction"""
        tx = {
            "from": self.wallet.address,
            "to_": to_address,
            "amount": str(int(amount * self.μ)),
            "nonce": int(nonce),
            "ou": "1" if amount < 1000 else "3",  # Output unit
            "timestamp": time.time() + random.random() * 0.01
        }
        
        if message:
            tx["message"] = message
        
        # Create transaction blob for signing
        blob = json.dumps({k: v for k, v in tx.items() if k != "message"}, separators=(",", ":"))
        
        # Sign transaction
        signature = base64.b64encode(self.wallet.signing_key.sign(blob.encode()).signature).decode()
        
        # Add signature and public key
        tx.update({
            "signature": signature,
            "public_key": self.wallet.public_key
        })
        
        # Generate transaction hash
        tx_hash = hashlib.sha256(blob.encode()).hexdigest()
        
        return tx, tx_hash
    
    async def send_transaction(self, to_address: str, amount: float, message: str = None) -> Dict:
        """Send a single transaction"""
        try:
            # Get current balance and nonce
            balance, nonce = await self.wallet.get_balance_and_nonce()
            
            if balance is None or nonce is None:
                return {"success": False, "error": "Failed to get wallet state"}
            
            if balance < amount:
                return {"success": False, "error": f"Insufficient balance ({balance:.6f} < {amount:.6f})"}
            
            # Create transaction
            tx, tx_hash = self._create_transaction(to_address, amount, nonce + 1, message)
            
            # Send transaction
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
    
    async def send_multi_transactions(self, recipients: List[Dict]) -> Dict:
        """Send multiple transactions"""
        try:
            # Calculate total amount
            total_amount = sum(float(r['amount']) for r in recipients)
            
            # Get current balance and nonce
            balance, nonce = await self.wallet.get_balance_and_nonce()
            
            if balance is None or nonce is None:
                return {"success": False, "error": "Failed to get wallet state"}
            
            if balance < total_amount:
                return {"success": False, "error": f"Insufficient balance ({balance:.6f} < {total_amount:.6f})"}
            
            # Send transactions in batches
            batch_size = 5
            batches = [recipients[i:i+batch_size] for i in range(0, len(recipients), batch_size)]
            
            results = []
            success_count = 0
            failed_count = 0
            
            for batch_idx, batch in enumerate(batches):
                batch_tasks = []
                
                for i, recipient in enumerate(batch):
                    tx_nonce = nonce + 1 + (batch_idx * batch_size) + i
                    tx, tx_hash = self._create_transaction(
                        recipient['address'], 
                        float(recipient['amount']), 
                        tx_nonce,
                        recipient.get('message')
                    )
                    
                    # Create send task
                    batch_tasks.append(self._send_single_tx(tx, tx_hash, recipient))
                
                # Execute batch
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, Exception):
                        failed_count += 1
                        results.append({"success": False, "error": str(result)})
                    else:
                        if result["success"]:
                            success_count += 1
                        else:
                            failed_count += 1
                        results.append(result)
                
                # Small delay between batches
                if batch_idx < len(batches) - 1:
                    await asyncio.sleep(0.1)
            
            return {
                "success": True,
                "total_sent": len(recipients),
                "success_count": success_count,
                "failed_count": failed_count,
                "results": results
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _send_single_tx(self, tx: Dict, tx_hash: str, recipient: Dict) -> Dict:
        """Send a single transaction (helper method)"""
        try:
            start_time = time.time()
            status, text, json_data = await self.wallet._make_request("POST", "/send-tx", tx)
            send_time = time.time() - start_time
            
            if status == 200:
                if json_data and json_data.get('status') == 'accepted':
                    return {
                        "success": True,
                        "tx_hash": json_data.get('tx_hash', tx_hash),
                        "send_time": send_time,
                        "recipient": recipient
                    }
                elif text.lower().startswith('ok'):
                    return {
                        "success": True,
                        "tx_hash": text.split()[-1] if ' ' in text else tx_hash,
                        "send_time": send_time,
                        "recipient": recipient
                    }
            
            error_msg = json_data.get('error', text) if json_data else text
            return {
                "success": False,
                "error": error_msg,
                "recipient": recipient
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "recipient": recipient
            }

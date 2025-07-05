from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os
from dotenv import load_dotenv
from api.wallet import WalletManager
from api.transactions import TransactionManager
from api.utils import validate_address, validate_amount
import asyncio
import json

load_dotenv()

app = FastAPI(title="Octra Wallet Web", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Global wallet manager
wallet_manager = None

def get_wallet_manager():
    global wallet_manager
    if not wallet_manager:
        wallet_manager = WalletManager()
    return wallet_manager

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/init-wallet")
async def init_wallet(data: dict):
    """Initialize wallet with private key"""
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
    """Get wallet information"""
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
    """Get transaction history"""
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
    """Send a single transaction"""
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

@app.post("/api/send-multi-transaction")
async def send_multi_transaction(data: dict):
    """Send multiple transactions"""
    try:
        wallet = get_wallet_manager()
        if not wallet.is_initialized():
            raise HTTPException(status_code=400, detail="Wallet not initialized")
        
        recipients = data.get("recipients", [])
        
        if not recipients:
            raise HTTPException(status_code=400, detail="No recipients provided")
        
        # Validate all recipients
        for recipient in recipients:
            if not validate_address(recipient.get("address")):
                raise HTTPException(status_code=400, detail=f"Invalid address: {recipient.get('address')}")
            if not validate_amount(recipient.get("amount")):
                raise HTTPException(status_code=400, detail=f"Invalid amount: {recipient.get('amount')}")
        
        tx_manager = TransactionManager(wallet)
        results = await tx_manager.send_multi_transactions(recipients)
        
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/refresh")
async def refresh_wallet():
    """Refresh wallet data"""
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
    """Export wallet data"""
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

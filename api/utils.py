import re

def validate_address(address: str) -> bool:
    """Validate Octra address format"""
    if not address:
        return False
    
    # Check if address matches the pattern: oct + 44 base58 characters
    pattern = r"^oct[1-9A-HJ-NP-Za-km-z]{44}$"
    return bool(re.match(pattern, address))

def validate_amount(amount) -> bool:
    """Validate transaction amount"""
    if not amount:
        return False
    
    try:
        amount_float = float(amount)
        return amount_float > 0
    except (ValueError, TypeError):
        return False

def format_amount(amount: float) -> str:
    """Format amount for display"""
    return f"{amount:.6f}"

def format_address(address: str, length: int = 20) -> str:
    """Format address for display"""
    if len(address) <= length:
        return address
    return f"{address[:length//2]}...{address[-length//2:]}"

def format_hash(tx_hash: str, length: int = 16) -> str:
    """Format transaction hash for display"""
    if len(tx_hash) <= length:
        return tx_hash
    return f"{tx_hash[:length]}..."

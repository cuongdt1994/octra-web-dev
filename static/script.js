let currentWallet = null;

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    loadWallets();
    setupEventListeners();
});

function setupEventListeners() {
    // Create wallet form
    document.getElementById('create-wallet-form').addEventListener('submit', function(e) {
        e.preventDefault();
        createWallet();
    });

    // Import wallet form
    document.getElementById('import-wallet-form').addEventListener('submit', function(e) {
        e.preventDefault();
        importWallet();
    });

    // Send transaction form
    document.getElementById('send-tx-form').addEventListener('submit', function(e) {
        e.preventDefault();
        sendTransaction();
    });

    // Encrypt balance form
    document.getElementById('encrypt-form').addEventListener('submit', function(e) {
        e.preventDefault();
        encryptBalance();
    });

    // Decrypt balance form
    document.getElementById('decrypt-form').addEventListener('submit', function(e) {
        e.preventDefault();
        decryptBalance();
    });
}

// Wallet Management Functions
async function loadWallets() {
    try {
        const response = await fetch('/api/get_wallets');
        const data = await response.json();
        
        const walletsContainer = document.getElementById('wallets-list');
        walletsContainer.innerHTML = '';
        
        if (data.wallets.length === 0) {
            walletsContainer.innerHTML = '<p class="text-center">No wallets found. Create or import a wallet to get started.</p>';
            return;
        }
        
        data.wallets.forEach(wallet => {
            const walletCard = createWalletCard(wallet);
            walletsContainer.appendChild(walletCard);
        });
    } catch (error) {
        showNotification('Error loading wallets: ' + error.message, 'error');
    }
}

function createWalletCard(wallet) {
    const card = document.createElement('div');
    card.className = 'wallet-card';
    card.onclick = () => selectWallet(wallet);
    
    const shortAddress = wallet.address.substring(0, 15) + '...';
    const badge = wallet.has_mnemonic ? 
        '<span class="wallet-badge badge-mnemonic">Mnemonic</span>' : 
        '<span class="wallet-badge badge-imported">Imported</span>';
    
    card.innerHTML = `
        <h3><i class="fas fa-wallet"></i> ${wallet.name}</h3>
        <p><strong>Address:</strong> <span class="address-display">${shortAddress}</span></p>
        ${badge}
    `;
    
    return card;
}

async function createWallet() {
    const walletName = document.getElementById('wallet-name').value.trim();
    const submitBtn = document.querySelector('#create-wallet-form button[type="submit"]');
    
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="loading"></span> Creating...';
    
    try {
        const response = await fetch('/api/create_wallet', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                name: walletName
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Wallet created successfully!', 'success');
            closeModal('create-wallet-modal');
            document.getElementById('create-wallet-form').reset();
            
            // Show wallet details
            showWalletDetails(data.wallet);
            
            // Reload wallets list
            loadWallets();
        } else {
            showNotification('Error: ' + data.error, 'error');
        }
    } catch (error) {
        showNotification('Error creating wallet: ' + error.message, 'error');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = 'Create Wallet';
    }
}

async function importWallet() {
    const privateKey = document.getElementById('private-key').value.trim();
    const walletName = document.getElementById('import-wallet-name').value.trim();
    const submitBtn = document.querySelector('#import-wallet-form button[type="submit"]');
    
    if (!privateKey) {
        showNotification('Please enter a private key', 'error');
        return;
    }
    
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="loading"></span> Importing...';
    
    try {
        const response = await fetch('/api/import_wallet', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                private_key: privateKey,
                name: walletName
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Wallet imported successfully!', 'success');
            closeModal('import-wallet-modal');
            document.getElementById('import-wallet-form').reset();
            loadWallets();
        } else {
            showNotification('Error: ' + data.error, 'error');
        }
    } catch (error) {
        showNotification('Error importing wallet: ' + error.message, 'error');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = 'Import Wallet';
    }
}

async function selectWallet(wallet) {
    currentWallet = wallet;
    
    // Hide wallet selection and show dashboard
    document.getElementById('wallet-selection').style.display = 'none';
    document.getElementById('wallet-dashboard').style.display = 'block';
    
    // Update wallet info
    document.getElementById('current-wallet-name').textContent = wallet.name;
    document.getElementById('wallet-address').textContent = wallet.address;
    
    // Load wallet balance
    await loadWalletBalance(wallet.address);
}

async function loadWalletBalance(address) {
    try {
        const response = await fetch('/api/get_balance', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                address: address
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('public-balance').textContent = data.balance.toFixed(6);
            document.getElementById('encrypted-balance').textContent = data.encrypted_balance.toFixed(6);
            document.getElementById('wallet-nonce').textContent = data.nonce;
        } else {
            showNotification('Error loading balance: ' + data.error, 'error');
        }
    } catch (error) {
        showNotification('Error loading balance: ' + error.message, 'error');
    }
}

async function sendTransaction() {
    const toAddress = document.getElementById('to-address').value.trim();
    const amount = parseFloat(document.getElementById('amount').value);
    const submitBtn = document.querySelector('#send-tx-form button[type="submit"]');
    
    if (!toAddress || !amount || amount <= 0) {
        showNotification('Please enter valid recipient address and amount', 'error');
        return;
    }
    
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="loading"></span> Sending...';
    
    try {
        const response = await fetch('/api/send_transaction', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                from_address: currentWallet.address,
                to_address: toAddress,
                amount: amount
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Transaction sent successfully!', 'success');
            document.getElementById('send-tx-form').reset();
            
            // Refresh balance
            await loadWalletBalance(currentWallet.address);
        } else {
            showNotification('Error: ' + data.error, 'error');
        }
    } catch (error) {
        showNotification('Error sending transaction: ' + error.message, 'error');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = 'Send Transaction';
    }
}

async function encryptBalance() {
    const amount = parseFloat(document.getElementById('encrypt-amount').value);
    const submitBtn = document.querySelector('#encrypt-form button[type="submit"]');
    
    if (!amount || amount <= 0) {
        showNotification('Please enter a valid amount', 'error');
        return;
    }
    
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="loading"></span> Encrypting...';
    
    try {
        const response = await fetch('/api/encrypt_balance', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                address: currentWallet.address,
                amount: amount
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Balance encrypted successfully!', 'success');
            document.getElementById('encrypt-form').reset();
            
            // Refresh balance
            await loadWalletBalance(currentWallet.address);
        } else {
            showNotification('Error: ' + data.error, 'error');
        }
    } catch (error) {
        showNotification('Error encrypting balance: ' + error.message, 'error');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = 'Encrypt Balance';
    }
}

async function decryptBalance() {
    const amount = parseFloat(document.getElementById('decrypt-amount').value);
    const submitBtn = document.querySelector('#decrypt-form button[type="submit"]');
    
    if (!amount || amount <= 0) {
        showNotification('Please enter a valid amount', 'error');
        return;
    }
    
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="loading"></span> Decrypting...';
    
    try {
        const response = await fetch('/api/decrypt_balance', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                address: currentWallet.address,
                amount: amount
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Balance decrypted successfully!', 'success');
            document.getElementById('decrypt-form').reset();
            
            // Refresh balance
            await loadWalletBalance(currentWallet.address);
        } else {
            showNotification('Error: ' + data.error, 'error');
        }
    } catch (error) {
        showNotification('Error decrypting balance: ' + error.message, 'error');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = 'Decrypt Balance';
    }
}

async function exportWallet() {
    try {
        const response = await fetch('/api/export_wallet', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                address: currentWallet.address
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            const walletData = data.wallet_data;
            const exportText = `
=== OCTRA WALLET EXPORT ===
Name: ${walletData.name}
Address: ${walletData.address}
Private Key: ${walletData.private_key}
Public Key: ${walletData.public_key}
Mnemonic: ${walletData.mnemonic || 'N/A (Imported wallet)'}

⚠️ KEEP THIS INFORMATION SECURE AND PRIVATE!
            `.trim();
            
            // Create and download file
            const blob = new Blob([exportText], { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `octra_wallet_${walletData.name.replace(/\s+/g, '_')}.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            
            showNotification('Wallet exported successfully!', 'success');
        } else {
            showNotification('Error: ' + data.error, 'error');
        }
    } catch (error) {
        showNotification('Error exporting wallet: ' + error.message, 'error');
    }
}

// UI Helper Functions
function showCreateWallet() {
    document.getElementById('create-wallet-modal').style.display = 'block';
}

function showImportWallet() {
    document.getElementById('import-wallet-modal').style.display = 'block';
}

function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
}

function backToWalletSelection() {
    document.getElementById('wallet-dashboard').style.display = 'none';
    document.getElementById('wallet-selection').style.display = 'block';
    currentWallet = null;
}

function showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.className = `notification ${type} show`;
    
    setTimeout(() => {
        notification.classList.remove('show');
    }, 5000);
}

function showWalletDetails(wallet) {
    const details = `
🎉 Wallet Created Successfully!

📛 Name: ${wallet.name}
📍 Address: ${wallet.address}
🔑 Private Key: ${wallet.private_key}
🔐 Mnemonic: ${wallet.mnemonic}

⚠️ IMPORTANT: Save your mnemonic and private key securely!
    `;
    
    alert(details);
}

// Close modals when clicking outside
window.onclick = function(event) {
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
}

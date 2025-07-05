class OctraWallet {
    constructor() {
        this.isInitialized = false;
        this.walletData = null;
        this.transactions = [];
        this.recipients = [];
        
        this.initializeEventListeners();
        this.updateTime();
        setInterval(() => this.updateTime(), 1000);
    }
    
    initializeEventListeners() {
        // Wallet initialization
        document.getElementById('init-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.initializeWallet();
        });
        
        // Send transaction
        document.getElementById('send-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.sendTransaction();
        });
        
        // Close modals on outside click
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                this.closeAllModals();
            }
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeAllModals();
            }
        });
    }
    
    updateTime() {
        const now = new Date();
        const timeString = now.toLocaleTimeString('vi-VN');
        document.getElementById('current-time').textContent = timeString;
    }
    
    async initializeWallet() {
        const privateKey = document.getElementById('private-key').value.trim();
        const rpcUrl = document.getElementById('rpc-url').value.trim();
        
        if (!privateKey) {
            this.showToast('Lỗi', 'Vui lòng nhập private key', 'error');
            return;
        }
        
        this.showLoading('Đang khởi tạo ví...');
        
        try {
            const response = await fetch('/api/init-wallet', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    private_key: privateKey,
                    rpc_url: rpcUrl
                })
            });
            
            const data = await response.json();
            
            if (response.ok && data.success) {
                this.isInitialized = true;
                this.walletData = data;
                
                document.getElementById('wallet-init').style.display = 'none';
                document.getElementById('wallet-interface').style.display = 'block';
                
                this.updateWalletInfo();
                this.loadTransactions();
                
                this.showToast('Thành công', 'Ví đã được khởi tạo thành công', 'success');
            } else {
                this.showToast('Lỗi', data.detail || 'Không thể khởi tạo ví', 'error');
            }
        } catch (error) {
            this.showToast('Lỗi', 'Lỗi kết nối: ' + error.message, 'error');
        } finally {
            this.hideLoading();
        }
    }
    
    async updateWalletInfo() {
        try {
            const response = await fetch('/api/wallet-info');
            const data = await response.json();
            
            if (response.ok) {
                document.getElementById('wallet-address').textContent = this.formatAddress(data.address);
                document.getElementById('wallet-balance').textContent = `${data.balance.toFixed(6)} OCT`;
                document.getElementById('wallet-nonce').textContent = data.nonce;
                document.getElementById('staging-count').textContent = data.staging_count;
            }
        } catch (error) {
            console.error('Error updating wallet info:', error);
        }
    }
    
    async loadTransactions() {
        try {
            const response = await fetch('/api/transactions');
            const data = await response.json();
            
            if (response.ok) {
                this.transactions = data.transactions;
                this.renderTransactions();
            }
        } catch (error) {
            console.error('Error loading transactions:', error);
        }
    }
    
    renderTransactions() {
        const container = document.getElementById('transactions-list');
        
        if (this.transactions.length === 0) {
            container.innerHTML = `
                <div class="no-transactions">
                    <i class="fas fa-inbox"></i>
                    <p>Chưa có giao dịch nào</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = this.transactions.map(tx => `
            <div class="transaction-item">
                <div class="transaction-time">${this.formatTime(tx.time)}</div>
                <div class="transaction-type ${tx.type}">
                    ${tx.type === 'incoming' ? 'Nhận' : 'Gửi'}
                </div>
                <div class="transaction-amount ${tx.type}">
                    ${tx.type === 'incoming' ? '+' : '-'}${tx.amount.toFixed(6)}
                </div>
                <div class="transaction-address" title="${tx.address}">
                    ${this.formatAddress(tx.address)}
                </div>
                <div class="transaction-status ${tx.confirmed ? 'confirmed' : 'pending'}">
                    ${tx.confirmed ? 'Đã xác nhận' : 'Đang chờ'}
                </div>
            </div>
        `).join('');
    }
    
    showSendForm() {
        document.getElementById('send-modal').style.display = 'block';
        document.getElementById('send-address').focus();
    }
    
    closeSendModal() {
        document.getElementById('send-modal').style.display = 'none';
        document.getElementById('send-form').reset();
    }
    
    async sendTransaction() {
        const address = document.getElementById('send-address').value.trim();
        const amount = parseFloat(document.getElementById('send-amount').value);
        const message = document.getElementById('send-message').value.trim();
        
        if (!this.validateAddress(address)) {
            this.showToast('Lỗi', 'Địa chỉ không hợp lệ', 'error');
            return;
        }
        
        if (!amount || amount <= 0) {
            this.showToast('Lỗi', 'Số tiền không hợp lệ', 'error');
            return;
        }
        
        this.showLoading('Đang gửi giao dịch...');
        
        try {
            const response = await fetch('/api/send-transaction', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    to_address: address,
                    amount: amount,
                    message: message || undefined
                })
            });
            
            const data = await response.json();
                        if (response.ok && data.success) {
                this.showToast('Thành công', `Giao dịch đã được gửi thành công! Hash: ${data.tx_hash.substring(0, 16)}...`, 'success');
                this.closeSendModal();
                this.updateWalletInfo();
                this.loadTransactions();
            } else {
                this.showToast('Lỗi', data.error || 'Không thể gửi giao dịch', 'error');
            }
        } catch (error) {
            this.showToast('Lỗi', 'Lỗi kết nối: ' + error.message, 'error');
        } finally {
            this.hideLoading();
        }
    }
    
    showMultiSendForm() {
        document.getElementById('multi-send-modal').style.display = 'block';
        this.updateMultiSendSummary();
    }
    
    closeMultiSendModal() {
        document.getElementById('multi-send-modal').style.display = 'none';
        this.recipients = [];
        this.renderRecipients();
        this.updateMultiSendSummary();
    }
    
    addRecipient() {
        const address = document.getElementById('recipient-address').value.trim();
        const amount = parseFloat(document.getElementById('recipient-amount').value);
        
        if (!this.validateAddress(address)) {
            this.showToast('Lỗi', 'Địa chỉ không hợp lệ', 'error');
            return;
        }
        
        if (!amount || amount <= 0) {
            this.showToast('Lỗi', 'Số tiền không hợp lệ', 'error');
            return;
        }
        
        // Check if address already exists
        if (this.recipients.some(r => r.address === address)) {
            this.showToast('Lỗi', 'Địa chỉ đã tồn tại trong danh sách', 'error');
            return;
        }
        
        this.recipients.push({ address, amount });
        this.renderRecipients();
        this.updateMultiSendSummary();
        
        // Clear inputs
        document.getElementById('recipient-address').value = '';
        document.getElementById('recipient-amount').value = '';
    }
    
    removeRecipient(index) {
        this.recipients.splice(index, 1);
        this.renderRecipients();
        this.updateMultiSendSummary();
    }
    
    renderRecipients() {
        const container = document.getElementById('recipients-list');
        
        if (this.recipients.length === 0) {
            container.innerHTML = '<div style="padding: 20px; text-align: center; color: #6c757d;">Chưa có người nhận nào</div>';
            return;
        }
        
        container.innerHTML = this.recipients.map((recipient, index) => `
            <div class="recipient-item">
                <div class="recipient-info">
                    <div class="recipient-address">${this.formatAddress(recipient.address)}</div>
                    <div class="recipient-amount">${recipient.amount.toFixed(6)} OCT</div>
                </div>
                <button class="remove-recipient" onclick="wallet.removeRecipient(${index})">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `).join('');
    }
    
    updateMultiSendSummary() {
        const totalRecipients = this.recipients.length;
        const totalAmount = this.recipients.reduce((sum, r) => sum + r.amount, 0);
        
        document.getElementById('total-recipients').textContent = totalRecipients;
        document.getElementById('total-amount').textContent = `${totalAmount.toFixed(6)} OCT`;
    }
    
    async sendMultiTransactions() {
        if (this.recipients.length === 0) {
            this.showToast('Lỗi', 'Vui lòng thêm ít nhất một người nhận', 'error');
            return;
        }
        
        this.showLoading('Đang gửi nhiều giao dịch...');
        
        try {
            const response = await fetch('/api/send-multi-transaction', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    recipients: this.recipients
                })
            });
            
            const data = await response.json();
            
            if (response.ok && data.success) {
                this.showToast('Thành công', 
                    `Đã gửi ${data.success_count}/${data.total_sent} giao dịch thành công`, 
                    data.failed_count > 0 ? 'warning' : 'success'
                );
                this.closeMultiSendModal();
                this.updateWalletInfo();
                this.loadTransactions();
            } else {
                this.showToast('Lỗi', data.error || 'Không thể gửi giao dịch', 'error');
            }
        } catch (error) {
            this.showToast('Lỗi', 'Lỗi kết nối: ' + error.message, 'error');
        } finally {
            this.hideLoading();
        }
    }
    
    async refreshWallet() {
        this.showLoading('Đang làm mới...');
        
        try {
            const response = await fetch('/api/refresh', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });
            
            if (response.ok) {
                await this.updateWalletInfo();
                await this.loadTransactions();
                this.showToast('Thành công', 'Dữ liệu ví đã được làm mới', 'success');
            } else {
                this.showToast('Lỗi', 'Không thể làm mới dữ liệu', 'error');
            }
        } catch (error) {
            this.showToast('Lỗi', 'Lỗi kết nối: ' + error.message, 'error');
        } finally {
            this.hideLoading();
        }
    }
    
    showExportModal() {
        document.getElementById('export-modal').style.display = 'block';
    }
    
    closeExportModal() {
        document.getElementById('export-modal').style.display = 'none';
    }
    
    async showPrivateKey() {
        try {
            const response = await fetch('/api/export-wallet');
            const data = await response.json();
            
            if (response.ok) {
                const modal = document.createElement('div');
                modal.className = 'modal';
                modal.innerHTML = `
                    <div class="modal-content">
                        <div class="modal-header">
                            <h3><i class="fas fa-key"></i> Private Key</h3>
                            <button class="close-btn" onclick="this.closest('.modal').remove()">&times;</button>
                        </div>
                        <div style="padding: 30px;">
                            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                                <p style="color: #dc3545; font-weight: 600; margin-bottom: 10px;">
                                    <i class="fas fa-exclamation-triangle"></i> CẢNH BÁO: Giữ bí mật thông tin này!
                                </p>
                                <p style="color: #6c757d; font-size: 0.9rem;">
                                    Không chia sẻ private key với bất kỳ ai. Ai có private key sẽ có toàn quyền kiểm soát ví của bạn.
                                </p>
                            </div>
                            <div class="form-group">
                                <label>Private Key:</label>
                                <textarea readonly style="font-family: monospace; font-size: 0.9rem; color: #dc3545; background: #fff5f5;">${data.private_key}</textarea>
                            </div>
                            <div class="form-group">
                                <label>Public Key:</label>
                                <textarea readonly style="font-family: monospace; font-size: 0.9rem;">${data.public_key}</textarea>
                            </div>
                            <div class="form-actions">
                                <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Đóng</button>
                                <button class="btn btn-primary" onclick="this.previousElementSibling.previousElementSibling.previousElementSibling.querySelector('textarea').select(); document.execCommand('copy'); wallet.showToast('Thành công', 'Đã copy private key', 'success');">
                                    <i class="fas fa-copy"></i> Copy Private Key
                                </button>
                            </div>
                        </div>
                    </div>
                `;
                document.body.appendChild(modal);
                modal.style.display = 'block';
            }
        } catch (error) {
            this.showToast('Lỗi', 'Không thể lấy thông tin ví', 'error');
        }
    }
    
    async downloadWallet() {
        try {
            const response = await fetch('/api/export-wallet');
            const data = await response.json();
            
            if (response.ok) {
                const walletData = {
                    address: data.address,
                    private_key: data.private_key,
                    public_key: data.public_key,
                    rpc_url: data.rpc_url,
                    exported_at: new Date().toISOString()
                };
                
                const blob = new Blob([JSON.stringify(walletData, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `octra_wallet_${Date.now()}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                
                this.showToast('Thành công', 'File ví đã được tải xuống', 'success');
            }
        } catch (error) {
            this.showToast('Lỗi', 'Không thể tải file ví', 'error');
        }
    }
    
    async copyAddress() {
        try {
            const response = await fetch('/api/wallet-info');
            const data = await response.json();
            
            if (response.ok) {
                await navigator.clipboard.writeText(data.address);
                this.showToast('Thành công', 'Địa chỉ đã được copy', 'success');
            }
        } catch (error) {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = document.getElementById('wallet-address').textContent;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            this.showToast('Thành công', 'Địa chỉ đã được copy', 'success');
        }
    }
    
    closeAllModals() {
        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => {
            modal.style.display = 'none';
        });
    }
    
    showLoading(text = 'Đang xử lý...') {
        document.getElementById('loading-text').textContent = text;
        document.getElementById('loading-overlay').style.display = 'block';
    }
    
    hideLoading() {
        document.getElementById('loading-overlay').style.display = 'none';
    }
    
    showToast(title, message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <div class="toast-header">
                <div class="toast-title">${title}</div>
                <button class="toast-close" onclick="this.closest('.toast').remove()">&times;</button>
            </div>
            <div class="toast-message">${message}</div>
        `;
        
        document.getElementById('toast-container').appendChild(toast);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (toast.parentNode) {
                toast.remove();
            }
        }, 5000);
    }
    
    validateAddress(address) {
        if (!address) return false;
        const pattern = /^oct[1-9A-HJ-NP-Za-km-z]{44}$/;
        return pattern.test(address);
    }
    
    formatAddress(address, length = 20) {
        if (!address) return '';
        if (address.length <= length) return address;
        return `${address.substring(0, length/2)}...${address.substring(address.length - length/2)}`;
    }
    
    formatTime(timeString) {
        const date = new Date(timeString);
        return date.toLocaleString('vi-VN', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            day: '2-digit',
            month: '2-digit'
        });
    }
}

// Global functions for onclick handlers
function showSendForm() { wallet.showSendForm(); }
function closeSendModal() { wallet.closeSendModal(); }
function showMultiSendForm() { wallet.showMultiSendForm(); }
function closeMultiSendModal() { wallet.closeMultiSendModal(); }
function addRecipient() { wallet.addRecipient(); }
function sendMultiTransactions() { wallet.sendMultiTransactions(); }
function refreshWallet() { wallet.refreshWallet(); }
function showExportModal() { wallet.showExportModal(); }
function closeExportModal() { wallet.closeExportModal(); }
function showPrivateKey() { wallet.showPrivateKey(); }
function downloadWallet() { wallet.downloadWallet(); }
function copyAddress() { wallet.copyAddress(); }
function loadTransactions() { wallet.loadTransactions(); }

function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    const text = element.textContent;
    
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            wallet.showToast('Thành công', 'Đã copy vào clipboard', 'success');
        });
    } else {
        // Fallback
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        wallet.showToast('Thành công', 'Đã copy vào clipboard', 'success');
    }
}

// Initialize wallet when page loads
const wallet = new OctraWallet();

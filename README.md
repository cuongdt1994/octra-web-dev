# Octra Wallet Web

Web-based wallet application for Octra Network, converted from terminal application to full web interface.

## Features

- **Wallet Management**: Initialize wallet with private key
- **Balance Tracking**: Real-time balance and nonce updates
- **Transaction History**: View recent transactions with detailed information
- **Send Transactions**: Send single transactions with optional messages
- **Multi-Send**: Send multiple transactions in batches
- **Export Functions**: Export private keys and wallet data
- **Responsive Design**: Works on desktop and mobile devices
- **Real-time Updates**: Auto-refresh wallet data and transaction history

## Tech Stack

- **Backend**: FastAPI (Python)
- **Frontend**: Vanilla JavaScript, HTML5, CSS3
- **Styling**: Custom CSS with modern design
- **Deployment**: Vercel-ready configuration

## Installation

### Local Development

1. Clone the repository:
git clone <repository-url>
cd octra-wallet-web
2. Install dependencies:
pip install -r requirements.txt
3. Create environment file:
cp .env.example .env
4. Run the application:
uvicorn app:app --reload --host 0.0.0.0 --port 8000
5. Open browser and navigate to `http://localhost:8000`
### Deploy to Vercel

1. Install Vercel CLI:
npm i -g vercel
2. Deploy:
vercel --prod

## Usage

### Initialize Wallet

1. Enter your private key in the initialization form
2. Optionally change the RPC URL (default: https://octra.network)
3. Click "Khởi tạo Ví" to initialize

### Send Transactions

1. Click "Gửi Giao dịch" button
2. Enter recipient address (must start with 'oct')
3. Enter amount to send
4. Optionally add a message
5. Confirm and send

### Multi-Send

1. Click "Gửi Nhiều" button
2. Add recipients one by one with address and amount
3. Review the summary
4. Send all transactions in batches

### Export Wallet

1. Click "Xuất Ví" button
2. Choose export option:
   - Show private key
   - Download wallet file
   - Copy address to clipboard

## Security Notes

- **Never share your private key** with anyone
- **Keep your private key secure** - anyone with access can control your wallet
- **This is testnet** - tokens have no commercial value
- **Use HTTPS** in production environments
- **Verify addresses** before sending transactions

## API Endpoints

- `POST /api/init-wallet` - Initialize wallet
- `GET /api/wallet-info` - Get wallet information
- `GET /api/transactions` - Get transaction history
- `POST /api/send-transaction` - Send single transaction
- `POST /api/send-multi-transaction` - Send multiple transactions
- `POST /api/refresh` - Refresh wallet data
- `GET /api/export-wallet` - Export wallet data

## File Structure

octra-wallet-web/
├── api/
│ ├── init.py
│ ├── wallet.py
│ ├── transactions.py
│ └── utils.py
├── static/
│ ├── css/
│ │ └── style.css
│ └── js/
│ └── app.js
├── templates/
│ └── index.html
├── app.py
├── requirements.txt
├── vercel.json
├── .env.example
└── README.md


## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For support and questions, please open an issue in the repository.


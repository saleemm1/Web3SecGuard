from web3 import Web3
import requests
import tkinter as tk

# Set up connection to the Ethereum network
infura_url = 'https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID'
web3 = Web3(Web3.HTTPProvider(infura_url))

# Set up API keys
etherscan_api_key = 'YOUR_ETHERSCAN_API_KEY'

def is_connected():
    """Check if connected to the Ethereum network."""
    return web3.isConnected()

def get_contract_source_code(contract_address):
    """
    Fetch the source code of a smart contract from Etherscan.
    :param contract_address: The address of the smart contract
    :return: The contract's source code if available, or None if retrieval fails
    """
    url = f'https://api.etherscan.io/api?module=contract&action=getsourcecode&address={contract_address}&apikey={etherscan_api_key}'
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors
        data = response.json()
        if data['status'] == '1':
            return data['result'][0]['SourceCode']
    except requests.RequestException as e:
        result_text.set(f"Error fetching source code: {e}")
    return None

def analyze_code(source_code):
    """
    Analyze the source code of the contract to detect potential vulnerabilities.
    :param source_code: The source code of the smart contract
    :return: A list of potential vulnerabilities
    """
    vulnerabilities = []

    # Check for potential reentrancy attack
    if 'call.value' in source_code or 'delegatecall' in source_code:
        vulnerabilities.append("Potential reentrancy attack vulnerability detected.")

    # Check for authorization issues
    if 'changeOwner' in source_code and 'require' not in source_code:
        vulnerabilities.append("Potential authorization issue detected.")

    # Check for input validation issues
    if 'setValue' in source_code and 'require' not in source_code:
        vulnerabilities.append("Potential input validation vulnerability detected.")

    return vulnerabilities

def scan_contract():
    """Start scanning the smart contract for vulnerabilities."""
    contract_address = entry_address.get()
    if not web3.isAddress(contract_address):
        result_text.set("Invalid address.")
        return

    source_code = get_contract_source_code(contract_address)
    if not source_code:
        result_text.set("Failed to retrieve contract source code.")
        return

    vulnerabilities = analyze_code(source_code)

    if not vulnerabilities:
        vulnerabilities.append("No vulnerabilities detected.")

    result_text.set("\n".join(vulnerabilities))

# Set up the user interface with tkinter
root = tk.Tk()
root.title("Advanced Web3 Vulnerability Scanner")

tk.Label(root, text="Enter Contract Address:").pack(pady=5)
entry_address = tk.Entry(root, width=50)
entry_address.pack(pady=5)

scan_button = tk.Button(root, text="Start Scan", command=scan_contract)
scan_button.pack(pady=10)

result_text = tk.StringVar()
result_label = tk.Label(root, textvariable=result_text, justify=tk.LEFT)
result_label.pack(pady=5)

if is_connected():
    result_text.set("Connected to Ethereum network.")
else:
    result_text.set("Failed to connect to Ethereum network.")

root.mainloop()

import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    DB_URL = os.getenv("DB_URL")
    ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
    ALCHEMY_ENDPOINT = f"https://eth-mainnet.g.alchemy.com/v2/{os.getenv('ALCHEMY_API_KEY')}"
    
    APIKEY = os.getenv("APIKEY")
    BASEURL = os.getenv("BASEURL")
    PROMPT = os.getenv("PROMPT")
    MODELNAME = os.getenv("MODELNAME")
    DATASET_PROMPT = os.getenv("DATASET_PROMPT")

    # Base Network配置
    BASE_RPC_URL = "https://mainnet.base.org"
    BASE_ETHERSCAN_URL = "https://api.etherscan.io/v2/api?chainid=8453"
    BASE_ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")  # 使用与以太坊相同的API Key
    
    # Ankr API配置
    ANKR_API_KEY = os.getenv("ANKR_API_KEY", "")
    
    # 网络配置
    NETWORKS = {
        "ethereum": {
            "rpc_url": f"https://rpc.ankr.com/eth/{os.getenv('ANKR_API_KEY')}" if os.getenv('ANKR_API_KEY') else ALCHEMY_ENDPOINT,
            "explorer_url": "https://api.etherscan.io/api",
            "explorer_key": ETHERSCAN_API_KEY,
            "chain_id": 1
        },
        "base": {
            "rpc_url": BASE_RPC_URL,
            "explorer_url": BASE_ETHERSCAN_URL,
            "explorer_key": ETHERSCAN_API_KEY,  # 使用与以太坊相同的API Key
            "chain_id": 8453
        }
    }

settings = Settings()
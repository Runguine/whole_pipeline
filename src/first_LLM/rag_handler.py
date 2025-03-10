import json
import os
from typing import Dict, Optional, Tuple
from rapidfuzz import process, fuzz
from web3 import Web3
from config.settings import settings

class TokenRAGSystem:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        # 使用 Infura, Alchemy 或其他以太坊节点提供者
        self.w3 = Web3(Web3.HTTPProvider(settings.ALCHEMY_ENDPOINT))
        self.token_db = self._build_token_database()
    
    def _build_token_database(self) -> Dict:
        token_db = {}
        for filename in os.listdir(self.data_dir):
            if filename.endswith('.json'):
                address = filename.split('.')[0]
                if not self.w3.is_address(address):
                    continue
                with open(os.path.join(self.data_dir, filename)) as f:
                    try:
                        data = json.load(f)
                        token_db[data['name'].lower()] = data
                        token_db[data['symbol'].lower()] = data
                    except:
                        continue
        return token_db

    def search_with_block_range(self, query: str) -> Tuple[Optional[dict], Tuple[int, int]]:
        """增强版搜索：返回地址和自动计算的区块范围"""
        # 基础搜索逻辑
        clean_query = query.strip().lower()
        if clean_query in self.token_db:
            data = self.token_db[clean_query]
            return data, self._calculate_block_range(data)
        
        # 模糊搜索逻辑...
        
    def _calculate_block_range(self, token_data: dict) -> Tuple[int, int]:
        """根据代币创建时间计算合理区块范围"""
        try:
            # 获取最新区块
            latest_block = self.w3.eth.block_number
            
            # 以太坊平均出块时间约为12秒
            BLOCKS_PER_MINUTE = 60 // 12  # 约5个区块
            BLOCKS_PER_HOUR = BLOCKS_PER_MINUTE * 60  # 约300个区块
            BLOCKS_PER_DAY = BLOCKS_PER_HOUR * 24  # 约7200个区块
            BLOCKS_PER_WEEK = BLOCKS_PER_DAY * 7
            BLOCKS_PER_MONTH = BLOCKS_PER_DAY * 30
            
            # 根据time_range_hint计算区块范围
            time_range = token_data.get('time_range_hint', '').lower()
            
            if '分钟' in time_range or 'min' in time_range:
                minutes = int(''.join(filter(str.isdigit, time_range)) or 1)
                blocks = BLOCKS_PER_MINUTE * minutes
            elif '小时' in time_range or 'hour' in time_range:
                hours = int(''.join(filter(str.isdigit, time_range)) or 1)
                blocks = BLOCKS_PER_HOUR * hours
            elif '天' in time_range or 'day' in time_range:
                days = int(''.join(filter(str.isdigit, time_range)) or 1)
                blocks = BLOCKS_PER_DAY * days
            elif '周' in time_range or 'week' in time_range:
                weeks = int(''.join(filter(str.isdigit, time_range)) or 1)
                blocks = BLOCKS_PER_WEEK * weeks
            elif '月' in time_range or 'month' in time_range:
                months = int(''.join(filter(str.isdigit, time_range)) or 1)
                blocks = BLOCKS_PER_MONTH * months
            else:
                # 默认分析最近一小时的数据
                blocks = BLOCKS_PER_HOUR
                
            start_block = max(0, latest_block - blocks)
            return start_block, latest_block
            
        except Exception as e:
            print(f"计算区块范围失败: {str(e)}")
            # 如果计算失败，返回最近一小时的区块范围
            return latest_block - 300, latest_block

# 初始化（添加自动更新检测）
if not hasattr(TokenRAGSystem, '_instance'):
    TokenRAGSystem._instance = TokenRAGSystem(
        "/root/whole_pipeline/src/first_LLM/label_RAG/assets/blockchains/ethereum/assets"
    )
RAG_INSTANCE = TokenRAGSystem._instance
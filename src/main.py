import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config')))

import json
import requests
from web3 import Web3
from tqdm import tqdm
from datetime import datetime
from config.database import get_db_connection
import os
from dotenv import load_dotenv
from ethereum.bytecode_fetcher import get_bytecode
from ethereum.decompiler.gigahorse_wrapper import decompile_bytecode
from database import get_db
from database.crud import update_bytecode, update_decompiled_code
from database.models import Contract
from ethereum.abi_fetcher import get_contract_metadata, process_contract_metadata
from database.crud import upsert_contract

from first_LLM.llm_processor import LLMQueryProcessor
from analyze_user_behavior import process_user_query


load_dotenv()


FOUR_BYTE_DB_PATH = "4byte.json"


def load_4byte_database():
    """加载本地 4-byte 选择器数据库"""
    if os.path.exists(FOUR_BYTE_DB_PATH):
        with open(FOUR_BYTE_DB_PATH, "r") as f:
            return json.load(f).get("results", [])
    return []


FOUR_BYTE_DATABASE = load_4byte_database()


def lookup_method_from_4byte(selector):
    """从 4-byte 选择器数据库查询方法签名"""
    for entry in FOUR_BYTE_DATABASE:
        if entry["hex_signature"] == selector:
            return entry["text_signature"]
    return None


class ContractPipeline:
    def __init__(self):
        self.analyzer = ContractAnalyzer()
        self.db = next(get_db())

    def process_with_metadata(self, address: str):
        """增强的合约处理流程（保留元数据存储）"""
        # 处理代理链
        self.analyzer.process_contract(address)
        
        # 获取并存储元数据
        metadata = get_contract_metadata(address)
        if not metadata:
            print("未验证合约")
            return
        
        processed = process_contract_metadata(metadata)
        contract_data = {
            "target_contract": address.lower(),
            **processed
        }
        
        # 更新数据库（关键保留部分）
        upsert_contract(self.db, contract_data)
        print(f"已存储 {address} 的ABI和源代码")





class ContractAnalyzer:
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(os.getenv("ALCHEMY_URL")))
        self.abi_cache = {}
        self.processed_contracts = set()
        self.max_recursion_depth = 3
        self.decompiler_enabled = True  # 反编译开关
        
    def get_contract_abi(self, address):
        """带缓存的ABI获取方法"""
        address = address.lower()
        if address not in self.abi_cache:
            try:
                url = f"https://api.etherscan.io/api?module=contract&action=getabi&address={address}&apikey={os.getenv('ETHERSCAN_API_KEY')}"
                response = requests.get(url)
                self.abi_cache[address] = json.loads(response.json()['result'])
            except Exception as e:
                print(f"获取ABI失败: {str(e)}")
                self.abi_cache[address] = []
        return self.abi_cache[address]
    
    def get_method_name(self, contract_address, input_data):
        """
        解析 method_name：
        1. 先尝试基于 ABI 解析
        2. 如果 ABI 解析失败，则查询 4-byte 选择器数据库
        3. 如果 4-byte 也失败，则使用反编译代码
        """
        db = next(get_db())
        contract = db.query(Contract).filter(Contract.target_contract == contract_address.lower()).first()

        # **1. 使用 ABI 解析**
        if contract and contract.abi:
            try:
                contract_obj = self.w3.eth.contract(address=contract_address, abi=contract.abi)
                func_obj, _ = contract_obj.decode_function_input(input_data[:4].hex())
                return func_obj.fn_name  # 直接返回解析成功的函数名
            except:
                pass  # 解析失败，继续查询 4-byte

        # **2. 4-byte 选择器数据库**
        selector = input_data[:4].hex()  # 获取前 4 字节，形如 "0xa9059cbb"
        url = f"https://api.openchain.xyz/signature-database/v1/lookup?function={selector}"
        response = requests.get(url).json()
        if response["ok"] and response["result"]["function"] and selector in response["result"]["function"]:
            return response["result"]["function"][selector][0]["name"]

        # **3. 反编译代码**
        if contract and contract.decompiled_code:
            return f"Unknown_{selector} (from decompiled code)"

        return f"Unknown_{selector} (unresolved)"  # 返回前10位作为fallback


    def detect_proxy(self, contract_address):
        checks = [
            # 检查 EIP-1967 逻辑合约存储槽
            (Web3.keccak(text="eip1967.proxy.implementation").hex()[:-2], "EIP-1967"),
            
            # 检查Gnosis Safe风格代理（masterCopy）
            (Web3.keccak(text="gnosis.proxy.masterCopy").hex()[:-2], "Gnosis"),
            
            # 直接检查slot 0（适用于简单代理合约）
            ("0x0000000000000000000000000000000000000000000000000000000000000000", "Slot0"),
            
            # 检查OpenZeppelin升级模式
            (Web3.keccak(text="eip1967.proxy.admin").hex()[:-2], "EIP-1967-Admin")
        ]

        for slot_hex, slot_type in checks:
            try:
                logic_bytes = self.w3.eth.get_storage_at(
                    Web3.to_checksum_address(contract_address),
                    int(slot_hex, 16))
                logic_address = self.w3.to_checksum_address(logic_bytes[-20:].hex())
                
                if logic_address != '0x' + '0'*40:
                    print(f"通过 {slot_type} 检测到逻辑合约: {logic_address}")
                    return True, logic_address
                    
            except Exception as e:
                print(f"存储槽 {slot_hex} 检测失败: {str(e)}")

        # 检查ABI方法
        abi = self.get_contract_abi(contract_address)
        method_names = ['implementation', 'masterCopy', 'getLogicContract']
        for method in method_names:
            if any(fn['name'] == method for fn in abi if fn.get('type') == 'function'):
                try:
                    contract = self.w3.eth.contract(
                        address=Web3.to_checksum_address(contract_address),
                        abi=abi
                    )
                    logic_address = contract.functions[method]().call()
                    if logic_address != '0x' + '0'*40:
                        print(f"通过 {method}() 方法检测到逻辑合约: {logic_address}")
                        return True, logic_address
                except Exception as e:
                    print(f"方法 {method} 调用失败: {str(e)}")

        return False, None

    def process_contract(self, address, depth=0, parent_address=None):
        """改进后的合约处理逻辑"""
        if depth > self.max_recursion_depth:
            print(f"达到最大递归深度 {self.max_recursion_depth}")
            return

        address = Web3.to_checksum_address(address)
        if address.lower() in self.processed_contracts:
            return

        print(f"\n处理合约: {address} (层级: {depth})")
        self.processed_contracts.add(address.lower())

        # 检测代理状态
        is_proxy, logic_address = self.detect_proxy(address)
        
        # 准备基础数据
        contract_data = {
            "target_contract": address.lower(),
            "is_proxy": is_proxy,
            "parent_address": parent_address.lower() if parent_address else None,
        }

        # 获取元数据
        metadata = get_contract_metadata(address)
        if metadata:
            processed = process_contract_metadata(metadata)
            contract_data.update(processed)
            #print(contract_data)
        else:
            print("未验证的合约")

        # 获取并处理字节码
        bytecode = get_bytecode(address)
        decompiled_code = None
        
        if bytecode:
            # 需要反编译的情况：没有源码或ABI
            if self.decompiler_enabled and (not contract_data.get('source_code') or not contract_data.get('abi')):
                decompiled_code = decompile_bytecode(bytecode)
                if decompiled_code:
                    contract_data['decompiled_code'] = decompiled_code
                    print(f"反编译代码长度: {len(decompiled_code)} 字符")

            # 更新数据库
            db = next(get_db())
            upsert_contract(db, contract_data)
            update_bytecode(db, address, bytecode)
            if decompiled_code:
                update_decompiled_code(db, address, decompiled_code)

        # 递归处理逻辑合约
        if is_proxy and logic_address:
            print(f"发现代理合约，开始处理逻辑合约: {logic_address}")
            self.process_contract(logic_address, depth+1, parent_address=address)



    def analyze_contract(self, target_address, start_block, end_block):
        if start_block > end_block:
            print("Start block must be less than or equal to end block.")
            return
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        print(f"Analyzing from block {start_block} to {end_block}")
    
        count = 0
        for block_num in tqdm(range(start_block, end_block + 1)):
            block = self.w3.eth.get_block(block_num, full_transactions=True)
            for idx, tx in enumerate(block.transactions):
                tx_dict = dict(tx)
                tx_to = tx_dict.get('to', None)
            
                if tx_to and tx_to.lower() == target_address.lower():
                    method_name = self.get_method_name(target_address, tx.input)
                    
                    cur.execute("""
                        INSERT INTO users 
                        (target_contract, caller_contract, method_name, block_number, tx_hash, timestamp)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        target_address,
                        tx['from'],
                        method_name,
                        block_num,
                        tx.hash.hex(),
                        datetime.fromtimestamp(block.timestamp)
                    ))
                    count += 1
        conn.commit()
        cur.close()
        conn.close()
        print(f"Total transactions processed: {count}")

    def execute_full_analysis(self, address: str, start: int, end: int):
        """全流程入口（集成原有逻辑）"""
        # 初始化处理管道
        pipeline = ContractPipeline()
        
        # 步骤1：处理合约及元数据
        pipeline.process_with_metadata(address)
        
        # 步骤2：执行区块分析（原有analyze_contract）
        self.analyze_contract(address, start, end)
        
        # 步骤3：触发深度分析
        return process_user_query({
            "contract_address": address,
            "start_block": start,
            "end_block": end
        })


if __name__ == "__main__":
    user_input = input("请输入分析请求（例如：分析最近一周UNI代币的安全事件）：")
    
    # 第一步：LLM解析+RAG检索
    processor = LLMQueryProcessor()
    llm_params, rag_data = processor.parse_query(user_input)
    
    if not rag_data['address']:
        print("未找到相关代币信息")
        exit()
    
    # 打印分析信息（方便调试）
    print(f"\n=== 分析参数 ===")
    print(f"目标代币: {llm_params.get('token_identifier', 'Unknown')}")
    print(f"时间范围: {llm_params.get('time_range_hint', '1天')}")
    print(f"分析重点: {', '.join(llm_params.get('analysis_focus', ['资金流向']))}")
    print(f"区块范围: {rag_data['start_block']} - {rag_data['end_block']}")
    
    # 第二步：主分析流程
    analyzer = ContractAnalyzer()
    report = analyzer.execute_full_analysis(
        rag_data['address'],
        rag_data['start_block'],
        rag_data['end_block']
    )
    
    # 第三步：输出结果
    print("\n=== 最终分析报告 ===")
    print(report)

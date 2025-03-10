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
from analyze_user_behavior import process_user_query, request_ds


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
        """增强的代理合约检测"""
        checks = [
            # EIP-1967 代理模式
            (Web3.keccak(text="eip1967.proxy.implementation").hex()[:-2], "EIP-1967"),
            
            # OpenZeppelin 代理模式
            ("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", "OpenZeppelin"),
            
            # Gnosis Safe 代理模式
            (Web3.keccak(text="gnosis.proxy.masterCopy").hex()[:-2], "Gnosis"),
            
            # UUPS 代理模式
            ("0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3", "UUPS"),
            
            # 透明代理模式
            ("0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7", "Transparent"),
            
            # Beacon 代理模式
            ("0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50", "Beacon"),
            
            # 简单代理模式（slot 0）
            ("0x0000000000000000000000000000000000000000000000000000000000000000", "Simple"),
            
            # 自定义存储槽（一些项目会使用自定义的存储槽）
            ("0x000000000000000000000000000000000000000000000000000000000000000a", "Custom-A"),
            ("0x000000000000000000000000000000000000000000000000000000000000000b", "Custom-B"),
        ]

        # 1. 检查存储槽
        for slot_hex, slot_type in checks:
            try:
                logic_bytes = self.w3.eth.get_storage_at(
                    Web3.to_checksum_address(contract_address),
                    int(slot_hex, 16)
                )
                logic_address = self.w3.to_checksum_address(logic_bytes[-20:].hex())
                
                if logic_address != '0x' + '0'*40:
                    print(f"通过 {slot_type} 存储槽检测到逻辑合约: {logic_address}")
                    return True, logic_address
                    
            except Exception as e:
                print(f"存储槽 {slot_hex} 检测失败: {str(e)}")

        # 2. 检查字节码中的代理特征
        try:
            bytecode = self.w3.eth.get_code(Web3.to_checksum_address(contract_address))
            bytecode_hex = bytecode.hex()
            
            # 检查常见的代理合约特征
            proxy_patterns = [
                "delegatecall",  # delegatecall 操作码
                "5880", # PUSH1 0x80 (常见的代理合约开头)
                "363d3d373d3d3d363d73", # 最小代理合约特征
                "363d3d373d3d3d363d", # 另一种代理特征
            ]
            
            for pattern in proxy_patterns:
                if pattern.lower() in bytecode_hex.lower():
                    print(f"在字节码中检测到代理特征: {pattern}")
                    return True, None  # 返回True但没有具体的逻辑合约地址
                    
        except Exception as e:
            print(f"字节码检测失败: {str(e)}")

        # 3. 检查ABI方法
        abi = self.get_contract_abi(contract_address)
        proxy_methods = [
            'implementation',
            'masterCopy',
            'getLogicContract',
            'getImplementation',
            'getBeacon',
            'upgradeTo',
            'upgradeToAndCall'
        ]
        
        for method in proxy_methods:
            if any(fn.get('name') == method for fn in abi if isinstance(fn, dict)):
                try:
                    contract = self.w3.eth.contract(
                        address=Web3.to_checksum_address(contract_address),
                        abi=abi
                    )
                    if hasattr(contract.functions, method):
                        try:
                            logic_address = getattr(contract.functions, method)().call()
                            if logic_address and logic_address != '0x' + '0'*40:
                                print(f"通过 {method}() 方法检测到逻辑合约: {logic_address}")
                                return True, logic_address
                        except Exception as e:
                            print(f"方法 {method} 调用失败: {str(e)}")
                except Exception as e:
                    print(f"合约方法检查失败: {str(e)}")

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
        
        # 用于存储所有相关地址（包括caller和input_data中的地址）
        related_addresses = set()
    
        count = 0
        for block_num in tqdm(range(start_block, end_block + 1)):
            block = self.w3.eth.get_block(block_num, full_transactions=True)
            for idx, tx in enumerate(block.transactions):
                tx_dict = dict(tx)
                tx_to = tx_dict.get('to', None)
            
                if tx_to and tx_to.lower() == target_address.lower():
                    input_data = tx.input.hex()
                    method_name = self.get_method_name(target_address, tx.input)
                    caller_address = tx['from']
                    
                    # 添加caller地址到相关地址集合
                    related_addresses.add(Web3.to_checksum_address(caller_address))
                    
                    # 解析input_data中的地址
                    input_addresses = self._extract_addresses_from_input(input_data)
                    related_addresses.update(input_addresses)
                    
                    cur.execute("""
                        INSERT INTO users 
                        (target_contract, caller_contract, method_name, block_number, tx_hash, timestamp, input_data)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        target_address,
                        caller_address,
                        method_name,
                        block_num,
                        tx.hash.hex(),
                        datetime.fromtimestamp(block.timestamp),
                        input_data
                    ))
                    count += 1
                    
        conn.commit()
        cur.close()
        conn.close()
        print(f"Total transactions processed: {count}")
        
        # 处理所有相关地址
        print("\n开始处理相关合约...")
        for addr in related_addresses:
            # 检查是否是合约地址
            code = self.w3.eth.get_code(addr)
            if code and code.hex() != '0x':  # 如果有代码，说明是合约
                print(f"\n处理相关合约: {addr}")
                self.process_contract(addr)
            else:
                print(f"跳过普通地址: {addr}")
        
        return related_addresses  # 返回相关地址集合供后续分析使用

    def _extract_addresses_from_input(self, input_data):
        """从input_data中提取以太坊地址"""
        addresses = set()
        
        # 移除0x前缀
        if input_data.startswith('0x'):
            input_data = input_data[2:]
            
        # 方法ID在前4个字节
        method_id = input_data[:8]
        data = input_data[8:]
        
        # 每32字节（64个字符）为一个参数
        for i in range(0, len(data), 64):
            param = data[i:i+64]
            # 检查是否可能是地址（通过检查前24个字节是否为0）
            if param.startswith('000000000000000000000000'):
                potential_address = '0x' + param[-40:]
                if Web3.is_address(potential_address):
                    addresses.add(Web3.to_checksum_address(potential_address))
                    
        return addresses

    def execute_full_analysis(self, address: str, start: int, end: int, analysis_type: str = "transaction_analysis", user_input: str = ""):
        """全流程入口（集成原有逻辑）"""
        # 初始化处理管道
        pipeline = ContractPipeline()
        
        # 步骤1：处理目标合约及元数据
        print("\n=== 步骤1：处理目标合约 ===")
        pipeline.process_with_metadata(address)
        
        # 步骤2：执行区块分析和相关合约处理
        related_addresses = set()
        if analysis_type == "transaction_analysis" and end > start:
            print("\n=== 步骤2：分析交易历史 ===")
            related_addresses = self.analyze_contract(address, start, end)
        
        # 步骤3：触发深度分析
        print("\n=== 步骤3：生成深度分析 ===")
        analysis_result = process_user_query({
            "contract_address": address,
            "start_block": start,
            "end_block": end,
            "analysis_type": analysis_type,
            "related_addresses": list(related_addresses),  # 传入相关地址列表
            "user_input": user_input  # 传入原始用户输入
        })
        
        # 检查是否获得了有意义的深度分析
        if "在指定区块范围内未发现任何交互" in analysis_result or len(analysis_result) < 200:
            print("\n=== 未获得足够的深度分析信息，生成直接回答 ===")
            from analyze_user_behavior import request_ds
            
            direct_answer_prompt = f"""
            作为区块链安全分析专家，请直接回答用户的问题。
            
            我们已经分析了合约 {address}，但未能获取足够的交互数据或相关信息进行深度分析。
            请基于合约地址和用户问题提供一般性的专业回答。
            
            用户问题：{user_input}
            目标合约：{address}
            
            请提供专业、准确的回答，包括可能的安全建议或分析方向。
            """
            
            return request_ds(direct_answer_prompt, "")
        
        return analysis_result


if __name__ == "__main__":
    user_input = input("请输入分析请求（例如：分析最近一周UNI代币的安全事件）：")
    
    # 第一步：LLM解析+RAG检索
    processor = LLMQueryProcessor()
    llm_params, rag_data = processor.parse_query(user_input)
    
    # 如果无法解析出地址，直接使用LLM回答
    if not rag_data['address']:
        print("\n=== 无法解析具体合约地址，直接回答用户问题 ===")
        from analyze_user_behavior import request_ds
        
        direct_answer_prompt = f"""
        作为区块链安全分析专家，请直接回答用户的问题。由于无法识别具体的合约地址或区块范围，
        请基于你的知识提供一般性的回答。
        
        用户问题：{user_input}
        
        请提供专业、准确的回答，包括可能的安全建议或分析方向。
        """
        
        answer = request_ds(direct_answer_prompt, "")
        print("\n=== 回答 ===")
        print(answer)
        exit()
    
    # 打印分析信息（方便调试）
    print(f"\n=== 分析参数 ===")
    print(f"目标代币/合约: {llm_params.get('token_identifier', 'Unknown')}")
    print(f"时间范围: {llm_params.get('time_range_hint', '1天')}")
    print(f"分析重点: {', '.join(llm_params.get('analysis_focus', ['资金流向']))}")
    print(f"分析类型: {llm_params.get('analysis_type', 'transaction_analysis')}")
    print(f"区块范围: {rag_data['start_block']} - {rag_data['end_block']}")
    
    # 第二步：主分析流程
    analyzer = ContractAnalyzer()
    report = analyzer.execute_full_analysis(
        rag_data['address'],
        rag_data['start_block'],
        rag_data['end_block'],
        llm_params.get('analysis_type', 'transaction_analysis'),  # 传入分析类型
        user_input  # 传入原始用户输入，用于生成直接回答
    )
    
    # 第三步：输出结果
    print("\n=== 最终分析报告 ===")
    print(report)

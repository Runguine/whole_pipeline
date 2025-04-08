import sys
import os
import time
import traceback  # 用于打印详细的错误堆栈

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
from database.crud import update_bytecode, update_decompiled_code, get_contract_full_info as db_get_contract_full_info
from database.models import Contract,UserInteraction
from ethereum.abi_fetcher import get_contract_metadata, process_contract_metadata
from database.crud import upsert_contract

from first_LLM.llm_processor import LLMQueryProcessor
from analyze_user_behavior import process_user_query, request_ds
from config.settings import settings


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
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.db = next(get_db())

    def process_with_metadata(self, address: str):
        """增强的合约处理流程（保留元数据存储）"""
        # 处理代理链
        contract_info = self.analyzer.process_contract(address)
        
        # 如果已经在数据库中找到合约信息，则不需要再获取元数据
        if contract_info and contract_info.get('address') == address.lower():
            print(f"已从数据库获取到合约 {address} 的信息，跳过元数据获取")
            return contract_info
        
        # 获取并存储元数据（使用当前网络配置）
        network_config = settings.NETWORKS[self.analyzer.current_network]
        try:
            url = f"{network_config['explorer_url']}?module=contract&action=getsourcecode&address={address}&apikey={network_config['explorer_key']}"
            response = requests.get(url)
            response_data = response.json()
            
            # 检查响应格式
            if isinstance(response_data, dict) and response_data.get('status') == '1' and response_data.get('result'):
                metadata_list = response_data.get('result', [])
                if metadata_list and isinstance(metadata_list, list) and len(metadata_list) > 0:
                    metadata = metadata_list[0]
                    if metadata and isinstance(metadata, dict) and metadata.get('SourceCode'):
                        processed = process_contract_metadata(metadata)
                        contract_data = {
                            "target_contract": address.lower(),
                            "network": self.analyzer.current_network,  # 添加网络信息
                            **processed
                        }
            
                        # 更新数据库
                        upsert_contract(self.db, contract_data)
                        print(f"已存储 {address} 的ABI和源代码")
                    else:
                        print("未验证合约或元数据格式不正确")
                else:
                    print("API返回的结果列表为空或格式不正确")
            else:
                print(f"API返回数据格式不正确: {response_data}")
        except Exception as e:
            print(f"获取元数据失败: {str(e)}")
            # 打印详细的错误信息和堆栈跟踪
            traceback.print_exc()





class ContractAnalyzer:
    def __init__(self):
        # 只保留以太坊网络的Web3实例
        self.w3_instances = {
            "ethereum": Web3(Web3.HTTPProvider(settings.NETWORKS["ethereum"]["rpc_url"]))
        }
        self.current_network = "ethereum"  # 固定为以太坊网络
        self.abi_cache = {}
        self.processed_contracts = set()
        self.max_recursion_depth = 3
        self.decompiler_enabled = True
        self.current_level = 0  # 添加递归深度跟踪
        self.db = next(get_db())  # 添加数据库连接
    
    @property
    def w3(self):
        """获取当前网络的Web3实例"""
        return self.w3_instances["ethereum"]

    def get_contract_abi(self, address):
        """带缓存的ABI获取方法，支持多网络"""
        cache_key = f"{self.current_network}_{address.lower()}"
        if cache_key not in self.abi_cache:
            try:
                network_config = settings.NETWORKS[self.current_network]
                url = f"{network_config['explorer_url']}?module=contract&action=getabi&address={address}&apikey={network_config['explorer_key']}"
                response = requests.get(url)
                self.abi_cache[cache_key] = json.loads(response.json()['result'])
            except Exception as e:
                print(f"获取ABI失败: {str(e)}")
                self.abi_cache[cache_key] = []
        return self.abi_cache[cache_key]
    
    def get_method_name(self, contract_address, input_data):
        """获取方法名称（从ABI或4byte目录）"""
        if not input_data or len(input_data) < 8:
            return "unknown"
        
        # 确保input_data格式正确
        if isinstance(input_data, bytes):
            selector = input_data[:4].hex()
        else:
            # 如果是字符串，确保没有0x前缀
            if input_data.startswith('0x'):
                input_data = input_data[2:]
            selector = input_data[:8]
        
        # 确保selector格式正确
        if len(selector) == 8:
            selector_with_prefix = '0x' + selector
        else:
            selector_with_prefix = selector
        
        # 首先尝试从ABI获取
        try:
            # 确保合约地址是校验和格式
            checksum_address = Web3.to_checksum_address(contract_address)
            
            abi = self.get_contract_abi(checksum_address)
            if abi:
                contract = self.w3.eth.contract(address=checksum_address, abi=abi)
                for func in contract.functions:
                    if func.function_signature_hash == selector_with_prefix:
                        return func.fn_name
        except Exception as e:
            print(f"从ABI获取方法名称失败: {str(e)}")
        
        # 然后尝试从4byte目录获取
        try:
            url = f"https://www.4byte.directory/api/v1/signatures/?hex_signature={selector_with_prefix}"
            response = requests.get(url, timeout=5).json()
            
            if response.get('results') and len(response['results']) > 0:
                return response['results'][0]['text_signature'].split('(')[0]
        except Exception as e:
            print(f"从4byte目录获取方法名称失败: {str(e)}")
        
        # 如果都失败了，返回选择器
        return f"0x{selector}"


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

    def get_contract_metadata(self, address):
        """获取合约元数据"""
        max_retries = 3
        retry_delay = 2
        
        # 打印网络配置信息（调试用）
        network_config = settings.NETWORKS[self.current_network]
        #print(f"\n当前网络配置:")
        #print(f"网络: {self.current_network}")
        #print(f"浏览器API: {network_config['explorer_url']}")
        #print(f"API Key长度: {len(network_config['explorer_key']) if network_config['explorer_key'] else 0}")
        
        if not network_config['explorer_key']:
            print(f"警告: {self.current_network} 网络的API Key未设置")
            return {
                'ABI': '[]',
                'SourceCode': '',
                'ContractName': f'Contract_{address[:8]}'
            }
        
        for attempt in range(max_retries):
            try:
                # 构建URL - 注意Base网络使用的是完整URL，不需要添加额外参数
                if "chainid=" in network_config['explorer_url']:
                    # 已经包含chainid参数的URL (如Base网络)
                    url = f"{network_config['explorer_url']}&module=contract&action=getsourcecode&address={address}&apikey={network_config['explorer_key']}"
                else:
                    # 标准URL (如以太坊主网)
                    url = f"{network_config['explorer_url']}?module=contract&action=getsourcecode&address={address}&apikey={network_config['explorer_key']}"
                
                print(f"\n尝试获取合约元数据 (尝试 {attempt + 1}/{max_retries})")
                #print(f"请求URL: {url}")
                
                response = requests.get(url)
                if response.status_code == 200:
                    data = response.json()
                    
                    # 打印完整的响应数据（调试用）
                    #print(f"API响应: {data}")
                    
                    # 检查数据类型并适当处理
                    if isinstance(data, str):
                        try:
                            import json
                            data = json.loads(data)
                        except:
                            print("无法解析字符串响应为JSON")
                            data = {"status": "0", "result": []}
                    
                    # 检查响应格式
                    if isinstance(data, dict) and data.get('status') == '1' and data.get('result'):
                        result = data['result']
                        if isinstance(result, list) and len(result) > 0:
                            result_item = result[0]
                            if isinstance(result_item, dict):
                                print(f"成功获取合约元数据")
                                return result_item
                            elif isinstance(result_item, str):
                                # 尝试将字符串解析为字典
                                try:
                                    import json
                                    result_dict = json.loads(result_item)
                                    print(f"成功解析字符串元数据")
                                    return result_dict
                                except:
                                    print(f"无法解析元数据字符串")
                                    return {
                                        'ABI': '[]',
                                        'SourceCode': '',
                                        'ContractName': f'Contract_{address[:8]}'
                                    }
                    
                    # 检查是否是API Key错误
                    if data.get('message') == 'NOTOK' and 'Invalid API Key' in str(data.get('result', '')):
                        print(f"API Key验证失败，请检查环境变量是否正确设置")
                        return {
                            'ABI': '[]',
                            'SourceCode': '',
                            'ContractName': f'Contract_{address[:8]}'
                        }
                        
                    print(f"API返回数据格式不正确: {data}")
                else:
                    print(f"API请求失败，状态码: {response.status_code}")
                    print(f"响应内容: {response.text}")
                
                if attempt < max_retries - 1:
                    print(f"将在 {retry_delay} 秒后重试...")
                    time.sleep(retry_delay)
                    
            except Exception as e:
                print(f"获取元数据时发生错误: {str(e)}")
                if attempt < max_retries - 1:
                    print(f"将在 {retry_delay} 秒后重试...")
                    time.sleep(retry_delay)
                    
        # 所有重试都失败，返回基本元数据
        print("所有重试都失败了，返回基本元数据")
        return {
            'ABI': '[]',
            'SourceCode': '',
            'ContractName': f'Contract_{address[:8]}'
        }

    def process_contract(self, address):
        if self.current_level >= self.max_recursion_depth:
            print(f"达到最大递归深度 {self.max_recursion_depth}，停止处理")
            return None
            
        print(f"\n处理合约: {address} (层级: {self.current_level})")
        
        # 确保地址是校验和格式
        try:
            address_checksum = Web3.to_checksum_address(address)
        except Exception as e:
            print(f"转换地址为校验和格式失败: {str(e)}")
            address_checksum = address  # 保留原始格式
        
        # 检查数据库中是否已存在
        contract_info = self.get_contract_full_info(address)
        has_existing_info = bool(contract_info)
        
        # 检测是否是代理合约（即使在数据库中找到了合约信息，也检查代理状态）
        is_proxy, logic_address = self.detect_proxy(address_checksum)
        
        # 如果是代理合约且有逻辑合约地址，处理逻辑合约
        if is_proxy and logic_address:
            print(f"检测到代理合约，逻辑合约地址: {logic_address}")
            # 递归处理逻辑合约
            self.current_level += 1
            logic_contract_info = self.process_contract(logic_address)
            self.current_level -= 1
            
            # 如果已有合约信息且不包含代理信息，更新它
            if has_existing_info and (not contract_info.get('is_proxy') or contract_info.get('parent_address') != logic_address):
                print(f"更新合约 {address} 的代理信息，指向逻辑合约 {logic_address}")
                contract_data = {
                    'target_contract': address.lower(),
                    'is_proxy': True,
                    'parent_address': logic_address
                }
                self.update_contract_info(contract_data)
                
                # 刷新合约信息
                contract_info = self.get_contract_full_info(address)
        
        # 如果之前找到了合约信息，现在可以返回（可能已更新）
        if has_existing_info:
            print("使用数据库中的合约信息")
            if contract_info.get('decompiled_code'):
                decompiled_code = contract_info['decompiled_code']
                if isinstance(decompiled_code, str):
                    print("使用数据库中的反编译代码 (字符串格式)")
                else:
                    print("使用数据库中的反编译代码 (对象格式)")
            return contract_info

        print("数据库中未找到合约信息，需要获取新数据")
        
        # 获取合约元数据
        try:
            metadata = self.get_contract_metadata(address_checksum)
            #print(f"获取到的元数据类型: {type(metadata)}")
            if metadata:
                print(f"元数据包含的键: {metadata.keys() if isinstance(metadata, dict) else '非字典类型'}")
        except Exception as e:
            print(f"处理元数据时出错: {str(e)}")
            traceback.print_exc()
            metadata = {
                'ABI': '[]',
                'SourceCode': '',
                'ContractName': ''
            }
        
        # 获取字节码
        bytecode = self.get_bytecode(address_checksum)
        if not bytecode:
            print("警告：无法获取合约字节码")
            bytecode = ''
        
        # 准备数据库记录
        contract_data = {
            'target_contract': address.lower(),
            'abi': metadata.get('ABI', '[]'),
            'source_code': metadata.get('SourceCode', ''),
            'c_name': metadata.get('ContractName', ''),
            'bytecode': bytecode,
            'decompiled_code': '""',
            'is_proxy': is_proxy,
            'parent_address': logic_address if is_proxy else None,
            'network': self.current_network,
            'created_at': datetime.now()
        }
        
        try:
            self.update_contract_info(contract_data)
            print("已更新数据库")
            return contract_data
        except Exception as e:
            print(f"数据库更新失败: {str(e)}")
            return None

    def analyze_contract(self, target_address, start_block, end_block):
        """分析指定区块范围内的合约交互，增强错误处理"""
        try:
            # 验证目标地址格式
            if not target_address or not Web3.is_address(target_address):
                error_msg = f"无效的目标地址: {target_address}"
                print(error_msg)
                # 返回友好的错误信息而不是抛出异常
                return {
                    "error": True,
                    "message": error_msg,
                    "related_addresses": set()
                }
            
            # 确保目标地址是校验和格式
            target_address_checksum = Web3.to_checksum_address(target_address)
            
            # 确保区块范围有效
            if start_block is None or end_block is None:
                print("未指定区块范围，将使用默认范围")
                start_block = max(0, self.w3.eth.block_number - 1000)  # 默认查询最近1000个区块
                end_block = self.w3.eth.block_number
            elif start_block > end_block:
                print("起始区块大于结束区块，将交换顺序")
                start_block, end_block = end_block, start_block
            
            print(f"\n分析区块范围: {start_block} - {end_block}")
        
        # 验证区块是否存在
            try:
                latest_block = self.w3.eth.block_number
                if end_block > latest_block:
                    print(f"警告：结束区块 {end_block} 超过当前区块高度 {latest_block}，将使用当前区块高度")
                    end_block = latest_block
            except Exception as e:
                print(f"获取最新区块失败: {str(e)}")
                end_block = start_block + 1000  # 使用一个合理的默认值
        
            # 用于存储所有相关地址
            related_addresses = set()
        
            count = 0
            for block_num in tqdm(range(start_block, end_block + 1)):
                try:
                    block = self.w3.eth.get_block(block_num, full_transactions=True)
                    
                    for tx in block.transactions:
                        try:
                                # 确保tx.to存在（不是合约创建交易）
                                if tx.to is None:
                                    continue
                                
                                # 确保tx.to是校验和格式
                                tx_to_checksum = Web3.to_checksum_address(tx.to) if tx.to else None
                                tx_from_checksum = Web3.to_checksum_address(tx['from']) if tx['from'] else None
                                
                                # 检查交易是否与目标合约相关
                                if tx_to_checksum and tx_to_checksum.lower() == target_address.lower():
                                    # 处理调用目标合约的交易
                                    tx_input = tx.input
                                    if isinstance(tx_input, str):
                                        # 如果是字符串，确保格式正确
                                        if tx_input.startswith('0x'):
                                            tx_input = tx_input[2:]
                                    elif isinstance(tx_input, bytes):
                                        # 如果是字节，转换为十六进制字符串
                                        tx_input = tx_input.hex()
                                        if tx_input.startswith('0x'):
                                            tx_input = tx_input[2:]
                                    
                                    # 先获取交易追踪（trace）以获取内部交易和完整调用链
                                    trace_data = self.get_transaction_trace(tx.hash)
                                    
                                    # 先创建tx_data字典，确保包含所有必要的字段
                                    tx_data = {
                                        'target_contract': target_address.lower(),
                                        'caller_contract': tx_from_checksum.lower(),
                                        'method_name': self.get_method_name(target_address, tx_input),
                                        'block_number': block_num,  # 确保这个字段总是存在
                                        'tx_hash': tx.hash.hex() if isinstance(tx.hash, bytes) else tx.hash,
                                        'timestamp': datetime.fromtimestamp(block.timestamp),
                                        'input_data': tx_input,
                                        'network': self.current_network
                                    }
                                    
                                    # 先保存基本交互数据到数据库
                                    self.save_interaction(tx_data)
                                    count += 1
                                    
                                    # 集合用于存储所有提取的地址
                                    all_extracted_addresses = set()
                                    
                                    # 从input_data中提取地址
                                    input_addresses = self._extract_addresses_from_input(tx_input)
                                    all_extracted_addresses.update(input_addresses)
                                    
                                    # 从trace中提取所有相关合约地址
                                    trace_addresses = set()
                                    if trace_data:
                                        trace_addresses = self.extract_addresses_from_trace(trace_data)
                                        all_extracted_addresses.update(trace_addresses)
                                        
                                        # 保存trace数据到交易记录
                                        tx_data['trace_data'] = json.dumps(trace_data)
                                        self.update_interaction_trace(tx_data)
                                    
                                    # 输出合并后的地址信息
                                    print(f"从交易 {tx.hash.hex() if isinstance(tx.hash, bytes) else tx.hash} 中提取了 {len(all_extracted_addresses)} 个地址")
                                    print(f"其中input_data提供 {len(input_addresses)} 个，trace补充了 {len(trace_addresses) if trace_data else 0} 个")
                                    
                                    # 加入到总的相关地址集合
                                    related_addresses.update(all_extracted_addresses)
                                    
                                    # 处理交易收据中的事件日志
                                    try:
                                        receipt = self.w3.eth.get_transaction_receipt(tx.hash)
                                        if receipt and hasattr(receipt, 'logs') and receipt.logs:
                                            # 将日志转换为可序列化格式
                                            serialized_logs = []
                                            for log in receipt.logs:
                                                log_dict = {}
                                                # 处理地址
                                                if hasattr(log, 'address'):
                                                    log_dict['address'] = Web3.to_checksum_address(log.address).lower()
                                                    # 添加日志中的合约地址到相关地址集合
                                                    related_addresses.add(log_dict['address'].lower())
                                                
                                                # 处理topics
                                                log_dict['topics'] = []
                                                if hasattr(log, 'topics'):
                                                    for topic in log.topics:
                                                        if isinstance(topic, bytes):
                                                            log_dict['topics'].append('0x' + topic.hex())
                                                        else:
                                                            log_dict['topics'].append(topic)
                                                
                                                # 处理data
                                                if hasattr(log, 'data'):
                                                    if isinstance(log.data, bytes):
                                                        log_dict['data'] = '0x' + log.data.hex()
                                                    else:
                                                        log_dict['data'] = log.data
                                                
                                                # 其他字段
                                                if hasattr(log, 'blockNumber'):
                                                    log_dict['blockNumber'] = log.blockNumber
                                                if hasattr(log, 'transactionHash'):
                                                    log_dict['transactionHash'] = log.transactionHash.hex() if isinstance(log.transactionHash, bytes) else log.transactionHash
                                                
                                                serialized_logs.append(log_dict)
                                            
                                            # 更新交易数据中的事件日志
                                            tx_data['event_logs'] = json.dumps(serialized_logs)
                                            self.update_interaction_logs(tx_data)
                                    except Exception as e:
                                        print(f"处理事件日志时出错: {str(e)}")
                        
                        except Exception as e:
                            print(f"处理交易详情时出错: {str(e)}")
                            traceback.print_exc()
                            continue
                        
                except Exception as e:
                    print(f"获取区块 {block_num} 时出错: {str(e)}")
                    continue
                            
            print(f"分析完成，共处理 {count} 笔交易")
            
            # 处理所有相关地址
            print("\n开始处理相关合约...")
            for addr in related_addresses:
                try:
                    # 确保地址是校验和格式
                    addr_checksum = Web3.to_checksum_address(addr)
                    
                    # 检查是否是合约地址
                    code = self.w3.eth.get_code(addr_checksum)
                    if code and code.hex() != '0x':  # 如果有代码，说明是合约
                        print(f"\n处理相关合约: {addr_checksum}")
                        self.process_contract(addr_checksum)
                    else:
                        print(f"跳过普通地址: {addr_checksum}")
                except Exception as e:
                    print(f"处理地址 {addr} 时出错: {str(e)}")
                    traceback.print_exc()
            
            return related_addresses
            
        except Exception as e:
            error_msg = f"合约分析过程中出错: {str(e)}"
            print(error_msg)
            traceback.print_exc()
            # 返回错误信息而不是抛出异常
            return {
                "error": True,
                "message": error_msg,
                "related_addresses": set()
            }

    def get_transaction_trace(self, tx_hash):
        """获取交易的完整调用追踪"""
        try:
            # 规范化tx_hash格式
            if isinstance(tx_hash, bytes):
                tx_hash = tx_hash.hex()
                if not tx_hash.startswith('0x'):
                    tx_hash = '0x' + tx_hash
            elif isinstance(tx_hash, str):
                if not tx_hash.startswith('0x'):
                    tx_hash = '0x' + tx_hash
            
            # 使用trace_transaction替代debug_traceTransaction
            trace_params = {
                "jsonrpc": "2.0",
                "method": "trace_transaction",  # 使用Ankr支持的trace API
                "params": [tx_hash],
                "id": 1
            }
            
            # 获取当前网络的RPC URL
            rpc_url = settings.NETWORKS[self.current_network]['rpc_url']
            
            # 添加必要的请求头
            headers = {
                "Content-Type": "application/json"
            }
            
            # 如果有Ankr API密钥，添加到请求头
            ankr_api_key = os.getenv('ANKR_API_KEY')
            if ankr_api_key:
                headers["Authorization"] = f"Bearer {ankr_api_key}"
            
            # 添加重试逻辑
            max_retries = 3
            retry_delay = 2
            
            for attempt in range(max_retries):
                try:
                    # 发送RPC请求
                    response = requests.post(
                        rpc_url,
                        headers=headers,
                        json=trace_params,
                        timeout=30  # 添加超时设置
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        if 'result' in result:
                            print(f"成功获取交易 {tx_hash} 的追踪信息")
                            return result['result']
                        elif 'error' in result:
                            error_msg = result.get('error', {}).get('message', '未知错误')
                            print(f"获取交易追踪失败: {error_msg}")
                            
                            # 如果错误是关于格式的，尝试修改格式
                            if "hex string" in error_msg and "want 64 for common.Hash" in error_msg:
                                if attempt == 0:  # 只在第一次尝试时切换格式
                                    print("尝试调整哈希格式后重试...")
                                    # 移除0x前缀
                                    if trace_params["params"][0].startswith("0x"):
                                        trace_params["params"][0] = trace_params["params"][0][2:]
                                    else:
                                        trace_params["params"][0] = "0x" + trace_params["params"][0]
                                        continue
                    else:
                        print(f"RPC请求失败，状态码: {response.status_code}")
                        print(f"响应内容: {response.text}")
                    
                    # 如果不是第一次尝试的格式问题，等待后重试
                    if attempt < max_retries - 1:
                        print(f"将在 {retry_delay} 秒后重试...")
                        time.sleep(retry_delay)
                
                except requests.exceptions.Timeout:
                    print(f"请求超时 (尝试 {attempt+1}/{max_retries})")
                    if attempt < max_retries - 1:
                        print(f"将在 {retry_delay} 秒后重试...")
                        time.sleep(retry_delay)
                    
                except Exception as e:
                    print(f"请求过程中出错: {str(e)}")
                    if attempt < max_retries - 1:
                        print(f"将在 {retry_delay} 秒后重试...")
                        time.sleep(retry_delay)
            
            # 所有重试都失败，尝试替代方法
            print("尝试使用替代方法获取交易信息...")
            return self._get_transaction_trace_alternative(tx_hash)
                                    
        except Exception as e:
            print(f"获取交易追踪时出错: {str(e)}")
            traceback.print_exc()
            return None
        
    def _get_transaction_trace_alternative(self, tx_hash):
        """当主要trace方法失败时的替代方法"""
        try:
            # 确保tx_hash格式正确
            if not tx_hash.startswith('0x'):
                tx_hash = '0x' + tx_hash
            
            # 获取交易收据
            receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            if not receipt:
                return None
            
            # 获取交易本身
            tx = self.w3.eth.get_transaction(tx_hash)
            
            # 构造简化的trace结构
            trace = {
                "action": {
                    "from": receipt['from'],
                    "to": receipt.get('to', '0x0000000000000000000000000000000000000000'),
                    "value": str(tx.get('value', 0)),
                    "gas": str(tx.get('gas', 0)),
                    "input": tx.get('input', '0x')
                },
                "result": {
                    "gasUsed": str(receipt.get('gasUsed', 0))
                },
                "subtraces": len(receipt.get('logs', [])),
                "type": "call"
            }
            
            # 如果是合约创建
            if not receipt.get('to'):
                trace["type"] = "create"
                trace["result"]["address"] = receipt.get('contractAddress')
            
            print(f"成功创建替代trace结构")
            return trace
                                
        except Exception as e:
            print(f"替代方法失败: {str(e)}")
            return None

    def extract_addresses_from_trace(self, trace_data):
        """从交易追踪数据中提取所有相关合约地址"""
        addresses = set()
        
        def process_call(call_data):
            # 添加当前调用的to地址
            if 'to' in call_data and call_data['to']:
                try:
                    # 确保地址格式正确
                    addr = call_data['to']
                    if Web3.is_address(addr):
                        addresses.add(Web3.to_checksum_address(addr).lower())
                except Exception as e:
                    print(f"处理trace地址时出错: {str(e)}")
                    
            # 添加当前调用的from地址
            if 'from' in call_data and call_data['from']:
                try:
                    addr = call_data['from']
                    if Web3.is_address(addr):
                        addresses.add(Web3.to_checksum_address(addr).lower())
                except Exception as e:
                    print(f"处理trace地址时出错: {str(e)}")
            
            # 递归处理子调用
            if 'calls' in call_data and isinstance(call_data['calls'], list):
                for subcall in call_data['calls']:
                    process_call(subcall)
        
        # 开始处理根调用
        if trace_data:
            process_call(trace_data)
        
        return addresses

    def update_interaction_trace(self, tx_data):
        """更新交互数据的trace信息"""
        try:
            # 查找现有记录
            interaction = self.db.query(UserInteraction).filter(
                UserInteraction.tx_hash == tx_data['tx_hash']
            ).first()
            
            if interaction:
                # 更新trace数据
                interaction.trace_data = tx_data.get('trace_data')
                self.db.commit()
                return True
            return False
        except Exception as e:
            self.db.rollback()
            print(f"更新trace数据时出错: {str(e)}")
            return False

    def _extract_addresses_from_input(self, input_data):
        """从input_data中提取以太坊地址"""
        addresses = set()
        
        # 确保input_data是字符串格式
        if isinstance(input_data, bytes):
            input_data = input_data.hex()
        
        # 移除0x前缀
        if input_data.startswith('0x'):
            input_data = input_data[2:]
            
        # 方法ID在前4个字节（8个字符）
        method_id = input_data[:8]
        data = input_data[8:]
        
        # 每32字节（64个字符）为一个参数
        for i in range(0, len(data), 64):
            if i + 64 <= len(data):
                param = data[i:i+64]
            # 检查是否可能是地址（通过检查前24个字节是否为0）
                if param.startswith('000000000000000000000000'):
                    potential_address = '0x' + param[-40:]
                    if Web3.is_address(potential_address):
                            try:
                                # 转换为校验和格式
                                checksum_address = Web3.to_checksum_address(potential_address)
                                addresses.add(checksum_address.lower())
                                print(f"从input_data中提取到地址: {checksum_address}")
                            except Exception as e:
                                print(f"转换地址格式时出错: {str(e)}")
                    
        return addresses

    def execute_full_analysis(self, address: str, start: int, end: int, analysis_type: str = "transaction_analysis", user_input: str = "", network: str = "ethereum"):
        """全流程入口（集成原有逻辑）"""
        # 强制使用以太坊网络，忽略传入的network参数
        self.current_network = "ethereum"
        #print(f"\n=== 网络配置 ===")
        #print(f"当前网络: ethereum")
        #print(f"RPC URL: {settings.NETWORKS['ethereum']['rpc_url']}")
        
        # 验证网络连接
        try:
            current_block = self.w3.eth.block_number
            print(f"当前区块高度: {current_block}")
        except Exception as e:
            error_msg = f"网络连接失败: {str(e)}"
            print(error_msg)
            return error_msg
        
        # 初始化处理管道（传递当前实例）
        pipeline = ContractPipeline(self)
        
        # 步骤1：处理目标合约及元数据
        print("\n=== 步骤1：处理目标合约 ===")
        try:
            contract_info = pipeline.process_with_metadata(address)
            if not contract_info:
                print("警告：无法获取合约信息，但将继续分析")
        except Exception as e:
            print(f"处理合约时出错: {str(e)}")
            traceback.print_exc()
            print("将继续分析交易历史...")
        
        # 步骤2：执行区块分析和相关合约处理
        related_addresses = set()
        if analysis_type in ["transaction_analysis", "security_analysis"]:
            print("\n=== 步骤2：分析交易历史 ===")
            print(f"分析区块范围: {start} - {end}")
            try:
                related_addresses = self.analyze_contract(address, start, end)
            except Exception as e:
                error_msg = f"交易分析失败: {str(e)}"
                print(error_msg)
                return error_msg
        
        # 步骤3：触发深度分析
        print("\n=== 步骤3：生成深度分析 ===")
        analysis_result = process_user_query({
            "contract_address": address,
            "start_block": start,
            "end_block": end,
            "analysis_type": analysis_type,
            "related_addresses": list(related_addresses),
            "user_input": user_input,
            "network": "ethereum"  # 固定为以太坊网络
        })
        
        return analysis_result

    def get_contract_full_info(self, address):
        """获取合约完整信息"""
        return db_get_contract_full_info(self.db, address.lower())
        
    def get_bytecode(self, address):
        """获取合约字节码"""
        try:
            bytecode = self.w3.eth.get_code(Web3.to_checksum_address(address))
            return bytecode.hex()
        except Exception as e:
            print(f"获取字节码失败: {str(e)}")
            return ""
            
    def update_contract_info(self, contract_data):
        """更新合约信息到数据库"""
        try:
            upsert_contract(self.db, contract_data)
        except Exception as e:
            print(f"更新合约信息失败: {str(e)}")

    def save_interaction(self, tx_data):
        """保存交互数据到数据库"""
        try:
            # 检查是否已存在相同的交易哈希
            existing = self.db.query(UserInteraction).filter(
                UserInteraction.tx_hash == tx_data['tx_hash']
            ).first()
            
            if not existing:
                # 创建新记录
                interaction = UserInteraction(
                    target_contract=tx_data['target_contract'],
                    caller_contract=tx_data['caller_contract'],
                    method_name=tx_data['method_name'],
                    block_number=tx_data['block_number'],
                    tx_hash=tx_data['tx_hash'],
                    timestamp=tx_data['timestamp'],
                    input_data=tx_data.get('input_data', ''),
                    network=tx_data.get('network', 'ethereum')
                )
                self.db.add(interaction)
                self.db.commit()
                return True
            return False
        except Exception as e:
            self.db.rollback()
            print(f"保存交互数据时出错: {str(e)}")
            return False

    def update_interaction_logs(self, tx_data):
        """更新交互数据的事件日志"""
        try:
            # 查找现有记录
            interaction = self.db.query(UserInteraction).filter(
                UserInteraction.tx_hash == tx_data['tx_hash']
            ).first()
            
            if interaction:
                # 更新事件日志
                interaction.event_logs = tx_data.get('event_logs')
                self.db.commit()
                return True
            return False
        except Exception as e:
            self.db.rollback()
            print(f"更新事件日志时出错: {str(e)}")
            return False


if __name__ == "__main__":
    user_input = input("请输入分析请求（例如：分析最近一周UNI代币的安全事件 或 分析地址0x123...在区块15000000至15001000的交易）：")
    
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
    
    # 强制设置为以太坊网络
    rag_data['network'] = "ethereum"
    
    # 打印分析信息（方便调试）
    print(f"\n=== 分析参数 ===")
    print(f"目标代币/合约: {llm_params.get('token_identifier', 'Unknown')}")
    print(f"时间范围: {llm_params.get('time_range_hint', '1天')}")
    print(f"分析重点: {', '.join(llm_params.get('analysis_focus', ['资金流向']))}")
    print(f"分析类型: {llm_params.get('analysis_type', 'transaction_analysis')}")
    print(f"网络: ethereum")  # 固定显示以太坊网络
    
    # 显示区块范围来源
    if llm_params.get('user_specified_blocks', False):
        print(f"区块范围(用户指定): {rag_data['start_block']} - {rag_data['end_block']}")
    else:
        print(f"区块范围(系统推断): {rag_data['start_block']} - {rag_data['end_block']}")
    
    # 第二步：主分析流程
    analyzer = ContractAnalyzer()
    report = analyzer.execute_full_analysis(
        rag_data['address'],
        rag_data['start_block'],
        rag_data['end_block'],
        llm_params.get('analysis_type', 'transaction_analysis'),
        user_input,
        "ethereum"  # 强制使用以太坊网络
    )
    
    # 第三步：输出结果
    print("\n=== 最终分析报告 ===")
    print(report)

import sys
import os
from collections import Counter
from sqlalchemy.orm import Session
from database.models import Contract,UserInteraction
import json
from web3 import Web3
import time
from datetime import datetime
import traceback
import requests
from sqlalchemy.pool import QueuePool
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import and_, or_

# 新增在analyze_user_behavior.py顶部
USER_QUERY_PROMPT = """
As a blockchain security analysis assistant, please extract the following information from the user's question:
1. Contract address (hexadecimal string starting with 0x)
2. Block range (start and end block numbers)
3. Associated security event name

User question: {user_input}

Please return in JSON format with the following fields:
- "contract_address" (string|null)
- "start_block" (number|null)
- "end_block" (number|null) 
- "event_name" (string|null)

Example response:
{{"contract_address": "0x...", "start_block": 21895238, "end_block": 21895251, "event_name": "Bybit attack event"}}
"""

PRELIMINARY_ANALYSIS_PROMPT = """
As a blockchain security expert, please generate a preliminary event analysis based on the following information:
1. Known event name: {event_name}
2. Original user description: {user_input}

Analysis requirements:
1. Event background and industry impact (100 words)
2. Possible vulnerability types involved
3. Preliminary fund flow estimation
4. Suggested investigation directions

Output format:
### Event Background
[content]

### Potential Vulnerabilities
[content]

### Fund Flow Estimation  
[content]

### Investigation Recommendations
[content]
"""

FINAL_REPORT_PROMPT = """
Based on the provided contract code and transaction data, generate a definitive security analysis report:

# Preliminary Contract Analysis
{preliminary_analysis}

# Detailed Security Analysis  
{behavior_analysis}

## CRITICAL ANALYSIS REQUIREMENTS

1. **CODE-BASED ANALYSIS ONLY** - Your analysis must be based strictly on the actual code provided and transaction data. DO NOT include speculative statements or hypothetical scenarios.

2. **IDENTIFY EXACT VULNERABILITY FUNCTIONS** - You must identify the specific function(s) in the victim contract where the vulnerability exists. Quote the exact vulnerable code segments and explain precisely how they were exploited.

3. **CONCRETE ATTACK CHAIN** - Reconstruct the exact attack sequence based solely on transaction data and code evidence. Each step must reference specific function calls backed by transaction evidence.

4. **DEFINITIVE LANGUAGE** - Use only definitive language throughout your analysis. Avoid terms like "could be", "might have", "possibly", etc. If you cannot determine something with certainty from the code or transaction data, state that it cannot be determined rather than speculating.

## Output Format

# Security Incident Analysis Report

## Vulnerability Summary
[Precise description of the identified vulnerability with exact function name and code location]

## Contract Analysis
- Target Contract: [Analysis with specific function and line references]
- Attacker Contract(s): [Analysis with specific function and line references]

## Attack Chain Reconstruction
[Step-by-step breakdown of the exact attack flow with specific transaction and function call references]

## Exploitation Mechanism
[Detailed technical explanation of exactly how the vulnerability was exploited, with code references]

## Root Cause
[Definitive statement on the exact code issue that enabled the attack]

## Security Recommendations
[Specific code fixes that would prevent this exact vulnerability]
"""

def parse_user_query(user_input):
    """解析用户查询并提取参数"""
    prompt = USER_QUERY_PROMPT.format(user_input=user_input)
    try:
        response = request_ds(prompt, "")
        return json.loads(response.strip("`").replace("json\n",""))
    except Exception as e:
        print(f"参数解析失败: {str(e)}")
        return None

def generate_preliminary_analysis(params):
    """生成事件初步分析"""
    prompt = PRELIMINARY_ANALYSIS_PROMPT.format(
        event_name=params.get("event_name","未知安全事件"),
        user_input=params.get("user_input","")
    )
    return request_ds(prompt, "")

def generate_final_report(preliminary, behavior):
    """生成最终安全分析报告，整合初步分析和详细行为分析"""
    prompt = FINAL_REPORT_PROMPT.format(
        preliminary_analysis=preliminary,
        behavior_analysis=behavior
    )
    
    final_report = request_ds(prompt, "")
    return final_report




sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from database import get_db
from database.crud import (
    get_user_interactions,
    get_contract_full_info  # 需要新增的CRUD函数
)
from config.settings import settings

BEHAVIOR_PROMPT = """
作为区块链安全分析专家，请对以下合约进行全面分析：

目标合约: {target_contract}
区块范围: {block_range}
相关合约: {related_contracts}

== 方法调用统计 ==
{method_list}

== 调用模式分析 ==
{call_patterns}

== 代码分析 ==
{code_context}

请结合上述信息，提供详细的安全分析报告，包括:
1. 合约功能和目的
2. 潜在的安全问题和漏洞
3. 交易行为模式分析
4. 安全建议

如果目标合约没有源码，请重点分析它创建的合约和与之交互的合约代码。
"""

from openai import OpenAI
from config.settings import settings

APIKEY = settings.APIKEY
BASEURL = settings.BASEURL
MODELNAME = settings.MODELNAME

client = OpenAI(
  base_url = BASEURL,
  api_key = APIKEY,
)

def request_ds(prompt, abi, max_retries=3, retry_delay=2):
    """
    向大模型发送请求并获取回复
    增加了错误处理和重试机制
    """
    if not prompt or len(prompt.strip()) == 0:
        return "提示词为空，无法生成分析"
        
    last_error = None
    
    for attempt in range(max_retries):
        try:
            if attempt > 0:
                time.sleep(retry_delay)
            
            # 确保prompt不为空且为字符串
            if not isinstance(prompt, str):
                prompt = str(prompt)
            
            # 添加系统角色提示
            messages = [
                {
                    "role": "system",
                    "content": "你是一个专业的区块链安全分析专家，请基于提供的信息进行分析。"
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
            
            completion = client.chat.completions.create(
                model=MODELNAME,
                messages=messages,
                temperature=0.7,
                max_tokens=2000
            )
            
            if completion and hasattr(completion, 'choices') and len(completion.choices) > 0:
                return completion.choices[0].message.content
            
            print(f"API返回无效响应 (尝试 {attempt+1}/{max_retries})")
            last_error = "Invalid API response"
            
        except Exception as e:
            print(f"API调用出错: {str(e)} (尝试 {attempt+1}/{max_retries})")
            last_error = str(e)
    
    # 所有重试都失败后的降级处理
    error_response = f"""
### 分析过程中遇到技术问题

很抱歉，在分析过程中遇到了API调用问题：
{last_error}

建议：
1. 检查网络连接
2. 确认API配置是否正确
3. 稍后重试

如果问题持续存在，请联系技术支持。
"""
    return error_response

# 新增CRUD函数需要添加到crud.py中
def get_contract_full_info(db: Session, address: str):
    """
    获取合约完整信息（包含代理关系）
    返回数据结构：
    {
        "address": str,
        "is_proxy": bool,
        "parent_address": str,
        "source_code": str,
        "abi": list,
        "decompiled_code": str
    }
    """
    contract = (
        db.query(Contract)
        .filter(Contract.target_contract == address.lower())
        .first()
    )
    if not contract:
        return None
    
    result = {
        "address": contract.target_contract,
        "is_proxy": contract.is_proxy,
        "parent_address": contract.parent_address,
        "source_code": contract.source_code,
        "abi": contract.abi,
        "decompiled_code": contract.decompiled_code
    }
    
    # 递归获取父合约信息
    if contract.is_proxy and contract.parent_address:
        parent_info = get_contract_full_info(db, contract.parent_address)
        if parent_info:
            result["parent_info"] = parent_info
    
    return result

def load_contract_code(db, target_contract):
    """加载合约代码，优先使用源代码，其次是反编译代码"""
    contract_info = get_contract_full_info(db, target_contract)
    
    if contract_info:
        # 检查源代码存在且不为空
        has_source = bool(contract_info.get('source_code'))
        if has_source:
            source_code = contract_info['source_code']
            # 确保源码不是空字符串、空列表、空字典等
            if source_code and not (isinstance(source_code, (list, dict)) and len(source_code) == 0):
                print(f"使用源代码分析合约 {target_contract}")
                return {
                    'source_code': source_code,
                    'contract_type': 'source_code'
                }
        elif contract_info.get('decompiled_code'):
            print(f"使用反编译代码分析合约 {target_contract}")
            return {
                'decompiled_code': contract_info['decompiled_code'],
                'contract_type': 'decompiled_code'
            }
    
    print(f"未找到合约 {target_contract} 的代码")
    return None

def generate_code_context(contracts_chain):
    """生成LLM需要的代码上下文"""
    context = []
    
    for contract in contracts_chain:
        code_sections = []
        
        # 源码部分
        source_code = contract.get("source_code", "")
        if source_code:
            try:
                if isinstance(source_code, list) and len(source_code) > 0:
                    source_code_str = "\n".join([str(item) for item in source_code])
                elif isinstance(source_code, dict):
                    source_code_str = json.dumps(source_code, indent=2)
                else:
                    source_code_str = str(source_code)
                    code_sections.append(
                        f"// 验证源码（{contract['type']}合约 {contract['address']}）\n"
                                    f"{source_code_str}"
                    )
            except Exception as e:
                print(f"处理源码时出错: {str(e)}")
                code_sections.append(
                    f"// 验证源码（{contract['type']}合约 {contract['address']}）\n"
                    f"// 处理源码时出错: {str(e)}"
                )
        
        # 反编译代码
        decompiled_code = contract.get("decompiled_code", "")
        if decompiled_code:
            try:
                if isinstance(decompiled_code, dict):
                    decompiled_code_str = json.dumps(decompiled_code, indent=2)
                elif isinstance(decompiled_code, str) and decompiled_code.strip().startswith('{'):
                    # 尝试解析JSON字符串
                    try:
                        decompiled_json = json.loads(decompiled_code)
                        decompiled_code_str = json.dumps(decompiled_json, indent=2)
                    except:
                        decompiled_code_str = decompiled_code
                else:
                    decompiled_code_str = str(decompiled_code)
                    
                    code_sections.append(
                        f"// 反编译代码（{contract['type']}合约 {contract['address']}）\n"
                                    f"{decompiled_code_str}"
                    )
            except Exception as e:
                print(f"处理反编译代码时出错: {str(e)}")
                code_sections.append(
                    f"// 反编译代码（{contract['type']}合约 {contract['address']}）\n"
                    f"// 处理反编译代码时出错: {str(e)}"
                )
        
        # ABI信息
        abi = contract.get("abi", [])
        if abi and isinstance(abi, list):
            try:
                code_sections.append(
                    f"// ABI定义（{contract['type']}合约 {contract['address']}）\n"
                    f"{json.dumps(abi, indent=2)}"
                )
            except Exception as e:
                print(f"处理ABI时出错: {str(e)}")
                code_sections.append(
                    f"// ABI定义（{contract['type']}合约 {contract['address']}）\n"
                    f"// 处理ABI时出错: {str(e)}"
                )
        
        context.append("\n\n".join(code_sections))
    
    return "\n\n" + "="*50 + "\n\n".join(context) + "\n\n" + "="*50

def analyze_input_data(input_data, abi):
    """分析input_data中的参数，并提取地址"""
    try:
        # 确保input_data是正确的格式
        if not input_data:
            return {
                'method_id': 'empty',
                'params': [],
                'extracted_addresses': []
            }
            
        if isinstance(input_data, bytes):
            input_data = input_data.hex()
        
        # 如果是十六进制字符串但没有0x前缀，添加前缀
        if isinstance(input_data, str) and not input_data.startswith('0x'):
            input_data = '0x' + input_data
        
        # 检查input_data长度是否足够
        if len(input_data) < 10:  # 0x + 8个字符
            return {
                'method_id': 'too_short',
                'params': [],
                'extracted_addresses': []
            }
        
        # 提取地址
        extracted_addresses = []
        
        # 如果有ABI，尝试解码
        if abi and isinstance(abi, list) and len(abi) > 0:
            try:
                # 创建Web3合约对象
                contract = Web3().eth.contract(abi=abi)
                
                # 尝试解码函数输入
                try:
                    decoded = contract.decode_function_input(input_data)
                    
                    # 从解码后的参数中提取地址
                    for param_name, param_value in decoded[1].items():
                        if isinstance(param_value, str) and Web3.is_address(param_value):
                            extracted_addresses.append(param_value)
                    
                            return {
                                'method': decoded[0].fn_name,
                                'params': dict(decoded[1]),
                                'extracted_addresses': extracted_addresses
                            }
                except ValueError as e:
                    if "Could not find any function with matching selector" in str(e):
                        # 这是正常的，意味着ABI中没有匹配的函数
                        # 继续使用基础解析
                        pass
                    else:
                        print(f"ABI解码失败: {str(e)}")
            except Exception as e:
                print(f"创建合约对象失败: {str(e)}")
    
        # 基础解析
        if isinstance(input_data, str) and input_data.startswith('0x'):
            input_data = input_data[2:]
    
            method_id = input_data[:8]
            params = []
            data = input_data[8:]
            
            # 每32字节（64个字符）为一个参数
            for i in range(0, len(data), 64):
                if i + 64 > len(data):
                    # 处理不完整的参数
                    param = data[i:]
                    params.append(f"Incomplete: {param}")
                    continue
                    
        param = data[i:i+64]
        # 检查是否是地址
        if param.startswith('000000000000000000000000'):
                potential_address = '0x' + param[-40:]
                if Web3.is_address(potential_address):
                    extracted_addresses.append(potential_address)
                    params.append(f"Address: {potential_address}")
                else:
                    params.append(f"Potential Address (invalid): 0x{param[-40:]}")
        else:
            # 尝试转换为整数
            try:
                value = int(param, 16)
                params.append(f"Value: {value}")
            except:
                params.append(f"Raw: {param}")
                return {
                        'method_id': f"0x{method_id}",
                        'params': params,
                        'extracted_addresses': extracted_addresses
                }
    except Exception as e:
        print(f"分析input_data时出错: {str(e)}")
        traceback.print_exc()
        return {
            'method_id': 'error',
            'params': [f'解析失败: {str(e)}'],
            'extracted_addresses': []
        }

def process_user_query(params):
    """处理用户查询，生成分析报告"""
    print(f"\n=== 处理用户查询 ===")
    print(f"查询参数: {params}")
    
    try:
        # 验证必要参数并处理参数名称不一致问题
        if 'contract_address' in params and 'target_contract' not in params:
            params['target_contract'] = params['contract_address']
            
        # 验证必要参数
        for key in ['target_contract', 'start_block', 'end_block']:
            if key not in params:
                raise KeyError(f"缺少必要参数: {key}")
                
        # 打印参数详情
        print(f"合约地址: {params['target_contract']}")
        print(f"区块范围: {params['start_block']} - {params['end_block']}")
        
        # 添加调用链分析
        call_graph = build_transaction_call_graph(
            params['target_contract'],
            params['start_block'],
            params['end_block'],
            max_depth=3,
            pruning_enabled=True  # 启用剪枝
        )
        
        # 生成初步分析
        print("\n=== 生成初步分析 ===")
        preliminary_analysis = generate_preliminary_analysis(params)
        
        # 分析行为
        print("\n=== 分析合约行为 ===")
        behavior_analysis = analyze_behavior_new(
            target_contract=params['target_contract'],
            start_block=params['start_block'],
            end_block=params['end_block'],
            related_addresses=params.get('related_addresses', []),
            call_graph=call_graph  # 传递调用图给行为分析
        )
        
        # 检查行为分析结果
        if isinstance(behavior_analysis, str) and '错误' in behavior_analysis:
            print(f"行为分析失败: {behavior_analysis}")
            return behavior_analysis
            
        # 生成最终报告
        print("\n=== 生成最终报告 ===")
        final_report = generate_final_report(preliminary_analysis, behavior_analysis)
        
        # 保存报告
        report_file = save_report(final_report, params)
        print(f"报告已保存至: {report_file}")
        
        return final_report
        
    except KeyError as ke:
        error_msg = f"缺少必要字段：{str(ke)}"
        print(f"处理用户查询时出错: {error_msg}")
        traceback.print_exc()
        return f"### 分析过程出错\n\n在处理您的查询时遇到了错误：缺少必要字段 '{str(ke)}'"
        
    except Exception as e:
        error_msg = f"在处理您的查询时遇到了错误：{str(e)}"
        print(f"处理用户查询时出错: {error_msg}")
        traceback.print_exc()
        return f"### 分析过程出错\n\n{error_msg}"

def save_report(report_content, params):
    """
    保存分析报告为txt文件
    """
    try:
        # 创建reports目录（如果不存在）
        os.makedirs('reports', exist_ok=True)
        
        # 生成文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        contract_addr = params.get('target_contract', 'unknown')[:10]
        blocks = f"{params.get('start_block', 0)}-{params.get('end_block', 0)}"
        filename = f"reports/security_analysis_{contract_addr}_{blocks}_{timestamp}.txt"
        
        # 添加报告头部信息
        header = f"""安全分析报告
生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
目标合约: {params.get('target_contract', '未指定')}
区块范围: {params.get('start_block', 0)} - {params.get('end_block', 0)}
分析类型: {params.get('analysis_type', '未指定')}
原始查询: {params.get('user_input', '未指定')}

{'='*80}

"""
        
        # 写入文件
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(header + report_content)
            
        print(f"\n报告已保存至: {filename}")
        
    except Exception as e:
        print(f"\n保存报告时出错: {str(e)}")

def analyze_behavior_new(target_contract=None, start_block=None, end_block=None, related_addresses=None, call_graph=None):
    # 输出调试信息
    print(f"开始分析行为，参数：target={target_contract}, start={start_block}, end={end_block}")
    print(f"相关地址数量: {len(related_addresses) if related_addresses else 0}")
    
    # 获取数据库会话
    db = next(get_db())
    w3 = Web3(Web3.HTTPProvider(settings.NETWORKS["ethereum"]["rpc_url"]))
    
    try:
        from sqlalchemy import and_, or_
        
        # 构建基本查询条件
        query_conditions = [
            or_(
                UserInteraction.target_contract == target_contract.lower(),
                UserInteraction.caller_contract == target_contract.lower()
            )
        ]
        
        # 添加区块范围过滤
        if start_block is not None:
            query_conditions.append(UserInteraction.block_number >= start_block)
        if end_block is not None:
            query_conditions.append(UserInteraction.block_number <= end_block)
            
        # 添加trace数据条件
        query_conditions.append(UserInteraction.trace_data.isnot(None))
        
        # 执行查询
        transactions = db.query(UserInteraction).filter(
            and_(*query_conditions)
        ).all()
        
        # 检查是否有交易记录
        if not transactions:
            print(f"未找到任何符合条件的交易记录！")
            return "未找到任何符合条件的交易记录，请检查合约地址和区块范围是否正确。"
        
        # 处理数据前，确保所有交易记录都有必要字段
        for idx, tx in enumerate(transactions):
            if not hasattr(tx, 'block_number') or tx.block_number is None:
                print(f"交易记录 #{idx} (hash: {tx.tx_hash}) 缺少block_number字段")
                
                try:
                    # 尝试从区块链获取这个信息
                    receipt = w3.eth.get_transaction_receipt(tx.tx_hash)
                    if receipt:
                        tx.block_number = receipt.blockNumber
                        print(f"已从区块链获取block_number: {tx.block_number}")
                        # 更新数据库
                        db.add(tx)
                        db.commit()
                    else:
                        # 如果无法获取，使用查询范围的起始区块
                        tx.block_number = start_block or 0
                        print(f"无法从区块链获取block_number，使用默认值: {tx.block_number}")
                except Exception as e:
                    # 出错时使用默认值
                    tx.block_number = start_block or 0
                    print(f"获取block_number时出错: {str(e)}，使用默认值: {tx.block_number}")
        
        # 新增：收集并去重所有相关合约地址
        all_contracts = set([target_contract.lower()])
        
        # 添加所有相关地址（去重）
        if related_addresses:
            all_contracts.update([addr.lower() for addr in related_addresses if Web3.is_address(addr)])
        
        # 移除零地址、预编译合约等特殊地址
        special_addresses = {
            '0x0000000000000000000000000000000000000000',
            '0x0000000000000000000000000000000000000001',
            '0x0000000000000000000000000000000000000002',
            '0x0000000000000000000000000000000000000003',
            '0x0000000000000000000000000000000000000004',
            '0x0000000000000000000000000000000000000005',
            '0x0000000000000000000000000000000000000006',
            '0x0000000000000000000000000000000000000007',
            '0x0000000000000000000000000000000000000008',
            '0x0000000000000000000000000000000000000009'
        }
        all_contracts = all_contracts - special_addresses
        
        print(f"去重后需要分析的合约数量: {len(all_contracts)}")
        
        # 创建一个专用的ContractAnalyzer实例用于获取合约元数据
        from main import ContractAnalyzer
        analyzer = ContractAnalyzer()
        
        # 收集每个合约的代码
        contracts_code = {}
        for contract_addr in all_contracts:
            try:
                # 1. 先尝试加载已有代码
                contract_code = load_contract_code(db, contract_addr)
                
                if contract_code:
                    contracts_code[contract_addr] = contract_code
                    print(f"已从数据库加载合约 {contract_addr} 的代码")
                else:
                    print(f"未找到合约 {contract_addr} 的代码，尝试获取源码")
                    
                    # 2. 尝试通过API获取合约源码
                    try:
                        # 创建一个ContractPipeline实例
                        from main import ContractPipeline
                        pipeline = ContractPipeline(analyzer)
                        
                        # 通过pipeline获取合约信息（包括源码）
                        contract_info = pipeline.process_with_metadata(contract_addr)
                        
                        # 重新尝试从数据库加载（应该有了）
                        contract_code = load_contract_code(db, contract_addr)
                        if contract_code:
                            contracts_code[contract_addr] = contract_code
                            print(f"已成功加载新获取的合约 {contract_addr} 代码")
                            # 成功获取源码后，继续处理下一个合约
                            continue
                        else:
                            # 如果API获取成功但数据库加载仍然失败，说明有问题
                            print(f"警告：合约 {contract_addr} 源码已获取但加载失败，检查数据库")
                    except Exception as e:
                        print(f"通过API获取合约 {contract_addr} 源码失败: {str(e)}")
                    
                    # 3. 只有在无法获取源码的情况下，才尝试反编译字节码
                    print(f"尝试反编译合约 {contract_addr}")
                    try:
                        # 获取字节码
                        bytecode = analyzer.get_bytecode(contract_addr)
                        
                        if bytecode and len(bytecode) > 2:  # 确保不是空字节码
                            # 反编译
                            from ethereum.decompiler.gigahorse_wrapper import decompile_bytecode
                            decompiled_code = decompile_bytecode(bytecode)
                            
                            if decompiled_code:
                                # 保存反编译结果到数据库
                                from database.crud import update_decompiled_code
                                update_decompiled_code(db, contract_addr, decompiled_code)
                                
                                # 添加到当前分析中
                                contracts_code[contract_addr] = {
                                    'decompiled_code': decompiled_code,
                                    'contract_type': 'decompiled_code'
                                }
                                print(f"成功反编译合约 {contract_addr}")
                            else:
                                print(f"合约 {contract_addr} 反编译失败")
                        else:
                            print(f"合约 {contract_addr} 没有字节码或是EOA账户")
                    except Exception as e:
                        print(f"处理合约 {contract_addr} 字节码和反编译时出错: {str(e)}")
            except Exception as e:
                print(f"加载合约 {contract_addr} 代码时出错: {str(e)}")
        
        print(f"成功加载 {len(contracts_code)} 个合约的代码")
        
        # 生成代码上下文
        code_context = ""
        for addr, code in contracts_code.items():
            context = f"合约 {addr} 的代码:\n"
            if isinstance(code, dict):
                if code.get('source_code'):
                    # 处理可能的格式化问题
                    src_code = code['source_code']
                    if isinstance(src_code, list):
                        src_code = "\n".join(src_code)
                    elif isinstance(src_code, dict):
                        src_code = json.dumps(src_code, indent=2)
                    
                    context += f"源代码：\n{src_code}\n\n"
                elif code.get('decompiled_code'):
                    # 处理可能的格式化问题
                    decompiled = code['decompiled_code']
                    if isinstance(decompiled, dict):
                        decompiled = json.dumps(decompiled, indent=2)
                    
                    context += f"反编译代码：\n{decompiled}\n\n"
            code_context += context + "\n" + "="*50 + "\n"
        
        # 统计方法调用频率
        method_calls = {}
        for tx in transactions:
            method_name = getattr(tx, 'method_name', 'unknown')
            if method_name not in method_calls:
                method_calls[method_name] = 0
            method_calls[method_name] += 1
            
        # 按频率排序
        sorted_methods = sorted(method_calls.items(), key=lambda x: x[1], reverse=True)
        method_list = "\n".join([f"{method}: {count} 次调用" for method, count in sorted_methods])
        
        # 识别目标合约创建的合约
        created_contracts = identify_created_contracts(call_graph, target_contract)
        has_created_contracts = bool(created_contracts)
        
        if has_created_contracts:
            print(f"发现目标合约创建的合约: {len(created_contracts)} 个")
            for idx, contract in enumerate(created_contracts, 1):
                print(f"{idx}. 合约地址: {contract['address']}")
                print(f"   创建交易: {contract['tx_hash']}")
            
            # 确定优先分析的合约地址
            priority_addresses = [contract['address'] for contract in created_contracts]
        else:
            priority_addresses = []
        
        # 分析调用模式
        call_patterns = analyze_call_patterns(call_graph, target_contract)
        
        # 转换调用模式为文本格式
        if isinstance(call_patterns, dict):
            call_patterns_text = json.dumps(call_patterns, indent=2)
        elif isinstance(call_patterns, str):
            call_patterns_text = call_patterns
        else:
            call_patterns_text = "No specific call patterns detected"
        
        # 分析复杂交易
        transactions = get_transactions_for_analysis(db, target_contract)
        complex_transactions = analyze_complex_transactions(transactions, call_graph)
        
        # 提取合约代码，优先处理目标创建的合约
        contracts_info = extract_contract_codes_from_db(
            db, 
            list(related_addresses), 
            priority_addresses
        )
        
        # 生成合约代码上下文
        code_context = generate_code_context(contracts_info)
        
        # 使用两种提示模板 - 基本行为分析和增强的安全分析
        # 1. 基本行为分析
        basic_prompt = BEHAVIOR_PROMPT.format(
            code_context=code_context,
            method_list=method_list,
            target_contract=target_contract,
            block_range=f"{start_block}-{end_block}",
            related_contracts=", ".join(list(all_contracts)[:50]),
            call_patterns=call_patterns_text
        )
        
        # 2. 增强的安全分析，重点关注被创建的合约
        enhanced_prompt = build_enhanced_security_prompt(
            call_graph, 
            target_contract,
            complex_transactions,
            created_contracts
        )
        
        # 将代码上下文添加到增强的安全分析提示中
        enhanced_prompt += f"\n\n## Contract Code Analysis\n\n{code_context}\n"
        
        # 生成基本报告
        basic_report = request_ds(basic_prompt, "")
        
        # 生成增强的安全分析报告
        enhanced_report = request_ds(enhanced_prompt, "")
        
        # 当生成最终报告时，明确告知LLM需要基于具体代码分析
        final_prompt = FINAL_REPORT_PROMPT.format(
            preliminary_analysis=basic_report,
            behavior_analysis=enhanced_report
        )
        
        # 添加代码上下文到最终prompt
        final_prompt += f"\n\n## Available Contract Code\n\n{code_context}\n"
        
        final_report = request_ds(final_prompt, "")
        
        # 保存结果
        filename = f"report_{target_contract or 'all'}.md"
        with open(filename, "w") as f:
            f.write(final_report)
        
        print(f"分析报告已生成：{filename}")
        
        # 构建返回结果
        behavior_data = {
            "target_contract": target_contract,
            "block_range": f"{start_block}-{end_block}",
            "related_contracts": list(all_contracts),
            "code_context": code_context,
            "method_list": method_list,
            "call_patterns": call_patterns,
            "created_contracts": created_contracts if has_created_contracts else [],
            "basic_report": basic_report,
            "enhanced_report": enhanced_report,
            "final_report": final_report
        }
        
        return behavior_data
        
    except Exception as e:
        print(f"处理交易数据时出错: {str(e)}")
        traceback.print_exc()
        return f"在处理您的查询时遇到了错误：{str(e)}"

def analyze_call_patterns(call_graph, target_contract):
    """
    分析调用图中的模式，寻找可能的攻击路径
    """
    patterns = {
        'unusual_paths': [],
        'circular_calls': [],
        'high_value_transfers': [],
        'suspicious_contracts': set()
    }
    
    for tx_hash, data in call_graph.items():
        # 检查是否有循环调用
        circular_paths = find_circular_paths(data['call_hierarchy'])
        if circular_paths:
            patterns['circular_calls'].append({
                'tx_hash': tx_hash,
                'paths': circular_paths
            })
        
        # 检查高价值转账
        high_value_calls = find_high_value_transfers(data['call_hierarchy'])
        if high_value_calls:
            patterns['high_value_transfers'].append({
                'tx_hash': tx_hash,
                'transfers': high_value_calls
            })
        
        # 检查不寻常的调用路径（长度超过3的路径）
        unusual_paths = find_unusual_paths(data['call_hierarchy'], target_contract)
        if unusual_paths:
            patterns['unusual_paths'].append({
                'tx_hash': tx_hash,
                'paths': unusual_paths
            })
            
            # 将不寻常路径中的合约添加到可疑合约集合
            for path in unusual_paths:
                for address in path['addresses']:
                    patterns['suspicious_contracts'].add(address)
    
    # 转换为列表以便JSON序列化
    patterns['suspicious_contracts'] = list(patterns['suspicious_contracts'])
    return patterns

def find_circular_paths(call_hierarchy):
    """
    在调用层级中查找循环调用
    """
    circular_paths = []
    address_path = []
    
    def dfs(node, current_path=None):
        if current_path is None:
            current_path = []
        
        # 当前地址
        addr = node['to'].lower()
        
        # 如果当前地址已经在路径中，发现循环
        if addr in current_path:
            start_idx = current_path.index(addr)
            circular_path = current_path[start_idx:] + [addr]
            circular_paths.append({
                'path': circular_path,
                'description': f"发现循环调用: {' -> '.join(circular_path)}"
            })
            return
        
        # 添加当前地址到路径
        new_path = current_path + [addr]
        
        # 递归处理子调用
        for child in node.get('children', []):
            dfs(child, new_path)
    
    # 从根节点开始DFS
    dfs(call_hierarchy, [call_hierarchy['from'].lower()])
    
    return circular_paths

def find_high_value_transfers(call_hierarchy):
    """
    在调用层级中查找高价值转账
    """
    high_value_transfers = []
    
    def dfs(node):
        # 检查当前调用是否包含高价值转账
        if node.get('value', '0') != '0':
            try:
                value = int(node['value'], 16) if node['value'].startswith('0x') else int(node['value'])
                # 转换为ETH (1 ETH = 10^18 wei)
                eth_value = value / 10**18
                if eth_value > 1.0:  # 超过1 ETH的转账
                    high_value_transfers.append({
                        'from': node['from'],
                        'to': node['to'],
                        'value': eth_value,
                        'description': f"{eth_value} ETH 从 {node['from']} 转移到 {node['to']}"
                    })
            except:
                pass
        
        # 递归处理子调用
        for child in node.get('children', []):
            dfs(child)
    
    # 从根节点开始DFS
    dfs(call_hierarchy)
    
    return high_value_transfers

def find_unusual_paths(call_hierarchy, target_contract):
    """
    在调用层级中查找不寻常的路径
    """
    unusual_paths = []
    
    def dfs(node, current_path=None, depth=0):
        if current_path is None:
            current_path = []
        
        # 当前地址
        addr = node['to'].lower()
        
        # 添加当前地址到路径
        new_path = current_path + [addr]
        
        # 如果路径长度超过3且包含目标合约，认为是不寻常的路径
        if depth >= 3 and target_contract.lower() in new_path:
            unusual_paths.append({
                'addresses': new_path,
                'depth': depth,
                'description': f"深度为{depth}的调用路径: {' -> '.join(new_path)}"
            })
        
        # 递归处理子调用
        for child in node.get('children', []):
            dfs(child, new_path, depth + 1)
    
    # 从根节点开始DFS
    dfs(call_hierarchy, [call_hierarchy['from'].lower()])
    
    return unusual_paths

def analyze_behavior(target_contract=None):
    db = next(get_db())
    
    # 获取用户交互数据
    interactions = get_user_interactions(db)
    
    # 筛选目标合约
    filtered = [
        i for i in interactions 
        if not target_contract or i['target_contract'] == target_contract
    ]
    
    # 统计方法调用频率
    method_counter = Counter([i['method_name'] for i in filtered])
    sorted_methods = method_counter.most_common(10)
    
    # 加载所有相关合约代码
    all_contracts = set(i['target_contract'] for i in filtered)
    contracts_code = {}
    for contract in all_contracts:
        contracts_code[contract] = load_contract_code(db, contract)
    
    # 构建提示词
    method_list_str = "\n".join(
        [f"- {method} (调用次数: {count})" 
         for method, count in sorted_methods]
    )
    
    code_context = "\n\n".join(
        [f"合约 {addr} 的代码链分析：\n{generate_code_context(chain)}" 
         for addr, chain in contracts_code.items()]
    )
    
    # 添加ERC-20标准方法检测
    erc20_methods = {
        'transfer', 'transferFrom', 'approve', 
        'balanceOf', 'allowance', 'totalSupply'
    }
    detected_erc20 = erc20_methods & set(method_counter.keys())
    if detected_erc20:
        code_context += "\n\n检测到标准ERC-20方法：" + ", ".join(detected_erc20)
    
    # 生成报告
    full_prompt = BEHAVIOR_PROMPT.format(
        code_context=code_context,
        method_list=method_list_str
    )
    
    report = request_ds(full_prompt, "")
    
    # 保存结果
    filename = f"report_{target_contract or 'all'}.md"
    with open(filename, "w") as f:
        f.write(report)
    
    print(f"分析报告已生成：{filename}")


def get_transaction_trace(tx_hash, network="ethereum"):
    """
    使用Ankr高级API获取交易的跟踪信息
    
    Args:
        tx_hash (str): 交易哈希
        network (str): 网络名称，默认为"ethereum"
        
    Returns:
        dict: 跟踪结果，如果失败则返回None
    """
    # 确保tx_hash格式正确
    if isinstance(tx_hash, bytes):
        tx_hash = tx_hash.hex()
    elif isinstance(tx_hash, str) and tx_hash.startswith('0x'):
        tx_hash = tx_hash[2:]  # 移除0x前缀，因为Ankr API要求的是没有前缀的交易哈希
    
    try:
        # 构建请求负载 - 注意这里直接使用不带0x前缀的哈希
        payload = {
            "jsonrpc": "2.0",
            "method": "trace_transaction",
            "params": ["0x" + tx_hash],  # 仍然需要添加0x前缀
            "id": 1
        }
        
        # 添加认证头部
        headers = {
            "Content-Type": "application/json"
        }
        
        # 如果有API密钥，添加到请求头
        ankr_api_key = os.getenv('ANKR_API_KEY')
        if ankr_api_key:
            headers["Authorization"] = f"Bearer {ankr_api_key}"
        
        # 获取RPC URL
        network_config = settings.NETWORKS.get(network, settings.NETWORKS["ethereum"])
        rpc_url = network_config.get("rpc_url")
        
        print(f"正在从Ankr获取交易 {tx_hash} 的跟踪信息...")
        
        # 添加重试机制和错误处理
        max_retries = 3
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                # 发送请求
                response = requests.post(
                    rpc_url,
                    headers=headers,
                    json=payload,
                    timeout=30  # 设置30秒超时
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if 'result' in result:
                        print(f"成功获取交易 {tx_hash} 的跟踪信息")
                        trace_data = result['result']
                        print(f"预览trace数据: {str(trace_data)[:200]}...")  # 仅显示前200个字符
                        return trace_data
                    elif 'error' in result:
                        print(f"获取跟踪信息失败: {result['error']}")
                        # 检查是否是格式错误，如果是，可以尝试调整格式后重试
                        if 'invalid argument' in str(result['error'].get('message', '')):
                            # 尝试不同的哈希格式
                            if attempt == 0:
                                print("尝试使用不同的哈希格式...")
                                if payload["params"][0].startswith("0x"):
                                    payload["params"][0] = payload["params"][0][2:]
                                else:
                                    payload["params"][0] = "0x" + payload["params"][0]
                                continue
                        
                        # 如果不是格式错误或者已经尝试过不同格式，使用备用方法
                        return _get_transaction_trace_alternative(tx_hash, network)
                else:
                    print(f"请求失败，状态码: {response.status_code}")
                    print(f"响应内容: {response.text}")
                    if attempt < max_retries - 1:
                        print(f"将在 {retry_delay} 秒后重试...")
                        time.sleep(retry_delay)
                    else:
                        # 最后一次尝试失败，使用备用方法
                        return _get_transaction_trace_alternative(tx_hash, network)
            
            except requests.exceptions.Timeout:
                print(f"请求超时 (尝试 {attempt+1}/{max_retries})")
                if attempt < max_retries - 1:
                    print(f"将在 {retry_delay} 秒后重试...")
                    time.sleep(retry_delay)
                else:
                    # 最后一次尝试也超时，使用备用方法
                    return _get_transaction_trace_alternative(tx_hash, network)
                    
            except Exception as e:
                print(f"获取交易跟踪时出错: {str(e)}")
                traceback.print_exc()
                if attempt < max_retries - 1:
                    print(f"将在 {retry_delay} 秒后重试...")
                    time.sleep(retry_delay)
                else:
                    # 最后一次尝试也失败，使用备用方法
                    return _get_transaction_trace_alternative(tx_hash, network)
        
        # 所有重试都失败
        return None
            
    except Exception as e:
        print(f"获取交易跟踪时出错: {str(e)}")
        traceback.print_exc()
        # 如果出现异常，尝试使用备用方法
        return _get_transaction_trace_alternative(tx_hash, network)

def _get_transaction_trace_alternative(tx_hash, network="ethereum"):
    """
    当trace_transaction API调用失败时的备用方法，使用交易收据获取基本信息
    
    Args:
        tx_hash (str): 交易哈希
        network (str): 网络名称
        
    Returns:
        dict: 简化的trace结构，如果失败则返回None
    """
    print(f"使用备用方法获取交易 {tx_hash} 的信息...")
    
    try:
        # 确保tx_hash格式正确
        if not tx_hash.startswith('0x'):
            tx_hash = '0x' + tx_hash
            
        # 获取Web3实例
        network_config = settings.NETWORKS.get(network, settings.NETWORKS["ethereum"])
        w3 = Web3(Web3.HTTPProvider(network_config.get("rpc_url")))
        
        # 获取交易收据
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        if not receipt:
            print("无法获取交易收据")
            return None
            
        # 获取交易详情
        tx = w3.eth.get_transaction(tx_hash)
        if not tx:
            print("无法获取交易详情")
            return None
            
        # 构建简化的trace结构
        trace = {
            "action": {
                "from": receipt['from'],
                "to": receipt.get('to', '0x0000000000000000000000000000000000000000'),
                "value": str(tx.get('value', 0)),
                "gas": str(tx.get('gas', 0)),
                "input": tx.get('input', '0x')
            },
            "result": {
                "gasUsed": str(receipt.get('gasUsed', 0)),
                "status": "0x1" if receipt.get('status') == 1 else "0x0"
            },
            "subtraces": len(receipt.get('logs', [])),
            "type": "call"
        }
        
        # 如果是合约创建交易
        if not receipt.get('to'):
            trace["type"] = "create"
            trace["result"]["address"] = receipt.get('contractAddress')
            
        # 处理日志作为内部调用
        if receipt.get('logs'):
            calls = []
            for log in receipt.get('logs', []):
                calls.append({
                    "action": {
                        "from": receipt['from'],
                        "to": log['address'],
                        "input": "0x" + log['topics'][0][2:] if log['topics'] else "0x",
                        "gas": "0"
                    },
                    "result": {
                        "gasUsed": "0"
                    },
                    "type": "call"
                })
            trace["calls"] = calls
            
        print(f"成功创建备用trace结构")
        return trace
            
    except Exception as e:
        print(f"备用方法失败: {str(e)}")
        traceback.print_exc()
        return None

def extract_addresses_from_trace(trace_data):
    """从交易追踪数据中提取所有相关合约地址"""
    addresses = set()
    
    print("="*50)
    print("开始处理trace数据")
    
    # 检查trace_data是否为None
    if trace_data is None:
        print("警告: trace_data为None")
        return addresses
    
    # 打印trace_data的结构（用于调试）
    print(f"Trace数据类型: {type(trace_data)}")
    if isinstance(trace_data, list):
        print(f"Trace数据是一个列表，长度: {len(trace_data)}")
        if len(trace_data) > 0:
            print(f"第一个元素类型: {type(trace_data[0])}")
            if isinstance(trace_data[0], dict):
                print(f"第一个元素键: {trace_data[0].keys()}")
    elif isinstance(trace_data, dict):
        print(f"Trace数据键: {trace_data.keys()}")
        # 打印完整的前三层结构
        print("前三层结构预览:")
        try:
            import json
            preview = json.dumps(trace_data, indent=2)[:500]  # 限制输出长度
            print(preview)
        except:
            print("无法序列化trace_data")
    
    # 处理不同格式的trace数据
    try:
        # 处理列表格式的trace数据
        if isinstance(trace_data, list):
            for item in trace_data:
                if isinstance(item, dict):
                    # 处理列表中的每个trace项
                    if 'action' in item:
                        action = item['action']
                        # 提取from地址
                        if 'from' in action and action['from']:
                            try:
                                addr = action['from']
                                if Web3.is_address(addr):
                                    addresses.add(Web3.to_checksum_address(addr).lower())
                                    print(f"从trace列表项提取到from地址: {addr}")
                            except Exception as e:
                                print(f"处理from地址时出错: {str(e)}")
                        
                        # 提取to地址
                        if 'to' in action and action['to']:
                            try:
                                addr = action['to']
                                if Web3.is_address(addr):
                                    addresses.add(Web3.to_checksum_address(addr).lower())
                                    print(f"从trace列表项提取到to地址: {addr}")
                            except Exception as e:
                                print(f"处理to地址时出错: {str(e)}")
        
        # 处理字典格式的trace数据
        elif isinstance(trace_data, dict):
            # 处理action字段
            if 'action' in trace_data:
                action = trace_data['action']
                
                # 提取from地址
                if 'from' in action and action['from']:
                    try:
                        addr = action['from']
                        if Web3.is_address(addr):
                            addresses.add(Web3.to_checksum_address(addr).lower())
                            print(f"从trace提取到from地址: {addr}")
                    except Exception as e:
                        print(f"处理from地址时出错: {str(e)}")
                
                # 提取to地址
                if 'to' in action and action['to']:
                    try:
                        addr = action['to']
                        if Web3.is_address(addr):
                            addresses.add(Web3.to_checksum_address(addr).lower())
                            print(f"从trace提取到to地址: {addr}")
                    except Exception as e:
                        print(f"处理to地址时出错: {str(e)}")
    except Exception as e:
        print(f"处理trace数据时出错: {str(e)}")
        traceback.print_exc()
    
    print(f"从trace中共提取到 {len(addresses)} 个地址")
    print("="*50)
    
    return addresses

def extract_addresses_from_input(input_data):
    """
    从input_data中提取以太坊地址
    
    Args:
        input_data (str): 交易输入数据
        
    Returns:
        set: 提取到的地址集合
    """
    from web3 import Web3
    
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
                    except Exception as e:
                        print(f"转换地址格式时出错: {str(e)}")
    
    return addresses

def get_internal_transactions_from_etherscan(tx_hash, network="ethereum"):
    """
    使用Etherscan API获取内部交易
    
    Args:
        tx_hash (str): 交易哈希
        network (str): 网络名称
        
    Returns:
        list: 内部交易列表
    """
    try:
        network_config = settings.NETWORKS.get(network, settings.NETWORKS["ethereum"])
        etherscan_url = network_config.get("explorer_url")
        etherscan_key = network_config.get("explorer_key")
        
        if not etherscan_key:
            print("缺少Etherscan API密钥")
            return None
            
        # 确保tx_hash格式正确
        if not tx_hash.startswith('0x'):
            tx_hash = '0x' + tx_hash
            
        # 构建API URL
        url = f"{etherscan_url}?module=account&action=txlistinternal&txhash={tx_hash}&apikey={etherscan_key}"
        
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == '1':
                return data.get('result', [])
            else:
                print(f"Etherscan API返回错误: {data.get('message')}")
        else:
            print(f"Etherscan API请求失败，状态码: {response.status_code}")
            
    except Exception as e:
        print(f"获取内部交易失败: {str(e)}")
        
    return None

def is_dex_pool_contract(contract_address, contract_code=None, contract_abi=None):
    """检查合约是否为DEX池子或代币合约"""
    db = next(get_db())
    
    try:
        # 如果没有提供代码或ABI，尝试从数据库获取
        if not contract_code or not contract_abi:
            contract_info = get_contract_full_info(db, contract_address)
            if contract_info:
                contract_code = {
                    'source_code': contract_info.get('source_code'),
                    'decompiled_code': contract_info.get('decompiled_code')
                }
                contract_abi = contract_info.get('abi')
        
        # 简化判断逻辑：如果有源代码或ABI，即为DEX池子或代币合约
        if (contract_code and contract_code.get('source_code')) or contract_abi:
            # 更新合约类型为dex_pool_or_token
            update_contract_type(db, contract_address, "dex_pool_or_token")
            return True
        else:
            # 如果有反编译代码但没有源代码和ABI，标记为potential_hacker
            if contract_code and contract_code.get('decompiled_code'):
                update_contract_type(db, contract_address, "potential_hacker")
            return False
            
    except Exception as e:
        print(f"检查DEX池子合约时出错: {str(e)}")
        return False

def process_trace_recursively(trace, parent_node, related_contracts, call_path, current_depth, max_depth, pruning_enabled=True):
    """递归处理trace数据，支持多种trace格式"""
    if current_depth >= max_depth:
        return
    
    try:
        # 处理单个trace格式
        if isinstance(trace, dict):
            # 新的trace结构 (trace_transaction 格式)
            if 'action' in trace:
                process_single_trace(trace, parent_node, related_contracts, call_path, current_depth, max_depth, pruning_enabled)
            # 旧格式
            elif 'from' in trace and 'to' in trace:
                process_old_format_trace(trace, parent_node, related_contracts, call_path, current_depth, max_depth, pruning_enabled)
        
        # 处理trace列表
        elif isinstance(trace, list):
            for subtrace in trace:
                process_trace_recursively(subtrace, parent_node, related_contracts, call_path, current_depth, max_depth, pruning_enabled)
    
    except Exception as e:
        print(f"递归处理trace时出错：{str(e)}")
        import traceback
        traceback.print_exc()

def process_single_trace(call, parent_node, related_contracts, call_path, current_depth, max_depth, pruning_enabled=True):
    """处理单个trace格式"""
    from web3 import Web3
    
    try:
        # 预判断是否是创建合约的trace
        is_create = call.get('type') == 'create'
        
        # 从action中获取基本信息
        action = call.get('action', {})
        from_address = action.get('from', '').lower() if action.get('from') else ''
        
        # 对于创建合约，to地址存在于result.address中
        if is_create and call.get('result', {}).get('address'):
            to_address = call['result']['address'].lower()
        else:
            to_address = action.get('to', '').lower() if action.get('to') else ''
            
        input_data = action.get('input', '0x')
        call_type = "create" if is_create else action.get('callType', action.get('type', 'call'))
        value = action.get('value', '0x0')
        
        # 检查地址是否有效
        has_from = bool(from_address and Web3.is_address(from_address))
        has_to = bool(to_address and Web3.is_address(to_address))
        
        # 调试信息
        method_id = "create" if is_create else "0x"
        if not is_create and input_data and len(input_data) >= 10:
            method_id = input_data[:10]
        
        print(f"处理trace: from={from_address}({has_from}), to={to_address}({has_to}), type={call_type}, method_id={method_id}")
        
        if has_from or has_to:
            # 将有效地址添加到相关合约集合
            if has_from:
                related_contracts.add(from_address)
            if has_to:
                related_contracts.add(to_address)
            
            # 创建调用节点
            call_node = {
                'from': from_address if has_from else "unknown",
                'to': to_address if has_to else "unknown",
                'method_id': method_id,
                'call_type': call_type,
                'value': value,
                'children': []
            }
            
            # 添加到父节点
            parent_node['children'].append(call_node)
            
            # 构建新调用路径
            new_call_path = call_path
            if has_to:
                new_call_path = call_path + [to_address]
            
            # 递归处理子trace
            if 'subtraces' in call and call['subtraces'] > 0:
                # 检查是否可以继续处理更深的调用
                if current_depth < max_depth:
                    if 'calls' in call and isinstance(call['calls'], list):
                        for subcall in call['calls']:
                            process_trace_recursively(
                                subcall, 
                                call_node,
                                related_contracts, 
                                new_call_path,
                                current_depth + 1, 
                                max_depth,
                                pruning_enabled
                            )
                else:
                    print(f"达到最大深度 {max_depth}，停止处理子调用")
    except Exception as e:
        print(f"处理trace时出错: {str(e)}")
        import traceback
        traceback.print_exc()

def process_old_format_trace(trace, parent_node, related_contracts, call_path, current_depth, max_depth, pruning_enabled=True):
    """处理旧格式的trace调用"""
    from web3 import Web3
    
    try:
        from_address = trace.get('from', '').lower() if trace.get('from') else ''
        to_address = trace.get('to', '').lower() if trace.get('to') else ''
        
        # 检查地址是否有效
        has_from = bool(from_address and Web3.is_address(from_address))
        has_to = bool(to_address and Web3.is_address(to_address))
        
        print(f"处理旧格式trace: from={from_address}({has_from}), to={to_address}({has_to})")
        
        if has_from or has_to:
            # 将有效地址添加到相关合约集合
            if has_from:
                related_contracts.add(from_address)
            if has_to:
                related_contracts.add(to_address)
            
            # 创建新的调用节点
            call_node = {
                'from': from_address if has_from else "unknown",
                'to': to_address if has_to else "unknown",
                'method_id': trace.get('method_id', '0x'),
                'call_type': trace.get('type', 'call'),
                'value': trace.get('value', '0x0'),
                'children': []
            }
            
            # 将调用节点添加到父节点的children列表
            parent_node['children'].append(call_node)
            
            # 构建新的调用路径
            new_call_path = call_path
            if has_to:
                new_call_path = call_path + [to_address]
            
            # 递归处理子trace
            if 'children' in trace and isinstance(trace['children'], list):
                for child in trace['children']:
                    process_trace_recursively(
                        child,
                        call_node,
                        related_contracts,
                        new_call_path,
                        current_depth + 1,
                        max_depth,
                        pruning_enabled
                    )
        else:
            print(f"跳过无效地址的旧格式trace")
    
    except Exception as e:
        print(f"处理旧格式trace时出错: {str(e)}")
        import traceback
        traceback.print_exc()

def build_transaction_call_graph(target_contract, start_block, end_block, max_depth=3, pruning_enabled=True):
    """构建交易调用图"""
    db = next(get_db())
    w3 = Web3(Web3.HTTPProvider(settings.NETWORKS["ethereum"]["rpc_url"]))
    
    target_contract_lower = target_contract.lower()
    call_graph = {}
    processed_txs = set()  # 初始化已处理交易集合
    
    try:
        from sqlalchemy import and_, or_
        
        # 更新查询条件，查找所有可能与目标合约相关的交易
        interactions = db.query(UserInteraction).filter(
            and_(
                or_(
                    UserInteraction.target_contract == target_contract_lower,
                    UserInteraction.caller_contract == target_contract_lower,
                    # 包括method_name为'create'的交易(合约创建)
                    and_(
                        UserInteraction.method_name == 'create',
                        UserInteraction.caller_contract == target_contract_lower
                    )
                ),
                UserInteraction.block_number >= start_block,
                UserInteraction.block_number <= end_block
            )
        ).all()
        
        # 输出诊断信息
        print(f"找到 {len(interactions)} 笔与目标合约相关的交易")
        for idx, tx in enumerate(interactions, 1):
            print(f"交易 {idx}: {tx.tx_hash}")
            print(f"    Block: {tx.block_number}")
            print(f"    From: {tx.caller_contract}")
            print(f"    To: {tx.target_contract}")
            print(f"    Method: {tx.method_name}")
        
        # 收集所有交易中已提取的地址
        all_related_addresses = set()
        
        for interaction in interactions:
            tx_hash = interaction.tx_hash
            
            # 跳过已处理的交易
            if tx_hash in processed_txs:
                continue
            
            processed_txs.add(tx_hash)
            print(f"处理交易：{tx_hash}")
            
            # 初始化这个交易的调用图
            call_graph[tx_hash] = {
                'call_hierarchy': {},
                'related_contracts': set()
            }
            
            # 获取交易trace
            if interaction.trace_data:
                try:
                    trace_json = json.loads(interaction.trace_data)
                    print(f"成功加载trace数据：{type(trace_json)}")
                    
                    # 构建初始调用节点
                    root_node = {
                        'from': interaction.caller_contract,
                        'to': interaction.target_contract,
                        'method': interaction.method_name,
                        'method_id': interaction.input_data[:10] if interaction.input_data else "0x",
                        'input': interaction.input_data,
                        'children': []
                    }
                    
                    call_graph[tx_hash]['call_hierarchy'] = root_node
                    
                    # 从数据库中获取已提取的地址，而不是重新处理trace
                    # 假设我们已经在main.py中提取了地址并保存在某处
                    # 这里我们可以查询其他表或者解析日志来获取
                    
                    # 处理trace以构建调用层次结构，但不用于提取地址
                    # 这样可以避免频繁查询数据库来检查DEX池子
                    call_path = [interaction.target_contract]
                    process_trace_without_db_checks(
                        trace_json, 
                        root_node, 
                        call_graph[tx_hash]['related_contracts'],
                        call_path,
                        0,
                        max_depth,
                        pruning_enabled=False  # 禁用需要数据库查询的剪枝
                    )
                    
                    # 更新全局相关地址集合
                    all_related_addresses.update(call_graph[tx_hash]['related_contracts'])
                    
                except Exception as e:
                    print(f"处理交易trace时出错：{str(e)}")
                    traceback.print_exc()
            else:
                print(f"交易 {tx_hash} 没有trace数据")
        
        print(f"交易调用图构建完成，共包含 {len(call_graph)} 笔交易，涉及 {len(all_related_addresses)} 个相关合约")
        return call_graph
        
    except Exception as e:
        print(f"构建交易调用图时出错：{str(e)}")
        traceback.print_exc()
        return {}

def process_trace_without_db_checks(trace, parent_node, related_contracts, call_path, current_depth, max_depth, pruning_enabled=False):
    """处理trace数据以构建调用层次结构，避免数据库查询"""
    if current_depth >= max_depth:
        return
    
    try:
        # 处理单个trace格式
        if isinstance(trace, dict):
            # 新的trace结构 (trace_transaction 格式)
            if 'action' in trace:
                process_trace_action_without_db(trace, parent_node, related_contracts, call_path, current_depth, max_depth)
            # 旧格式
            elif 'from' in trace and 'to' in trace:
                process_trace_old_format_without_db(trace, parent_node, related_contracts, call_path, current_depth, max_depth)
        
        # 处理trace列表
        elif isinstance(trace, list):
            for subtrace in trace:
                process_trace_without_db_checks(subtrace, parent_node, related_contracts, call_path, current_depth, max_depth)
    
    except Exception as e:
        print(f"递归处理trace时出错：{str(e)}")
        import traceback
        traceback.print_exc()

def process_trace_action_without_db(call, parent_node, related_contracts, call_path, current_depth, max_depth):
    """处理action格式的trace，避免数据库查询"""
    from web3 import Web3
    
    try:
        action = call['action']
        from_address = action.get('from', '').lower() if action.get('from') else ''
        to_address = action.get('to', '').lower() if action.get('to') else ''
        input_data = action.get('input', '0x')
        call_type = action.get('callType', 'call')
        value = action.get('value', '0x0')
        
        # 检查地址是否有效
        has_from = bool(from_address and Web3.is_address(from_address))
        has_to = bool(to_address and Web3.is_address(to_address))
        
        print(f"处理trace: from={from_address}({has_from}), to={to_address}({has_to}), type={call_type}")
        
        if has_from or has_to:
            # 将有效地址添加到相关合约集合
            if has_from:
                related_contracts.add(from_address)
            if has_to:
                related_contracts.add(to_address)
            
            # 尝试提取方法ID
            method_id = "0x"
            if input_data and len(input_data) >= 10:
                method_id = input_data[:10]
            
            # 创建调用节点
            call_node = {
                'from': from_address if has_from else "unknown",
                'to': to_address if has_to else "unknown",
                'method_id': method_id,
                'call_type': call_type,
                'value': value,
                'children': []
            }
            
            # 添加到父节点
            parent_node['children'].append(call_node)
            
            # 构建新调用路径
            new_call_path = call_path
            if has_to:
                new_call_path = call_path + [to_address]
            
            # 递归处理子trace
            if 'subtraces' in call and call['subtraces'] > 0:
                if 'calls' in call and isinstance(call['calls'], list):
                    for subcall in call['calls']:
                        process_trace_without_db_checks(
                            subcall, 
                            call_node,
                            related_contracts, 
                            new_call_path,
                            current_depth + 1, 
                            max_depth
                        )
    except Exception as e:
        print(f"处理trace action时出错: {str(e)}")
        import traceback
        traceback.print_exc()

def process_trace_old_format_without_db(trace, parent_node, related_contracts, call_path, current_depth, max_depth):
    """处理旧格式的trace，避免数据库查询"""
    from web3 import Web3
    
    try:
        from_address = trace.get('from', '').lower() if trace.get('from') else ''
        to_address = trace.get('to', '').lower() if trace.get('to') else ''
        
        # 检查地址是否有效
        has_from = bool(from_address and Web3.is_address(from_address))
        has_to = bool(to_address and Web3.is_address(to_address))
        
        if has_from or has_to:
            # 将有效地址添加到相关合约集合
            if has_from:
                related_contracts.add(from_address)
            if has_to:
                related_contracts.add(to_address)
            
            # 创建调用节点
            call_node = {
                'from': from_address if has_from else "unknown",
                'to': to_address if has_to else "unknown",
                'method_id': trace.get('method_id', '0x'),
                'call_type': trace.get('type', 'call'),
                'value': trace.get('value', '0x0'),
                'children': []
            }
            
            # 添加到父节点
            parent_node['children'].append(call_node)
            
            # 构建新调用路径
            new_call_path = call_path
            if has_to:
                new_call_path = call_path + [to_address]
            
            # 递归处理子trace
            if 'children' in trace and isinstance(trace['children'], list):
                for child in trace['children']:
                    process_trace_without_db_checks(
                        child,
                        call_node,
                        related_contracts,
                        new_call_path,
                        current_depth + 1,
                        max_depth
                    )
    except Exception as e:
        print(f"处理旧格式trace时出错: {str(e)}")
        import traceback
        traceback.print_exc()

def extract_kg_triples_from_call_graph(call_graph):
    """从调用图中提取知识图谱三元组
    
    Args:
        call_graph (dict): 交易调用图
        
    Returns:
        list: 三元组列表，每个三元组形式为(caller, relation, callee)
    """
    triples = []
    
    def process_node(node, tx_hash):
        """递归处理调用节点，提取三元组"""
        if not isinstance(node, dict):
            return
            
        caller = node.get('from', 'unknown')
        callee = node.get('to', 'unknown')
        method = node.get('method', node.get('method_id', 'unknown'))
        call_type = node.get('call_type', 'call')
        value = node.get('value', '0x0')
        
        # 构建关系描述
        relation = call_type
        if method and method != 'unknown':
            relation = f"{call_type}_{method}"
            
        # 如果有价值转移，在关系中体现
        if value and value != '0x0' and value != '0':
            try:
                # 尝试将value转换为ETH
                value_int = int(value, 16) if value.startswith('0x') else int(value)
                eth_value = value_int / 10**18
                if eth_value > 0:
                    relation = f"{relation}_value_{eth_value:.4f}ETH"
            except:
                pass
        
        # 添加三元组，包含交易哈希作为上下文
        triple = {
            'caller': caller,
            'relation': relation,
            'callee': callee,
            'tx_hash': tx_hash,
            'context': f"({caller}) --{relation}--> ({callee}) [tx:{tx_hash}]"
        }
        triples.append(triple)
        
        # 递归处理子节点
        for child in node.get('children', []):
            process_node(child, tx_hash)
    
    # 遍历调用图中的每个交易
    for tx_hash, data in call_graph.items():
        if 'call_hierarchy' in data and isinstance(data['call_hierarchy'], dict):
            process_node(data['call_hierarchy'], tx_hash)
    
    return triples

def extract_neighbor_relations(triples, topic_entity):
    """提取与主题实体直接相关的关系
    
    Args:
        triples (list): 三元组列表
        topic_entity (str): 主题实体地址
        
    Returns:
        list: 相邻关系列表
    """
    # 标准化地址格式
    topic_entity = topic_entity.lower()
    
    # 收集与主题实体相关的关系
    neighbor_relations = []
    
    for triple in triples:
        caller = triple['caller'].lower()
        callee = triple['callee'].lower()
        
        # 主题实体作为调用者
        if caller == topic_entity:
            neighbor_relations.append({
                'direction': 'outgoing',
                'relation': triple['relation'],
                'entity': callee,
                'context': triple['context'],
                'tx_hash': triple['tx_hash']
            })
        
        # 主题实体作为被调用者
        if callee == topic_entity:
            neighbor_relations.append({
                'direction': 'incoming',
                'relation': triple['relation'],
                'entity': caller,
                'context': triple['context'],
                'tx_hash': triple['tx_hash']
            })
    
    return neighbor_relations

def extract_call_path_triples(triples, entity, max_depth=2):
    """提取围绕实体的多跳调用路径
    
    Args:
        triples (list): 三元组列表
        entity (str): 实体地址
        max_depth (int): 最大跳数
        
    Returns:
        list: 调用路径列表
    """
    entity = entity.lower()
    
    # 构建图结构
    graph = {}
    for triple in triples:
        caller = triple['caller'].lower()
        callee = triple['callee'].lower()
        
        if caller not in graph:
            graph[caller] = []
        graph[caller].append({
            'target': callee,
            'relation': triple['relation'],
            'context': triple['context'],
            'tx_hash': triple['tx_hash']
        })
    
    # 使用BFS寻找路径
    call_paths = []
    visited = set()
    queue = [(entity, [], 0)]  # (节点, 路径, 深度)
    
    while queue:
        node, path, depth = queue.pop(0)
        
        # 如果达到最大深度，继续下一个节点
        if depth >= max_depth:
            continue
        
        # 查找节点的邻居
        neighbors = graph.get(node, [])
        for neighbor in neighbors:
            next_node = neighbor['target']
            new_path = path + [neighbor]
            
            # 避免循环
            path_key = f"{node}_{next_node}"
            if path_key in visited:
                continue
            visited.add(path_key)
            
            # 将路径添加到结果中
            if path:  # 只添加非空路径
                call_paths.append(new_path)
            
            # 添加到队列继续搜索
            queue.append((next_node, new_path, depth + 1))
    
    return call_paths

def build_kg_prompt(call_graph, topic_entity):
    """构建基于知识图谱的LLM提示
    
    Args:
        call_graph (dict): 交易调用图
        topic_entity (str): 主题实体地址
        
    Returns:
        str: 构造的提示词
    """
    # 提取知识图谱三元组
    triples = extract_kg_triples_from_call_graph(call_graph)
    
    # 1. 提取与主题实体直接相关的关系
    neighbor_relations = extract_neighbor_relations(triples, topic_entity)
    
    # 分类为入向和出向关系
    incoming_relations = [rel for rel in neighbor_relations if rel['direction'] == 'incoming']
    outgoing_relations = [rel for rel in neighbor_relations if rel['direction'] == 'outgoing']
    
    # 构建关系描述字符串
    incoming_str = "入向调用路径:\n" + "\n".join([
        f"- {rel['entity']} --{rel['relation']}--> {topic_entity} [tx:{rel['tx_hash']}]" 
        for rel in incoming_relations[:10]  # 限制显示数量
    ]) if incoming_relations else "入向调用路径: 无"
    
    outgoing_str = "出向调用路径:\n" + "\n".join([
        f"- {topic_entity} --{rel['relation']}--> {rel['entity']} [tx:{rel['tx_hash']}]" 
        for rel in outgoing_relations[:10]  # 限制显示数量
    ]) if outgoing_relations else "出向调用路径: 无"
    
    # 2. 提取多跳调用路径
    call_paths = extract_call_path_triples(triples, topic_entity, max_depth=2)
    
    # 按交易哈希分组路径，选取最有代表性的路径
    tx_paths = {}
    for path in call_paths:
        if not path:
            continue
        tx_hash = path[0]['tx_hash']
        if tx_hash not in tx_paths or len(path) > len(tx_paths[tx_hash]):
            tx_paths[tx_hash] = path
    
    # 构建调用链描述
    call_chains_str = "代表性调用链:\n"
    for i, (tx_hash, path) in enumerate(list(tx_paths.items())[:5]):  # 限制显示数量
        chain_str = f"{i+1}. 交易 {tx_hash} 的调用链:\n"
        for hop in path:
            chain_str += f"   - {hop['context']}\n"
        call_chains_str += chain_str + "\n"
    
    if not tx_paths:
        call_chains_str += "无代表性调用链\n"
    
    # 3. 构建最终提示词
    final_prompt = f"""
## 基于知识图谱的合约调用分析

当前分析目标: {topic_entity}

### 直接调用关系
{incoming_str}

{outgoing_str}

### 调用链分析
{call_chains_str}

请根据上述合约调用图谱信息分析:
1. 该合约在调用链中扮演的角色（调用发起者、中间合约、终点合约）
2. 最重要的3条调用路径及其功能意义
3. 是否存在异常调用模式，如循环调用、可疑的价值转移等
4. 结合代码特征，该合约是否可能参与安全事件，及可能的攻击向量

输出格式:
- 角色分析: [分析结果]
- 关键路径: [路径1, 路径2, 路径3]
- 异常模式: [有/无，若有请详述]
- 安全评估: [低/中/高风险，原因]
"""
    
    return final_prompt

def enhance_behavior_analysis_with_kg(behavior_data, call_graph, target_contract):
    """用知识图谱分析增强行为分析报告
    
    Args:
        behavior_data (dict): 原始行为分析数据
        call_graph (dict): 交易调用图
        target_contract (str): 目标合约地址
        
    Returns:
        dict: 增强后的行为分析数据
    """
    if not call_graph:
        return behavior_data
    
    # 生成知识图谱分析
    kg_prompt = build_kg_prompt(call_graph, target_contract)
    
    # 请求LLM生成知识图谱分析结果
    try:
        kg_analysis = request_ds(kg_prompt, "")
        
        # 将知识图谱分析结果添加到行为分析数据中
        behavior_data['knowledge_graph_analysis'] = {
            'prompt': kg_prompt,
            'analysis': kg_analysis
        }
    except Exception as e:
        print(f"生成知识图谱分析时出错: {str(e)}")
        behavior_data['knowledge_graph_analysis'] = {
            'error': str(e)
        }
    
    return behavior_data

def build_attack_chain_analysis(call_graph, target_contract):
    """
    构建攻击链分析，使用知识图谱帮助LLM理解可能的攻击路径
    
    Args:
        call_graph (dict): 交易调用图
        target_contract (str): 目标合约地址
        
    Returns:
        dict: 攻击链分析结果
    """
    # 1. 提取关键函数调用关系
    suspicious_functions = [
        "transfer", "transferFrom", "approve", "swap", 
        "borrow", "liquidate", "flash", "execute", "delegatecall",
        "selfdestruct", "call", "withdraw"
    ]
    
    # 2. 构建调用关系图
    call_relations = []
    attack_paths = []
    
    for tx_hash, data in call_graph.items():
        if 'call_hierarchy' not in data:
            continue
            
        # 分析单个交易中的调用路径
        paths = []
        
        def traverse_hierarchy(node, current_path=None):
            if current_path is None:
                current_path = []
                
            # 记录当前节点信息
            method = node.get('method', node.get('method_id', '0x'))
            call_type = node.get('call_type', 'call')
            from_addr = node.get('from', 'unknown')
            to_addr = node.get('to', 'unknown')
            value = node.get('value', '0x0')
            
            # 构建节点描述
            node_info = {
                'from': from_addr,
                'to': to_addr,
                'method': method,
                'call_type': call_type,
                'value': value
            }
            
            # 添加到当前路径
            new_path = current_path + [node_info]
            
            # 检查是否有可疑函数调用
            is_suspicious = False
            if any(sus in str(method).lower() for sus in suspicious_functions):
                is_suspicious = True
                
            # 检查是否有价值转移
            has_value = False
            if value and value != '0x0':
                try:
                    value_int = int(value, 16) if value.startswith('0x') else int(value)
                    if value_int > 0:
                        has_value = True
                except:
                    pass
            
            # 如果是可疑调用或有价值转移，记录路径
            if is_suspicious or has_value or call_type == 'delegatecall':
                paths.append({
                    'path': new_path,
                    'suspicious': is_suspicious,
                    'has_value': has_value,
                    'special_call': call_type if call_type != 'call' else None
                })
            
            # 递归处理子节点
            for child in node.get('children', []):
                traverse_hierarchy(child, new_path)
        
        # 从根节点开始分析
        traverse_hierarchy(data['call_hierarchy'])
        
        # 如果找到可疑路径，添加到结果中
        if paths:
            attack_paths.append({
                'tx_hash': tx_hash,
                'paths': paths
            })
    
    # 3. 生成更有针对性的攻击链分析
    formatted_paths = []
    
    for tx_entry in attack_paths:
        tx_hash = tx_entry['tx_hash']
        
        for path_info in tx_entry['paths']:
            path = path_info['path']
            path_str = " -> ".join([
                f"{p['from']}:{p['method']}:{p['to']}" 
                for p in path
            ])
            
            # 标记路径特征
            features = []
            if path_info['suspicious']:
                features.append("可疑函数调用")
            if path_info['has_value']:
                features.append("ETH转移")
            if path_info['special_call']:
                features.append(f"{path_info['special_call']}调用")
            
            formatted_paths.append({
                'tx_hash': tx_hash,
                'path': path_str,
                'features': features,
                'raw_path': path
            })
    
    # 4. 针对每条可疑路径生成分析
    attack_chain_analysis = {
        'target_contract': target_contract,
        'potential_attack_paths': formatted_paths,
        'summary': {}
    }
    
    # 5. 统计特征出现频率，识别最可能的攻击模式
    pattern_counter = {}
    
    for path in formatted_paths:
        # 生成模式特征字符串
        pattern = "|".join(sorted(path['features']))
        if pattern not in pattern_counter:
            pattern_counter[pattern] = 0
        pattern_counter[pattern] += 1
    
    # 对模式按频率排序
    sorted_patterns = sorted(pattern_counter.items(), key=lambda x: x[1], reverse=True)
    attack_chain_analysis['summary']['patterns'] = [
        {'pattern': pattern, 'count': count} for pattern, count in sorted_patterns
    ]
    
    return attack_chain_analysis

def generate_attack_chain_prompt(attack_analysis, contracts_code):
    """
    根据攻击链分析生成针对性的提示，引导LLM分析攻击链
    
    Args:
        attack_analysis (dict): 攻击链分析结果
        contracts_code (dict): 合约代码信息
        
    Returns:
        str: 生成的提示
    """
    # 获取可能的攻击路径
    paths = attack_analysis['potential_attack_paths']
    
    # 选择最具代表性的路径(最多5条)
    representative_paths = sorted(
        paths, 
        key=lambda x: len(x['features']), 
        reverse=True
    )[:5]
    
    # 构建提示
    prompt = f"""
## 攻击链分析

对目标合约 {attack_analysis['target_contract']} 进行深入攻击链分析，基于以下发现的可疑调用路径：

"""
    
    # 添加可疑路径信息
    for i, path in enumerate(representative_paths):
        prompt += f"""
### 可疑路径 {i+1}
- 交易: {path['tx_hash']}
- 特征: {', '.join(path['features'])}
- 调用链: {path['path']}
"""
    
    # 添加具体合约代码分析指导
    prompt += """
## 攻击链分析指南

请基于以上调用路径和相关合约代码，分析以下几点：

1. 调用路径中是否存在漏洞利用的特征（如重入、访问控制缺失、价值转移异常等）
2. 结合每个合约的代码实现，分析调用序列如何形成完整攻击链
3. 针对每个关键调用点，说明其在攻击过程中的作用
4. 识别出主要攻击者地址和受害合约
5. 提供完整的攻击链重建，从攻击入口到最终获利

注意分析中需要结合合约代码中的具体实现，而不仅是基于函数名称进行猜测。
"""
    
    return prompt

def enhance_behavior_analysis_with_attack_chain(behavior_data, call_graph, target_contract):
    """集成攻击链分析到行为分析中
    
    Args:
        behavior_data (dict): 行为分析数据
        call_graph (dict): 交易调用图
        target_contract (str): 目标合约地址
        
    Returns:
        dict: 增强后的行为分析数据
    """
    if not call_graph:
        return behavior_data
    
    # 1. 构建攻击链分析
    attack_analysis = build_attack_chain_analysis(call_graph, target_contract)
    
    # 2. 如果找到潜在攻击路径，生成针对性提示
    if attack_analysis['potential_attack_paths']:
        contracts_code = {}  # 此处假设已有合约代码信息
        # 实际实现中需要从behavior_data中提取合约代码信息
        if 'code_context' in behavior_data:
            contracts_code = behavior_data['code_context']
        
        attack_chain_prompt = generate_attack_chain_prompt(attack_analysis, contracts_code)
        
        # 3. 请求LLM生成攻击链分析
        try:
            attack_chain_result = request_ds(attack_chain_prompt, "")
            
            # 4. 将攻击链分析结果添加到行为分析数据中
            behavior_data['attack_chain_analysis'] = {
                'raw_data': attack_analysis,
                'prompt': attack_chain_prompt,
                'analysis': attack_chain_result
            }
        except Exception as e:
            print(f"生成攻击链分析时出错: {str(e)}")
            behavior_data['attack_chain_analysis'] = {
                'error': str(e)
            }
    else:
        behavior_data['attack_chain_analysis'] = {
            'no_suspicious_paths': True,
            'message': "未发现可疑的攻击路径"
        }
    
    return behavior_data

def extract_contract_codes_from_db(db, contract_addresses, priority_addresses=None):
    """增强版合约代码提取，支持优先级合约"""
    if priority_addresses is None:
        priority_addresses = []
    
    # 确保优先地址格式统一
    priority_addresses = [addr.lower() for addr in priority_addresses if addr]
    
    # 将优先地址添加到合约地址列表开头
    for addr in reversed(priority_addresses):
        if addr in contract_addresses:
            contract_addresses.remove(addr)
        contract_addresses.insert(0, addr)
    
    contracts_info = []
    for address in contract_addresses:
        contract = get_contract_full_info(db, address)
        if contract:
            # 标记该合约是否为优先分析对象
            is_priority = address.lower() in [addr.lower() for addr in priority_addresses]
            
            # 添加合约类型标签
            contract_type = "未知"
            if contract.get('is_proxy'):
                contract_type = "代理合约"
            elif address.lower() == contract_addresses[0].lower():
                contract_type = "目标合约"
            elif is_priority:
                contract_type = "目标创建的合约" if address in priority_addresses else "关键合约"
            
            # 确保合约有类型字段
            contract['type'] = contract.get('type', contract_type)
            if is_priority:
                contract['is_priority'] = True
            
            contracts_info.append(contract)
    
    return contracts_info

def build_enhanced_security_prompt(call_graph, target_contract, complex_txs=None, created_contracts=None):
    """构建增强的安全分析提示，聚焦攻击链分析"""
    from web3 import Web3
    
    # 获取相关交易及调用统计
    tx_count = len(call_graph) if call_graph else 0
    
    # 获取所有相关合约
    all_contracts = set()
    for tx_hash, data in call_graph.items():
        all_contracts.update(data.get('related_contracts', []))
    
    # 获取方法调用统计
    method_counts = {}
    value_transfers = []
    circular_paths = []
    
    # 分析每个交易的调用图
    for tx_hash, data in call_graph.items():
        # 统计方法调用
        def count_methods(node):
            method_id = node.get('method_id', node.get('method', 'unknown'))
            if method_id not in method_counts:
                method_counts[method_id] = 0
            method_counts[method_id] += 1
            
            # 检查是否是价值转移
            if node.get('value') and node.get('value') != '0x0' and node.get('value') != '0':
                try:
                    value_wei = int(node['value'], 16) if isinstance(node['value'], str) and node['value'].startswith('0x') else int(node['value'])
                    if value_wei > 0:
                        value_eth = value_wei / 10**18
                        if value_eth > 0.01:  # 只记录大于0.01 ETH的转账
                            value_transfers.append({
                                'from': node['from'],
                                'to': node['to'],
                                'value_eth': value_eth,
                                'tx_hash': tx_hash
                            })
                except Exception as e:
                    print(f"解析转账金额时出错: {str(e)}")
            
            # 递归处理子调用
            for child in node.get('children', []):
                count_methods(child)
        
        # 处理调用图根节点
        count_methods(data['call_hierarchy'])
        
        # 查找循环调用路径
        paths = find_circular_paths(data['call_hierarchy'])
        if paths:
            for path in paths:
                circular_paths.append({
                    'tx_hash': tx_hash,
                    'path': path
                })
    
    # 排序方法调用
    sorted_methods = sorted(method_counts.items(), key=lambda x: x[1], reverse=True)
    method_statistics = "\n".join([f"{method}: {count} calls" for method, count in sorted_methods[:20]])
    
    # 格式化资金流向
    value_transfers.sort(key=lambda x: x['value_eth'], reverse=True)
    value_transfers_text = ""
    for idx, transfer in enumerate(value_transfers[:10], 1):
        value_transfers_text += f"{idx}. {transfer['value_eth']:.6f} ETH from {transfer['from']} to {transfer['to']}\n"
        value_transfers_text += f"   Transaction: {transfer['tx_hash']}\n\n"
    
    # 循环路径文本
    circular_paths_text = ""
    if circular_paths:
        circular_paths_text = "## Circular Call Patterns\n\n"
        for idx, path_info in enumerate(circular_paths[:5], 1):
            path_str = " -> ".join(path_info['path'])
            circular_paths_text += f"{idx}. Path: {path_str}\n"
            circular_paths_text += f"   Transaction: {path_info['tx_hash']}\n\n"
    
    # 创建的合约信息
    created_contracts_section = ""
    if created_contracts and len(created_contracts) > 0:
        created_contracts_section = """
## Target Created Contracts (CRITICAL FOCUS)

The following contracts were created by the target contract and are central to understanding the attack:
"""
        for idx, contract in enumerate(created_contracts, 1):
            created_contracts_section += f"\n{idx}. Contract Address: `{contract['address']}`"
            created_contracts_section += f"\n   Creation Transaction: `{contract['tx_hash']}`"
    
    # 复杂交易信息
    complex_txs_section = ""
    if complex_txs and len(complex_txs) > 0:
        complex_txs_section = "\n## Complex Transactions Analysis\n\n"
        for idx, tx in enumerate(complex_txs[:5], 1): # 只显示前5个最复杂的交易
            complex_txs_section += f"{idx}. Transaction Hash: `{tx['tx_hash']}`\n"
            complex_txs_section += f"   Call Depth: {tx['depth']}, Contracts Involved: {tx['contract_count']}\n\n"
    
    # 构建提示模板
    prompt = f"""
# Definitive Blockchain Security Analysis

## Primary Objective
Perform a code-centric security analysis of contract `{target_contract}` and its interactions. Your analysis must be based exclusively on provided contract code and transaction data.

{created_contracts_section}

## Focus Areas for Analysis

1. **CODE-SPECIFIC VULNERABILITY IDENTIFICATION**:
   - Examine the victim contract's code line-by-line to identify the EXACT vulnerable function(s)
   - Quote the specific vulnerable code segments and explain precisely how they enabled the attack
   - Identify pattern-matching for known vulnerabilities (e.g., reentrancy, flash loan attacks, price manipulation)

2. **TRANSACTION-BACKED ATTACK FLOW**:
   - Map each step in the attack chain to specific function calls and transactions
   - Explain which specific contract functions were called, in what order, and with what parameters
   - Directly reference transaction hashes when describing attack flow

3. **TECHNICAL EXPLOITATION DETAILS**:
   - Explain the exact technical mechanism of exploitation
   - Identify which specific lines of code in the attacker contract were used to exploit the vulnerability
   - Detail the exact sequence of state changes that occurred during the attack

## Transaction Data

### Method Call Statistics
{method_statistics}

### Value Transfers
{value_transfers_text}

{circular_paths_text}
{complex_txs_section}

## Mandatory Output Format

Your analysis MUST include:

1. **Exact Vulnerable Function(s)**: Name and quote the specific function(s) in the victim contract that contain the vulnerability.

2. **Precise Attack Sequence**: Document each step in the attack with reference to specific function calls and transactions.

3. **Definitive Root Cause**: Provide the exact code issue that enabled the attack, with line references.

4. **Code-Based Evidence**: Support all assertions with direct references to the contract code or transaction data.

IMPORTANT: Do NOT use speculative language (e.g., "could be", "might have", "possibly"). If information cannot be definitively determined from the code or transaction data, clearly state this rather than speculating.
"""
    
    return prompt

def update_behavior_analysis_with_code(behavior_data, call_graph, target_contract):
    """增强行为分析，重点分析目标合约创建的合约"""
    try:
        # 获取数据库连接
        db = next(get_db())
        
        # 先识别目标合约创建的合约
        created_contracts = identify_created_contracts(call_graph, target_contract)
        
        # 如果找到了创建的合约，添加到behavior_data
        if created_contracts:
            behavior_data['created_contracts'] = created_contracts
            print(f"发现 {len(created_contracts)} 个由目标合约创建的合约")
            
            # 优先分析被创建的合约的代码
            created_addresses = [contract['address'] for contract in created_contracts]
            print(f"将重点分析以下创建的合约: {', '.join(created_addresses)}")
            
            # 获取创建的合约的代码
            created_contracts_info = []
            for addr in created_addresses:
                contract_code = load_contract_code(db, addr)
                if contract_code:
                    contract_code['type'] = '目标创建的合约'  # 标记为被创建的合约
                    contract_code['address'] = addr
                    created_contracts_info.append(contract_code)
                    print(f"已加载合约 {addr} 的代码")
            
            # 生成被创建合约的代码上下文
            created_code_context = generate_code_context(created_contracts_info)
            
            # 添加到behavior_data
            behavior_data['created_contracts_code'] = created_code_context
            
            # 为了确保安全分析重点关注被创建的合约，我们把它添加到prompt中
            enhanced_prompt = f"""
## Security Analysis for Contract Created by Target

The target contract has created the following contract: `{created_addresses[0]}`

This contract is likely the key to understanding the attack/behavior, as it was specifically created by the target contract.

Below is the decompiled code of the created contract:

```solidity
{created_code_context}
```

Please analyze this contract's code with particular focus, as it's central to understanding the target's behavior.
"""
            
            # 使用增强的安全分析提示
            behavior_data['enhanced_analysis'] = request_ds(enhanced_prompt, [])
        
        return behavior_data
    except Exception as e:
        print(f"增强行为分析时出错: {str(e)}")
        traceback.print_exc()
        return behavior_data

def analyze_complex_transactions(transactions, call_graph):
    """识别并分析复杂交易模式"""
    complex_txs = []
    
    for tx in transactions:
        tx_hash = tx.tx_hash
        if tx_hash not in call_graph:
            continue
            
        # 分析调用深度和宽度
        call_data = call_graph[tx_hash]
        
        # 计算调用深度
        def get_max_depth(node, current_depth=0):
            if not node.get('children'):
                return current_depth
            
            child_depths = [get_max_depth(child, current_depth+1) 
                           for child in node['children']]
            return max(child_depths) if child_depths else current_depth
        
        # 计算涉及的不同合约数量
        involved_contracts = set()
        def count_contracts(node):
            if node.get('from'):
                involved_contracts.add(node['from'].lower())
            if node.get('to'):
                involved_contracts.add(node['to'].lower())
            
            for child in node.get('children', []):
                count_contracts(child)
        
        # 执行复杂度计算
        count_contracts(call_data['call_hierarchy'])
        max_depth = get_max_depth(call_data['call_hierarchy'])
        
        # 定义复杂交易的标准: 深度大于3或涉及5个以上合约
        is_complex = (max_depth > 3 or len(involved_contracts) > 5)
        if is_complex:
            complex_txs.append({
                'tx_hash': tx_hash,
                'depth': max_depth,
                'contract_count': len(involved_contracts),
                'involved_contracts': list(involved_contracts)
            })
    
    # 按复杂度排序
    complex_txs.sort(key=lambda x: (x['depth'], x['contract_count']), reverse=True)
    return complex_txs

def get_transactions_for_analysis(db, target_contract):
    """获取与目标合约相关的所有交易记录"""
    from sqlalchemy import or_
    
    try:
        # 查询交易数据
        transactions = db.query(UserInteraction).filter(
            or_(
                UserInteraction.target_contract == target_contract.lower(),
                UserInteraction.caller_contract == target_contract.lower()
            )
        ).all()
        
        return transactions
    except Exception as e:
        print(f"获取交易数据时出错: {str(e)}")
        return []

def identify_created_contracts(call_graph, target_contract):
    """从交易trace数据中识别由目标合约创建的合约"""
    created_contracts = []
    
    target_contract_lower = target_contract.lower()
    
    # 获取数据库连接
    db = next(get_db())
    
    # 查询与目标合约相关的所有交易
    from sqlalchemy import or_
    transactions = db.query(UserInteraction).filter(
        or_(
            UserInteraction.target_contract == target_contract_lower,
            UserInteraction.caller_contract == target_contract_lower
        )
    ).all()
    
    # 检查每个交易的trace数据
    for tx in transactions:
        if not tx.trace_data:
            continue
            
        try:
            trace_data = json.loads(tx.trace_data)
            
            # 处理单个trace对象
            if isinstance(trace_data, dict):
                if trace_data.get('type') == 'create' and trace_data.get('action', {}).get('from', '').lower() == target_contract_lower:
                    # 从result.address获取创建的合约地址
                    created_address = trace_data.get('result', {}).get('address')
                    if created_address:
                        created_contracts.append({
                            'address': created_address.lower(),
                            'creator': target_contract_lower,
                            'tx_hash': tx.tx_hash,
                            'block_number': tx.block_number
                        })
                        print(f"在交易 {tx.tx_hash} 中找到目标合约创建的合约: {created_address}")
            
            # 处理trace列表
            elif isinstance(trace_data, list):
                for item in trace_data:
                    if isinstance(item, dict) and item.get('type') == 'create' and item.get('action', {}).get('from', '').lower() == target_contract_lower:
                        created_address = item.get('result', {}).get('address')
                        if created_address:
                            created_contracts.append({
                                'address': created_address.lower(),
                                'creator': target_contract_lower,
                                'tx_hash': tx.tx_hash,
                                'block_number': tx.block_number
                            })
                            print(f"在交易 {tx.tx_hash} 中找到目标合约创建的合约: {created_address}")
        except Exception as e:
            print(f"处理交易 {tx.tx_hash} 的trace数据时出错: {str(e)}")
    
    # 去重
    unique_contracts = []
    seen_addresses = set()
    for contract in created_contracts:
        if contract['address'] not in seen_addresses:
            seen_addresses.add(contract['address'])
            unique_contracts.append(contract)
    
    print(f"发现目标合约创建的合约: {len(unique_contracts)} 个")
    for idx, contract in enumerate(unique_contracts, 1):
        print(f"{idx}. 合约地址: {contract['address']}")
        print(f"   创建交易: {contract['tx_hash']}")
    
    return unique_contracts

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--query":
        user_input = " ".join(sys.argv[2:])
        process_user_query(user_input)
    else:
        target = sys.argv[1] if len(sys.argv) > 1 else None
        analyze_behavior(target)
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
from typing import Dict, List, Any, Set, Union


def ensure_json_serializable(obj):
    """
    递归地确保对象可以被JSON序列化，主要将set转换为list
    
    Args:
        obj: 任何Python对象
        
    Returns:
        处理后的可JSON序列化对象
    """
    if isinstance(obj, set):
        return [ensure_json_serializable(item) for item in obj]
    elif isinstance(obj, list):
        return [ensure_json_serializable(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: ensure_json_serializable(value) for key, value in obj.items()}
    elif isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    else:
        # 尝试转换为字符串
        try:
            return str(obj)
        except:
            return None


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

# Contract Creation Information
{creator_info}

## CRITICAL ANALYSIS REQUIREMENTS

1. **IDENTIFY THE VICTIM CONTRACT** - The target address provided is the attacker/exploit contract, NOT the victim. You must first analyze the call graph to determine which contract was actually exploited. The victim is typically a protocol or service contract that lost assets, not a basic token contract.

2. **IDENTIFY EXPLOITATION PATTERN** - After identifying the victim contract, analyze its code to find the specific vulnerable function(s). Quote the exact vulnerable code segments.

3. **ANALYZE ATTACK CONTRACT CODE** - Examine both the target contract and any contracts it created to understand the exact exploitation technique used.

4. **PRECISE ATTACK RECONSTRUCTION** - Document the exact attack sequence with specific function calls and transaction evidence. Avoid speculation.

5. **RUGPULL DETECTION** - Specifically check for signs of a rugpull attack, including:
   - Contract owner/creator suddenly removing significant liquidity from pools
   - Suspicious privilege functions (unlimited minting, freezing transfers, changing fees)
   - Backdoor functions allowing creators to bypass safety mechanisms
   - Sudden large transfers of tokens to exchanges
   - Suspicious timing of privileged operations (e.g., modifying contract then draining funds)

## Output Format

# Security Incident Analysis Report

## Attack Overview
[Brief overview identifying the attack type (including rugpull if applicable) and affected protocol/contract]

## Contract Identification
- Attacker Contract: `{target_contract}` [Brief analysis]
- Victim Contract: [Identified vulnerable contract address with explanation of how you determined this is the victim]
- Helper Contracts: [Any contracts created by the attacker that participated in the exploit]

## Vulnerability Analysis
[Analysis of the specific vulnerability in the victim contract with exact function and code references]

## Attack Execution
[Step-by-step breakdown of the attack flow with specific transaction references]

## Exploitation Mechanism
[Technical explanation of how the vulnerability was exploited, referencing both victim and attacker code]

## Impact Assessment
[Description of the financial or technical impact of the exploit]

## Prevention Measures
[Specific code fixes that would prevent this vulnerability]
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
    # 如果是转账分析，使用转账专用的提示词
    if params.get("analysis_type") == "transfer_analysis":
        prompt = """
        作为区块链安全分析专家，请针对以下地址的普通转账交易提供初步分析：
        
        地址: {target_contract}
        区块范围: {start_block} - {end_block}
        原始查询: {user_input}
        
        请提供简要的分析，包括：
        1. 地址的基本情况
        2. 可能的交易目的（普通转账、交易所存提款等）
        3. 相关安全建议
        
        输出格式：
        ## 初步分析
        [分析内容]
        
        ## 建议关注点
        [建议关注的方向]
        """.format(
            target_contract=params.get("target_contract", "未知地址"),
            start_block=params.get("start_block", "未知"),
            end_block=params.get("end_block", "未知"),
            user_input=params.get("user_input", "")
        )
    else:
        # 使用原有的安全事件分析提示词
        prompt = PRELIMINARY_ANALYSIS_PROMPT.format(
            event_name=params.get("event_name", "未知安全事件"),
            user_input=params.get("user_input", "")
        )
    
    return request_ds(prompt, "")

def generate_final_report(preliminary, behavior, target_contract, creator_info=None):
    """生成最终安全分析报告，整合初步分析和详细行为分析"""
    # 准备创建者信息部分
    creator_section = "No creation information available."
    
    if creator_info:
        # 基本创建者信息
        creator_section = f"""
Target Contract: `{target_contract}`
Creator Address: `{creator_info.get('creator_address', 'Unknown')}`
Creation Transaction: `{creator_info.get('creation_tx_hash', 'Unknown')}`
Creation Block: {creator_info.get('creation_block', 'Unknown')}
Source: {creator_info.get('source', 'Unknown')}

IMPORTANT: Analyze the relationship between the creator and the target contract. 
Consider if the target contract might be:
1. An attack contract created by a malicious actor
2. A honeypot or scam token created specifically for a rugpull
3. A legitimate contract that was later compromised
"""
        
        # 添加置信度说明
        if creator_info.get('confidence') == 'low':
            creator_section += "\nNote: This creator information has low confidence and is based on inference rather than direct evidence."
            
        # 如果创建者创建了其他合约，添加这些信息
        other_contracts = creator_info.get('other_contracts', [])
        if other_contracts:
            creator_section += "\n\n## Creator's Other Contracts\n\n"
            creator_section += "The creator has deployed the following other contracts in the analyzed time period:\n\n"
            
            for idx, contract in enumerate(other_contracts, 1):
                creator_section += f"{idx}. Contract Address: `{contract.get('address', 'Unknown')}`\n"
                creator_section += f"   Creation Transaction: `{contract.get('creation_tx', 'Unknown')}`\n"
                creator_section += f"   Creation Block: {contract.get('creation_block', 'Unknown')}\n\n"
            
            creator_section += "CRITICAL: Analyze these contracts for patterns suggesting a coordinated attack or rugpull scheme. Focus on:\n"
            creator_section += "- Sequential contract deployment patterns\n"
            creator_section += "- Similar contract functionality or code patterns\n"
            creator_section += "- Cross-contract interactions and fund flows\n"
            creator_section += "- Timing correlation between contract deployments and suspicious transactions\n"
    
    prompt = FINAL_REPORT_PROMPT.format(
        preliminary_analysis=preliminary,
        behavior_analysis=behavior,
        creator_info=creator_section,
        target_contract=target_contract
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
    """生成代码上下文，格式化合约代码以供分析"""
    if not contracts_chain:
        return "无可用合约代码"
    
    code_context = ""
    for addr, code in contracts_chain.items():
        # 创建合约标题
        header = f"合约地址: {addr}"
        # 检查是否是特殊关注的合约（无源码合约）
        if code.get('is_priority') or not code.get('source_code'):
            header += " [需重点关注]"
        
        code_context += f"\n{'='*80}\n{header}\n{'='*80}\n"
        
        # 添加合约类型信息
        contract_type = code.get('type', "未知类型")
        if code.get('is_proxy'):
            contract_type = "代理合约"
            if code.get('parent_address'):
                code_context += f"代理类型: {contract_type}, 指向逻辑合约: {code.get('parent_address')}\n\n"
        else:
            code_context += f"合约类型: {contract_type}\n\n"
        
        # 添加合约名称（如果有）
        if code.get('c_name'):
            code_context += f"合约名称: {code.get('c_name')}\n\n"
        
        # 处理源代码
        has_source = False
        if code.get('source_code'):
            src_code = code['source_code']
            # 处理不同格式的源码
            if isinstance(src_code, str) and src_code.strip() and src_code != '""':
                has_source = True
                code_context += f"## 源代码\n```solidity\n{src_code}\n```\n\n"
            elif isinstance(src_code, dict) and any(src_code.values()):
                has_source = True
                # 如果是多文件合约，逐个显示文件
                code_context += "## 源代码 (多文件)\n"
                for filename, content in src_code.items():
                    if content and isinstance(content, str) and content.strip():
                        code_context += f"\n### 文件: {filename}\n```solidity\n{content}\n```\n"
        
        # 如果没有源码，优先显示反编译代码
        if not has_source and code.get('decompiled_code'):
            decompiled = code['decompiled_code']
            code_context += "## 反编译代码\n"
            
            # 处理不同格式的反编译代码
            if isinstance(decompiled, dict):
                # 如果是字典格式，可能包含多个函数
                for func_name, func_code in decompiled.items():
                    if func_code and isinstance(func_code, str):
                        code_context += f"\n### 函数: {func_name}\n```\n{func_code}\n```\n"
                    elif isinstance(func_code, dict):
                        # 如果函数也是字典结构
                        code_context += f"\n### 函数: {func_name}\n```\n{json.dumps(func_code, indent=2)}\n```\n"
            elif isinstance(decompiled, str) and decompiled.strip():
                code_context += f"```\n{decompiled}\n```\n\n"
            else:
                code_context += f"```\n{json.dumps(decompiled, indent=2)}\n```\n\n"
        
        # 如果既没有源码也没有反编译代码，显示字节码
        if not has_source and not code.get('decompiled_code') and code.get('bytecode'):
            code_context += f"## 字节码\n```\n{code.get('bytecode')[:200]}...(已截断)\n```\n\n"
        
        # 如果什么都没有，标记为无可用代码
        if not has_source and not code.get('decompiled_code') and not code.get('bytecode'):
            code_context += "无可用代码。这个合约可能需要特别关注，因为无法获取任何代码信息。\n\n"
    
    return code_context

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
        
        # 提取要重点关注的没有源码的合约
        contracts_without_source = params.get('contracts_without_source', [])
        if contracts_without_source:
            print(f"需要重点关注的无源码合约数量: {len(contracts_without_source)}")
        
        # 检查是否需要进行安全事件分析
        # 新的判断逻辑：如果指定了contracts_without_source，则进行安全事件分析
        if contracts_without_source:
            # 步骤1：首先构建初始调用图，仅包含目标合约
            call_graph = build_transaction_call_graph(
                params['target_contract'],
                params['start_block'],
                params['end_block'],
                max_depth=3,
                pruning_enabled=True,  # 启用剪枝
                related_addresses=params.get('related_addresses', [])  # 传递相关地址
            )
        
            # 步骤2：生成初步分析
            print("\n=== 生成初步分析 ===")
            preliminary_analysis = generate_preliminary_analysis(params)
            
            # 步骤3：执行完整的双向行为分析
            print("\n=== 分析合约行为（包括创建者和相关合约） ===")
            behavior_analysis = analyze_behavior_new(
                target_contract=params['target_contract'],
                start_block=params['start_block'],
                end_block=params['end_block'],
                related_addresses=params.get('related_addresses', []),
                call_graph=call_graph,  # 传递调用图给行为分析
                contracts_without_source=contracts_without_source  # 传递无源码合约列表
            )
            
            # 步骤4：获取创建者信息和相关合约
            creator_info = None
            related_addresses = []
            creator_contracts = []
            
            if isinstance(behavior_analysis, dict):
                # 提取创建者信息
                if behavior_analysis.get('creator_info'):
                    creator_info = behavior_analysis.get('creator_info')
                    # 将创建者添加到相关地址
                    if creator_info.get('creator_address'):
                        related_addresses.append(creator_info.get('creator_address'))
                
                # 提取创建者的其他合约
                if behavior_analysis.get('creator_other_contracts'):
                    creator_contracts = behavior_analysis.get('creator_other_contracts')
                    # 将这些合约添加到相关地址
                    for contract in creator_contracts:
                        if 'address' in contract:
                            related_addresses.append(contract['address'])
                
                # 提取目标合约创建的合约
                if behavior_analysis.get('created_contracts'):
                    for contract in behavior_analysis.get('created_contracts'):
                        if 'address' in contract:
                            related_addresses.append(contract['address'])
            
            # 步骤5：使用增强的相关地址集合重新构建更完整的调用图
            if related_addresses:
                print(f"\n=== 使用创建者及相关合约重新构建完整调用图 ===")
                print(f"相关地址数量: {len(related_addresses)}")
                enhanced_call_graph = build_transaction_call_graph(
                    params['target_contract'],
                    params['start_block'],
                    params['end_block'],
                    max_depth=3,
                    pruning_enabled=True,
                    related_addresses=related_addresses
                )
                
                # 更新调用图
                call_graph = enhanced_call_graph
                
                # 更新行为分析中的调用图
                if isinstance(behavior_analysis, dict):
                    behavior_analysis['enhanced_call_graph'] = True
            
            # 步骤6：现在执行Rugpull特征检测，使用完整的调用图和相关地址信息
            print("\n=== 检测Rugpull特征 ===")
            rugpull_analysis = detect_rugpull_patterns(
                call_graph, 
                params['target_contract'],
                creator_info=creator_info,
                related_addresses=related_addresses
            )
            
            if rugpull_analysis["is_likely_rugpull"]:
                print(f"检测到可能的Rugpull行为，置信度: {rugpull_analysis['confidence']}")
                for reason in rugpull_analysis["reasons"]:
                    print(f"- {reason}")
            else:
                print("未检测到明显的Rugpull特征")
            
            # 将rugpull分析结果添加到行为分析中
            if isinstance(behavior_analysis, dict):
                behavior_analysis['rugpull_analysis'] = rugpull_analysis
            
            # 检查行为分析结果
            if isinstance(behavior_analysis, str) and '错误' in behavior_analysis:
                print(f"行为分析失败: {behavior_analysis}")
                return behavior_analysis
                
                    # 生成最终报告
            print("\n=== 生成最终报告 ===")
            
            # 获取创建者信息
            creator_info = None
            if isinstance(behavior_analysis, dict) and behavior_analysis.get('creator_info'):
                creator_info = behavior_analysis.get('creator_info')
            
            final_report = generate_final_report(
                preliminary_analysis, 
                behavior_analysis,
                params['target_contract'],  # 传入target_contract参数
                creator_info=creator_info   # 传入创建者信息
            )
            
            # 保存报告
            report_file = save_report(final_report, params)
            print(f"报告已保存至: {report_file}")
            
            return final_report
        else:
            # 如果没有指定特殊合约，直接进入普通转账分析
            print("未发现无源码合约，转入普通转账分析")
            from analyze_transfer import analyze_eth_transfers
            return analyze_eth_transfers(
                from_address=params['target_contract'],
                start_block=params['start_block'],
                end_block=params['end_block']
            )
        
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

def analyze_behavior_new(target_contract=None, start_block=None, end_block=None, related_addresses=None, call_graph=None, contracts_without_source=None):
    # 输出调试信息
    print(f"开始分析行为，参数：target={target_contract}, start={start_block}, end={end_block}")
    print(f"相关地址数量: {len(related_addresses) if related_addresses else 0}")
    if contracts_without_source:
        print(f"待重点分析的无源码合约数量: {len(contracts_without_source)}")
    
    # 获取数据库会话
    db = next(get_db())
    w3 = Web3(Web3.HTTPProvider(settings.NETWORKS["ethereum"]["rpc_url"]))
    
    # 新增：识别目标合约的创建者
    creator_info = identify_contract_creator(target_contract)
    creator_contracts = []  # 存储创建者可能创建的其他合约
    
    if creator_info:
        creator_address = creator_info['creator_address']
        creation_block = creator_info['creation_block']
        
        print(f"\n=== 识别到目标合约的创建者 ===")
        print(f"创建者地址: {creator_address}")
        print(f"创建交易: {creator_info['creation_tx_hash']}")
        print(f"创建区块: {creation_block}")
        print(f"数据来源: {creator_info['source']}")
        
        # 将创建者添加到相关地址中
        if not related_addresses:
            related_addresses = []
        if creator_address not in related_addresses:
            related_addresses.append(creator_address)
        
        # 调整区块范围以包含创建交易
        if creation_block and (start_block is None or creation_block < start_block):
            # 向前扩展10个区块，以捕获可能的前置交易
            adjusted_start = max(1, creation_block - 10)
            print(f"调整起始区块从 {start_block} 到 {adjusted_start} 以包含创建交易")
            start_block = adjusted_start
            
        # 重要：主动获取创建者在目标时间范围内的所有交易并保存到数据库
        print(f"\n=== 主动获取创建者 {creator_address} 的交易 ===")
        tx_count = fetch_related_address_transactions(creator_address, start_block, end_block)
        print(f"成功获取创建者 {tx_count} 笔交易并保存到数据库，这将使调用图更完整")
        
        # 查找创建者在同一时间范围内创建的其他合约
        try:
            # 查询该创建者在分析时间段内的所有create交易
            print(f"\n=== 查找创建者 {creator_address} 创建的其他合约 ===")
            from sqlalchemy import and_
            other_creation_txs = db.query(UserInteraction).filter(
                and_(
                    UserInteraction.caller_contract == creator_address.lower(),
                    UserInteraction.method_name == 'create',
                    UserInteraction.block_number >= start_block,
                    UserInteraction.block_number <= end_block
                )
            ).all()
            
            # 记录所有创建的合约
            for tx in other_creation_txs:
                if tx.target_contract != target_contract.lower():
                    creator_contracts.append({
                        'address': tx.target_contract,
                        'creation_tx': tx.tx_hash,
                        'creation_block': tx.block_number
                    })
                    # 添加到相关地址
                    if tx.target_contract not in related_addresses:
                        related_addresses.append(tx.target_contract)
                    print(f"发现创建者创建的其他合约: {tx.target_contract}, 交易: {tx.tx_hash}, 区块: {tx.block_number}")
                    
                    # 获取该合约的交易数据
                    other_contract_tx_count = fetch_related_address_transactions(tx.target_contract, start_block, end_block)
                    print(f"获取创建者创建的合约 {tx.target_contract} 的 {other_contract_tx_count} 笔交易")
                    
            if not creator_contracts:
                print("未发现创建者创建的其他合约")
        except Exception as e:
            print(f"查询创建者其他合约时出错: {str(e)}")
    
        # 将创建者信息和相关合约添加到分析结果中供后续使用
        creator_result = {
            'creator_address': creator_address,
            'creation_tx_hash': creator_info['creation_tx_hash'],
            'creation_block': creation_block,
            'source': creator_info['source'],
            'other_contracts': creator_contracts
        }
        if 'confidence' in creator_info:
            creator_result['confidence'] = creator_info['confidence']
    
    try:
        from sqlalchemy import and_, or_
        
        # 构建包含目标合约和相关地址的查询条件
        address_conditions = []
        target_contract_lower = target_contract.lower()
        
        # 添加目标合约条件
        address_conditions.append(UserInteraction.target_contract == target_contract_lower)
        address_conditions.append(UserInteraction.caller_contract == target_contract_lower)
        
        # 如果有相关地址（如创建者），添加相关地址的条件
        if related_addresses:
            for addr in related_addresses:
                if addr and Web3.is_address(addr):
                    addr_lower = addr.lower()
                    # 避免重复添加目标合约
                    if addr_lower != target_contract_lower:
                        address_conditions.append(UserInteraction.target_contract == addr_lower)
                        address_conditions.append(UserInteraction.caller_contract == addr_lower)
                        print(f"添加相关地址 {addr_lower} 到查询条件")
        
        # 构建基本查询条件
        query_conditions = [or_(*address_conditions)]
        
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
        
        # 如果有指定无源码合约，将其添加到优先分析列表
        priority_contracts = []
        if contracts_without_source:
            priority_contracts = [addr.lower() for addr in contracts_without_source if Web3.is_address(addr)]
            print(f"优先分析以下 {len(priority_contracts)} 个无源码合约:")
            for addr in priority_contracts:
                print(f"- {addr}")
        
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
        
        # 调整合约分析顺序，优先分析没有源码的合约
        sorted_contracts = []
        
        # 首先添加无源码优先合约
        for addr in priority_contracts:
            if addr in all_contracts:
                sorted_contracts.append(addr)
        
        # 然后添加其他合约
        for addr in all_contracts:
            if addr not in sorted_contracts:
                sorted_contracts.append(addr)
        
        # 打印合约分析顺序
        print("\n合约分析顺序:")
        for idx, addr in enumerate(sorted_contracts, 1):
            contract_type = "无源码合约" if addr in priority_contracts else "普通合约"
            print(f"{idx}. {addr} ({contract_type})")
        
        # 获取所有合约的代码（优先使用无源码合约）
        print("\n获取合约代码...")
        contracts_chain = extract_contract_codes_from_db(db, sorted_contracts, priority_addresses=priority_contracts)
        
        # 生成代码上下文
        code_context = generate_code_context(contracts_chain)
        
        # 分析调用路径模式
        print("\n分析调用模式...")
        call_patterns = analyze_call_patterns(call_graph, target_contract)
        
        # 跟踪分析进度
        print("\n构建交易调用信息...")
        call_data = {
            'call_patterns': call_patterns,
            'code_context': code_context
        }
        
        # 增强安全分析
        print("\n生成增强安全分析...")
        enhanced_security_prompt = build_enhanced_security_prompt(
            call_graph, 
            target_contract,
            created_contracts=identify_created_contracts(call_graph, target_contract)
        )
        
        if enhanced_security_prompt:
            call_data['enhanced_security_analysis'] = request_ds(enhanced_security_prompt, "")
            
        # 添加攻击链分析
        print("\n构建攻击链分析...")
        behavior_data = enhance_behavior_analysis_with_attack_chain(call_data, call_graph, target_contract)
        
        # 更新行为分析以包含代码分析
        print("\n整合代码分析结果...")
        behavior_data = update_behavior_analysis_with_code(behavior_data, call_graph, target_contract)
        
        # 如果有优先合约（无源码合约），在分析中特别标注
        if priority_contracts:
            if isinstance(behavior_data, dict):
                behavior_data['suspicious_contracts'] = priority_contracts
                behavior_data['has_suspicious_contracts'] = True
                # 添加特别提示
                behavior_data['warning'] = "警告：在交易调用图中发现了未验证源码的合约，这些合约可能存在安全风险。"
            elif isinstance(behavior_data, str):
                behavior_data += "\n\n**警告**：在分析的交易中涉及了未验证源码的合约，这些合约可能存在安全风险。"
        
        # 保存合约创建者信息（如果有）
        if creator_info and isinstance(behavior_data, dict):
            behavior_data['creator_info'] = creator_result  # 使用包含其他合约的增强版创建者信息
            
            # 如果发现创建者创建的其他合约，添加到分析结果中
            if creator_contracts:
                behavior_data['creator_other_contracts'] = creator_contracts
                print(f"已将创建者创建的 {len(creator_contracts)} 个其他合约添加到分析结果中")
        
        # 确保所有数据可以被JSON序列化
        behavior_data = ensure_json_serializable(behavior_data)
        return behavior_data
        
    except Exception as e:
        error_msg = f"分析行为时出错: {str(e)}"
        print(error_msg)
        traceback.print_exc()
        return f"### 分析过程出错\n\n{error_msg}"

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
    
    # 确保所有数据可以被JSON序列化
    patterns = ensure_json_serializable(patterns)
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
    addresses = set()  # 注意：返回前会转换为list
    
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

def build_transaction_call_graph(target_contract, start_block, end_block, max_depth=3, pruning_enabled=True, related_addresses=None):
    """构建交易调用图，包括目标合约和相关地址（如创建者）的交易"""
    db = next(get_db())
    w3 = Web3(Web3.HTTPProvider(settings.NETWORKS["ethereum"]["rpc_url"]))
    
    target_contract_lower = target_contract.lower()
    call_graph = {}
    processed_txs = set()  # 初始化已处理交易集合
    
    # 处理相关地址列表
    if related_addresses is None:
        related_addresses = []
    
    # 确保地址格式正确，并转为小写
    related_addresses_lower = [addr.lower() for addr in related_addresses if Web3.is_address(addr)]
    
    # 将目标合约也添加到相关地址列表
    all_addresses = [target_contract_lower] + related_addresses_lower
    print(f"构建调用图，包括目标合约和 {len(related_addresses_lower)} 个相关地址")
    
    try:
        from sqlalchemy import and_, or_
        
        # 构建包含所有相关地址的查询条件
        address_conditions = []
        for addr in all_addresses:
            address_conditions.append(UserInteraction.target_contract == addr)
            address_conditions.append(UserInteraction.caller_contract == addr)
            # 包括method_name为'create'的交易(合约创建)
            address_conditions.append(
                and_(
                    UserInteraction.method_name == 'create',
                    UserInteraction.caller_contract == addr
                )
            )
        
        # 更新查询条件，查找所有可能与目标合约及相关地址相关的交易
        interactions = db.query(UserInteraction).filter(
            and_(
                or_(*address_conditions),
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
        # 确保所有数据可以被JSON序列化
        call_graph = ensure_json_serializable(call_graph)
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

def generate_attack_chain_prompt(attack_analysis, contracts_code, rugpull_detected=False):
    """
    根据攻击链分析生成针对性的提示，引导LLM分析攻击链
    
    Args:
        attack_analysis (dict): 攻击链分析结果
        contracts_code (dict): 合约代码信息
        rugpull_detected (bool): 是否检测到Rugpull特征
        
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
    
    # 构建基础提示
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
    
    # 如果检测到Rugpull，添加专门的Rugpull分析指南
    if rugpull_detected:
        prompt += """
## Rugpull特征检测

系统检测到此案例可能是Rugpull（跑路）事件。请特别关注以下方面：

1. **权限分析** - 检查合约中是否存在过度特权函数，如：
   - 无限铸币权限
   - 暂停交易功能
   - 修改交易费用的能力
   - 黑名单/白名单功能
   - 紧急提款功能

2. **流动性池操作** - 分析流动性池交互，特别是：
   - 是否有异常大额的流动性移除
   - 是否有单方面移除（只取出一种代币）
   - 是否在短时间内进行多次移除操作

3. **资金流向** - 跟踪资金最终去向，特别关注：
   - 向中心化交易所的大额转账
   - 分散到多个地址的小额转账
   - 向混币服务的转账
   - 是否转为稳定币

4. **时间线分析** - 构建完整的Rugpull时间线：
   - 合约部署时间
   - 修改关键参数的时间
   - 大额资金提取的时间
   - 社交媒体活动停止的时间（如有信息）
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
    
    # 2. 检查是否有Rugpull分析结果
    rugpull_analysis = behavior_data.get('rugpull_analysis', None)
    rugpull_details = ""
    
    if rugpull_analysis and rugpull_analysis.get('is_likely_rugpull', False):
        # 如果检测到Rugpull，增加Rugpull相关的提示
        rugpull_details += "\n## Rugpull Analysis\n\n"
        rugpull_details += f"Rugpull Confidence: {rugpull_analysis['confidence']}\n\n"
        rugpull_details += "Rugpull Indicators:\n"
        for reason in rugpull_analysis.get('reasons', []):
            rugpull_details += f"- {reason}\n"
        
        # 添加详细的Rugpull指标
        indicators = rugpull_analysis.get('indicators', {})
        
        if indicators.get('liquidity_removal') and len(indicators['liquidity_removal']) > 0:
            rugpull_details += "\n### Liquidity Removal Evidence\n"
            for idx, removal in enumerate(indicators['liquidity_removal'][:5], 1):
                rugpull_details += f"{idx}. TX: {removal['tx_hash']}\n"
                rugpull_details += f"   {removal['value_eth']:.4f} ETH removed via {removal['method']}\n"
                rugpull_details += f"   From {removal['from']} to {removal['to']}\n"
        
        if indicators.get('exchange_transfers') and len(indicators['exchange_transfers']) > 0:
            rugpull_details += "\n### Exchange Transfers Evidence\n"
            for idx, transfer in enumerate(indicators['exchange_transfers'][:5], 1):
                rugpull_details += f"{idx}. TX: {transfer['tx_hash']}\n"
                rugpull_details += f"   {transfer['value_eth']:.4f} ETH sent to {transfer['exchange']} ({transfer['to']})\n"
    
    # 3. 如果找到潜在攻击路径，生成针对性提示
    if attack_analysis['potential_attack_paths']:
        contracts_code = {}  # 此处假设已有合约代码信息
        # 实际实现中需要从behavior_data中提取合约代码信息
        if 'code_context' in behavior_data:
            contracts_code = behavior_data['code_context']
        
        # 检查是否存在Rugpull并传递正确的参数
        is_rugpull = rugpull_analysis and rugpull_analysis.get('is_likely_rugpull', False)
        attack_chain_prompt = generate_attack_chain_prompt(attack_analysis, contracts_code, is_rugpull)
        
        # 如果有Rugpull分析，添加到提示中
        if rugpull_details:
            attack_chain_prompt += rugpull_details
        
        # 4. 请求LLM生成攻击链分析
        try:
            attack_chain_result = request_ds(attack_chain_prompt, "")
            
            # 5. 将攻击链分析结果添加到行为分析数据中
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
    """从数据库中提取合约代码，并根据优先级排序"""
    if not contract_addresses:
        return {}
    
    print(f"从数据库提取 {len(contract_addresses)} 个合约的代码")
    
    # 确保地址列表唯一性
    contract_addresses = list(set(contract_addresses))
    
    # 如果提供了优先地址，将其移到列表前面
    if priority_addresses:
        # 建立一个新的排序列表
        sorted_addresses = []
        # 优先添加priority_addresses中的地址
        for addr in priority_addresses:
            if addr in contract_addresses:
                sorted_addresses.append(addr)
                print(f"优先处理合约: {addr}")
        # 添加剩余的地址
        for addr in contract_addresses:
            if addr not in sorted_addresses:
                sorted_addresses.append(addr)
        # 替换原始列表
        contract_addresses = sorted_addresses
    
    contracts_code = {}
    
    # 创建一个专用的ContractAnalyzer实例用于获取合约元数据
    from main import ContractAnalyzer
    analyzer = ContractAnalyzer()
    
    # 创建一个ContractPipeline实例
    from main import ContractPipeline
    pipeline = ContractPipeline(analyzer)
    
    # 收集每个合约的代码
    for idx, contract_addr in enumerate(contract_addresses, 1):
        is_priority = priority_addresses and contract_addr in priority_addresses
        priority_tag = "[优先]" if is_priority else ""
        print(f"提取合约代码 ({idx}/{len(contract_addresses)}) {priority_tag}: {contract_addr}")
        
        try:
            # 0. 先验证是否为合约（有bytecode）
            bytecode = analyzer.get_bytecode(contract_addr)
            if not bytecode or len(bytecode) <= 2:  # 非合约地址
                print(f"  地址 {contract_addr} 不是合约（可能是EOA账户），跳过")
                continue
                
            # 1. 尝试加载已有代码
            contract_info = get_contract_full_info(db, contract_addr)
            
            if contract_info:
                contracts_code[contract_addr] = contract_info
                # 检查是否有源码
                has_source = False
                if contract_info.get('source_code'):
                    source_code = contract_info.get('source_code')
                    if isinstance(source_code, str) and source_code.strip() and source_code != '""':
                        has_source = True
                        print(f"  已从数据库加载合约源码")
                    elif isinstance(source_code, dict) and any(source_code.values()):
                        has_source = True
                        print(f"  已从数据库加载合约源码 (JSON格式)")
                
                # 检查是否有反编译代码
                has_decompiled = False
                if contract_info.get('decompiled_code'):
                    has_decompiled = True
                    print(f"  已从数据库加载反编译代码")
                
                # 如果既没有源码也没有反编译代码，标记为需要进一步处理
                if not has_source and not has_decompiled:
                    print(f"  合约信息存在但无源码或反编译代码，尝试获取")
                else:
                    # 如果有源码或反编译代码，跳过后续处理
                    continue
            
            # 2. 如果没有找到代码或代码不完整，尝试通过API获取合约源码
            print(f"  尝试通过API获取合约源码")
            try:
                # 通过pipeline获取合约信息（包括源码）
                contract_info = pipeline.process_with_metadata(contract_addr)
                
                # 重新尝试从数据库加载（应该有了）
                updated_info = get_contract_full_info(db, contract_addr)
                if updated_info:
                    contracts_code[contract_addr] = updated_info
                    # 检查是否获取到了源码
                    if updated_info.get('source_code'):
                        source_code = updated_info.get('source_code')
                        if isinstance(source_code, str) and source_code.strip() and source_code != '""':
                            print(f"  成功获取合约源码")
                            # 成功获取源码后，继续处理下一个合约
                            continue
                        elif isinstance(source_code, dict) and any(source_code.values()):
                            print(f"  成功获取合约源码 (JSON格式)")
                            # 成功获取源码后，继续处理下一个合约
                            continue
                    
                    print(f"  合约源码获取失败或为空")
                else:
                    print(f"  无法从数据库加载更新后的合约信息")
            except Exception as e:
                print(f"  通过API获取合约源码失败: {str(e)}")
            
            # 3. 如果无法获取源码，尝试反编译字节码
            print(f"  尝试反编译合约字节码")
            try:
                # 已经有bytecode了，直接使用
                if bytecode and len(bytecode) > 2:  # 确保不是空字节码
                    print(f"  成功获取字节码，长度: {len(bytecode)}")
                    
                    # 反编译
                    from ethereum.decompiler.gigahorse_wrapper import decompile_bytecode
                    decompiled_code = decompile_bytecode(bytecode)
                    
                    if decompiled_code:
                        # 保存反编译结果到数据库
                        from database.crud import update_decompiled_code
                        update_decompiled_code(db, contract_addr, decompiled_code)
                        
                        # 重新获取更新后的合约信息
                        updated_info = get_contract_full_info(db, contract_addr)
                        if updated_info:
                            contracts_code[contract_addr] = updated_info
                            print(f"  成功反编译合约，并更新数据库")
                        else:
                            # 手动构建代码信息
                            contracts_code[contract_addr] = {
                                'target_contract': contract_addr,
                                'decompiled_code': decompiled_code,
                                'bytecode': bytecode
                            }
                            print(f"  成功反编译合约，但数据库未更新")
                    else:
                        print(f"  反编译失败，无法获取反编译代码")
                else:
                    print(f"  合约没有字节码或字节码为空")
            except Exception as e:
                print(f"  反编译过程出错: {str(e)}")
                traceback.print_exc()
                
        except Exception as e:
            print(f"  处理合约代码时出错: {str(e)}")
    
    # 添加标记，指示哪些合约是优先处理的
    for addr in contracts_code:
        if priority_addresses and addr in priority_addresses:
            contracts_code[addr]['is_priority'] = True
    
    print(f"成功加载 {len(contracts_code)} 个合约的代码信息")
    return contracts_code

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
# Blockchain Attack Analysis: Victim Identification and Exploitation Analysis

## Critical Context
IMPORTANT: The target address `{target_contract}` is likely the ATTACKER'S contract, not the victim. You must analyze the call graph to identify which contract was actually exploited.

{created_contracts_section}

## Analysis Requirements

1. **VICTIM CONTRACT IDENTIFICATION**:
   - Analyze the call graph and value transfers to determine which contract was attacked
   - Look for patterns such as:
     * Contracts that lost significant value
     * Contracts that were called with unusual parameters
     * Protocols that showed unusual behavior (e.g., large withdrawals, price manipulation)
   - The victim is typically NOT a simple token contract, but a more complex protocol contract

2. **ATTACK CONTRACT ANALYSIS**:
   - Analyze the target contract (`{target_contract}`) and any contracts it created
   - Identify how these contracts were designed to exploit the victim

3. **VULNERABILITY IDENTIFICATION**:
   - Once the victim is identified, analyze its code to find the exact vulnerable function(s)
   - Quote specific vulnerable code segments and explain the technical weakness

4. **ATTACK FLOW RECONSTRUCTION**:
   - Map each step in the attack chain to specific function calls and transactions
   - Explain which functions were called, in what order, and with what parameters
   - Directly reference transaction hashes when describing the attack flow

5. **RUGPULL ATTACK DETECTION**:
   - Check for Rugpull-specific indicators:
     * Suspicious outflows from liquidity pools to creator/owner addresses
     * Privileged functions being called just before large value transfers
     * `removeLiquidity`, `withdraw`, or similar functions being called with unusual parameters
     * Presence of backdoor functions or excessive admin privileges in contract code
     * Suspicious token transfers to exchanges shortly after liquidity drains
     * One-sided removal of assets from liquidity pools
     * Changes to key contract parameters (fees, transfer restrictions) prior to value extraction
   - Pay special attention to large value transfers to centralized exchanges or mixer services

6. **MEV ATTACK PATTERN IDENTIFICATION**:
   - Analyze the call graph to identify potential common MEV (Maximal Extractable Value) extraction patterns
   - Look specifically for:
     * Sandwich attacks: Transactions that bracket a victim's trade with buy orders before and sell orders after
     * Arbitrage: Quick trades across multiple DEXs to profit from price differences
     * Front-running: Transactions that extract value by ordering before user transactions
     * Back-running: Transactions that extract value by ordering after key transactions
   - Check for rapid interactions with multiple DEX contracts in a single transaction
   - Identify if flashloans were used to amplify MEV extraction
   - Determine if the transaction directly competes with or manipulates other pending transactions

## Transaction Data

### Method Call Statistics
{method_statistics}

### Value Transfers (Critical for Victim Identification)
{value_transfers_text}

{circular_paths_text}
{complex_txs_section}

## Mandatory Output Format

Your analysis MUST include:

1. **Victim Contract Identification**: Explain which contract was exploited and how you determined this.

2. **Exploit Technique**: Describe the specific exploitation technique used by the attacker (including if it was a rugpull).

3. **Vulnerable Function(s)**: Name and quote the specific function(s) in the victim contract that contain the vulnerability.

4. **Attack Sequence**: Document each step in the attack with reference to specific function calls and transactions.

5. **Code-Based Evidence**: Support all assertions with direct references to contract code or transaction data.

IMPORTANT: Avoid speculation. If information cannot be definitively determined from the code or transaction data, clearly state this rather than guessing.
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
            
            # 主动获取被创建合约的交易数据
            print("\n=== 获取目标合约创建的其他合约的交易 ===")
            for contract_addr in created_addresses:
                created_tx_count = fetch_related_address_transactions(contract_addr, start_block, end_block)
                print(f"获取目标合约创建的合约 {contract_addr} 的 {created_tx_count} 笔交易")
            
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
            
        # 如果在分析过程中发现创建者的其他合约，也将其添加到分析结果
        if isinstance(behavior_data, dict) and behavior_data.get('creator_other_contracts'):
            creator_other_contracts = behavior_data['creator_other_contracts']
            print(f"\n=== 分析创建者创建的其他合约 ===")
            
            # 获取创建者创建的其他合约代码
            other_contracts_info = []
            other_addresses = [contract['address'] for contract in creator_other_contracts]
            
            for addr in other_addresses:
                contract_code = load_contract_code(db, addr)
                if contract_code:
                    contract_code['type'] = '创建者创建的其他合约'
                    contract_code['address'] = addr
                    other_contracts_info.append(contract_code)
                    print(f"已加载创建者其他合约 {addr} 的代码")
            
            # 生成创建者其他合约的代码上下文
            if other_contracts_info:
                other_code_context = generate_code_context(other_contracts_info)
                behavior_data['creator_other_contracts_code'] = other_code_context
                print(f"已添加 {len(other_contracts_info)} 个创建者其他合约的代码到分析结果中")
            
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
    
    print(f"找到与目标合约 {target_contract_lower} 相关的交易 {len(transactions)} 笔")
    
    # 创建合约相关的方法名关键词
    creation_method_keywords = ["create", "deploy", "new", "build", "spawn", "clone", "factory"]
    
    # 检查每个交易的trace数据
    for tx in transactions:
        if not tx.trace_data:
            continue
            
        try:
            trace_data = json.loads(tx.trace_data)
            
            # 递归处理trace数据查找创建合约的操作
            def process_trace_recursively(trace_item, parent_from=None, depth=0):
                """递归处理trace数据查找创建合约的操作"""
                # 防止过深递归
                if depth > 8:
                    return
            
            # 处理单个trace对象
                if isinstance(trace_item, dict):
                    # 检查是否是create类型
                    trace_type = trace_item.get('type', '')
                    
                    # 获取action和result信息
                    action = trace_item.get('action', {})
                    result = trace_item.get('result', {})
                    
                    # 获取from地址
                    from_address = action.get('from', '')
                    if not from_address and parent_from:
                        from_address = parent_from
                    
                    from_address = from_address.lower() if from_address else ''
                    
                    # 检查是否是create类型且from是目标合约
                    is_create = trace_type.lower() == 'create'
                    
                    if is_create and from_address == target_contract_lower:
                        created_address = None
                        if result and 'address' in result:
                            created_address = result.get('address')
                        if created_address:
                            created_contracts.append({
                                'address': created_address.lower(),
                                'creator': target_contract_lower,
                                'tx_hash': tx.tx_hash,
                                'block_number': tx.block_number,
                                'creation_type': 'direct_create'
                            })
                            print(f"在交易 {tx.tx_hash} 中找到目标合约直接创建的合约: {created_address}")
                    
                    # 检查是否通过method创建合约
                    # 获取方法ID/名称
                    method_id = ''
                    if action.get('input'):
                        input_data = action.get('input')
                        if isinstance(input_data, str) and len(input_data) >= 10:
                            method_id = input_data[:10].lower()
                    
                    method_name = tx.method_name.lower() if tx.method_name else ''
                    
                    # 如果from是目标合约且方法名包含创建关键词
                    if from_address == target_contract_lower and any(keyword in method_name for keyword in creation_method_keywords):
                        # 尝试从result中找出创建的合约地址
                        created_address = None
                        if 'address' in result:
                            created_address = result.get('address')
                        if created_address:
                            created_contracts.append({
                                'address': created_address.lower(),
                                'creator': target_contract_lower,
                                'tx_hash': tx.tx_hash,
                                'block_number': tx.block_number,
                                'creation_type': 'method_create'
                            })
                            print(f"在交易 {tx.tx_hash} 方法{method_name}中找到创建的合约: {created_address}")
                    
                    # 递归处理子调用
                    # 检查多种可能的子调用结构
                    if 'calls' in trace_item and isinstance(trace_item['calls'], list):
                        for subcall in trace_item['calls']:
                            process_trace_recursively(subcall, from_address, depth + 1)
                    
                    if 'subtraces' in trace_item and trace_item['subtraces'] > 0:
                        if 'trace' in trace_item and isinstance(trace_item['trace'], list):
                            for subtrace in trace_item['trace']:
                                process_trace_recursively(subtrace, from_address, depth + 1)
                    
                    if 'children' in trace_item and isinstance(trace_item['children'], list):
                        for child in trace_item['children']:
                            process_trace_recursively(child, from_address, depth + 1)
                
                # 处理trace列表
                elif isinstance(trace_item, list):
                    for item in trace_item:
                        process_trace_recursively(item, parent_from, depth)
            
            # 处理trace数据
            process_trace_recursively(trace_data)
            
            # 检查事件日志中的合约创建
            if tx.event_logs:
                try:
                    event_logs = json.loads(tx.event_logs) if isinstance(tx.event_logs, str) else tx.event_logs
                    
                    for log in event_logs:
                        # 检查是否是来自目标合约的事件
                        if log.get('address', '').lower() == target_contract_lower:
                            # 提取事件主题
                            topics = log.get('topics', [])
                            
                            # 典型的合约创建事件主题
                            creation_topics = [
                                # 常见合约创建事件的签名
                                "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b",  # Created
                                "0x4db17dd5e4732fb6da34a148104a592783ca119a1e7bb8829eba6cbadef0b511",  # ProxyCreated
                                "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"   # RoleGranted (通常在创建后授权)
                            ]
                            
                            if topics and any(topic in str(topics) for topic in creation_topics):
                                # 从事件数据中提取合约地址
                                data = log.get('data', '')
                                if isinstance(data, str) and len(data) >= 42:
                                    # 尝试从数据中提取地址
                                    import re
                                    address_pattern = re.compile(r'0x[a-fA-F0-9]{40}')
                                    matches = address_pattern.findall(data)
                                    
                                    for addr in matches:
                                        created_contracts.append({
                                            'address': addr.lower(),
                                            'creator': target_contract_lower,
                                            'tx_hash': tx.tx_hash,
                                            'block_number': tx.block_number,
                                            'creation_type': 'event_create'
                                        })
                                        print(f"从事件日志中检测到创建的合约: {addr}")
                
                except Exception as e:
                    print(f"处理交易 {tx.tx_hash} 的事件日志时出错: {str(e)}")
            
            # 如果caller是目标合约，检查交易收据中的合约创建
            if tx.caller_contract == target_contract_lower:
                try:
                    method_name = tx.method_name.lower() if tx.method_name else ''
                    
                    # 如果方法名包含创建关键词，进一步检查
                    if any(keyword in method_name for keyword in creation_method_keywords):
                        # 查询交易收据以获取contractAddress
                        try:
                            w3 = Web3(Web3.HTTPProvider(settings.NETWORKS["ethereum"]["rpc_url"]))
                            receipt = w3.eth.get_transaction_receipt(tx.tx_hash)
                            
                            if receipt and receipt.get('contractAddress'):
                                created_address = receipt['contractAddress']
                                created_contracts.append({
                                    'address': created_address.lower(),
                                    'creator': target_contract_lower,
                                    'tx_hash': tx.tx_hash,
                                    'block_number': tx.block_number,
                                    'creation_type': 'receipt_create'
                                })
                                print(f"从交易收据中检测到创建的合约: {created_address}")
                        except Exception as e:
                            print(f"获取交易 {tx.tx_hash} 收据时出错: {str(e)}")
                except Exception as e:
                    print(f"处理交易 {tx.tx_hash} input时出错: {str(e)}")
                    
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
        print(f"   创建类型: {contract['creation_type']}")
    
    # 验证这些合约确实存在（有字节码）
    verified_contracts = []
    for contract in unique_contracts:
        address = contract['address']
        try:
            # 检查地址是否有字节码
            w3 = Web3(Web3.HTTPProvider(settings.NETWORKS["ethereum"]["rpc_url"]))
            code = w3.eth.get_code(Web3.to_checksum_address(address))
            
            if code and code != '0x' and len(code) > 2:
                verified_contracts.append(contract)
                print(f"已验证合约 {address} 存在有效代码")
            else:
                print(f"警告: 合约 {address} 没有代码，可能是普通账户或已自毁合约")
        except Exception as e:
            print(f"验证合约 {address} 时出错: {str(e)}")
    
    print(f"最终验证的合约数: {len(verified_contracts)}/{len(unique_contracts)}")
    return verified_contracts

def detect_rugpull_patterns(call_graph, target_contract, creator_info=None, related_addresses=None):
    """
    在交易调用图中检测Rugpull特征，特别关注代币部署者/owner与资金转出的关联性
    
    Args:
        call_graph (dict): 交易调用图
        target_contract (str): 目标合约地址
        creator_info (dict, optional): 合约创建者信息
        related_addresses (list, optional): 相关地址列表，包括创建者地址和创建者的其他合约
        
    Returns:
        dict: Rugpull分析结果
    """
    rugpull_indicators = {
        "liquidity_removal": [],      # 1. 流动性突然减少
        "privilege_abuse": [],        # 权限滥用
        "exchange_transfers": [],     # 2. 向交易所的大额转账(创建者资金转移)
        "suspicious_functions": [],   # 可疑函数调用
        "parameter_changes": [],      # 关键参数变更
        "price_volatility": [],       # 3. 代币价格暴涨暴跌
        "trade_imbalance": [],        # 4. 买入者远多于卖出者
        "failed_transactions": [],    # 5. 买入后无法卖出(交易失败)
        "suspicious_contracts": [],   # 6. 合约没有公开源码或调用异常
        "short_lifecycle": None,      # 7. 上线时间短
        "creator_funds_outflow": []   # 8. 新增: 合约创建者/owner资金外流
    }
    
    # 常见交易所地址
    exchange_addresses = {
        "0xdac17f958d2ee523a2206206994597c13d831ec7": "Tether Treasury",
        "0x28c6c06298d514db089934071355e5743bf21d60": "Binance",
        "0x21a31ee1afc51d94c2efccaa2092ad1028285549": "Binance",
        "0xbe0eb53f46cd790cd13851d5eff43d12404d33e8": "Binance",
        "0x5a52e96bacdabb82fd05763e25335261b270efcb": "Binance",
        "0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be": "Binance",
        "0xd551234ae421e3bcba99a0da6d736074f22192ff": "Binance",
        "0x564286362092d8e7936f0549571a803b203aaced": "Binance",
        "0x0681d8db095565fe8a346fa0277bffde9c0edbbf": "Binance",
        "0x4e9ce36e442e55ecd9025b9a6e0d88485d628a67": "Binance",
        "0x8d12a197cb00d4747a1fe03395095ce2a5cc6819": "EtherDelta",
        "0x2a0c0dbecc7e4d658f48e01e3fa353f44050c208": "IDEX",
        "0x876eabf441b2ee5b5b0554fd502a8e0600950cfa": "Bitfinex",
        "0x742d35cc6634c0532925a3b844bc454e4438f44e": "Bitfinex",
        "0x1151314c646ce4e0efd76d1af4760ae66a9fe30f": "Bitfinex",
        "0xcafb10ee663f465f9d10588ac44ed20ed608c11e": "Bitfinex",
        "0x7180eb39a6264938fdb3effd7341c4727c382153": "Bitfinex",
        "0x0a869d79a7052c7f1b55a8ebabbea3420f0d1e13": "Kraken",
        "0xe853c56864a2ebe4576a807d26fdc4a0ada51919": "Kraken",
        "0x267be1c1d684f78cb4f6a176c4911b741e4ffdc0": "Kraken",
        "0xfa52274dd61e1643d2205169732f29114bc240b3": "Kraken",
        "0x53d284357ec70ce289d6d64134dfac8e511c8a3d": "Kraken",
    }
    
    # 跨链桥地址
    bridge_addresses = {
        "0x40ec5b33f54e0e8a33a975908c5ba1c14e5bbbdf": "Polygon Bridge",
        "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1": "Optimism Bridge",
        "0x8ece0a50a025a7e13398212a5bed2ded11959949": "Arbitrum Bridge",
        "0x3ee18b2214aff97000d974cf647e7c347e8fa585": "Wormhole Bridge",
        "0x0ac2d6f5f5afc669d3ca38f830dad2b4f238ad3f": "Hop Protocol",
        "0xabea9132b05a70803a4e85094fd0e1800777fbef": "zkSync Bridge"
    }
    
    # 常见DEX和流动性池相关合约
    dex_addresses = {
        "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
        "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
        "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "SushiSwap Router",
        "0x1111111254fb6c44bac0bed2854e76f90643097d": "1inch Router",
        "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Router"
    }
    
    # 可疑函数名称模式
    suspicious_functions = [
        "removeLiquidity", "withdraw", "emergencyWithdraw", "setFee", "updateFee",
        "transferOwnership", "renounceOwnership", "pause", "unpause", "mint",
        "burn", "blacklist", "setTaxFee", "excludeFromFee", "setMaxTxAmount",
        "addToBlacklist", "removeFromBlacklist", "whitelist", "changeTransferLimit",
        "updateBlacklist", "disableTrading", "lockTokens", "enableSwap", "disableSwap",
        "setMaxWallet", "setSwapAndLiquify", "updateMigrator", "setMigrator", "migrateTokens"
    ]
    
    # 获取数据库连接以便查询合约创建者和owner
    db = next(get_db())
    
    # 尝试识别合约创建者和owner地址
    creator_addresses = set()
    owner_addresses = set()
    
    # 使用提供的创建者信息增强分析
    if creator_info and creator_info.get('creator_address'):
        creator_address = creator_info.get('creator_address').lower()
        creator_addresses.add(creator_address)
        print(f"从创建者信息中添加创建者地址: {creator_address}")
        
        # 检查创建者的其他合约
        other_contracts = creator_info.get('other_contracts', [])
        if other_contracts:
            print(f"分析创建者部署的 {len(other_contracts)} 个其他合约")
            for contract in other_contracts:
                if contract.get('address'):
                    print(f"添加创建者的其他合约: {contract.get('address')}")
    
    # 使用提供的相关地址增强分析
    if related_addresses:
        print(f"分析 {len(related_addresses)} 个相关地址的行为")
        
    # 交易统计变量初始化
    total_txs = 0
    buy_txs = 0
    sell_txs = 0
    tx_timestamps = []
    
    # 多合约协同行为分析
    cross_contract_transfers = []  # 记录合约间的资金转移
    contract_creation_sequence = []  # 记录合约创建顺序
    contract_similarity = {}  # 记录合约间的相似性
    
    # 1. 查询创建交易以识别创建者
    try:
        from sqlalchemy import and_
        creation_txs = db.query(UserInteraction).filter(
            and_(
                UserInteraction.target_contract == target_contract.lower(),
                UserInteraction.method_name == 'create'
            )
        ).all()
        
        for tx in creation_txs:
            if tx.caller_contract:
                creator_addresses.add(tx.caller_contract.lower())
                print(f"识别到合约创建者地址: {tx.caller_contract}")
    except Exception as e:
        print(f"查询合约创建者时出错: {str(e)}")
    
    # 2. 在调用图中查找owner相关调用
    for tx_hash, data in call_graph.items():
        if 'call_hierarchy' not in data:
            continue
            
        def find_owner_calls(node):
            method = node.get('method_id', node.get('method', '')).lower()
            
            # 检查是否与所有权相关的函数
            if any(kw in method.lower() for kw in ['owner', 'admin', 'auth', 'onlyowner']):
                from_addr = node.get('from', '').lower()
                if from_addr and from_addr != target_contract.lower():
                    owner_addresses.add(from_addr)
                    print(f"可能的合约owner地址: {from_addr}")
            
            # 递归处理子调用
            for child in node.get('children', []):
                find_owner_calls(child)
        
        # 从根节点开始分析
        if 'call_hierarchy' in data:
            find_owner_calls(data['call_hierarchy'])
            total_txs += 1  # 增加交易计数
            
            # 检测买入卖出交易
            def analyze_transaction_type(node):
                method = node.get('method_id', node.get('method', '')).lower()
                from_addr = node.get('from', '').lower()
                to_addr = node.get('to', '').lower()
                value = node.get('value', '0x0')
                
                # 计算转账价值（如果有）
                eth_value = 0
                if value and value != '0x0':
                    try:
                        value_int = int(value, 16) if value.startswith('0x') else int(value)
                        eth_value = value_int / 10**18  # 转换为ETH
                    except:
                        pass
                
                # 判断是否是买入交易
                if any(buy_term in method.lower() for buy_term in ['buy', 'swap', 'purchase']):
                    nonlocal buy_txs
                    buy_txs += 1
                
                # 判断是否是卖出交易
                elif any(sell_term in method.lower() for sell_term in ['sell', 'withdraw', 'remove']):
                    nonlocal sell_txs
                    sell_txs += 1
                
                # 检测流动性移除
                if any(term in method.lower() for term in ['removeliquidity', 'withdraw']) and eth_value > 0.1:
                    # 检查是否由创建者执行
                    is_creator = from_addr in creator_addresses
                    
                    rugpull_indicators['liquidity_removal'].append({
                        'tx_hash': tx_hash,
                        'from': from_addr,
                        'to': to_addr,
                        'method': method,
                        'value_eth': eth_value,
                        'is_creator': is_creator
                    })
                    
                    print(f"检测到流动性移除: {eth_value} ETH, 交易: {tx_hash}")
                
                # 检测向交易所的转账
                if eth_value > 0.5:  # 超过0.5 ETH的转账
                    # 检查目标地址是否是交易所
                    to_addr_lower = to_addr.lower()
                    if to_addr_lower in exchange_addresses:
                        # 检查是否由创建者执行
                        is_creator = from_addr in creator_addresses
                        
                        rugpull_indicators['exchange_transfers'].append({
                            'tx_hash': tx_hash,
                            'from': from_addr,
                            'to': to_addr,
                            'exchange': exchange_addresses[to_addr_lower],
                            'value_eth': eth_value,
                            'is_creator': is_creator
                        })
                        
                        print(f"检测到向交易所转账: {eth_value} ETH 到 {exchange_addresses[to_addr_lower]}")
                
                # 检查可疑函数调用
                for sus_func in suspicious_functions:
                    if sus_func.lower() in method.lower():
                        rugpull_indicators['suspicious_functions'].append({
                            'tx_hash': tx_hash,
                            'from': from_addr,
                            'to': to_addr,
                            'method': method
                        })
                        print(f"检测到可疑函数调用: {method}")
                        break
                
                # 检查创建者相关行为
                if from_addr in creator_addresses:
                    # 记录创建者操作，特别关注向交易所转账、移除流动性等操作
                    if eth_value > 0.05:  # 超过0.05 ETH的转账
                        rugpull_indicators['creator_funds_outflow'].append({
                            'tx_hash': tx_hash,
                            'from': from_addr,
                            'to': to_addr,
                            'value_eth': eth_value,
                            'method': method
                        })
                        print(f"检测到创建者资金流出: {eth_value} ETH, 从 {from_addr} 到 {to_addr}")
                
                # 检查合约间交互，特别是在相关合约之间
                if related_addresses and from_addr in related_addresses and to_addr in related_addresses:
                    cross_contract_transfers.append({
                        'tx_hash': tx_hash,
                        'from': from_addr,
                        'to': to_addr,
                        'value_eth': eth_value,
                        'method': method
                    })
                    print(f"检测到相关合约间交互: {from_addr} -> {to_addr}, 方法: {method}")
                
                # 递归检查子交易
                for child in node.get('children', []):
                    analyze_transaction_type(child)
            
            # 分析交易类型
            analyze_transaction_type(data['call_hierarchy'])
            
            # 记录交易时间戳（如果有）
            if 'timestamp' in data:
                tx_timestamps.append(data['timestamp'])
    
    # 分析交易结构失衡
    if total_txs > 0:
        buy_percentage = (buy_txs / total_txs) * 100
        sell_percentage = (sell_txs / total_txs) * 100
        
        # 计算买入卖出比例失衡程度
        if buy_txs > 0 and sell_txs > 0:
            buy_sell_ratio = buy_txs / sell_txs
        else:
            buy_sell_ratio = buy_txs if sell_txs == 0 else 0
        
        # 记录交易结构失衡指标
        rugpull_indicators["trade_imbalance"] = {
            'buy_txs': buy_txs,
            'sell_txs': sell_txs,
            'total_txs': total_txs,
            'buy_percentage': buy_percentage,
            'sell_percentage': sell_percentage,
            'buy_sell_ratio': buy_sell_ratio,
            'is_imbalanced': buy_sell_ratio > 3  # 买入是卖出的3倍以上视为失衡
        }
    
    # 分析时间序列以检测短生命周期
    if tx_timestamps and len(tx_timestamps) > 1:
        tx_timestamps.sort()
        first_tx = tx_timestamps[0]
        last_tx = tx_timestamps[-1]
        lifecycle_days = (last_tx - first_tx) / (24 * 3600)  # 转换为天数
        
        rugpull_indicators["short_lifecycle"] = {
            'first_tx_time': first_tx,
            'last_tx_time': last_tx,
            'lifecycle_days': lifecycle_days,
            'is_short': lifecycle_days < 7  # 少于7天视为短生命周期
        }
    
    # 计算rugpull分数（扩展启发式评分）
    score = 0
    reasons = []
    
    # 1. 流动性突然减少
    if len(rugpull_indicators["liquidity_removal"]) > 0:
        weight = 30
        # 如果这些操作是由创建者执行的，增加权重
        creator_removals = len([r for r in rugpull_indicators["liquidity_removal"] if r.get('is_creator', False)])
        if creator_removals > 0:
            weight += 10
            reasons.append(f"发现{creator_removals}次由创建者执行的大额流动性移除")
        else:
            reasons.append(f"发现{len(rugpull_indicators['liquidity_removal'])}次大额流动性移除")
        score += weight
    
    # 2. 向交易所的大额转账
    if len(rugpull_indicators["exchange_transfers"]) > 0:
        weight = 25
        # 如果这些转账是由创建者执行的，增加权重
        creator_transfers = len([t for t in rugpull_indicators["exchange_transfers"] if t.get('is_creator', False)])
        if creator_transfers > 0:
            weight += 10
            reasons.append(f"发现{creator_transfers}次由创建者执行的向交易所的大额转账")
        else:
            reasons.append(f"发现{len(rugpull_indicators['exchange_transfers'])}次向交易所的大额转账")
        score += weight
    
    # 3. 特权操作
    if len(rugpull_indicators["privilege_abuse"]) > 0:
        score += 20
        reasons.append(f"发现{len(rugpull_indicators['privilege_abuse'])}次特权操作")
    
    # 4. 可疑函数调用
    if len(rugpull_indicators["suspicious_functions"]) > 0:
        score += 15
        reasons.append(f"发现{len(rugpull_indicators['suspicious_functions'])}次可疑函数调用")
    
    # 5. 关键参数变更
    if len(rugpull_indicators["parameter_changes"]) > 0:
        score += 10
        reasons.append(f"发现{len(rugpull_indicators['parameter_changes'])}次关键参数变更")
    
    # 6. 交易结构失衡
    if rugpull_indicators["trade_imbalance"] and rugpull_indicators["trade_imbalance"].get('is_imbalanced'):
        imbalance = rugpull_indicators["trade_imbalance"]
        score += 15
        reasons.append(f"交易结构严重失衡: 买入{imbalance['buy_txs']}次vs卖出{imbalance['sell_txs']}次，比例{imbalance['buy_sell_ratio']:.2f}")
    
    # 7. 短生命周期
    if rugpull_indicators["short_lifecycle"] and rugpull_indicators["short_lifecycle"].get('is_short'):
        lifecycle = rugpull_indicators["short_lifecycle"]
        score += 20
        reasons.append(f"项目生命周期很短: {lifecycle['lifecycle_days']:.2f}天")
    
    # 8. 多次交易失败
    if len(rugpull_indicators["failed_transactions"]) > 5:  # 多于5次交易失败视为异常
        fail_ratio = len(rugpull_indicators["failed_transactions"]) / total_txs if total_txs > 0 else 0
        if fail_ratio > 0.1:  # 失败率超过10%
            score += 15
            reasons.append(f"高交易失败率: {len(rugpull_indicators['failed_transactions'])}次失败，占比{fail_ratio:.2%}")
    
    # 9. 存在可疑未开源合约
    if len(rugpull_indicators["suspicious_contracts"]) > 0:
        score += 20
        reasons.append(f"发现{len(rugpull_indicators['suspicious_contracts'])}个无源码可疑合约")
    
    # 10. 创建者资金流出 (新增)
    if len(rugpull_indicators["creator_funds_outflow"]) > 0:
        total_outflow = sum(flow.get('value_eth', 0) for flow in rugpull_indicators["creator_funds_outflow"])
        if total_outflow > 1.0:  # 超过1 ETH的总流出
            weight = min(int(total_outflow * 5), 40)  # 根据流出量计算权重，最大40分
            score += weight
            reasons.append(f"发现创建者大额资金流出: 总计{total_outflow:.2f} ETH")
    
    # 11. 分析多合约协同模式 (新增)
    if cross_contract_transfers and len(cross_contract_transfers) > 2:
        score += 15
        reasons.append(f"发现{len(cross_contract_transfers)}次相关合约之间的可疑资金转移")
    
    # 12. 综合分析创建者模式 (新增)
    if creator_info and creator_info.get('other_contracts') and len(creator_info.get('other_contracts')) > 1:
        # 创建者创建了多个合约，这可能是复杂Rugpull的迹象
        score += 10
        reasons.append(f"创建者在短时间内部署了多个相关合约({len(creator_info.get('other_contracts'))}个)")
    
    # 返回分析结果，包含新增的指标
    return {
        "indicators": rugpull_indicators,
        "score": score,
        "reasons": reasons,
        "cross_contract_transfers": cross_contract_transfers,  # 新增跨合约交互数据
        "is_likely_rugpull": score > 50,  # 分数超过50，可能是rugpull
        "confidence": "高" if score > 70 else "中" if score > 50 else "低",
        "multi_contract_pattern": bool(cross_contract_transfers)  # 是否存在多合约协同模式
    }

def identify_contract_creator(target_contract):
    """
    识别目标合约的创建者，并返回创建者地址及创建交易详情
    
    Args:
        target_contract (str): 目标合约地址
        
    Returns:
        dict: 包含创建者信息的字典，如果找不到则返回None
    """
    db = next(get_db())
    w3 = Web3(Web3.HTTPProvider(settings.NETWORKS["ethereum"]["rpc_url"]))
    creator_info = None
    
    try:
        # 检查目标合约地址格式
        if not Web3.is_address(target_contract):
            print(f"无效的合约地址: {target_contract}")
            return None
        
        target_contract_lower = target_contract.lower()
        
        # 方法1：查询数据库中是否有合约创建交易的记录
        from sqlalchemy import and_
        creation_tx = db.query(UserInteraction).filter(
            and_(
                UserInteraction.target_contract == target_contract_lower,
                UserInteraction.method_name == 'create'
            )
        ).first()
        
        if creation_tx:
            creator_address = creation_tx.caller_contract
            creation_block = creation_tx.block_number
            print(f"从数据库找到合约创建者: {creator_address}, 创建区块: {creation_block}")
            return {
                'creator_address': creator_address,
                'creation_tx_hash': creation_tx.tx_hash,
                'creation_block': creation_block,
                'source': 'database'
            }
        
        # 方法2：通过API查询合约创建信息
        try:
            # 获取首个区块的交易，通常是创建交易
            code = w3.eth.get_code(Web3.to_checksum_address(target_contract))
            if code and len(code) > 2:  # 确认是合约
                # 通过Etherscan API查询合约创建信息
                network_config = settings.NETWORKS["ethereum"]
                url = f"{network_config['explorer_url']}?module=contract&action=getcontractcreation&contractaddresses={target_contract}&apikey={network_config['explorer_key']}"
                
                response = requests.get(url)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == '1' and data.get('result'):
                        result = data['result'][0]
                        creator_address = result.get('contractCreator')
                        tx_hash = result.get('txHash')
                        
                        # 获取交易所在的区块
                        tx_data = w3.eth.get_transaction(tx_hash)
                        block_number = tx_data.get('blockNumber')
                        
                        print(f"通过API找到合约创建者: {creator_address}, 创建区块: {block_number}")
                        return {
                            'creator_address': creator_address,
                            'creation_tx_hash': tx_hash,
                            'creation_block': block_number,
                            'source': 'api'
                        }
        except Exception as e:
            print(f"通过API查询合约创建者出错: {str(e)}")
        
        # 方法3：尝试通过链上数据找出最早的交易
        try:
            # 查询与该合约相关的最早交易
            earliest_tx = db.query(UserInteraction).filter(
                or_(
                    UserInteraction.target_contract == target_contract_lower,
                    UserInteraction.caller_contract == target_contract_lower
                )
            ).order_by(UserInteraction.block_number).first()
            
            if earliest_tx:
                # 如果最早的交易是对这个合约的调用，创建者可能是调用者
                if earliest_tx.target_contract == target_contract_lower:
                    creator_address = earliest_tx.caller_contract
                    creation_block = earliest_tx.block_number
                    print(f"推测合约创建者(基于最早交易): {creator_address}, 创建区块: {creation_block}")
                    return {
                        'creator_address': creator_address,
                        'creation_tx_hash': earliest_tx.tx_hash,
                        'creation_block': creation_block,
                        'source': 'earliest_tx',
                        'confidence': 'low'  # 置信度低，因为这只是推测
                    }
        except Exception as e:
            print(f"查询最早交易时出错: {str(e)}")
        
        print(f"无法确定合约 {target_contract} 的创建者")
        return None
        
    except Exception as e:
        print(f"识别合约创建者时出错: {str(e)}")
        return None

def fetch_related_address_transactions(address, start_block, end_block):
    """
    主动获取相关地址(如创建者)在指定区块范围内的所有交易，并保存到数据库
    
    Args:
        address (str): 要查询的地址
        start_block (int): 起始区块
        end_block (int): 结束区块
    
    Returns:
        int: 获取并保存的交易数量
    """
    if not Web3.is_address(address):
        print(f"无效的地址: {address}")
        return 0
        
    db = next(get_db())
    w3 = Web3(Web3.HTTPProvider(settings.NETWORKS["ethereum"]["rpc_url"]))
    address_lower = address.lower()
    tx_count = 0
    
    try:
        print(f"获取地址 {address} 在区块 {start_block} 到 {end_block} 范围内的交易...")
        
        # 获取地址作为发送方的交易
        for block_num in range(start_block, end_block + 1):
            try:
                # 获取区块
                block = w3.eth.get_block(block_num, full_transactions=True)
                
                # 遍历区块中的所有交易
                for tx in block.transactions:
                    tx_hash = tx.hash.hex()
                    from_address = tx['from'].lower()
                    to_address = tx['to'].lower() if tx['to'] else None
                    
                    # 检查交易是否与目标地址相关
                    if from_address == address_lower or to_address == address_lower:
                        # 检查交易是否已存在于数据库
                        existing_tx = db.query(UserInteraction).filter(
                            UserInteraction.tx_hash == tx_hash
                        ).first()
                        
                        if not existing_tx:
                            # 获取交易细节并保存到数据库
                            tx_data = {
                                'tx_hash': tx_hash,
                                'block_number': block_num,
                                'from_address': from_address,
                                'to_address': to_address,
                                'value': tx['value'],
                                'input_data': tx['input'],
                                'target_contract': to_address,
                                'caller_contract': from_address,
                                'method_name': '未知',  # 稍后会尝试解析
                                'network': 'ethereum'
                            }
                            
                            # 获取交易追踪数据
                            trace_data = get_transaction_trace(tx_hash)
                            if trace_data:
                                tx_data['trace_data'] = json.dumps(trace_data)
                                
                                # 提取地址
                                extracted_addresses = extract_addresses_from_trace(trace_data)
                                if extracted_addresses:
                                    # 确保提取的地址是可序列化的列表而不是集合
                                    extracted_addresses = ensure_json_serializable(extracted_addresses)
                            
                            # 尝试解析方法名
                            if to_address and tx['input'] and len(tx['input']) >= 10:
                                try:
                                    # 获取合约实例
                                    contract_code = w3.eth.get_code(Web3.to_checksum_address(to_address))
                                    if contract_code and len(contract_code) > 2:  # 确认是合约地址
                                        # 修复：创建ContractAnalyzer实例后调用其方法
                                        from main import ContractAnalyzer
                                        analyzer = ContractAnalyzer()
                                        method_name = analyzer.get_method_name(to_address, tx['input'])
                                        if method_name:
                                            tx_data['method_name'] = method_name
                                except Exception as e:
                                    print(f"解析方法名出错: {str(e)}")
                            
                            # 检查是否是合约创建交易
                            if not to_address and tx['input']:
                                tx_data['method_name'] = 'create'
                                # 从交易收据中获取创建的合约地址
                                receipt = w3.eth.get_transaction_receipt(tx_hash)
                                if receipt and receipt.get('contractAddress'):
                                    tx_data['target_contract'] = receipt['contractAddress'].lower()
                            
                            # 创建UserInteraction对象并保存
                            interaction = UserInteraction(
                                tx_hash=tx_data['tx_hash'],
                                block_number=tx_data['block_number'],
                                target_contract=tx_data['target_contract'],
                                caller_contract=tx_data['caller_contract'],
                                method_name=tx_data['method_name'],
                                input_data=tx_data['input_data'],
                                trace_data=tx_data.get('trace_data'),
                                network=tx_data['network']
                                # 移除不支持的字段 extracted_addresses
                            )
                            
                            db.add(interaction)
                            db.commit()
                            tx_count += 1
                            print(f"保存地址 {address} 的交易: {tx_hash}, 方法: {tx_data['method_name']}")
            
            except Exception as e:
                print(f"处理区块 {block_num} 时出错: {str(e)}")
                continue
        
        print(f"成功获取并保存地址 {address} 的 {tx_count} 笔交易")
        return tx_count
    
    except Exception as e:
        print(f"获取地址 {address} 的交易时出错: {str(e)}")
        traceback.print_exc()
        return 0

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--query":
        user_input = " ".join(sys.argv[2:])
        process_user_query(user_input)
    else:
        target = sys.argv[1] if len(sys.argv) > 1 else None
        analyze_behavior(target)
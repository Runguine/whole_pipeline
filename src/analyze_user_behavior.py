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

# 新增在analyze_user_behavior.py顶部
USER_QUERY_PROMPT = """
作为区块链安全分析助手，请从用户提问中提取以下信息：
1. 合约地址（以0x开头的十六进制字符串）
2. 区块范围（起始和结束区块号）
3. 关联的安全事件名称

用户提问：{user_input}

请用JSON格式返回，包含以下字段：
- "contract_address" (string|null)
- "start_block" (number|null)
- "end_block" (number|null) 
- "event_name" (string|null)

示例响应：
{{"contract_address": "0x...", "start_block": 21895238, "end_block": 21895251, "event_name": "Bybit被攻击事件"}}
"""

PRELIMINARY_ANALYSIS_PROMPT = """
作为区块链安全专家，请根据以下信息生成事件初步分析：
1. 已知事件名称：{event_name}
2. 用户原始描述：{user_input}

分析要求：
1. 事件背景和行业影响（100字）
2. 可能涉及的漏洞类型
3. 初步资金流向推测
4. 建议调查方向

输出格式：
### 事件背景
[内容]

### 潜在漏洞
[内容]

### 资金流向推测  
[内容]

### 调查建议
[内容]
"""

FINAL_REPORT_PROMPT = """
基于以下信息生成深度安全分析报告：

# 初步事件分析
{preliminary_analysis}

# 详细合约分析  
{behavior_analysis}

报告要求：
1. 综合分析目标合约和相关合约的安全状况
2. 识别所有参与的合约地址及其角色
3. 分析合约间的调用关系和依赖关系
4. 完整还原可能的攻击链条
5. 提供具体的安全改进建议

格式要求：
## 深度安全分析报告

### 事件概述
[包含时间、涉及合约、交互模式等关键信息]

### 合约分析
1. 目标合约
   [详细分析]

2. 相关合约
   [各合约分析及其关系]

### 交互分析
[详细的调用关系和行为模式分析]

### 漏洞分析
[发现的安全问题及潜在风险]

### 攻击链重现
[可能的攻击路径和步骤]

### 安全建议
[具体的防护措施和改进方案]
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
    """生成综合分析报告"""
    prompt = FINAL_REPORT_PROMPT.format(
        preliminary_analysis=preliminary,
        behavior_analysis=behavior
    )
    return request_ds(prompt, "")




sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from database import get_db
from database.crud import (
    get_user_interactions,
    get_contract_full_info  # 需要新增的CRUD函数
)
from config.settings import settings

BEHAVIOR_PROMPT = """
作为区块链安全分析专家，请对指定区块范围内的合约交互进行全面的安全分析，重点关注：

1. 交互行为分析
   - 识别可疑的调用模式和频率异常
   - 分析input_data中的参数是否存在异常值
   - 追踪资金流向和价值转移路径
   - 检测是否存在权限滥用

2. 事件日志分析
   - 分析合约触发的关键事件
   - 识别异常的事件序列
   - 追踪通过事件传递的重要参数
   - 关联多个合约间的事件链

3. 相关合约分析
   - 详细分析所有反编译代码，包括：
     * 存储布局和状态变量
     * 函数签名和调用关系
     * 关键操作的实现逻辑
   - 识别合约间的依赖关系
   - 检查权限控制机制
   - 评估合约间交互的安全性

4. 攻击特征识别
   - 基于反编译代码匹配已知攻击模式
   - 检测异常的调用序列
   - 识别可疑的地址行为模式
   - 分析可能的攻击向量

分析数据：
目标合约及相关合约代码（包含反编译代码）：
{contract_code_context}

交互方法统计：
{method_list}

事件时序分析：
{timeline_analysis}

关键交易分析：
{input_data_analysis}

事件日志分析：
{event_logs_analysis}

请按以下格式输出分析报告：

### 交互行为分析
1. 时序分析
   [详细分析交易的时间顺序和模式]

2. 可疑行为识别
   [列出所有异常的交互模式]

3. 参数分析
   [分析input_data中的异常参数]

4. 调用链分析
   [分析合约间的调用关系]

### 事件日志分析
1. 关键事件分析
   [分析重要事件的触发模式和参数]

2. 事件序列追踪
   [分析相关事件的时序关系]

3. 跨合约事件关联
   [分析多个合约间的事件关联]

### 合约安全分析
1. 反编译代码分析
   [详细分析每个合约的反编译代码，包括：
    - 存储布局和状态变量的用途
    - 关键函数的实现逻辑
    - 可能存在的漏洞]

2. 相关合约漏洞
   [基于反编译代码，分析交互合约可能对目标合约带来的安全问题]

3. 权限控制审计
   [基于反编译代码评估权限管理机制]

4. 合约依赖风险
   [分析合约间依赖可能带来的风险]

### 攻击链分析
1. 攻击模式匹配
   [基于反编译代码分析是否存在已知攻击模式]

2. 攻击路径重现
   [基于反编译代码分析可能的攻击路径]

3. 漏洞利用分析
   [基于反编译代码分析漏洞如何被利用]

### 安全建议
1. 紧急修复建议
   [需要立即处理的问题]

2. 长期加固方案
   [系统性的安全改进建议]

### 风险等级评估
[综合评估安全风险等级，并说明理由]
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
    """
    加载合约代码信息（包含代理链）
    返回结构：
    [
        {
            "address": "0x...",
            "type": "Proxy"|"Logic",
            "source_code": str,
            "decompiled_code": str,
            "abi": list
        },
        ...
    ]
    """
    contracts_chain = []
    
    # 获取初始合约信息
    current_contract = get_contract_full_info(db, target_contract)
    if not current_contract:
        return []
    
    # 处理代理链
    while current_contract:
        contract_type = "Proxy" if current_contract["is_proxy"] else "Logic"
        
        # 确保ABI是有效的列表
        abi = current_contract.get("abi", [])
        if not isinstance(abi, list):
            if isinstance(abi, str):
                try:
                    # 尝试解析ABI字符串
                    if abi.strip().startswith('['):
                        import json
                        abi = json.loads(abi)
                    elif abi == "Contract source code not verified":
                        print(f"合约 {target_contract} 源码未验证，使用空ABI")
                        abi = []
                    else:
                        print(f"无法识别的ABI格式: {abi[:50]}...")
                        abi = []
                except Exception as e:
                    print(f"解析ABI字符串失败: {str(e)}")
                    abi = []
            else:
                print(f"无效的ABI格式: {type(abi)}")
                abi = []
        
        # 确保ABI是有效的格式
        if not isinstance(abi, list):
            print(f"转换后ABI仍然不是列表: {type(abi)}")
            abi = []
        
        code_info = {
            "address": current_contract["address"],
            "type": contract_type,
            "source_code": current_contract.get("source_code", ""),
            "decompiled_code": current_contract.get("decompiled_code", ""),
            "abi": abi
        }
        contracts_chain.append(code_info)
        
        # 移动到父合约
        current_contract = current_contract.get("parent_info")
    
    return contracts_chain

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
                        import json
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
    """
    处理用户查询
    params: 包含以下字段的字典
        - contract_address: 合约地址
        - start_block: 起始区块
        - end_block: 结束区块
        - analysis_type: 分析类型
        - related_addresses: 相关地址列表
        - user_input: 用户原始输入
    """
    try:
        # 参数验证
        if not params.get('contract_address'):
            raise ValueError("缺少合约地址参数")
        
        # 强制设置为以太坊网络
        params['network'] = "ethereum"
        
        # 生成初步分析
        print("\n=== 生成初步分析 ===")
        params_with_input = {
            **params,
            "user_input": params.get("user_input", ""),
            "event_name": "区块链事件分析"
        }
        
        print(params_with_input)

        preliminary = generate_preliminary_analysis(params_with_input)
        if "分析过程中遇到技术问题" in preliminary:
            print("初步分析生成失败，尝试继续进行行为分析...")
        
        # 分析目标合约及相关合约的行为
        print("\n=== 分析合约行为 ===")
        behavior = analyze_behavior_new(
            params['contract_address'], 
            params.get('start_block', 0),
            params.get('end_block', 0),
            params.get('related_addresses', [])
        )
        
        # 如果行为分析也失败，返回简单分析结果
        if "分析过程中遇到技术问题" in behavior or behavior == "在指定区块范围内未发现任何交互":
            simple_report = f"""
### 合约基础信息分析

目标合约: {params['contract_address']}
分析区块范围: {params.get('start_block', 0)} - {params.get('end_block', 0)}

{behavior}

由于技术原因无法生成完整的深度分析报告。建议：
1. 稍后重试
2. 缩小分析的区块范围
3. 使用其他工具辅助分析
"""
            # 保存简单报告
            save_report(simple_report, params)
            return simple_report
        
        # 生成最终深度分析报告
        print("\n=== 生成深度分析报告 ===")
        final_report = generate_final_report(preliminary, behavior)
        
        # 保存完整报告
        save_report(final_report, params)
        
        return final_report
        
    except Exception as e:
        error_report = f"""
### 分析过程出错

在处理您的查询时遇到了错误：{str(e)}

请检查：
1. 合约地址是否正确
2. 区块范围是否有效
3. 系统状态是否正常

建议稍后重试或联系技术支持。
"""
        # 保存错误报告
        save_report(error_report, params)
        return error_report

def save_report(report_content, params):
    """
    保存分析报告为txt文件
    """
    try:
        # 创建reports目录（如果不存在）
        os.makedirs('reports', exist_ok=True)
        
        # 生成文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        contract_addr = params.get('contract_address', 'unknown')[:10]
        blocks = f"{params.get('start_block', 0)}-{params.get('end_block', 0)}"
        filename = f"reports/security_analysis_{contract_addr}_{blocks}_{timestamp}.txt"
        
        # 添加报告头部信息
        header = f"""安全分析报告
生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
目标合约: {params.get('contract_address')}
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

def analyze_behavior_new(target_contract=None, start_block=None, end_block=None, related_addresses=None):
    """
    增强版行为分析函数，添加事件日志分析和交易追踪分析
    """
    db = next(get_db())
    
    # 获取并过滤用户交互数据
    interactions = get_user_interactions(db)
    
    # 过滤目标合约和相关地址的交互
    filtered = []
    for i in interactions:
        # 检查是否在区块范围内
        if start_block and i['block_number'] < start_block:
            continue
        if end_block and i['block_number'] > end_block:
            continue
            
        # 检查是否与目标合约或相关地址有关
        if (i['target_contract'].lower() == target_contract.lower() or
            i['target_contract'].lower() in [addr.lower() for addr in (related_addresses or [])] or
            i['caller_contract'].lower() in [addr.lower() for addr in (related_addresses or [])]):
            filtered.append(i)
    
    # 如果没有交互数据，返回提示信息
    if not filtered:
        return "在指定区块范围内未发现任何交互"
    
    # 按区块号排序交易
    filtered.sort(key=lambda x: x['block_number'])
    
    # 生成时序分析
    timeline_analysis = []
    for idx, tx in enumerate(filtered, 1):
        timeline_analysis.append(
            f"{idx}. 区块 {tx['block_number']} - 交易 {tx['tx_hash']}\n"
            f"   调用者: {tx['caller_contract']}\n"
            f"   目标合约: {tx['target_contract']}\n"
            f"   调用方法: {tx['method_name']}\n"
            f"   时间戳: {tx['timestamp']}\n"
        )
    
    # 统计方法调用
    method_counter = Counter([i['method_name'] for i in filtered])
    sorted_methods = method_counter.most_common(10)
    
    # 加载所有相关合约代码
    all_contracts = {target_contract.lower()}
    all_contracts.update(addr.lower() for addr in (related_addresses or []))
    
    contracts_code = {}
    for contract in all_contracts:
        chain = load_contract_code(db, contract)
        if chain:
            contracts_code[contract] = chain
    
    # 分析重要交易的input_data、event_logs和trace_data
    important_txs = []
    event_logs_analysis = []
    trace_analysis = []
    input_data_addresses = set()  # 新增：存储从input_data中提取的地址
    
    for interaction in filtered:
        # 分析input_data
        if interaction.get('input_data'):
            contract_chain = contracts_code.get(interaction['target_contract'].lower(), [])
            abi = contract_chain[0].get('abi') if contract_chain else None
            
            analysis = analyze_input_data(interaction['input_data'], abi)
            important_txs.append({
                'tx_hash': interaction['tx_hash'],
                'target_contract': interaction['target_contract'],
                'caller_contract': interaction['caller_contract'],
                'block_number': interaction['block_number'],
                'timestamp': interaction['timestamp'],
                'analysis': analysis
            })
            
            # 收集从input_data中提取的地址
            if 'extracted_addresses' in analysis:
                for addr in analysis['extracted_addresses']:
                    if Web3.is_address(addr):
                        input_data_addresses.add(addr.lower())
        
        # 分析event_logs
        if interaction.get('event_logs'):
            try:
                logs = json.loads(interaction['event_logs'])
                for log in logs:
                    contract_chain = contracts_code.get(log['address'].lower(), [])
                    abi = contract_chain[0].get('abi') if contract_chain else None
                    
                    # 确保ABI是有效的列表
                    if not isinstance(abi, list):
                        continue
                        
                    # 尝试解码事件
                    event_analysis = {
                        'contract': log['address'],
                        'topics': log['topics'],
                        'data': log['data'],
                        'block_number': log['blockNumber'],
                        'tx_hash': log['transactionHash']
                    }
                    
                    if abi and len(abi) > 0:
                        try:
                            # 尝试根据ABI解码事件
                            contract = Web3().eth.contract(abi=abi)
                            event_obj = contract.events
                            for event_name in dir(event_obj):
                                if event_name.startswith('__'):
                                    continue
                                try:
                                    event = getattr(event_obj, event_name)
                                    decoded = event().process_log(log)
                                    event_analysis['decoded'] = {
                                        'name': event_name,
                                        'args': {k: str(v) for k, v in decoded['args'].items()}  # 确保所有值都是可序列化的
                                    }
                                    break
                                except Exception as e:
                                    # 这个事件不匹配，继续尝试下一个
                                    continue
                        except Exception as e:
                            print(f"事件解码失败: {str(e)}")
                    
                    event_logs_analysis.append(event_analysis)
            except Exception as e:
                print(f"事件日志分析失败: {str(e)}")
                traceback.print_exc()
        
        # 分析trace_data
        if interaction.get('trace_data'):
            try:
                trace_data = json.loads(interaction['trace_data'])
                
                # 分析调用链
                call_chain = []
                
                def process_call(call_data, depth=0):
                    if not call_data:
                        return
                    
                    # 获取当前调用的基本信息
                    call_info = {
                        'depth': depth,
                        'from': call_data.get('from', ''),
                        'to': call_data.get('to', ''),
                        'value': call_data.get('value', '0'),
                        'gas': call_data.get('gas', '0'),
                        'input': call_data.get('input', ''),
                        'type': call_data.get('type', ''),
                        'method': 'unknown'
                    }
                    
                    # 尝试解析方法名称
                    if call_info['to'] and call_info['input'] and call_info['input'].startswith('0x'):
                        # 获取目标合约的ABI
                        contract_chain = contracts_code.get(call_info['to'].lower(), [])
                        abi = contract_chain[0].get('abi') if contract_chain else None
                        
                        if abi:
                            try:
                                contract = Web3().eth.contract(abi=abi)
                                selector = call_info['input'][:10]  # 方法选择器是前10个字符（包括0x）
                                
                                for func in contract.functions:
                                    if func.function_signature_hash == selector:
                                        call_info['method'] = func.fn_name
                                        break
                            except Exception as e:
                                print(f"解析方法名称失败: {str(e)}")
                    
                    call_chain.append(call_info)
                    
                    # 递归处理子调用
                    if 'calls' in call_data and isinstance(call_data['calls'], list):
                        for subcall in call_data['calls']:
                            process_call(subcall, depth + 1)
                
                # 处理根调用
                process_call(trace_data)
                
                trace_analysis.append({
                    'tx_hash': interaction['tx_hash'],
                    'block_number': interaction['block_number'],
                    'timestamp': interaction['timestamp'],
                    'call_chain': call_chain
                })
                
            except Exception as e:
                print(f"交易追踪分析失败: {str(e)}")
    
    # 将从input_data中提取的地址添加到相关合约中
    print(f"\n从input_data中提取了 {len(input_data_addresses)} 个地址")
    for addr in input_data_addresses:
        if addr not in contracts_code:
            try:
                # 检查是否是合约地址
                code = Web3(Web3.HTTPProvider(settings.NETWORKS['ethereum']['rpc_url'])).eth.get_code(addr)
                if code and code.hex() != '0x':  # 如果有代码，说明是合约
                    print(f"从input_data中发现新合约: {addr}")
                    chain = load_contract_code(db, addr)
                    if chain:
                        contracts_code[addr] = chain
            except Exception as e:
                print(f"检查地址 {addr} 时出错: {str(e)}")
    
    # 构建分析上下文
    block_range_info = f" (区块范围: {start_block} - {end_block})"
    method_list_str = "\n".join(
        [f"- {method} (调用次数: {count}){block_range_info}" 
         for method, count in sorted_methods]
    )
    
    code_context = "\n\n".join(
        [f"合约 {addr} 的代码链分析：\n{generate_code_context(chain)}" 
         for addr, chain in contracts_code.items()]
    )
    
    # 生成时序分析字符串
    timeline_str = "\n".join(timeline_analysis)
    
    # 生成input_data分析字符串，包括提取的地址
    input_data_analysis = "\n".join([
        f"交易 {tx['tx_hash']} (调用者: {tx['caller_contract']}, 目标: {tx['target_contract']}, 区块: {tx['block_number']}, 时间: {tx['timestamp']}):\n" +
        f"方法: {tx['analysis'].get('method', tx['analysis'].get('method_id', 'unknown'))}\n" +
        f"参数: {json.dumps(tx['analysis'].get('params', []), indent=2)}\n" +
        f"提取的地址: {json.dumps(tx['analysis'].get('extracted_addresses', []), indent=2)}"
        for tx in important_txs
    ])
    
    # 生成event_logs分析字符串
    event_logs_str = "\n".join([
        f"事件日志 (合约: {log['contract']}, 交易: {log['tx_hash']}, 区块: {log['block_number']}):\n{json.dumps(log.get('decoded', {'topics': log['topics'], 'data': log['data']}), indent=2)}"
        for log in event_logs_analysis
    ])
    
    # 生成trace分析字符串
    trace_str = "\n".join([
        f"交易追踪 (交易: {trace['tx_hash']}, 区块: {trace['block_number']}, 时间: {trace['timestamp']}):\n" +
        "\n".join([
            f"  {'  ' * call['depth']}[{call['depth']}] {call['from']} -> {call['to']} ({call['method']}) [类型: {call['type']}, 值: {call['value']}]"
            for call in trace['call_chain']
        ])
        for trace in trace_analysis
    ])
    
    # 更新提示词模板，添加trace分析部分
    BEHAVIOR_PROMPT_WITH_TRACE = BEHAVIOR_PROMPT.replace(
        "事件日志分析：\n{event_logs_analysis}",
        "事件日志分析：\n{event_logs_analysis}\n\n交易追踪分析：\n{trace_analysis}"
    )
    
    # 生成分析报告
    full_prompt = BEHAVIOR_PROMPT_WITH_TRACE.format(
        contract_code_context=code_context,
        method_list=method_list_str,
        input_data_analysis=input_data_analysis,
        timeline_analysis=timeline_str,
        event_logs_analysis=event_logs_str,
        trace_analysis=trace_str
    )
    
    return request_ds(full_prompt, "")


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
        contract_code_context=code_context,
        method_list=method_list_str
    )
    
    report = request_ds(full_prompt, "")
    
    # 保存结果
    filename = f"report_{target_contract or 'all'}.md"
    with open(filename, "w") as f:
        f.write(report)
    
    print(f"分析报告已生成：{filename}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--query":
        user_input = " ".join(sys.argv[2:])
        process_user_query(user_input)
    else:
        target = sys.argv[1] if len(sys.argv) > 1 else None
        analyze_behavior(target)
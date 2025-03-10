import sys
import os
from collections import Counter
from sqlalchemy.orm import Session
from database.models import Contract,UserInteraction
import json
from web3 import Web3

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
作为区块链行为分析专家，请完成以下任务：
1. 分析目标合约和相关合约的代码实现（包括代理合约逻辑）
2. 结合调用频率和input_data解释用户行为模式
3. 分析合约之间的调用关系和交互模式
4. 识别可能的漏洞和安全风险
5. 分析input_data中包含的地址和参数信息

合约代码信息：
{contract_code_context}

调用方法列表（按频率排序）：
{method_list}

重要交易的input_data分析：
{input_data_analysis}

输出格式：
### 合约代码分析
1. 目标合约分析
   - 合约类型：[代理合约/实现合约/普通合约]
   - 主要功能：[功能描述]
   - 关键方法：[方法列表及说明]

2. 相关合约分析
   - 合约地址：[地址]
   - 合约类型：[类型]
   - 与目标合约的关系：[调用关系/依赖关系]

### 交互行为分析
1. 高频方法分析
   - 方法名称：[方法名]
   - 调用次数：[次数]
   - 功能描述：[分析]
   - 参数分析：[基于input_data的解析]

2. 合约间调用关系
   [分析合约之间的调用链和依赖关系]

### 安全风险评估
1. 代码层面风险
   [分析代码中的潜在漏洞]

2. 交互层面风险
   [分析交互模式中的异常]

3. 权限管理风险
   [分析权限控制机制]
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

def request_ds(prompt, abi):
  completion = client.chat.completions.create(
    # extra_headers={
      # "HTTP-Referer": "<YOUR_SITE_URL>", # Optional. Site URL for rankings on openrouter.ai.
      # "X-Title": "<YOUR_SITE_NAME>", # Optional. Site title for rankings on openrouter.ai.
    # },
    model=MODELNAME,
    messages=[
      {
        "role": "system",
        "content": prompt+abi
      }
    ]
  )
  return completion.choices[0].message.content

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
        
        code_info = {
            "address": current_contract["address"],
            "type": contract_type,
            "source_code": current_contract["source_code"],
            "decompiled_code": current_contract["decompiled_code"],
            "abi": current_contract["abi"]
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
        if contract["source_code"]:
            code_sections.append(
                f"// 验证源码（{contract['type']}合约 {contract['address']}）\n"
                f"{contract['source_code']}"
            )
        
        # 反编译代码
        elif contract["decompiled_code"]:
            code_sections.append(
                f"// 反编译代码（{contract['type']}合约 {contract['address']}）\n"
                f"{contract['decompiled_code']}"
            )
        
        # ABI信息
        if contract["abi"]:
            code_sections.append(
                f"// ABI定义（{contract['type']}合约 {contract['address']}）\n"
                f"{json.dumps(contract['abi'], indent=2)}"
            )
        
        context.append("\n\n".join(code_sections))
    
    return "\n\n" + "="*50 + "\n\n".join(context) + "\n\n" + "="*50

def analyze_input_data(input_data, abi):
    """分析input_data中的参数"""
    try:
        # 如果有ABI，尝试解码
        if abi:
            contract = Web3().eth.contract(abi=abi)
            decoded = contract.decode_function_input(input_data)
            return {
                'method': decoded[0].fn_name,
                'params': dict(decoded[1])
            }
    except:
        pass
    
    # 如果没有ABI或解码失败，进行基础解析
    if input_data.startswith('0x'):
        input_data = input_data[2:]
    
    method_id = input_data[:8]
    params = []
    data = input_data[8:]
    
    # 每32字节（64个字符）为一个参数
    for i in range(0, len(data), 64):
        param = data[i:i+64]
        # 检查是否是地址
        if param.startswith('000000000000000000000000'):
            params.append(f"Address: 0x{param[-40:]}")
        else:
            # 尝试转换为整数
            try:
                value = int(param, 16)
                params.append(f"Value: {value}")
            except:
                params.append(f"Raw: {param}")
    
    return {
        'method_id': method_id,
        'params': params
    }

def process_user_query(params):
    """
    处理用户查询
    params: 包含以下字段的字典
        - contract_address: 合约地址
        - start_block: 起始区块
        - end_block: 结束区块
        - analysis_type: 分析类型
        - related_addresses: 相关地址列表（包括交互地址和input_data中的地址）
        - user_input: 用户原始输入
    """
    # 参数验证
    if not params.get('contract_address'):
        raise ValueError("缺少合约地址参数")
    
    # 生成初步分析
    print("\n=== 生成初步分析 ===")
    # 添加用户原始输入到参数中
    params_with_input = {
        **params,
        "user_input": params.get("user_input", ""),
        "event_name": "区块链安全分析"  # 默认事件名称
    }
    preliminary = generate_preliminary_analysis(params_with_input)
    
    # 分析目标合约及相关合约的行为
    print("\n=== 分析合约行为 ===")
    behavior = analyze_behavior_new(
        params['contract_address'], 
        params.get('start_block', 0),
        params.get('end_block', 0),
        params.get('related_addresses', [])  # 传入相关地址列表
    )
    
    # 检查行为分析是否有效
    if behavior == "在指定区块范围内未发现任何交互":
        return behavior
    
    # 生成最终深度分析报告
    print("\n=== 生成深度分析报告 ===")
    final_report = generate_final_report(
        preliminary, 
        behavior
    )
    
    return final_report

def analyze_behavior_new(target_contract=None, start_block=None, end_block=None, related_addresses=None):
    """
    增强版行为分析函数
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
    
    # 统计方法调用
    method_counter = Counter([i['method_name'] for i in filtered])
    sorted_methods = method_counter.most_common(10)
    
    # 加载所有相关合约代码（包括目标合约和相关地址）
    all_contracts = {target_contract.lower()}  # 从目标合约开始
    all_contracts.update(addr.lower() for addr in (related_addresses or []))  # 添加相关地址
    
    contracts_code = {}
    for contract in all_contracts:
        chain = load_contract_code(db, contract)
        if chain:  # 只添加有代码的合约
            contracts_code[contract] = chain
    
    # 分析重要交易的input_data
    important_txs = []
    for interaction in filtered[:10]:  # 分析最近的10笔交易
        if interaction.get('input_data'):
            contract_chain = contracts_code.get(interaction['target_contract'].lower(), [])
            abi = contract_chain[0].get('abi') if contract_chain else None
            
            analysis = analyze_input_data(interaction['input_data'], abi)
            important_txs.append({
                'tx_hash': interaction['tx_hash'],
                'target_contract': interaction['target_contract'],
                'caller_contract': interaction['caller_contract'],
                'block_number': interaction['block_number'],
                'analysis': analysis
            })
    
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
    
    input_data_analysis = "\n".join([
        f"交易 {tx['tx_hash']} (调用者: {tx['caller_contract']}, 目标: {tx['target_contract']}, 区块: {tx['block_number']}):\n{json.dumps(tx['analysis'], indent=2)}"
        for tx in important_txs
    ])
    
    # 生成分析报告
    full_prompt = BEHAVIOR_PROMPT.format(
        contract_code_context=code_context,
        method_list=method_list_str,
        input_data_analysis=input_data_analysis
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
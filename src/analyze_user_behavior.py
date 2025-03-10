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
结合以下分析生成最终安全报告：
# 初步事件分析
{preliminary_analysis}

# 详细合约分析  
{behavior_analysis}

报告要求：
1. 关联合约行为与安全事件
2. 确认漏洞利用的技术细节
3. 完整的攻击链条还原
4. 资金追踪方案建议
5. 安全防护改进建议

格式要求：
## 最终安全分析报告
### 事件概述
[包含时间、涉及金额等关键信息]

### 技术分析
[合约调用与漏洞的对应关系]

### 攻击链条还原
[按时间顺序的步骤分析]

### 资金追踪
[地址列表和追踪建议]

### 防护建议
[针对性的改进方案]
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
1. 分析用户调用的方法在合约代码中的具体功能（包括代理合约逻辑）
2. 结合调用频率和input_data解释用户行为模式
3. 如果是标准ERC-20方法但未在源码中找到实现，请按标准规范分析
4. 识别潜在安全问题
5. 分析input_data中包含的地址和参数信息

合约代码信息：
{contract_code_context}

调用方法列表（按频率排序）：
{method_list}

重要交易的input_data分析：
{input_data_analysis}

输出格式：
### 高频方法分析
1. 方法名称：[方法名]
   - 调用次数：[次数]
   - 功能描述：[LLM分析]
   - 代码来源：[主合约/代理合约/标准ERC20]
   - 参数分析：[基于input_data的参数解析]

### 相关地址分析
[分析从input_data中提取的地址的角色和行为]

### 用户行为总结
[用200字总结用户行为模式]

### 合约安全评估
[分析潜在风险和安全建议]
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

def analyze_behavior_new(target_contract=None, start_block=None, end_block=None):
    """
    增强版行为分析函数
    """
    db = next(get_db())
    
    # 获取并过滤用户交互数据
    interactions = get_user_interactions(db)
    filtered = [
        i for i in interactions 
        if (not target_contract or i['target_contract'] == target_contract) and
           (not start_block or i['block_number'] >= start_block) and
           (not end_block or i['block_number'] <= end_block)
    ]
    
    # 如果没有交互数据，返回提示信息
    if not filtered:
        return "在指定区块范围内未发现任何交互"
    
    # 统计方法调用
    method_counter = Counter([i['method_name'] for i in filtered])
    sorted_methods = method_counter.most_common(10)
    
    # 加载合约代码
    all_contracts = set(i['target_contract'] for i in filtered)
    contracts_code = {}
    for contract in all_contracts:
        contracts_code[contract] = load_contract_code(db, contract)
    
    # 分析重要交易的input_data
    important_txs = []
    for interaction in filtered[:5]:  # 分析最近的5笔交易
        if interaction.get('input_data'):
            contract_chain = contracts_code.get(interaction['target_contract'], [])
            abi = contract_chain[0].get('abi') if contract_chain else None
            
            analysis = analyze_input_data(interaction['input_data'], abi)
            important_txs.append({
                'tx_hash': interaction['tx_hash'],
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
        f"交易 {tx['tx_hash']}:\n{json.dumps(tx['analysis'], indent=2)}"
        for tx in important_txs
    ])
    
    # 检测ERC20方法
    erc20_methods = {
        'transfer', 'transferFrom', 'approve', 
        'balanceOf', 'allowance', 'totalSupply'
    }
    detected_erc20 = erc20_methods & set(method_counter.keys())
    if detected_erc20:
        code_context += "\n\n检测到标准ERC-20方法：" + ", ".join(detected_erc20)
    
    # 生成分析报告
    full_prompt = BEHAVIOR_PROMPT.format(
        contract_code_context=code_context,
        method_list=method_list_str,
        input_data_analysis=input_data_analysis
    )
    
    return request_ds(full_prompt, "")


def process_user_query(params):
    """
    处理用户查询
    params: 包含以下字段的字典
        - contract_address: 合约地址
        - start_block: 起始区块
        - end_block: 结束区块
        - analysis_type: 分析类型
        - related_addresses: 相关地址列表
        - preliminary_analysis: 初步分析结果（可选）
    """
    db = next(get_db())
    
    # 1. 获取目标合约信息
    target_contract_info = get_contract_full_info(db, params['contract_address'])
    if not target_contract_info:
        return "未找到目标合约信息"
    
    # 2. 获取所有相关合约信息
    related_contracts = {}
    if params.get('related_addresses'):
        for addr in params['related_addresses']:
            contract_info = get_contract_full_info(db, addr)
            if contract_info:  # 只收集合约地址的信息
                related_contracts[addr] = contract_info
    
    # 3. 获取交互历史
    interactions = get_user_interactions(db)
    filtered_interactions = [
        i for i in interactions 
        if (i['target_contract'] == params['contract_address']) and
           (not params.get('start_block') or i['block_number'] >= params['start_block']) and
           (not params.get('end_block') or i['block_number'] <= params['end_block'])
    ]
    
    # 4. 生成完整的分析上下文
    analysis_context = {
        "target_contract": {
            "address": params['contract_address'],
            "info": target_contract_info
        },
        "related_contracts": related_contracts,
        "interactions": filtered_interactions,
        "preliminary_analysis": params.get('preliminary_analysis', '')
    }
    
    # 5. 根据分析类型选择不同的处理流程
    if params.get('analysis_type') == 'contract_analysis':
        return analyze_contracts_only(analysis_context)
    
    # 6. 生成完整分析报告
    preliminary = generate_preliminary_analysis(params)
    behavior = analyze_behavior_new(
        params['contract_address'],
        params.get('start_block'),
        params.get('end_block')
    )
    
    final_report = generate_final_report(
        preliminary if not params.get('preliminary_analysis') else params['preliminary_analysis'],
        behavior
    )
    
    return final_report

def analyze_contracts_only(context):
    """仅分析合约代码的函数"""
    # 构建合约分析提示词
    prompt = """作为智能合约安全专家，请分析以下合约：

目标合约信息：
{target_info}

相关合约信息：
{related_info}

请重点关注：
1. 合约功能和架构
2. 代理合约关系
3. 潜在安全漏洞
4. 合约间的交互风险

输出格式：
### 合约架构分析
[分析合约的整体架构和主要功能]

### 安全风险评估
[详细列出发现的潜在安全问题]

### 改进建议
[具体的安全加固建议]
"""
    
    # 准备合约信息
    target_info = json.dumps(context['target_contract'], indent=2)
    related_info = json.dumps(context['related_contracts'], indent=2)
    
    # 生成分析报告
    return request_ds(
        prompt.format(
            target_info=target_info,
            related_info=related_info
        ),
        ""
    )

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
# llm_processor.py
import os
import json
import requests  # 新增用于直接查询区块号
from openai import OpenAI
from web3 import Web3
from datetime import datetime
from config.settings import settings

# 初始化客户端（保持不变）
client = OpenAI(base_url=settings.BASEURL, api_key=settings.APIKEY)
w3 = Web3(Web3.HTTPProvider(os.getenv("ALCHEMY_URL")))

SYSTEM_PROMPT = """作为区块链专家，你很了解目前区块链上线的项目新闻。当用户向你提问一些近期的热点事件时，你可以联网搜索后找到这些热点事件对应的合约地址以及涉及到的区块范围start_block和end_block，如果找不到区块范围，则返回start_date和end_date。你需要先输出你的分析结果，之后返回JSON格式响应，包含以下字段：
{
  "contract_address": "有效的以太坊地址",
  "start_block": 数字（可选）,
  "end_block": 数字（可选）,
  "start_date": "YYYY-MM-DD"（可选）,
  "end_date": "YYYY-MM-DD"（可选）
}

规则：
1. 必须包含contract_address
2. 区块号和时间范围至少提供一组
3. 如果知道确切区块号，优先使用区块号
4. 地址必须校验通过

示例响应：
{
  "contract_address": "0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4",
  "start_block": 18976543,
  "end_block": 19221876
}"""

def ask_llm(prompt):
    """改进版大模型交互"""
    try:
        completion = client.chat.completions.create(
            model=settings.MODELNAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            response_format={"type": "json_object"}
        )
        
        # 新增调试日志
        raw_response = completion.choices[0].message.content
        print(f"[DEBUG] 原始响应内容: {raw_response}")  # 调试关键点
        
        response = json.loads(raw_response)
        
        raw_content = response.json()['choices'][0]['message']['content']
        
        # 关键修复步骤
        raw_content = clean_json_string(raw_content)
        parsed = parse_json_response(raw_content)
        
        # 地址验证增强版
        addr = parsed.get("contract_address")
        if not addr:
            raise ValueError("contract_address字段缺失")
        if not Web3.is_address(addr):
            raise ValueError(f"非法地址格式: {addr}")
        parsed["contract_address"] = Web3.to_checksum_address(addr)
        
        # 区块号类型转换
        if "start_block" in parsed:
            parsed["start_block"] = int(parsed["start_block"])
        if "end_block" in parsed:
            parsed["end_block"] = int(parsed["end_block"])
            
        return parsed
    except Exception as e:
        print(f"最终解析失败: {str(e)}")
        return None

def validate_block_number(block_num):
    """区块号验证"""
    if not isinstance(block_num, int) or block_num <= 0:
        return False
    try:
        return w3.eth.get_block(block_num) is not None
    except:
        return False

def get_block_range_from_api(contract_address):
    """新增：通过Etherscan API获取最新区块信息"""
    api_url = f"https://api.etherscan.io/api?module=account&action=txlist&address={contract_address}&sort=asc&apikey={os.getenv('ETHERSCAN_API_KEY')}"
    
    try:
        response = requests.get(api_url).json()
        if response["status"] == "1":
            transactions = response["result"]
            return {
                "start_block": int(transactions[0]["blockNumber"]),
                "end_block": int(transactions[-1]["blockNumber"])
            }
        return None
    except:
        return None

def get_block_range(response_data):
    """智能获取区块范围"""
    contract_address = Web3.to_checksum_address(response_data["contract_address"])
    
    # 优先使用用户提供的区块号
    if "start_block" in response_data and "end_block" in response_data:
        start_block = int(response_data["start_block"])
        end_block = int(response_data["end_block"])
        
        if validate_block_number(start_block) and validate_block_number(end_block):
            if start_block > end_block:
                start_block, end_block = end_block, start_block
            return {"start_block": start_block, "end_block": end_block}
    
    # 次优先使用API查询
    api_result = get_block_range_from_api(contract_address)
    if api_result:
        return api_result
    
    # 最后使用日期转换
    if "start_date" in response_data and "end_date" in response_data:
        def date_to_block(date_str):
            # 保持原有日期转区块逻辑
            pass
        return {
            "start_block": date_to_block(response_data["start_date"]),
            "end_block": date_to_block(response_data["end_date"])
        }
    
    raise ValueError("无法确定区块范围")

def search_contract_info(question):
    """改进后的主处理函数"""
    llm_response = ask_llm(question)
    if not llm_response:
        return None
    
    try:
        contract_address = Web3.to_checksum_address(llm_response["contract_address"])
        block_range = get_block_range(llm_response)
        
        return {
            "contract_address": contract_address,
            "start_block": block_range["start_block"],
            "end_block": block_range["end_block"]
        }
    except Exception as e:
        print(f"数据处理错误: {str(e)}")
        return None
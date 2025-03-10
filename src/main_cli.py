from llm_processor import search_contract_info
from main import ContractAnalyzer, get_contract_metadata, process_contract_metadata, upsert_contract, get_db, get_bytecode, decompile_bytecode
import os

def main():
    # 用户输入自然语言问题
    question = input("请输入你的分析需求（例如：分析Bybit最近的黑客事件）: ")
    
    # 1. 通过大模型获取信息
    contract_info = search_contract_info(question)
    if not contract_info:
        print("无法获取合约信息")
        return
    
    print(f"分析目标：{contract_info['contract_address']}")
    print(f"区块范围：{contract_info['start_block']} - {contract_info['end_block']}")
    
    # 2. 执行原有逻辑
    analyzer = ContractAnalyzer()
    
    # 获取元数据
    metadata = get_contract_metadata(contract_info["contract_address"])
    processed = process_contract_metadata(metadata)
    
    # 准备合约数据
    contract_data = {
        "address": contract_info["contract_address"].lower(),
        "block_number": contract_info["start_block"],
        **processed
    }
    
    # 更新数据库
    db = next(get_db())
    upsert_contract(db, contract_data)
    
    # 处理字节码
    bytecode = get_bytecode(contract_info["contract_address"])
    if bytecode:
        decompile_bytecode(bytecode, contract_info["contract_address"])
    
    # 执行分析
    analyzer.analyze_contract(
        contract_info["contract_address"],
        contract_info["start_block"],
        contract_info["end_block"]
    )

if __name__ == "__main__":
    main()
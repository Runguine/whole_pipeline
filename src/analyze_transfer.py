import sys
import os
import json
import time
from datetime import datetime
from web3 import Web3
import traceback
from sqlalchemy import and_, or_

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from database import get_db
from database.models import UserInteraction
from config.settings import settings
from analyze_user_behavior import request_ds, save_report
from database.crud import get_contract_full_info as get_contract_full_info


# 定义普通转账分析提示词
TRANSFER_ANALYSIS_PROMPT = """
作为区块链安全分析专家，请对以下普通转账交易进行全面分析：

转账发送方: {from_address}
转账接收方: {to_address}
转账金额: {value} ETH
区块范围: {block_range}
交易数量: {tx_count}

== 转账模式分析 ==
{transfer_patterns}

== 地址特征分析 ==
{address_characteristics}

请结合上述信息，提供详细的转账分析报告，包括:
1. 转账交易的目的和特点
2. 资金流向分析
3. 可能的意图判断（普通交易、投资行为、兑换、套利等）
4. 风险评估（如果有可疑特征）
5. 相关建议

请特别关注以下模式，并给出专业分析：
1. 资金拆分：大额资金被拆分成多笔小额转账
2. 快速转入转出：资金在短时间内转入后立即转出
3. 异常时间模式：非交易高峰期的异常交易行为
4. 来源/去向特征：与已知交易所、混币器等特殊地址的交互
"""


def analyze_eth_transfers(from_address, to_address=None, start_block=None, end_block=None):
    """
    分析普通ETH转账交易
    
    Args:
        from_address (str): 转账发送方地址
        to_address (str): 转账接收方地址，可选
        start_block (int): 开始区块
        end_block (int): 结束区块
        
    Returns:
        str: 分析报告
    """
    print(f"\n=== 开始分析普通转账 ===")
    print(f"发送方: {from_address}")
    print(f"接收方: {to_address if to_address else '任意'}")
    print(f"区块范围: {start_block} - {end_block}")
    
    # 获取数据库会话
    db = next(get_db())
    w3 = Web3(Web3.HTTPProvider(settings.NETWORKS["ethereum"]["rpc_url"]))
    
    try:
        # 构建查询条件
        query_conditions = []
        
        # 地址条件
        from_condition = UserInteraction.caller_contract == from_address.lower()
        query_conditions.append(from_condition)
        
        if to_address:
            to_condition = UserInteraction.target_contract == to_address.lower()
            query_conditions.append(to_condition)
        
        # 区块范围条件
        if start_block is not None:
            query_conditions.append(UserInteraction.block_number >= start_block)
        if end_block is not None:
            query_conditions.append(UserInteraction.block_number <= end_block)
        
        # 执行查询
        transactions = db.query(UserInteraction).filter(
            and_(*query_conditions)
        ).all()
        
        # 检查是否有交易记录
        if not transactions:
            print(f"未找到任何符合条件的交易记录！")
            return "未找到任何符合条件的交易记录，请检查地址和区块范围是否正确。"
        
        print(f"找到 {len(transactions)} 笔相关交易")
        
        # 分析转账模式
        transfer_patterns = analyze_transfer_patterns(transactions)
        
        # 分析地址特征
        address_characteristics = analyze_address_characteristics(from_address, to_address)
        
        # 组装分析参数
        analysis_params = {
            "from_address": from_address,
            "to_address": to_address if to_address else "多个接收方",
            "value": sum_transaction_values(transactions),
            "block_range": f"{start_block} - {end_block}",
            "tx_count": len(transactions),
            "transfer_patterns": transfer_patterns,
            "address_characteristics": address_characteristics
        }
        
        # 使用LLM进行分析
        report = generate_transfer_analysis(analysis_params)
        
        # 保存报告
        report_file = save_transfer_report(report, analysis_params)
        print(f"报告已保存至: {report_file}")
        
        return report
        
    except Exception as e:
        error_msg = f"分析普通转账时出错: {str(e)}"
        print(error_msg)
        traceback.print_exc()
        return f"### 分析过程出错\n\n{error_msg}"


def analyze_transfer_patterns(transactions):
    """
    分析转账交易模式
    
    Args:
        transactions (list): 交易列表
        
    Returns:
        str: 转账模式分析文本
    """
    if not transactions:
        return "无交易数据可分析"
    
    # 按时间排序
    sorted_txs = sorted(transactions, key=lambda x: x.timestamp if x.timestamp else datetime.now())
    
    # 提取关键信息
    tx_details = []
    for tx in sorted_txs:
        try:
            # 解析交易数据
            value = 0
            if tx.trace_data:
                trace = json.loads(tx.trace_data)
                if isinstance(trace, dict) and 'action' in trace:
                    value_hex = trace['action'].get('value', '0x0')
                    value = int(value_hex, 16) / 10**18  # 转换为ETH
            
            tx_details.append({
                'hash': tx.tx_hash,
                'from': tx.caller_contract,
                'to': tx.target_contract,
                'value': value,
                'timestamp': tx.timestamp.strftime('%Y-%m-%d %H:%M:%S') if tx.timestamp else 'Unknown',
                'block': tx.block_number
            })
        except Exception as e:
            print(f"解析交易 {tx.tx_hash} 时出错: {str(e)}")
    
    # 分析转账模式
    patterns = []
    
    # 1. 检查交易频率
    if len(tx_details) > 10:
        avg_interval = calculate_average_interval(tx_details)
        if avg_interval < 300:  # 少于5分钟
            patterns.append(f"高频交易：平均交易间隔 {avg_interval:.1f} 秒")
    
    # 2. 检查交易金额分布
    values = [tx['value'] for tx in tx_details if tx['value'] > 0]
    if values:
        avg_value = sum(values) / len(values)
        max_value = max(values)
        min_value = min(values)
        patterns.append(f"交易金额：最小 {min_value:.4f} ETH，最大 {max_value:.4f} ETH，平均 {avg_value:.4f} ETH")
        
        # 检查金额是否相似（可能是拆分交易）
        if len(values) > 3 and max_value / min_value < 1.2:
            patterns.append("金额相似：多笔交易金额非常接近，可能是拆分交易")
    
    # 3. 检查是否有快速转入转出
    if to_from_pattern_exists(tx_details):
        patterns.append("检测到快速转入转出模式：资金在短时间内被接收后又转出")
    
    # 组装结果
    result = "\n".join([
        "交易总数：" + str(len(tx_details)),
        "交易时间范围：" + (tx_details[0]['timestamp'] + " 至 " + tx_details[-1]['timestamp'] if tx_details else "无数据"),
        "交易模式：",
        "- " + "\n- ".join(patterns) if patterns else "- 未发现明显模式"
    ])
    
    # 添加交易列表样本
    sample_size = min(5, len(tx_details))
    sample_txs = tx_details[:sample_size]
    tx_list = "\n交易样本：\n"
    for idx, tx in enumerate(sample_txs, 1):
        tx_list += f"{idx}. 哈希: {tx['hash']}\n"
        tx_list += f"   块高: {tx['block']}, 时间: {tx['timestamp']}\n"
        tx_list += f"   从 {tx['from']} 到 {tx['to']}\n"
        tx_list += f"   金额: {tx['value']:.6f} ETH\n"
    
    return result + tx_list


def analyze_address_characteristics(from_address, to_address=None):
    """
    分析地址特征
    
    Args:
        from_address (str): 发送方地址
        to_address (str): 接收方地址
        
    Returns:
        str: 地址特征分析文本
    """
    db = next(get_db())
    w3 = Web3(Web3.HTTPProvider(settings.NETWORKS["ethereum"]["rpc_url"]))
    
    result = []
    
    # 分析发送方地址
    try:
        # 检查发送方余额
        balance = w3.eth.get_balance(Web3.to_checksum_address(from_address))
        balance_eth = balance / 10**18
        result.append(f"发送方({from_address})当前余额: {balance_eth:.6f} ETH")
        
        # 检查发送方交易历史
        tx_count = w3.eth.get_transaction_count(Web3.to_checksum_address(from_address))
        result.append(f"发送方总交易数: {tx_count}")
        
        # 检查是否为合约
        code = w3.eth.get_code(Web3.to_checksum_address(from_address))
        is_contract = len(code) > 2  # 如果返回的不只是"0x"
        result.append(f"发送方地址类型: {'合约' if is_contract else '外部账户(EOA)'}")
    except Exception as e:
        result.append(f"分析发送方地址时出错: {str(e)}")
    
    # 分析接收方地址
    if to_address:
        try:
            # 检查接收方余额
            balance = w3.eth.get_balance(Web3.to_checksum_address(to_address))
            balance_eth = balance / 10**18
            result.append(f"接收方({to_address})当前余额: {balance_eth:.6f} ETH")
            
            # 检查接收方交易历史
            tx_count = w3.eth.get_transaction_count(Web3.to_checksum_address(to_address))
            result.append(f"接收方总交易数: {tx_count}")
            
            # 检查是否为合约
            code = w3.eth.get_code(Web3.to_checksum_address(to_address))
            is_contract = len(code) > 2
            result.append(f"接收方地址类型: {'合约' if is_contract else '外部账户(EOA)'}")
        except Exception as e:
            result.append(f"分析接收方地址时出错: {str(e)}")
    
    return "\n".join(result)


def generate_transfer_analysis(params):
    """
    使用LLM生成转账分析报告
    
    Args:
        params (dict): 分析参数
        
    Returns:
        str: 分析报告
    """
    prompt = TRANSFER_ANALYSIS_PROMPT.format(
        from_address=params['from_address'],
        to_address=params['to_address'],
        value=params['value'],
        block_range=params['block_range'],
        tx_count=params['tx_count'],
        transfer_patterns=params['transfer_patterns'],
        address_characteristics=params['address_characteristics']
    )
    
    return request_ds(prompt, "")


def save_transfer_report(report_content, params):
    """
    保存转账分析报告
    
    Args:
        report_content (str): 报告内容
        params (dict): 分析参数
        
    Returns:
        str: 报告文件路径
    """
    try:
        # 创建reports目录（如果不存在）
        os.makedirs('reports', exist_ok=True)
        
        # 生成文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        from_addr = params['from_address'][:10]
        to_addr = params['to_address'][:10] if isinstance(params['to_address'], str) else 'multiple'
        filename = f"reports/transfer_analysis_{from_addr}_to_{to_addr}_{timestamp}.txt"
        
        # 添加报告头部信息
        header = f"""转账分析报告
生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
发送方地址: {params['from_address']}
接收方地址: {params['to_address']}
区块范围: {params['block_range']}
交易数量: {params['tx_count']}

{'='*80}

"""
        
        # 写入文件
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(header + report_content)
            
        print(f"\n报告已保存至: {filename}")
        return filename
        
    except Exception as e:
        print(f"\n保存报告时出错: {str(e)}")
        return None


def sum_transaction_values(transactions):
    """计算交易总额"""
    total_value = 0
    for tx in transactions:
        try:
            if tx.trace_data:
                trace = json.loads(tx.trace_data)
                if isinstance(trace, dict) and 'action' in trace:
                    value_hex = trace['action'].get('value', '0x0')
                    value = int(value_hex, 16) / 10**18  # 转换为ETH
                    total_value += value
        except Exception as e:
            print(f"解析交易 {tx.tx_hash} 的值时出错: {str(e)}")
    
    return total_value


def calculate_average_interval(tx_details):
    """计算平均交易时间间隔（秒）"""
    if len(tx_details) < 2:
        return 0
    
    try:
        timestamps = []
        for tx in tx_details:
            if 'timestamp' in tx and tx['timestamp'] != 'Unknown':
                dt = datetime.strptime(tx['timestamp'], '%Y-%m-%d %H:%M:%S')
                timestamps.append(dt)
        
        timestamps.sort()
        
        if len(timestamps) < 2:
            return 0
            
        intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                    for i in range(len(timestamps)-1)]
        
        return sum(intervals) / len(intervals)
    except Exception as e:
        print(f"计算交易间隔时出错: {str(e)}")
        return 0


def to_from_pattern_exists(tx_details):
    """检查是否存在快速转入转出模式"""
    if len(tx_details) < 2:
        return False
    
    # 构建地址接收和发送映射
    address_timeline = {}
    
    for tx in tx_details:
        from_addr = tx['from']
        to_addr = tx['to']
        timestamp = tx['timestamp']
        
        if from_addr not in address_timeline:
            address_timeline[from_addr] = {'received': [], 'sent': []}
        if to_addr not in address_timeline:
            address_timeline[to_addr] = {'received': [], 'sent': []}
        
        address_timeline[from_addr]['sent'].append((timestamp, tx['value'], to_addr))
        address_timeline[to_addr]['received'].append((timestamp, tx['value'], from_addr))
    
    # 检查每个地址是否有快速转入转出
    for addr, timeline in address_timeline.items():
        if not timeline['received'] or not timeline['sent']:
            continue
            
        for rec_time, rec_value, rec_from in timeline['received']:
            if isinstance(rec_time, str):
                rec_dt = datetime.strptime(rec_time, '%Y-%m-%d %H:%M:%S')
            else:
                rec_dt = rec_time
                
            for send_time, send_value, send_to in timeline['sent']:
                if isinstance(send_time, str):
                    send_dt = datetime.strptime(send_time, '%Y-%m-%d %H:%M:%S')
                else:
                    send_dt = send_time
                
                # 如果在收到后30分钟内发送，且金额相近，视为快速转入转出
                time_diff = abs((send_dt - rec_dt).total_seconds())
                value_ratio = min(rec_value, send_value) / max(rec_value, send_value) if max(rec_value, send_value) > 0 else 0
                
                if time_diff < 1800 and value_ratio > 0.8:
                    return True
    
    return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze_transfer.py <from_address> [to_address] [start_block] [end_block]")
        sys.exit(1)
        
    from_address = sys.argv[1]
    to_address = sys.argv[2] if len(sys.argv) > 2 else None
    start_block = int(sys.argv[3]) if len(sys.argv) > 3 else None
    end_block = int(sys.argv[4]) if len(sys.argv) > 4 else None
    
    report = analyze_eth_transfers(from_address, to_address, start_block, end_block)
    print(report) 
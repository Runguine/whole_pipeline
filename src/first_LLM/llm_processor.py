from typing import Tuple, Dict
from src.first_LLM.rag_handler import RAG_INSTANCE 
import re
from openai import OpenAI
from config.settings import settings
import json
import os
from web3 import Web3

class LLMQueryProcessor:
    PROMPT_TEMPLATE = """作为区块链安全分析专家，请从用户查询中提取：
1. 目标合约地址（以0x开头的十六进制字符串）
2. 区块范围（起始和结束区块号）
3. 分析重点，重点关注：
   - 安全事件/黑客攻击分析
   - 合约交互行为分析
   - 相关合约代码分析
   - 资金流向追踪
4. 分析类型：
   - "security_analysis": 分析合约交互和相关合约的安全问题
   - "contract_analysis": 仅分析单个合约代码
   - "transaction_analysis": 仅分析交易历史

用户输入：{user_input}

严格按照以下JSON格式返回结果，不要包含任何其他文字：
{{
  "token_identifier": "目标合约地址",
  "time_range_hint": "具体时间范围",
  "analysis_focus": ["安全事件分析", "交互行为分析", "代码分析", "资金流向"],
  "analysis_type": "security_analysis/contract_analysis/transaction_analysis"
}}"""
    APIKEY = settings.APIKEY
    BASEURL = settings.BASEURL
    MODELNAME = settings.MODELNAME
    client = OpenAI(
        base_url = BASEURL,
        api_key = APIKEY,
    )

    def parse_query(self, user_input: str) -> Tuple[Dict, Dict]:
        """返回(LLM解析结果, RAG数据)"""
        # 获取当前区块（在函数开始就获取，避免重复调用）
        w3 = Web3(Web3.HTTPProvider(os.getenv("ALCHEMY_URL")))
        current_block = w3.eth.block_number
        
        # 初始化变量
        start_block = None
        end_block = None
        time_range_hint = None
        network = "ethereum"  # 固定使用以太坊网络
        
        # 检查是否指定了区块范围
        block_pattern = re.compile(
            r'区块\s*'          # "区块"开头
            r'(\d+)'            # 捕获起始区块号（第1组）
            r'\s*'              # 允许空格
            r'(?:'              # 非捕获分组开始
            r'[至到\-~]+\s*'    # 匹配任意分隔符（至/到/-/~等）
            r'(?:区块\s*)?'     # 允许可选的"区块"关键字
            r')'                # 非捕获分组结束
            r'(\d+)'            # 捕获结束区块号（第2组）
        )
        block_match = block_pattern.search(user_input)
        
        # 检查是否指定了时间范围（如"最近一小时"）
        time_pattern = re.compile(
            r'最近'              # "最近"开头
            r'(?:(\d*)\s*)?'    # 可选的数字（注意：改为\d*允许省略数字1）
            r'(一)?'            # 可选的"一"字
            r'(小时|分钟|天|周|月)'  # 时间单位
        )
        time_match = time_pattern.search(user_input)
        
        # 首先处理区块范围
        if block_match:
            start_block = int(block_match.group(1))
            end_block = int(block_match.group(2))
            time_range_hint = f"区块范围: {start_block} - {end_block}"
            print(f"检测到用户指定区块范围: {start_block} - {end_block}")
        # 然后处理时间范围
        elif time_match:
            # 解析时间单位和数量
            amount = int(time_match.group(1)) if time_match.group(1) else 1
            unit = time_match.group(3)  # 注意：由于添加了(一)?分组，单位现在在group(3)
            time_range_hint = f"最近{amount}{unit}"
            
            # 根据时间单位计算区块数（假设平均15秒一个区块）
            blocks_per_unit = {
                '小时': 240,    # 3600/15 = 240个区块/小时
                '分钟': 4,      # 60/15 = 4个区块/分钟
                '天': 5760,     # 24*240 = 5760个区块/天
                '周': 40320,    # 7*5760 = 40320个区块/周
                '月': 172800    # 30*5760 = 172800个区块/月
            }
            
            blocks_to_subtract = blocks_per_unit.get(unit, 240) * amount
            start_block = max(0, current_block - blocks_to_subtract)
            end_block = current_block
            print(f"根据时间范围'{amount}{unit}'推算区块范围: {start_block} - {end_block}")
        # 最后设置默认值
        else:
            start_block = current_block - 240  # 默认查询最近1小时
            end_block = current_block
            time_range_hint = "最近1小时（默认）"
            print("未指定时间范围，使用默认值：最近1小时")
        
        # 检查是否是以太坊地址格式
        address_pattern = re.compile(r'0x[a-fA-F0-9]{40}')
        address_match = address_pattern.search(user_input)
        
        # 检查是否包含代币标识符
        token_pattern = re.compile(r'\b(USDT|UNI|ETH|BTC|[A-Z]{2,10})\b')
        token_match = token_pattern.search(user_input)
        token_identifier = token_match.group(1) if token_match else None
        
        # 确定分析类型
        security_keywords = ['安全', '攻击', '黑客', '漏洞', '风险']
        interaction_keywords = ['交互', '调用', '行为']
        
        is_security_analysis = any(keyword in user_input for keyword in security_keywords)
        has_interaction_focus = any(keyword in user_input for keyword in interaction_keywords)
        
        # 第一步：LLM结构化解析
        llm_result = self._get_structured_parse(user_input)
        
        # 如果找到了地址，使用找到的地址
        if address_match:
            address = address_match.group()
        else:
            # 尝试从LLM结果中获取地址
            address = llm_result.get('token_identifier')
            if not address or not re.match(r'0x[a-fA-F0-9]{40}', address):
                # 如果地址无效，尝试通过RAG获取
                try:
                    # 使用用户指定的代币标识符，如果没有则使用LLM结果
                    search_token = token_identifier or llm_result.get('token_identifier', '')
                    if not search_token:
                        print("未能识别到代币标识符")
                        return {
                            "token_identifier": "",
                            "time_range_hint": time_range_hint,
                            "analysis_focus": ["资金流向"],
                            "analysis_type": "transaction_analysis"
                        }, {
                            'address': None,
                            'start_block': start_block,
                            'end_block': end_block,
                            'raw_data': None,
                            'user_input': user_input
                        }
                    
                    print(f"正在查找代币 {search_token} 的合约地址...")
                    token_data, _ = RAG_INSTANCE.search_with_block_range(search_token)
                    if token_data:
                        address = token_data.get('id')
                        print(f"找到 {search_token} 的合约地址: {address}")
                    else:
                        print(f"未找到 {search_token} 的合约地址")
                except Exception as e:
                    print(f"查找代币地址时出错: {str(e)}")
                    address = None
        
        # 确定分析类型和重点
        analysis_type = "security_analysis" if is_security_analysis else (
            "transaction_analysis" if has_interaction_focus else "contract_analysis"
        )
        
        analysis_focus = []
        if is_security_analysis:
            analysis_focus.extend(["安全事件分析", "交互行为分析", "代码分析"])
        if has_interaction_focus:
            analysis_focus.extend(["交互行为分析", "资金流向"])
        if not analysis_focus:
            analysis_focus = ["合约分析"]
        
        # 构建最终结果
        final_llm_result = {
            "token_identifier": address,
            "time_range_hint": time_range_hint,
            "analysis_focus": list(set(analysis_focus)),  # 去重
            "analysis_type": analysis_type,
            "user_input": user_input,
            "user_specified_blocks": block_match is not None or time_match is not None,
            "network": "ethereum"  # 固定为以太坊网络
        }
        
        final_rag_data = {
            'address': address,
            'start_block': start_block,
            'end_block': end_block,
            'raw_data': {'id': address} if address else None,
            'user_input': user_input,
            'network': "ethereum"  # 固定为以太坊网络
        }
        
        return final_llm_result, final_rag_data

    def _get_structured_parse(self, text: str) -> Dict:
        """使用LLM+规则混合解析"""
        # 规则引擎优先
        rule_result = self._rule_based_parse(text)
        if rule_result['confidence'] > 0.8:
            return rule_result

        try:
            response = self.client.chat.completions.create(
                model=self.MODELNAME,
                messages=[{
                    "role": "system",
                    "content": self.PROMPT_TEMPLATE.format(user_input=text)
                }]
            )
            
            content = response.choices[0].message.content.strip()
            
            # 处理可能包含的markdown代码块
            if content.startswith('```json'):
                content = content.replace('```json\n', '').replace('\n```', '')
            elif content.startswith('```'):
                content = content.replace('```\n', '').replace('\n```', '')
                
            # 尝试解析JSON
            try:
                return json.loads(content)
            except json.JSONDecodeError as e:
                print(f"JSON解析错误: {str(e)}")
                print(f"原始内容: {content}")
                # 检查是否包含USDT地址
                if "0xdAC17F958D2ee523a2206206994597C13D831ec7" in content:
                    return {
                        "token_identifier": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                        "time_range_hint": "",  # 这里留空，让外层的time_range_hint生效
                        "analysis_focus": ["交互行为分析", "资金流向"],
                        "analysis_type": "transaction_analysis"
                    }
                return {
                    "token_identifier": "",
                    "time_range_hint": "",  # 这里留空，让外层的time_range_hint生效
                    "analysis_focus": ["资金流向"],
                    "analysis_type": "transaction_analysis"
                }
                
        except Exception as e:
            print(f"LLM调用出错: {str(e)}")
            return {
                "token_identifier": "",
                "time_range_hint": "",  # 这里留空，让外层的time_range_hint生效
                "analysis_focus": ["资金流向"],
                "analysis_type": "transaction_analysis"
            }

    def _rule_based_parse(self, text: str) -> Dict:
        """基于正则的快速解析"""
        patterns = {
            'token': r'\b([A-Z]{3,5})\b|(\bERC-20\s+代币\s+[\w\s]+)',
            'time_range': r'最近(\d+)天|过去(\d+)个月',
            'focus': r'安全事件|漏洞|资金流动'
        }
        result = {
            'confidence': 0,
            'time_range_hint': '',  # 初始化为空字符串
            'token_identifier': '',
            'analysis_focus': ["资金流向"],
            'analysis_type': "transaction_analysis"
        }
        
        # 代币识别
        token_match = re.search(patterns['token'], text)
        if token_match:
            result['token_identifier'] = token_match.group(1) or token_match.group(2)
            result['confidence'] += 0.5
        
        return result
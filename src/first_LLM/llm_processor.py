from typing import Tuple, Dict
from src.first_LLM.rag_handler import RAG_INSTANCE 
import re
from openai import OpenAI
from config.settings import settings
import json
class LLMQueryProcessor:
    PROMPT_TEMPLATE = """作为区块链分析助手，请从用户查询中提取：
1. 代币名称/符号（优先识别）或合约地址
2. 时间范围关键词，需要明确具体数值：
   - 分钟（例如：最近30分钟 -> "30分钟"）
   - 小时（例如：过去2小时 -> "2小时"）
   - 天数（例如：最近3天 -> "3天"）
   - 周数（例如：过去2周 -> "2周"）
   - 月数（例如：上个月 -> "1月"）
   如果未明确指定时间，默认为"1小时"
3. 分析重点（如安全事件、资金流向、合约分析等）
4. 分析类型：
   - "contract_analysis": 仅分析合约代码和方法
   - "transaction_analysis": 分析交易历史和资金流向

用户输入：{user_input}

严格按照以下JSON格式返回结果，不要包含任何其他文字：
{{
  "token_identifier": "代币标识或合约地址",
  "time_range_hint": "具体时间范围（如：30分钟、2小时、3天、2周、1月）",
  "analysis_focus": ["安全事件", "资金流向", "合约分析"],
  "analysis_type": "contract_analysis或transaction_analysis"
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
        # 检查是否是以太坊地址格式
        address_pattern = re.compile(r'0x[a-fA-F0-9]{40}')
        address_match = address_pattern.search(user_input)
        
        if address_match:
            # 如果是直接输入的地址，构造默认的返回值
            address = address_match.group()
            
            # 判断是否是合约分析请求
            contract_analysis_keywords = [
                '合约', '方法', '代码', 'abi', 'ABI', '功能', '函数', 
                '接口', '实现', '逻辑', '源码', '字节码', '分析'
            ]
            is_contract_analysis = any(keyword in user_input for keyword in contract_analysis_keywords)
            
            return {
                "token_identifier": address,
                "time_range_hint": "1小时",
                "analysis_focus": ["合约分析"] if is_contract_analysis else ["资金流向"],
                "analysis_type": "contract_analysis" if is_contract_analysis else "transaction_analysis"
            }, {
                'address': address,
                'start_block': 0,
                'end_block': 0 if is_contract_analysis else 999999999,  # 如果是合约分析，不需要区块范围
                'raw_data': {'id': address}
            }
            
        # 第一步：LLM结构化解析
        llm_result = self._get_structured_parse(user_input)
        
        # 第二步：RAG检索
        token_data, block_range = RAG_INSTANCE.search_with_block_range(
            llm_result.get('token_identifier', '')
        )
        
        if not token_data:
            # 如果RAG没有找到结果，返回默认值
            return llm_result, {
                'address': None,
                'start_block': 0,
                'end_block': 0,
                'raw_data': None
            }
            
        return llm_result, {
            'address': token_data['id'] if token_data else None,
            'start_block': block_range[0],
            'end_block': block_range[1],
            'raw_data': token_data
        }

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
                return {
                    "token_identifier": "",
                    "time_range_hint": "",
                    "analysis_focus": ["资金流向"]
                }
                
        except Exception as e:
            print(f"LLM调用出错: {str(e)}")
            return {
                "token_identifier": "",
                "time_range_hint": "",
                "analysis_focus": ["资金流向"]
            }

    def _rule_based_parse(self, text: str) -> Dict:
        """基于正则的快速解析"""
        patterns = {
            'token': r'\b([A-Z]{3,5})\b|(\bERC-20\s+代币\s+[\w\s]+)',
            'time_range': r'最近(\d+)天|过去(\d+)个月',
            'focus': r'安全事件|漏洞|资金流动'
        }
        result = {'confidence': 0}
        
        # 代币识别
        token_match = re.search(patterns['token'], text)
        if token_match:
            result['token_identifier'] = token_match.group(1) or token_match.group(2)
            result['confidence'] += 0.5
        
        # 时间范围识别...
        return result
from typing import Tuple, Dict, List
from src.first_LLM.rag_handler import RAG_INSTANCE 
import re
from openai import OpenAI
from config.settings import settings
import json
import os
from web3 import Web3
import traceback

class LLMQueryProcessor:
    PROMPT_TEMPLATE = """As a blockchain security analysis expert, please extract from the user query:
1. Target contract address (a hexadecimal string starting with 0x)
2. Block range (start and end block numbers)
3. Analysis focus, with emphasis on:
   - Security event/hack attack analysis
   - Contract interaction behavior analysis
   - Related contract code analysis
   - Fund flow tracking
4. Analysis type:
   - "security_analysis": Analyze contract interactions and related contract security issues
   - "contract_analysis": Analyze only a single contract code
   - "transaction_analysis": Analyze only transaction history

User input: {user_input}

Return the result strictly in the following JSON format, without any additional text:
{{
  "token_identifier": "Target contract address",
  "time_range_hint": "Specific time range",
  "analysis_focus": ["Security event analysis", "Interaction behavior analysis", "Code analysis", "Fund flow"],
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
        """Return (LLM parsing result, RAG data)"""
        # Get current block (at the start of the function to avoid repeated calls)
        w3 = Web3(Web3.HTTPProvider(os.getenv("ALCHEMY_URL")))
        current_block = w3.eth.block_number
        
        # Initialize variables
        start_block = None
        end_block = None
        time_range_hint = None
        network = "ethereum"  # Fixed to Ethereum network
        
        # Check if block range is specified
        block_pattern = re.compile(
            r'block\s*'          # "block" prefix
            r'(\d+)'            # Capture start block number (group 1)
            r'\s*'              # Allow spaces
            r'(?:'              # Non-capturing group start
            r'[to\-~]+\s*'    # Match any separator (to/-/~ etc.)
            r'(?:block\s*)?'     # Allow optional "block" keyword
            r')'                # Non-capturing group end
            r'(\d+)'            # Capture end block number (group 2)
        )
        block_match = block_pattern.search(user_input)
        
        # Check if time range is specified (e.g., "last hour")
        time_pattern = re.compile(
            r'last\s+'           # "last" prefix
            r'(\d*\s*)?'         # Optional number
            r'(hour|minute|day|week|month)s?'  # Time unit
        )
        time_match = time_pattern.search(user_input)
        
        # First process block range
        if block_match:
            start_block = int(block_match.group(1))
            end_block = int(block_match.group(2))
            time_range_hint = f"Block range: {start_block} - {end_block}"
            print(f"Detected user-specified block range: {start_block} - {end_block}")
        # Then process time range
        elif time_match:
            # Parse time unit and amount
            amount_text = time_match.group(1)
            amount = 1
            if amount_text and amount_text.strip():
                try:
                    amount = int(amount_text.strip())
                except ValueError:
                    amount = 1
                    
            unit = time_match.group(2)  # Get the time unit
            time_range_hint = f"Last {amount} {unit}{'s' if amount > 1 else ''}"
            
            # Calculate blocks based on time unit
            blocks_per_unit = {
                'hour': 300,    
                'minute': 5,      
                'day': 7200,     
                'week': 50400,    
                'month': 216000   
            }
            
            blocks_to_subtract = blocks_per_unit.get(unit, 300) * amount
            start_block = max(0, current_block - blocks_to_subtract)
            end_block = current_block
            print(f"Based on time range '{amount} {unit}{'s' if amount > 1 else ''}', calculated block range: {start_block} - {end_block}")
        # Finally set default values
        else:
            start_block = current_block - 300  # Default to last hour
            end_block = current_block
            time_range_hint = "Last 1 hour (default)"
            print("No time range specified, using default: Last 1 hour")
        
        # Check if it's an Ethereum address format
        address_pattern = re.compile(r'0x[a-fA-F0-9]{40}')
        address_match = address_pattern.search(user_input)
        
        # Check if it contains token identifier
        token_pattern = re.compile(r'\b(USDT|UNI|ETH|BTC|[A-Z]{2,10})\b')
        token_match = token_pattern.search(user_input)
        token_identifier = token_match.group(1) if token_match else None
        
        # Determine analysis type
        security_keywords = ['security', 'attack', 'hack', 'exploit', 'vulnerability', 'risk']
        interaction_keywords = ['interaction', 'call', 'behavior', 'trace']
        
        is_security_analysis = any(keyword in user_input.lower() for keyword in security_keywords)
        has_interaction_focus = any(keyword in user_input.lower() for keyword in interaction_keywords)
        
        # Step 1: LLM structured parsing
        llm_result = self._get_structured_parse(user_input)
        
        # Modify search logic
        if address_match:
            address = address_match.group()
        else:
            # Try to get address from LLM result
            address = llm_result.get('token_identifier')
            if not address or not re.match(r'0x[a-fA-F0-9]{40}', address):
                try:
                    # 1. First try to search in the event database
                    if "event" in user_input.lower() or "attack" in user_input.lower():
                        print("Searching in event database...")
                        try:
                            # Use "event" type for event searches
                            address = self._safe_extract_address_from_search(user_input, "event")
                            if address:
                                print(f"Found address in event database: {address}")
                        except Exception as e:
                            print(f"Error during event search: {str(e)}")
                    
                    # 2. If event search fails, try token/pool search with more flexible type matching
                    if not address or not Web3.is_address(address):
                        search_token = token_identifier or llm_result.get('token_identifier', '')
                        if search_token:
                            # Look for tokens, pools or any other type - using "any" instead of "token"
                            print(f"Searching for {search_token}...")
                            try:
                                # Use "any" to accept all types (token, pool, etc.)
                                address = self._safe_extract_address_from_search(search_token, "any")
                                if address:
                                    print(f"Found address: {address}")
                            except Exception as e:
                                print(f"Error during search: {str(e)}")
                
                except Exception as e:
                    print(f"Error during search process: {str(e)}")
                    address = None
        
        # Determine analysis type and focus
        analysis_type = "security_analysis" if is_security_analysis else (
            "transaction_analysis" if has_interaction_focus else "contract_analysis"
        )
        
        analysis_focus = []
        if is_security_analysis:
            analysis_focus.extend(["Security event analysis", "Interaction behavior analysis", "Code analysis"])
        if has_interaction_focus:
            analysis_focus.extend(["Interaction behavior analysis", "Fund flow"])
        if not analysis_focus:
            analysis_focus = ["Contract analysis"]
        
        # Build final result
        final_llm_result = {
            "token_identifier": address,
            "time_range_hint": time_range_hint,
            "analysis_focus": list(set(analysis_focus)),  # Remove duplicates
            "analysis_type": analysis_type,
            "user_input": user_input,
            "user_specified_blocks": block_match is not None or time_match is not None,
            "network": "ethereum"  # Fixed to Ethereum network
        }
        
        final_rag_data = {
            'address': address,
            'start_block': start_block,
            'end_block': end_block,
            'raw_data': {'id': address} if address else None,
            'user_input': user_input,
            'network': "ethereum"  # Fixed to Ethereum network
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
                        "analysis_focus": ["interaction behavior analysis", "fund flow"],
                        "analysis_type": "transaction_analysis"
                    }
                return {
                    "token_identifier": "",
                    "time_range_hint": "",  # 这里留空，让外层的time_range_hint生效
                    "analysis_focus": ["fund flow"],
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
            'time_range': r'in (\d+) days|past (\d+) months',
            'focus': r'security event|漏洞|fund flow'
        }
        result = {
            'confidence': 0,
            'time_range_hint': '',  # 初始化为空字符串
            'token_identifier': '',
            'analysis_focus': ["fund flow"],
            'analysis_type': "transaction_analysis"
        }
        
        # 代币识别
        token_match = re.search(patterns['token'], text)
        if token_match:
            result['token_identifier'] = token_match.group(1) or token_match.group(2)
            result['confidence'] += 0.5
        
        return result

    def _safe_extract_address_from_search(self, query, search_type="any"):
        """
        Safely extract address from search results, avoiding unpacking errors
        search_type: "token", "event", "any"
        """
        try:
            # Preprocess query to extract the most relevant parts
            processed_query = query
            
            # For event searches, use more advanced processing
            if search_type == "event":
                # First remove common action words that aren't part of the entity name
                processed_query = re.sub(r'(?i)analysis|analyze|query|understand|describe', '', query)
                
                # Try to extract the entity name after prepositions
                entity_match = re.search(r'(?i)(?:of|about|for|regarding|on)\s+([a-zA-Z0-9\s]+?)(?:\s+in\s+|\s+block|\s+during|\s*$)', processed_query)
                if entity_match:
                    extracted_entity = entity_match.group(1).strip()
                    if len(extracted_entity) > 3:  # Avoid very short extractions
                        processed_query = extracted_entity
                        print(f"Extracted entity from query: '{extracted_entity}'")
            
            # Log detailed search information
            print(f"Executing {search_type} type search, original query: '{query}'")
            print(f"Processed query: '{processed_query}'")
            
            # Direct call to search method
            results = RAG_INSTANCE.search(processed_query)
            
            # Log detailed search results
            print(f"Search results count: {len(results) if results else 0}")
            if results and len(results) > 0:
                for i, result in enumerate(results):
                    if isinstance(result, dict):
                        result_type = result.get('type', 'unknown')
                        result_addr = result.get('address', 'no_address')
                        print(f"Result #{i+1}: type={result_type}, address={result_addr}")
                    else:
                        print(f"Result #{i+1}: non-dictionary type ({type(result)})")
            
            # Process each result
            for item in (results or []):
                # Ensure result is dictionary type
                if not isinstance(item, dict):
                    print(f"Skipping non-dictionary result: {type(item)}")
                    continue
                    
                # Validate type match
                item_type = item.get('type', 'unknown')
                if search_type != "any" and item_type != search_type:
                    print(f"Skipping result with non-matching type: expected={search_type}, actual={item_type}")
                    continue
                
                # Extract and validate address
                addr = item.get('address')
                if not addr:
                    print(f"Result missing address field")
                    continue
                    
                # Validate address format
                try:
                    if Web3.is_address(addr):
                        valid_address = Web3.to_checksum_address(addr)
                        print(f"Found valid address: {valid_address}")
                        return valid_address
                    else:
                        print(f"Invalid Ethereum address: {addr}")
                except Exception as e:
                    print(f"Address validation failed: {str(e)}")
            
            # No matching valid address found
            print(f"No valid address found")
            return None
            
        except Exception as e:
            print(f"Error during address extraction: {str(e)}")
            print(f"Error details: {traceback.format_exc()}")
            return None

    def _get_entities_from_llm(self, query: str) -> List[str]:
        """
        使用LLM从查询中提取相关实体（代币名称、池子名称、安全事件等）
        """
        try:
            # 准备提示词，专门用于实体提取
            prompt = """Please analyze the following query and extract any blockchain-related entities such as:
1. Token names (e.g., USDT, BAL, ETH)
2. Pool names (e.g., "Balancer: B-stETH-STABLE pool", "Uniswap V3: USDC/ETH")
3. Security event names (e.g., "Bybit hack", "neobank Infini attack")
4. Protocol names (e.g., Aave, Compound, Uniswap)

Query: {query}

Return only the extracted entities as a JSON list, with no additional text:
["entity1", "entity2", ...]

If no relevant entities are found, return an empty list: []
"""
            
            # 调用LLM
            response = self.client.chat.completions.create(
                model=self.MODELNAME,
                messages=[{
                    "role": "system",
                    "content": prompt.format(query=query)
                }],
                temperature=0.2,  # 较低的温度，以获得更确定性的结果
            )
            
            content = response.choices[0].message.content.strip()
            
            # 处理可能包含的markdown代码块
            if content.startswith('```json'):
                content = content.replace('```json\n', '').replace('\n```', '')
            elif content.startswith('```'):
                content = content.replace('```\n', '').replace('\n```', '')
            
            # 解析JSON结果
            try:
                entities = json.loads(content)
                if isinstance(entities, list):
                    # 过滤掉过短的实体
                    filtered_entities = [e for e in entities if len(e) > 2]
                    print(f"LLM identified entities: {filtered_entities}")
                    return filtered_entities
                else:
                    print(f"LLM returned non-list result: {content}")
                    return []
            except json.JSONDecodeError as e:
                print(f"Failed to parse LLM response as JSON: {e}")
                print(f"Raw content: {content}")
                # 尝试从文本中提取可能的实体
                if "[" in content and "]" in content:
                    try:
                        # 尝试提取JSON数组部分
                        json_part = content[content.find("["):content.rfind("]")+1]
                        entities = json.loads(json_part)
                        if isinstance(entities, list):
                            return [e for e in entities if len(e) > 2]
                    except:
                        pass
            
            # 仍然失败，尝试正则表达式提取引号中的内容
            import re
            quoted_entities = re.findall(r'"([^"]+)"', content)
            if quoted_entities:
                return [e for e in quoted_entities if len(e) > 2]
            return []
        except Exception as e:
            print(f"Error using LLM for entity extraction: {str(e)}")
            return []
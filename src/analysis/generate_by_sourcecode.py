import sys
import os
import json
import time  # 引入time模块

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from src.database import get_db
from src.database.crud import get_all_contract_abis_by_block, get_latest_two_contract_abis, get_limit_contracts_source_code
from scripts.fetch_llm import request_ds
from config.settings import settings

DATASET_PROMPT = settings.DATASET_PROMPT
# DATASET_PROMPT3 = "You are an expert in blockchain and smart contracts. Please analyze the contract by first breaking it down into its key functions or stages. For each function or stage, explain its purpose and the logic behind it. After analyzing all parts, provide a brief summary of the contract’s overall functionality. Output the results in the following format: Function Name: [Function1] \ Function Name: [Description of Function2] \ … \ Overall: [Summary of the contract’s overall functionality]. Please ensure that each function description and the overall summary appear on separate lines in the final output."

import pandas as pd
data = []

db = next(get_db())
# 获取源码，转换为json格式
abis = get_limit_contracts_source_code(db)

for abi in abis:
    source_code = abi['source_code']
    address = abi['address']
    bytecode = abi['bytecode']
    if source_code is not None:
        explanation = request_ds(DATASET_PROMPT, source_code)
        print(explanation)
        data.append({'address': address, 'explanation': explanation})

results = pd.DataFrame(data)
results.to_csv('contract_explanations22_1.csv', index=False)
print('Generated Dataset.')
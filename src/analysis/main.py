import sys
import os
import json  # 导入 json 模块

# sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from src.database import get_db
from src.database.crud import get_all_contract_abis_by_block, get_latest_two_contract_abis
from scripts.fetch_llm import request_ds
from config.settings import settings

db = next(get_db())

abis = get_latest_two_contract_abis(db)
print(len(abis))
print(type(abis[0]))

# 将 abis[0] 转换为 JSON 格式
abis_json = json.dumps(abis)

# PROMPT = settings.PROMPT

# response = request_ds(PROMPT, abis_json)
# print(response)

# 将结果保存到txt文件中
with open("arr.txt", "w", encoding="utf-8") as file:
    # file.write(response)
    file.write(abis_json)

print("结果已保存到 output.txt 文件中。")
import subprocess
import os
import re

def clean_ansi_codes(text):
    """移除所有ANSI转义序列"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def decompile_bytecode(bytecode):
    """修改后的反编译函数（直接返回反编译结果）"""
    try:
        result = subprocess.run(
            ["panoramix", bytecode],
            capture_output=True,
            text=True,
            env={**os.environ, 'TERM': 'dumb'}
        )
        
        if result.returncode == 0:
            return clean_ansi_codes(result.stdout)
        print(f"反编译失败: {result.stderr}")
        return None
    except Exception as e:
        print(f"反编译错误: {str(e)}")
        return None
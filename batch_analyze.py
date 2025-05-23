#!/usr/bin/env python3
import pandas as pd
import subprocess
import time
import os
import sys
from tqdm import tqdm
import logging
import re

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("batch_analyze.log"),
        logging.StreamHandler()
    ]
)

def convert_date_format(date_str):
    """
    将日期格式从YYYY/MM/DD转换为YYYY-MM-DD
    
    Args:
        date_str: 原始日期字符串
    
    Returns:
        转换后的日期字符串
    """
    # 匹配YYYY/MM/DD格式
    pattern = re.compile(r'(\d{4})/(\d{1,2})/(\d{1,2})')
    match = pattern.match(date_str)
    
    if match:
        year, month, day = match.groups()
        # 确保月和日是两位数
        month = month.zfill(2)
        day = day.zfill(2)
        return f"{year}-{month}-{day}"
    
    # 如果不匹配，返回原始字符串
    return date_str

def run_analysis(csv_path, start_row=0, end_row=None, sleep_between_runs=5):
    """
    批量运行分析程序
    
    Args:
        csv_path: CSV文件路径
        start_row: 开始行（默认为0，即第一行）
        end_row: 结束行（默认为None，即所有行）
        sleep_between_runs: 每次运行之间的等待时间（秒）
    """
    try:
        # 读取CSV文件
        logging.info(f"读取CSV文件: {csv_path}")
        df = pd.read_csv(csv_path)
        
        # 验证CSV文件包含所需列
        if 'Address' not in df.columns or 'Date' not in df.columns:
            logging.error("CSV文件必须包含'Address'和'Date'列")
            return
        
        # 设置结束行
        if end_row is None or end_row > len(df):
            end_row = len(df)
        
        # 限制处理范围
        df = df.iloc[start_row:end_row]
        
        logging.info(f"将处理 {len(df)} 行数据，从索引 {start_row} 到 {end_row-1}")
        
        # 为每行运行分析
        for index, row in tqdm(df.iterrows(), total=len(df), desc="批量分析进度"):
            address = row['Address']
            original_date = row['Date']
            
            # 转换日期格式
            formatted_date = convert_date_format(original_date)
            logging.info(f"日期格式转换: {original_date} -> {formatted_date}")
            
            # 构建输入字符串
            input_text = f"Analyze the behavior of address {address} in {formatted_date}"
            logging.info(f"处理 #{index}: {input_text}")
            
            try:
                # 运行main.py并提供输入
                process = subprocess.Popen(
                    ["python", "src/main.py"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # 发送输入并获取输出
                stdout, stderr = process.communicate(input=input_text, timeout=10800)  # 超时设为3小时
                
                # 记录输出
                log_file = f"output_{address}_{formatted_date}.log"
                with open(log_file, 'w') as f:
                    f.write(f"INPUT: {input_text}\n\nOUTPUT:\n{stdout}\n\nERROR:\n{stderr}")
                
                logging.info(f"分析完成，输出已保存到 {log_file}")
                
                # 等待一段时间，避免连续请求
                logging.info(f"等待 {sleep_between_runs} 秒后继续下一个分析...")
                time.sleep(sleep_between_runs)
                
            except subprocess.TimeoutExpired:
                logging.error(f"处理超时: {input_text}")
                process.kill()
            except Exception as e:
                logging.error(f"处理时出错: {str(e)}")
        
        logging.info("批量分析完成！")
        
    except Exception as e:
        logging.error(f"批量处理时出错: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())

if __name__ == "__main__":
    # 检查命令行参数
    if len(sys.argv) < 2:
        print("用法: python batch_analyze.py <csv_file_path> [start_row] [end_row] [sleep_seconds]")
        sys.exit(1)
    
    csv_path = sys.argv[1]
    
    # 可选参数
    start_row = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    end_row = int(sys.argv[3]) if len(sys.argv) > 3 else None
    sleep_seconds = int(sys.argv[4]) if len(sys.argv) > 4 else 5
    
    # 运行批量分析
    run_analysis(csv_path, start_row, end_row, sleep_seconds) 
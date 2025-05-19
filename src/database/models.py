from sqlalchemy import Column, String, JSON, BigInteger, TIMESTAMP,Boolean
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Contract(Base):
    __tablename__ = "whole_pipeline"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    target_contract = Column(String(42), nullable=False)
    abi = Column(JSON)
    source_code = Column(JSON)
    c_name = Column(String(42))
    bytecode = Column(String(100000))  # 增加长度限制
    decompiled_code = Column(JSON)
    is_proxy = Column(Boolean, default=False)        # 新增字段
    parent_address = Column(String(42), index=True) 
    network = Column(String(20), default='ethereum')  # 新增：记录网络信息
    type = Column(String(50))  # 新增：记录合约类型
    created_at = Column(TIMESTAMP)  # 添加创建时间字段

class UserInteraction(Base):
    __tablename__ = "users"

    id = Column(BigInteger, primary_key=True)
    target_contract = Column(String(42), nullable=False)
    caller_contract = Column(String(42), nullable=False)
    method_name = Column(String(255), nullable=False)
    block_number = Column(BigInteger, nullable=False)
    tx_hash = Column(String(66), unique=True)
    timestamp = Column(TIMESTAMP)
    input_data = Column(String(20000))  # 增加长度到10000以存储完整的input data
    event_logs = Column(JSON)  # 存储交易收据中的事件日志
    trace_data = Column(JSON)  # 新增：存储交易追踪数据
    network = Column(String(20), default='ethereum')  # 固定为以太坊网络
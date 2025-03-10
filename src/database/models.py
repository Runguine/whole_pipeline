from sqlalchemy import Column, String, JSON, BigInteger, TIMESTAMP,Boolean
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Contract(Base):
    __tablename__ = "whole_pipeline"
    
    id = Column(BigInteger, primary_key=True)
    target_contract = Column(String(42), nullable=False)
    abi = Column(JSON)
    source_code = Column(JSON)
    c_name = Column(String(42))
    bytecode = Column(String)
    decompiled_code = Column(JSON)
    is_proxy = Column(Boolean, default=False)        # 新增字段
    parent_address = Column(String(42), index=True) 

class UserInteraction(Base):
    __tablename__ = "users"

    id = Column(BigInteger, primary_key=True)
    target_contract = Column(String(42), nullable=False)
    caller_contract = Column(String(42), nullable=False)
    method_name = Column(String(255), nullable=False)
    block_number = Column(BigInteger, nullable=False)
    tx_hash = Column(String(66), unique=True)
    timestamp = Column(TIMESTAMP)
    input_data = Column(String(255))
o
    ���g  �                   @   s~   d dl mZ ddlmZ d dlmZ dedefdd�Zded	ed
efdd�Z	dede
fdd�Zdefdd�Zdefdd�ZdS )�    )�Session�   )�Contract)�desc�db�contract_datac                 C   s�   | � t��tj|d k��� }|�dg �|�dg �|�dd�|�dd�|�dd�d�}|r=|�� D ]
\}}t|||� q1ntd	i i |�|���}| �|� | �	�  |S )
u"   增强版插入/更新合约数据�address�abi�source_code�contract_name� �block_number)r	   r
   r   r   r   N� )
�queryr   �filterr   �first�get�items�setattr�add�commit)r   r   �contract�update_data�key�valuer   r   �)/root/whole_pipeline/src/database/crud.py�upsert_contract   s   




��
r   r   �bytecodec                 C   s0   | � t��tj|k��� }|r||_| ��  |S )N)r   r   r   r   r   r   r   )r   r   r   r   r   r   r   �update_bytecode   s
   r   r   c                 C   s(   | � t��ttj���� }dd� |D �S )u�   
    查询特定区块中的所有合约记录，并返回它们的 ABI
    :param db: 数据库会话
    :param block_number: 区块号
    :return: 包含所有合约 ABI 的列表（JSON 格式），如果未找到则返回空列表
    c                 S   �   g | ]}|j r|j �qS r   �r	   ��.0r   r   r   r   �
<listcomp>1   �    z2get_all_contract_abis_by_block.<locals>.<listcomp>)r   r   �order_byr   �
created_atr   )r   r   �	contractsr   r   r   �get_all_contract_abis_by_block#   s
   �r(   c                 C   s"   | � t��d��� }dd� |D �S )��   
    查询数据库中最新创建的两条合约记录，并返回它们的 ABI
    :param db: 数据库会话
    :return: 包含最新两条合约 ABI 的列表（JSON 格式），如果未找到则返回空列表
    r   c                 S   r   r   r    r!   r   r   r   r#   ?   r$   z0get_latest_two_contract_abis.<locals>.<listcomp>�r   r   �limit�all)r   r'   r   r   r   �get_latest_two_contract_abis3   s
   �r-   c                 C   s&   | � t��d��� }dd� |D �}|S )r)   �   c                 S   s   g | ]}|j �qS r   )�__dict__r!   r   r   r   r#   N   s    z3get_limit_contracts_source_code.<locals>.<listcomp>r*   )r   r'   �contracts_dictr   r   r   �get_limit_contracts_source_codeA   s   �r1   N)�sqlalchemy.ormr   �modelsr   �
sqlalchemyr   �dictr   �strr   �intr(   r-   r1   r   r   r   r   �<module>   s    
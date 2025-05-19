DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS whole_pipeline;

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    target_contract VARCHAR(42) NOT NULL,
    caller_contract VARCHAR(42) NOT NULL,
    method_name VARCHAR(255) NOT NULL,
    block_number BIGINT NOT NULL,
    tx_hash VARCHAR(66) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    input_data VARCHAR(20000),
    event_logs JSON,
    trace_data JSON,
    network VARCHAR(20) DEFAULT 'ethereum'
);

CREATE INDEX idx_target_contract ON users (target_contract);
CREATE INDEX idx_caller_contract ON users (caller_contract);
CREATE UNIQUE INDEX idx_tx_hash ON users (tx_hash);


CREATE TABLE IF NOT EXISTS whole_pipeline (
    id SERIAL PRIMARY KEY,
    target_contract VARCHAR(42) NOT NULL,
    abi JSON,
    c_name VARCHAR(42),
    source_code JSON,
    bytecode VARCHAR(100000),
    decompiled_code JSON,
    is_proxy BOOLEAN DEFAULT FALSE,
    parent_address VARCHAR(42),
    network VARCHAR(20) DEFAULT 'ethereum',
    type VARCHAR(50),
    created_at TIMESTAMP
);

CREATE INDEX idx_target_contract_pipeline ON whole_pipeline (target_contract);
CREATE INDEX idx_parent_address ON whole_pipeline (parent_address);
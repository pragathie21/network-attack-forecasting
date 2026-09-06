-- AI-Based Network Attack Forecasting Database Schema
-- Database: network_attacks (MySQL 8.0+)

CREATE DATABASE IF NOT EXISTS network_attacks CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE network_attacks;

-- 1. Prediction History Table
CREATE TABLE IF NOT EXISTS prediction_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    src_ip VARCHAR(45) DEFAULT '192.168.1.100',
    dst_port INT NOT NULL,
    flow_duration BIGINT NOT NULL,
    tot_fwd_pkts INT NOT NULL,
    tot_bwd_pkts INT NOT NULL,
    attack_type VARCHAR(64) NOT NULL,
    probability DECIMAL(5, 4) NOT NULL,
    risk_score DECIMAL(5, 2) NOT NULL,
    risk_level ENUM('LOW', 'MEDIUM', 'HIGH') NOT NULL,
    forecast_status VARCHAR(128) NOT NULL,
    recommended_action TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp),
    INDEX idx_attack_type (attack_type),
    INDEX idx_risk_level (risk_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. Security Alerts Table (Early Warnings)
CREATE TABLE IF NOT EXISTS security_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attack_type VARCHAR(64) NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH') NOT NULL,
    mitre_id VARCHAR(32) NOT NULL,
    mitre_name VARCHAR(128) NOT NULL,
    alert_message TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    status ENUM('ACTIVE', 'INVESTIGATING', 'RESOLVED') DEFAULT 'ACTIVE',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_severity (severity),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Time-Window Statistics Table
CREATE TABLE IF NOT EXISTS traffic_window_stats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    window_size_flows INT NOT NULL,
    total_flows INT NOT NULL,
    benign_count INT NOT NULL,
    suspicious_count INT NOT NULL,
    attack_count INT NOT NULL,
    avg_risk_score DECIMAL(5, 2) NOT NULL,
    top_threat VARCHAR(64) DEFAULT 'None',
    forecast_trend VARCHAR(64) DEFAULT 'STABLE',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

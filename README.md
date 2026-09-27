# AI-Based Campus Network Behavior Analysis

An AI-based network monitoring and anomaly detection system designed to analyze network traffic using NetFlow and automatically respond to potential network threats.

## Project Overview

This project focuses on analyzing network behavior by collecting NetFlow traffic data and using machine learning to detect abnormal network activity.

The system uses Isolation Forest for anomaly detection, while Prometheus and Grafana are used for network monitoring and visualization. When suspicious traffic is detected, the system can apply automated mitigation based on predefined security policies.

## System Architecture

Network Traffic  
↓  
NetFlow Collector  
↓  
Matrix Builder  
↓  
ML Engine (Isolation Forest)  
↓  
Policy Engine  
↓  
Automated Response / Firewall  

Monitoring data is collected by Prometheus and visualized through Grafana dashboards.

## Key Features

- NetFlow-based network traffic collection
- Network behavior and anomaly detection
- Isolation Forest machine learning model
- Real-time monitoring with Prometheus
- Network visualization with Grafana
- Policy-based threat response
- Automated network threat mitigation
- Containerized services using Docker

## Technologies

- Python
- Docker & Docker Compose
- NetFlow
- Isolation Forest
- Prometheus
- Grafana
- Open vSwitch
- nftables
- GNS3

## Project Components

- `netflow-collector` - Collects network flow data
- `netflow-simulator` - Simulates network traffic for testing
- `matrix-builder` - Processes traffic data for analysis
- `ml-engine` - Performs anomaly detection
- `policy-engine` - Evaluates security policies
- `auto-response` - Handles automated response actions
- `firewall` - Handles traffic filtering and mitigation
- `prometheus` - Collects monitoring metrics
- `grafana` - Provides monitoring dashboards
- `alertmanager` - Handles monitoring alerts
- `llm-middleware` - Middleware component for LLM integration

## My Contribution

This project was developed as part of a team project. My work involved network-related implementation, system integration, testing, and understanding the overall network monitoring and anomaly detection workflow.

## Purpose

The project was developed to explore how networking, monitoring, machine learning, and automated security response can be integrated into a network behavior analysis system.

---

This repository is a fork of the original team project repository.

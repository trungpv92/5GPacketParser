# 5GFlowParser

**5GFlowParser** is an open-source Python tool for parsing NGAP and NAS protocol packets from 5G network traffic and extracting meaningful flow-level features from pcap files. This tool is designed for applications in network analysis, performance monitoring, anomaly detection, and research in 5G communication systems.

## Key Features
- **Comprehensive Parsing**: Handles NGAP and NAS protocol layers encapsulated in SCTP and IP packets.
- **Feature Extraction**: Captures flow features such as IP addresses, ports, timestamps, and protocol-specific metrics.
- **5G Traffic Insights**: Focuses on 5G-specific protocols, enabling precise analysis of 5G network behavior.
- **Customizable Workflow**: Offers flexibility in filtering packets and customizing output formats.

## Use Cases
- **Network Performance Monitoring**: Analyze flow behavior to optimize 5G network performance.
- **Security Analysis**: Extract features for use in intrusion detection or anomaly detection systems.
- **Research Applications**: Study traffic characteristics for academic or commercial research.

## Prerequisites
Before using **5GFlowParser**, ensure your environment meets the following requirements:
- Python 3.7 or higher
- `scapy` (for packet parsing)
- `pyshark` (for pcap handling)
- Additional libraries listed in `requirements.txt`

Install dependencies with:
```bash
pip install -r requirements.txt

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
- `pycrate` (for NGAP and NAS encoders and decoders)
- `pyshark` (for pcap handling)
- Additional libraries listed in `requirements.txt`

Install dependencies with:
```bash
pip install -r requirements.txt
```

## Installation
1. Clone the repository:
```bash
git clone https://github.com/trungpv92/5GFlowParser.git
```
2. Navigate to the project directory:
```bash
cd 5GFlowParser
```

## Usage
1. Place your pcap file(s) in the ```pcaps/``` directory.
2. Execute the tool with:
```bash
python 5G_flow_parser.py --input pcaps/example.pcap --output output/features.csv
```
3. Command-line options:
  - --input: Path to the input pcap file.
  - --output: Path to save extracted features.
  - --filter: Optional BPF filter for narrowing down packets (e.g., sctp).

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Contact
For any issues, questions, or feature requests, feel free to reach out:
  - Author: Trung Phan Van (trungpv92)
  - Email: trung.phan-van@etit.tu-chemnitz.de

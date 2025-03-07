# 5GPacketParser

**5GPacketParser** is an open-source Python tool for parsing NGAP and NAS protocol packets from 5G network traffic and extracting meaningful features from pcap files. This tool is designed for applications in network analysis, performance monitoring, anomaly detection, and research in 5G communication systems.

**About This Project**: 
The development of 5GPacketParser is part of ongoing research at Technische Universität Chemnitz, Germany. This work is supported by research projects funded by BSI (the Federal Cybersecurity Authority in Germany).

## Key Features
- **Comprehensive Parsing**: Handles NGAP and NAS protocol layers encapsulated in SCTP and IP packets.
- **5G Traffic Insights**: Focuses on 5G-specific protocols, enabling precise analysis of 5G network behavior.
- **Customizable Workflow**: Offers flexibility in filtering packets and customizing output formats, i.e., CSV (Currently).

## Feature Extraction Update
- **Current Version 1.0.1**:
In the current version of 5GPacketParser, the tool extracts a fixed set of features, including:

    _RequestMessages_, _SuccessfulResponseMessages_, _RequestResponseRatio_, _RegistrationRate_, 
    _PDURequestRate_, _RequestIAT_, _ProcedureCodeNumber_, _ProcedureCodeRate_.

- **Upcoming Version (Under Development)**:
The next version of 5GPacketParser will introduce user-defined feature extraction, allowing users to specify and customize the extracted features according to their needs. This enhancement will provide greater flexibility for network traffic analysis and research purposes.

_Stay tuned for updates!_ 🚀

## Use Cases
- **Network Performance Monitoring**: Analyze flow behavior to optimize 5G network performance.
- **Security Analysis**: Extract features for use in intrusion detection or anomaly detection systems.
- **Research Applications**: Study traffic characteristics for academic or commercial research.

## Prerequisites
Before using **5GPacketParser**, ensure your environment meets the following requirements:
- Python 3.7 or higher
- `scapy` (for packet parsing)
- `pycrate` (for NGAP and NAS encoders and decoders)
- Additional libraries listed in `requirements.txt`

Install dependencies with:
```bash
pip install -r requirements.txt
```

## Installation
1. Clone the repository:
```bash
git clone https://github.com/trungpv92/5GPacketParser.git
```
2. Navigate to the project directory:
```bash
cd 5GPacketParser/src
```

## Usage
1. Place your pcap file(s) in the ```pcaps/``` directory.
2. Execute the tool with:
```bash
python 5GPacketParser.py --input pcaps/example.pcap --output output/features.csv --packetcount 0 --windowtime 1.0
```
3. Command-line options:
  - --input: Path to the input pcap file.
  - --output: Path to save extracted features.
  - --packetcount: Number of packets to process (default: 0 that means all packets).
  - --windowtime: Time window for packet capture in seconds (default: 1.0).

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Contact
For any issues, questions, or feature requests, feel free to reach out:
  - Author: Trung Phan Van (trungpv92)
  - Email: trung.phan-van@etit.tu-chemnitz.de

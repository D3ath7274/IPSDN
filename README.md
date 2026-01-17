# IPSDN - Hybrid Intrusion Detection System in SDN

A hybrid intrusion detection and prevention system combining **signature-based detection** (Snort) and **anomaly-based detection** (Deep Learning) in a Software-Defined Networking (SDN) environment using the Ryu Controller.

---

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Attack Types](#attack-types)
- [Components](#components)
- [Dataset](#dataset)
- [Model Evaluation](#model-evaluation)
- [Configuration](#configuration)

---

## Overview
`
IPSDN is a comprehensive intrusion prevention system designed for SDN environments. It provides dual-layer protection:

1. **Signature-Based Detection**: Uses Snort rules to identify known attack patterns in real-time
2. **Anomaly-Based Detection**: Employs Machine Learning (MLP Neural Networks) to detect unknown/novel attacks through behavioral analysis

The system integrates with a Mininet virtual network topology and is controlled by the Ryu OpenFlow controller for dynamic traffic management and threat mitigation.

---

## Features

✓ **Dual Detection Mechanism**: Combines signature and anomaly-based approaches for comprehensive coverage  
✓ **Real-time Processing**: Processes network flows with minimal latency  
✓ **Deep Learning Models**: Neural network-based anomaly detection  
✓ **Automated Attack Detection**: Identifies multiple attack vectors simultaneously  
✓ **Flow Statistics Collection**: Extracts network flow features for analysis  
✓ **Performance Monitoring**: Tracks CPU usage, packet rates, and detection metrics  
✓ **Extensible Architecture**: Easy to add new attack types and detection rules  

---

## Project Structure

```
IPSDN-master/
├── Controller_Codes/                 # Core system controllers
│   ├── Controller.py                 # Main Ryu controller with detection logic
│   ├── Model_Evaluation.py          # ML model training and evaluation
│   ├── CPU_usage.py                 # System resource monitoring
│   ├── Dataset_Collect_Attack.py    # Attack traffic dataset collection
│   ├── Dataset_Collect_Normal.py    # Normal traffic dataset collection
│   ├── Anomaly_Based/
│   │   └── Anomaly_Controller.py    # Anomaly detection controller
│   ├── Signature_Based/
│   │   └── Signature_Controller.py  # Signature detection controller
│   ├── Dataset/                      # ML datasets
│   │   ├── train_dataset.csv        # Training data
│   │   ├── test_dataset.csv         # Testing data
│   │   ├── build_dataset.py         # Dataset generation script
│   │   └── clear_dataset.py         # Dataset cleanup script
│   └── Txt_Files/                    # Output logs and statistics
│
├── Scapy_Codes/                      # Attack traffic generation
│   ├── SYN_Flood.py                 # TCP SYN flood attack
│   ├── UDP_Flood.py                 # UDP flood attack
│   ├── Multi_SYN.py                 # Multi-target SYN flood
│   ├── Multi_UDP.py                 # Multi-target UDP flood
│   ├── LAND.py                      # LAND attack
│   ├── Smurf.py                     # Smurf attack
│   ├── Normal_TCP.py                # Normal TCP traffic
│   └── Normal_UDP.py                # Normal UDP traffic
│
├── Snort_Codes/                      # Signature-based detection
│   ├── IPSDN.rules                  # Custom Snort rules
│   └── Sending_Alert.py             # Alert handler
│
├── Mininet_Topology/                 # Network simulation
│   ├── Mininet_Topology.py          # Topology definition
│   └── Mininet_Topology.mn          # Mininet configuration file
│
└── README.md                         # This file
```

---

## Network Topology

The Mininet topology consists of the following hosts and interfaces:

| Host | IP Address | Interface | Role |
|---|---|---|---|
| **victim1** | 10.0.0.1 | victim1-eth0 | Target/Victim |
| **victim2** | 10.0.0.2 | victim2-eth0 | Target/Victim |
| **victim3** | 10.0.0.3 | victim3-eth0 | Target/Victim |
| **server** | 10.0.0.4 | server-eth0 | Server |
| **attacker** | 10.0.0.5 | attacker-eth0 | Attack Source |
| **nat0** | 10.0.0.6 | nat0-eth0 | NAT Gateway (enables internet access) |

**Switch:** switch1 (OpenFlow 1.3) with 6 interfaces  
**Controller:** RemoteController at 127.0.0.1:6633

---

## Prerequisites

### System Requirements
- **OS**: Ubuntu/Linux 16.04+ or similar
- **Python**: 3.6+
- **RAM**: 4GB minimum recommended
- **Disk Space**: 2GB for dependencies and datasets

### Required Software
- **Ryu Controller**: SDN controller framework
- **Snort**: Signature-based IDS/IPS
- **Mininet**: Network simulator
- **Scapy**: Packet manipulation library
- **scikit-learn**: Machine learning library
- **pandas**: Data processing
- **numpy**: Numerical computing

---

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/IPSDN.git
cd IPSDN-master
```

### 2. Install Python Dependencies

Install the required packages using pip:
```bash
pip install ryu scapy pandas scikit-learn numpy psutil
```

**Package descriptions:**
- **ryu**: SDN controller framework
- **scapy**: Packet manipulation library
- **pandas**: Data processing
- **scikit-learn**: Machine learning library
- **numpy**: Numerical computing
- **psutil**: System resource monitoring

### 3. Install Snort
```bash
sudo apt-get update
sudo apt-get install snort
```

### 4. Install Mininet
```bash
sudo apt-get install mininet
```

### 5. Configure Snort Rules
- Copy `Snort_Codes/IPSDN.rules` to Snort configuration directory
- Update Snort configuration to enable alerts

---

## Usage

### Step 1: Start Mininet Topology
```bash
sudo python3 Mininet_Topology/Mininet_Topology.py
```

### Step 2: Start Ryu Controller
```bash
cd Controller_Codes
ryu-manager Controller.py
```

### Step 3: Generate Network Traffic

**Important**: After running Step 1 (Mininet Topology), you'll see the `mininet>` prompt. All commands below must be run from this `mininet>` prompt, not from your host terminal.

#### Initial Setup: Install Dependencies in Mininet Nodes

Mininet nodes have **no internet connectivity by default**, which prevents package downloads. Use one of these solutions:

**Solution 1: Enable Internet Access in Mininet (Recommended)**

Modify your `Mininet_Topology.py` to give nodes internet access through NAT:
```python
# Add these lines to your topology setup
net.addNAT().configDefault()
```

Then install packages:
```bash
mininet> victim1 sudo apt-get update
mininet> victim1 sudo apt-get install -y python3-scapy
# Repeat for other nodes
```

**Solution 2: Run Scripts from Host Machine**

Instead of running scripts inside Mininet nodes, run them from the host with proper routing:

```bash
# From host terminal (not mininet> prompt):
cd ~/IPSDN

# Install dependencies on host first
sudo apt-get install -y python3-scapy
sudo pip3 install scapy

# Run traffic generation on host (packets will route through Mininet topology)
sudo python3 Scapy_Codes/Normal_TCP.py -s 1 -e 4
```

**Solution 3: Pre-Install on Host and Mount Filesystem**

Pre-install scapy on your host machine, then in your Mininet topology, mount the site-packages directory as a shared volume so nodes can access installed packages.

---

#### Normal Traffic (for training baseline)

**Method 1: Using xterm (Recommended)**
```bash
# At the mininet> prompt, open terminal windows on victim nodes
mininet> xterm victim1 victim2 victim3

# In each xterm window, run:
victim1# cd ~/IPSDN
victim1# python3 Scapy_Codes/Normal_TCP.py -s 1 -e 4
victim1# python3 Scapy_Codes/Normal_UDP.py -s 1 -e 4
```

**Method 2: Direct command from mininet> prompt**
```bash
# At the mininet> prompt:
mininet> victim1 python3 ~/IPSDN/Scapy_Codes/Normal_TCP.py -s 1 -e 4
mininet> victim2 python3 ~/IPSDN/Scapy_Codes/Normal_UDP.py -s 1 -e 4
```

#### Attack Traffic (for testing detection)

**Method 1: Using xterm**
```bash
# At the mininet> prompt, open a terminal on the attacker node
mininet> xterm attacker

# In the attacker xterm window:
attacker# cd ~/IPSDN

# SYN Flood Attack on victim1 (10.0.0.1)
attacker# sudo python3 Scapy_Codes/SYN_Flood.py 10.0.0.1

# UDP Flood Attack on victim2 (10.0.0.2)
attacker# sudo python3 Scapy_Codes/UDP_Flood.py 10.0.0.2

# Multi-target SYN Flood (all victims)
attacker# sudo python3 Scapy_Codes/Multi_SYN.py 10.0.0.1 10.0.0.2 10.0.0.3

# Multi-target UDP Flood (all victims)
attacker# sudo python3 Scapy_Codes/Multi_UDP.py 10.0.0.1 10.0.0.2 10.0.0.3

# LAND Attack on victim1 (10.0.0.1)
attacker# sudo python3 Scapy_Codes/LAND.py 10.0.0.1 6969

# Smurf Attack targeting victim3 (10.0.0.3)
attacker# sudo python3 Scapy_Codes/Smurf.py 10.255.255.255 10.0.0.3
```

**Method 2: Direct command from mininet> prompt**
```bash
# At the mininet> prompt:
mininet> attacker sudo python3 ~/IPSDN/Scapy_Codes/SYN_Flood.py 10.0.0.1
mininet> attacker sudo python3 ~/IPSDN/Scapy_Codes/UDP_Flood.py 10.0.0.2
```

**Troubleshooting Module Errors**:
- If you get `ModuleNotFoundError: No module named 'scapy'`, install scapy on that node: `mininet> <nodename> sudo pip install scapy`
- Repeat for any missing modules on other nodes as needed

**Note**: Use `python3` explicitly on Ubuntu 20.04. Attack scripts require `sudo` to manipulate network packets. All commands must be executed from the `mininet>` prompt.

### Data Collection Workflow

**Normal Traffic Dataset:**
1. Start Ryu controller with normal mode
2. Run `pingall` in Mininet
3. Execute `Normal_TCP.py` and `Normal_UDP.py`
4. Collect flow statistics

**Attack Traffic Dataset:**
1. Start Ryu controller with attack mode
2. Execute attack scripts (LAND, UDP Flood, SYN Flood, etc.)
3. Collect flow statistics

---

## Attack Types

The system can detect and respond to the following attack vectors:

| Attack Type | File | Description |
|---|---|---|
| **SYN Flood** | `SYN_Flood.py` | TCP SYN packet flood to exhaust resources |
| **UDP Flood** | `UDP_Flood.py` | UDP packet flood attack |
| **Multi-target SYN** | `Multi_SYN.py` | SYN flood targeting multiple hosts |
| **Multi-target UDP** | `Multi_UDP.py` | UDP flood targeting multiple hosts |
| **LAND** | `LAND.py` | Source and destination IP/port spoofing |
| **Smurf** | `Smurf.py` | ICMP broadcast amplification attack |

---

## Components

### Ryu Controller (`Controller_Codes/Controller.py`)
- Main SDN controller managing network flows
- Integrates signature detection (Snort) and anomaly detection (ML)
- Collects network statistics and flow information
- Enforces mitigation policies (dropping/redirecting malicious traffic)
- Monitors system performance (CPU, packet rates)

### Signature-Based Detection (`Snort_Codes/`)
- Custom Snort rules for known attack patterns (`IPSDN.rules`)
- Real-time packet inspection
- Alert generation for detected threats

### Anomaly-Based Detection (`Controller_Codes/Anomaly_Based/`)
- Multi-Layer Perceptron (MLP) neural network classifier
- Trained on normal traffic behavior
- Detects deviations from baseline behavior

### Dataset Management (`Controller_Codes/Dataset/`)
- **build_dataset.py**: Aggregates flow statistics into training/testing datasets
- **clear_dataset.py**: Resets datasets for fresh collection
- CSV format with flow features and classification labels

### Traffic Generation (`Scapy_Codes/`)
- Attack simulation using Scapy library
- Normal traffic generation for baseline establishment
- Customizable traffic parameters

---

## Dataset

### Dataset Features

Flow-based features extracted from network traffic:
- Source/Destination IP addresses and ports
- Protocol type (TCP/UDP/ICMP)
- Packet count and byte count
- Flow duration
- Flag distributions
- Inter-arrival times

### Dataset Format

CSV files with the following structure:
```
feature1,feature2,...,featureN,class
0.5,0.3,...,0.7,0  (normal traffic, class=0)
0.8,0.9,...,0.2,1  (attack traffic, class=1)
```

### Files
- `train_dataset.csv`: Training set for model development
- `test_dataset.csv`: Testing set for model evaluation
- `train_dataset_with-src-dst-port.csv`: Extended features including ports
- `test_dataset_with-src-dst-port.csv`: Extended test set

---

## Model Evaluation

### Training & Evaluation Script (`Model_Evaluation.py`)

The system evaluates MLP models with various configurations:

**Tested Models:**
- Different hidden layer sizes
- Multiple activation functions (logistic, ReLU)
- Various learning rates and momentum parameters
- Cross-validation with multiple iterations

**Evaluation Metrics:**
- Accuracy Score
- Confusion Matrix
- Precision, Recall, F1-Score
- Classification Report

**Output:**
Results saved to `Txt_Files/evaluation_results.txt`

### Performance Monitoring (`CPU_usage.py`)

Tracks:
- CPU usage percentage
- Memory consumption
- Process statistics
- Real-time performance impact

---

## Configuration

### Ryu Controller Configuration

Edit `Controller.py` to customize:
- Detection sensitivity thresholds
- Flow collection intervals
- Mitigation actions (drop/redirect policies)
- Alert notification methods

### Snort Rules Configuration

Edit `Snort_Codes/IPSDN.rules` to:
- Add custom detection rules
- Modify rule actions (alert/drop)
- Adjust threshold parameters

### Dataset Configuration

Edit dataset collection scripts to:
- Change flow statistics granularity
- Modify feature extraction parameters
- Adjust time windows for aggregation

---

## Output Files

The system generates various log and statistics files in `Controller_Codes/Txt_Files/`:
- `cpu_usage.txt`: CPU utilization over time
- `snort_alerts.txt`: Snort detection alerts
- `packets_in_time.txt`: Packet arrival rates
- `flow_stats_predict.txt`: ML model predictions
- `evaluation_results.txt`: Model performance metrics

---

## Troubleshooting

### Common Issues

**Issue**: Mininet network not connecting
- **Solution**: Run with sudo privileges, check if OVS is installed

**Issue**: Ryu controller not receiving packets
- **Solution**: Verify Mininet topology starts controller connection, check OpenFlow version

**Issue**: Low detection accuracy
- **Solution**: Ensure sufficient training data, check feature normalization in preprocessing

**Issue**: High false positive rate
- **Solution**: Retrain models with more balanced datasets, adjust detection thresholds

---

## Future Enhancements

- [ ] Integration with additional ML algorithms (SVM, Random Forest, Deep Neural Networks)
- [ ] Real-time model retraining with new attack patterns
- [ ] Distributed architecture for larger networks
- [ ] Advanced visualization dashboard
- [ ] Support for IPv6 traffic
- [ ] Automated response actions and mitigation

---

## License

[Add your license information here]

---

## Authors & Contributors

[Add author information here]

---

## References

- Ryu: https://github.com/osrg/ryu
- Snort: https://www.snort.org/
- Mininet: http://mininet.org/
- Scapy: https://scapy.readthedocs.io/

---

**Last Updated**: January 2026
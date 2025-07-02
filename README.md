# Waluigi - reverge collector framework

<div align="center">

![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)
![Version](https://img.shields.io/badge/version-v1.0.0-orange.svg)

**A comprehensive, distributed security scanning and reconnaissance framework**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Architecture](#architecture) • [Tools](#supported-tools) • [API](#api-reference)

</div>

---

## 🎯 Overview

**Waluigi** is a powerful, distributed security reconnaissance framework designed for bug bounty hunters, penetration testers, and security researchers. It acts as the collector component for the [reverge](https://www.reverge.io/) attack surface management tool. Built with Python and Luigi task orchestration, it provides automated, scalable scanning capabilities across multiple security tools and methodologies.

### Key Highlights

- 🚀 **Distributed Architecture** - Scalable collector-manager design
- 🔧 **Multi-Tool Integration** - Seamless integration with 10+ security tools
- 📊 **Intelligent Optimization** - Smart scan ordering and result correlation
- 🌐 **Web-Scale Scanning** - Handle massive target lists efficiently
- 🔒 **Secure Communication** - Encrypted data transmission and API authentication
- 📈 **Real-time Monitoring** - Live scan status and progress tracking

---

## ✨ Features

### 🎛️ **Comprehensive Scanning Capabilities**
- **Network Discovery**: Port scanning with Masscan and Nmap
- **Web Application Testing**: HTTP probing with HTTPX
- **Subdomain Enumeration**: Advanced DNS discovery with Subfinder
- **Vulnerability Assessment**: Template-based scanning with Nuclei
- **Directory Discovery**: Web path enumeration with Feroxbuster
- **Visual Analysis**: Screenshot capture and analysis
- **Certificate Analysis**: SSL/TLS certificate inspection and domain extraction

### 🏗️ **Advanced Architecture**
- **Luigi Task Orchestration**: Robust workflow management and dependency handling
- **Distributed Processing**: Multi-collector deployment with centralized management
- **Intelligent Scan Optimization**: Tool ordering based on previous results
- **Parallel Execution**: Concurrent scanning for maximum performance
- **Process Management**: Advanced process tracking and cancellation capabilities

### 🔐 **Security & Reliability**
- **Encrypted Communication**: AES-256 encryption for all data transmission
- **API Authentication**: Bearer token-based secure API access
- **Session Management**: Robust session handling with key rotation
- **Error Handling**: Comprehensive exception management and recovery
- **Resource Management**: Memory and CPU optimization for large-scale scans

### 📊 **Data Management**
- **Structured Data Models**: Comprehensive object-oriented data representation
- **Relationship Mapping**: Intelligent correlation between scan results
- **Deduplication**: Advanced duplicate detection and removal
- **Export Capabilities**: Multiple output formats and integration options
- **Historical Tracking**: Scan history and progress monitoring

---

## 🚀 Installation

### Prerequisites

- **Operating System**: Linux (Ubuntu 20.04+ recommended)
- **Python**: 3.9 or higher
- **Memory**: 4GB RAM minimum (8GB+ recommended)
- **Storage**: 10GB available space
- **Network**: Internet connectivity for tool downloads

### Quick Install

```bash
# Clone the repository
git clone https://github.com/securifera/reverge_collector.git
cd reverge_collector

# Run the automated installer
chmod +x install.sh
sudo ./install.sh

# Install Python dependencies
pip install -r requirements.txt

# Or use Poetry for dependency management
poetry install
```

### Manual Installation

<details>
<summary>Click to expand manual installation steps</summary>

```bash
# 1. Install system dependencies
sudo apt update
sudo apt install -y python3 python3-pip git curl wget

# 2. Install security tools
# Masscan
sudo apt install -y masscan

# Nmap
sudo apt install -y nmap

# Install Go (for ProjectDiscovery tools)
wget https://golang.org/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Install ProjectDiscovery tools
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Feroxbuster
wget https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb
sudo dpkg -i feroxbuster_amd64.deb

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Set up configuration
mkdir -p ~/.config/waluigi
```

</details>

### Docker Installation

```bash
# Build the Docker image
docker build -t waluigi .

# Run with Docker Compose
docker-compose up -d
```

---

## 📖 Usage

### Quick Start

```bash
# Start the scan collector
python -m waluigi.scan_poller -x YOUR_TOKEN

# Or with debugging enabled
python -m waluigi.scan_poller -x YOUR_TOKEN -d
```

### Configuration

```python
# Basic configuration example
from waluigi import recon_manager

# Initialize the reconnaissance manager
manager = recon_manager.ReconManager(
    token="your-api-token",
    manager_url="https://your-manager-url.com"
)

# Get available tools
tools = manager.get_tools()
print(f"Available tools: {len(tools)}")
```

### Interactive Console

Once running, the interactive console provides real-time control:

```
> h                    # Show help
> d                    # Toggle debug mode
> x                    # Toggle scanner thread
> q                    # Quit application
```

### API Integration

```python
# Example: Submit a scan programmatically
import requests

headers = {
    'Authorization': 'Bearer YOUR_TOKEN',
    'Content-Type': 'application/json'
}

scan_data = {
    "target": "example.com",
    "tools": ["subfinder", "httpx", "nuclei"],
    "scope": {
        "domains": ["example.com"],
        "ports": [80, 443, 8080]
    }
}

response = requests.post(
    'https://manager-url/api/scans',
    headers=headers,
    json=scan_data
)
```

---

## 🏛️ Architecture

### System Overview

```
┌─────────────────┐    ┌─────────────────┐
│   Reverge       │    │   Collectors    │
│                 │◄──►│                 │
│  - Dashboard    │    │  - Tool Exec    │
│  - Scan Config  │    │  - Data Proc    │
│  - Results View │    │  - Status Report│
└─────────────────┘    └─────────────────┘
         │                                             
         ┼
         │
┌─────────────────┐
│    Database     │
│                 │
│  - Scan Data    │
│  - Tool Results │
│  - User Config  │
└─────────────────┘
```

### Component Details

#### 🎯 **Scan Collector** (`scan_poller.py`)
- Polls manager for scheduled scans
- Orchestrates tool execution
- Reports scan progress and results
- Handles process management and cleanup

#### 🧠 **Reconnaissance Manager** (`recon_manager.py`)
- Central coordination hub
- API communication with manager
- Session and authentication management
- Network interface detection

#### 🔧 **Tool Integration**
Each tool is implemented as a Luigi task with:
- **Configuration Class**: Tool parameters and metadata
- **Scan Task**: Execution logic and process management
- **Import Task**: Result parsing and data model creation

#### 📊 **Data Models** (`data_model.py`)
Comprehensive object-oriented representation:
- `Host`, `Port`, `Domain` - Network assets
- `Certificate`, `WebComponent` - Security artifacts
- `ScanData`, `ToolExecutor` - Scan management
- `CollectionModule` - Modular scan components

---

## 🛠️ Supported Tools

| Tool | Purpose | Integration | Status |
|------|---------|-------------|--------|
| **Masscan** | Fast port scanning | Native binary | ✅ Active |
| **Nmap** | Comprehensive port scanning | python-libnmap | ✅ Active |
| **HTTPX** | HTTP/HTTPS probing | Native binary | ✅ Active |
| **Subfinder** | Subdomain enumeration | Native binary | ✅ Passive |
| **Nuclei** | Vulnerability scanning | Native binary | ✅ Active |
| **Feroxbuster** | Directory enumeration | Native binary | ✅ Active |
| **Shodan** | Search engine integration | Python API | ✅ Passive |
| **Pyshot** | Website Screenshot | PhantomJS | ✅ Active |
| **BadSecrets** | Secret detection | Custom implementation | ✅ Active |
| **WebCapture** | Website Screenshot | Chrome | ✅ Active |

### Tool Execution Flow

```mermaid
graph LR
    A[Masscan] --> B[Nmap]
    B --> C[HTTPX]
    C --> D[Subfinder]
    D --> E[Nuclei]
    E --> F[Feroxbuster]
    F --> G[Screenshots]
    
    A --> H[Data Import]
    B --> H
    C --> H
    D --> H
    E --> H
    F --> H
    G --> H
```

---

## 📚 API Reference

### Core Classes

#### `ReconManager`
Central management class for scan coordination.

```python
class ReconManager:
    def __init__(self, token: str, manager_url: str)
    def get_scheduled_scans() -> List[ScheduledScan]
    def get_scan_status(scan_id: str) -> ScanStatus
    def import_data(scan_id: str, tool_id: str, results: Dict)
```

#### `ScheduledScan`
Represents a configured scan with tools and targets.

```python
class ScheduledScan:
    def __init__(self, scan_thread: ScheduledScanThread, scan_data: Dict)
    def update_scan_status(status: ScanStatus, error_msg: str = None)
    def register_tool_executor(tool_id: str, executor: ToolExecutor)
    def kill_scan_processes(tool_ids: List[str] = [])
```

#### `WaluigiTool`
Base class for all integrated security tools.

```python
class WaluigiTool:
    name: str
    description: str
    scan_order: int
    args: str
    scan_func: Callable
    import_func: Callable
```

### Luigi Tasks

Each tool implements standardized Luigi tasks:

```python
class ToolScan(luigi.Task):
    scan_input = luigi.Parameter()
    
    def output(self) -> luigi.LocalTarget
    def run(self) -> None

class ImportToolOutput(luigi.Task):
    def requires(self) -> ToolScan
    def run(self) -> None
```

---

## 🔧 Configuration


### Tool Configuration

Tools can be configured with custom arguments:

```python
# Nmap configuration
nmap_tool = Nmap()
nmap_tool.args = "-sV --script +ssl-cert -T4"

# HTTPX configuration  
httpx_tool = Httpx()
httpx_tool.args = "-favicon -td -t 100 -timeout 5"
```

### API Keys

Configure external service API keys:

```yaml
# ~/.config/subfinder/provider-config.yaml
shodan: ["your-shodan-key"]
securitytrails: ["your-securitytrails-key"]
chaos: ["your-chaos-key"]
```

---

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest tests/

# Run specific test modules
pytest tests/routes/test_nmap_scan.py
pytest tests/routes/test_httpx_scan.py

```

### Test Structure

```
tests/
├── conftest.py              # Test configuration
├── routes/                  # Tool-specific tests
│   ├── test_nmap_scan.py
│   ├── test_httpx_scan.py
│   └── test_nuclei_scan.py
```

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/your-username/reverge_collector.git
cd reverge_collector

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements.txt

```

### Code Standards

- **Python Style**: Follow PEP 8 guidelines
- **Type Hints**: Use comprehensive type annotations
- **Documentation**: Sphinx-compatible docstrings required
- **Testing**: Maintain >80% test coverage
- **Security**: Follow security best practices

---

## 📋 Changelog

### v1.0.0 (Current)
- ✅ Initial release with 10 integrated tools
- ✅ Distributed collector-manager architecture
- ✅ Luigi task orchestration
- ✅ Comprehensive API framework
- ✅ Advanced process management

### Roadmap
- 🔄 Additional tool integrations
- 🔄 Machine learning result correlation
- 🔄 Advanced reporting capabilities

---

## 📞 Support

### Documentation
- **Wiki**: [GitHub Wiki](https://github.com/securifera/reverge_collector/wiki)
- **API Docs**: Auto-generated from docstrings
- **Examples**: `/examples` directory

### Community
- **Issues**: [GitHub Issues](https://github.com/securifera/reverge_collector/issues)
- **Discussions**: [GitHub Discussions](https://github.com/securifera/reverge_collector/discussions)
- **Security**: See [SECURITY.md](SECURITY.md) for reporting vulnerabilities

### Commercial Support
For enterprise support and consulting:
- **Website**: [reverge.io](https://www.reverge.io/)
- **Email**: support@reverge.io

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **ProjectDiscovery** - For excellent security tools (HTTPX, Subfinder, Nuclei)
- **Luigi** - For robust task orchestration framework
- **Security Community** - For continuous feedback and contributions

---

<div align="center">

**Built with ❤️ by Securifera**

[⬆ Back to Top](#waluigi---automated-security-reconnaissance-framework)

</div>

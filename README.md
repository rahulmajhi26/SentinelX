# SentinelX
SentinelX is a powerful Cyber Threat Intelligence (CTI) tool built for Linux systems. It empowers cybersecurity professionals and analysts to gather, analyze, and correlate threat data from various sources, helping to detect, track, and respond to cyber threats swiftly and effectively.



## Table of Contents

- [Features](#features)  
- [Installation](#installation)  
- [Usage](#usage)  
- [Configuration](#configuration)  
- [API Integration](#api-integration)  
- [How It Works](#how-it-works)  
- [Contributing](#contributing)  
- [License](#license)  
- [Contact](#contact)

---

## Features

- **VirusTotal Integration:** Analyze files, IPs, URLs, and domains for malware, phishing, and suspicious activity using VirusTotal's public API.
- **IOC Collection & Analysis:** Input Indicators of Compromise (hashes, IP addresses, domains) to fetch detailed threat intelligence.
- **Threat Actor Tracking:** Aggregate threat data to help profile and monitor potential attackers.
- **Automated Reporting:** Generate detailed HTML and text reports summarizing investigation results.
- **Modular CLI Interface:** Easy-to-use command-line interface with modular design for extensibility.
- **Cross-Platform Compatibility:** Designed primarily for Linux but compatible with other UNIX-like systems.
- **Real-Time Alerts Simulation:** Simulate real-time detection alerts for security operations readiness.

---

## Installation

### Prerequisites

- Python 3.7 or higher  
- Git  
- Internet connection (for API calls)

### Step 1: Clone the repository

```bash
git clone https://github.com/yourusername/SentinelX.git
cd SentinelX
````

### Step 2: Install dependencies

It's recommended to use a Python virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

*If `requirements.txt` does not exist yet, you can install dependencies manually like `requests`.*

### Step 3: Configure API Keys

Sign up on [VirusTotal](https://www.virustotal.com/) to get a free API key.
Create a `.env` file in the root directory and add your API key:

```
VT_API_KEY=your_virustotal_api_key_here
```

---

## Usage

Run the main tool script with Python:

```bash
python3 sentinelx.py
```

You will see an interactive CLI menu to:

* Scan an IP address
* Scan a domain
* Scan a file hash (MD5, SHA256)
* Generate detailed reports

Follow on-screen prompts to enter the data you want to investigate.

---

## Configuration

* API keys are loaded from `.env` file using `python-dotenv` (make sure to install it).
* Customize output folders and report formats inside the script if needed.

---

## API Integration

SentinelX currently supports VirusTotal API for threat intelligence. The tool sends requests to VirusTotal's endpoints to retrieve information about submitted IOCs.

*Note:* VirusTotal's free API has request rate limits. For heavy usage, consider upgrading your API subscription.

---

## How It Works

1. **User Input:** The user inputs an IOC (IP, domain, file hash).
2. **API Query:** SentinelX queries VirusTotal API with the IOC.
3. **Data Processing:** The tool processes JSON responses, extracts relevant threat details.
4. **Threat Correlation:** It correlates data such as malware detections, related URLs, and threat actors.
5. **Reporting:** Generates a human-readable report summarizing all findings.

---

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature-name`)
3. Commit your changes (`git commit -m 'Add feature'`)
4. Push to your branch (`git push origin feature-name`)
5. Create a Pull Request

Please follow code style guidelines and write clear commit messages.

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## Contact

Created and maintained by **Rahul Majhi**

* Twitter(X): https://x.com/r_dex_26
* Email: workforrdex@gmail.com

---

## Disclaimer

This tool is for **educational and ethical use only**. The author is not responsible for misuse or any damage caused by this tool.

---

*Thank you for using SentinelX! Stay vigilant, stay secure.*

```

---

If you want, I can help you generate:

- A **requirements.txt** file  
- The `.env` loader code snippet for your Python tool  
- License file content (MIT or other)  

Just ask!
```

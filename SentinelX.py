import requests
import re
import os
import datetime

# =======================
# Configuration Section
# =======================

VT_API_KEY = "14bc97ae3aafcb64252612865b55d809016d21feda056a5c167790eda4e258c8"

ALERT_KEYWORDS = [
    "APT28", "malware", "ransomware", "suspicious", "leak", "exploit", "phishing"
]

DARKWEB_DATA_DIR = "data/darkweb_samples"
FEEDS_DATA_DIR = "data/feeds"
OUTPUT_DIR = "output"

# Ensure necessary directories exist
for directory in [DARKWEB_DATA_DIR, FEEDS_DATA_DIR, OUTPUT_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory)

# =======================
# IOC Analyzer Module
# =======================

def analyze_ioc(ioc):
    print(f"\n🔍 Analyzing IOC: {ioc}")

    url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if "data" in data and len(data["data"]) > 0:
                stats = data["data"][0]["attributes"].get("last_analysis_stats")
                if stats:
                    print("✅ IOC found in VirusTotal with the following stats:")
                    for key, value in stats.items():
                        print(f"  {key.capitalize()}: {value}")
                else:
                    print("ℹ️ IOC found but no analysis stats available.")
            else:
                print("ℹ️ No data found for this IOC in VirusTotal.")
        else:
            print(f"❌ Error fetching data from VirusTotal. Status code: {response.status_code}")
            print(f"Response: {response.text}")
    except Exception as e:
        print(f"❌ Exception during VirusTotal query: {e}")

# =======================
# Dark Web Scanner Module
# =======================

def scan_darkweb(keyword):
    print(f"\n🌐 Scanning simulated Dark Web data for: '{keyword}'...")

    found = False
    for file in os.listdir(DARKWEB_DATA_DIR):
        if file.endswith(".txt"):
            filepath = os.path.join(DARKWEB_DATA_DIR, file)
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                if re.search(keyword, content, re.IGNORECASE):
                    print(f"✅ Found keyword '{keyword}' in file: {file}")
                    found = True

    if not found:
        print("🚫 No matches found in dark web data.")

# =======================
# Threat Actor Tracker Module
# =======================

def track_actor(keyword):
    print(f"\n🕵️ Tracking Threat Actor/TTP for: '{keyword}'\n")

    actor_db = {
        "APT28": {
            "aliases": ["Fancy Bear", "Sofacy"],
            "tactics": ["Credential Access", "Defense Evasion"],
            "country": "Russia"
        },
        "APT29": {
            "aliases": ["Cozy Bear", "The Dukes"],
            "tactics": ["Reconnaissance", "Spear Phishing"],
            "country": "Russia"
        },
        "Lazarus Group": {
            "aliases": ["Hidden Cobra"],
            "tactics": ["Financial Theft", "Malware Deployment"],
            "country": "North Korea"
        },
        "FIN7": {
            "aliases": ["Carbanak Group"],
            "tactics": ["Data Exfiltration", "Malware", "Backdoors"],
            "country": "Unknown"
        },
        "TA505": {
            "aliases": ["SectorJ04"],
            "tactics": ["Banking Malware", "Phishing Campaigns"],
            "country": "Global"
        }
    }

    found = False
    for actor, info in actor_db.items():
        if keyword.lower() in actor.lower() or any(keyword.lower() in alias.lower() for alias in info["aliases"]):
            print(f"🎯 Match Found: {actor}")
            print(f" - Aliases: {', '.join(info['aliases'])}")
            print(f" - Tactics: {', '.join(info['tactics'])}")
            print(f" - Suspected Origin: {info['country']}")
            found = True
            break

    if not found:
        print("🚫 No matching threat actor found in local database.")

# =======================
# Alert System Module
# =======================

def check_alerts():
    print("\n🔔 Checking for real-time alerts (simulated feed)...")

    triggered = False

    for filename in os.listdir(FEEDS_DATA_DIR):
        if filename.endswith(".log"):
            filepath = os.path.join(FEEDS_DATA_DIR, filename)
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()
                for line in lines:
                    for keyword in ALERT_KEYWORDS:
                        if re.search(keyword, line, re.IGNORECASE):
                            print(f"🚨 ALERT [{keyword.upper()}] found in {filename}:")
                            print(f"  → {line.strip()}\n")
                            triggered = True

    if not triggered:
        print("✅ No current alerts detected.")

# =======================
# Report Generator Module
# =======================

def generate_report():
    print("\n📝 Generating Threat Intelligence Report...")

    # You can replace this dummy data with actual data collected in runtime
    report_data = {
        "ioc_detected": ["198.50.100.12", "malicious.com", "e3b0c44298fc1c149"],
        "actors": ["APT28", "Lazarus Group"],
        "alerts": ["Ransomware attack via phishing", "Data leak detected"]
    }

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_name = f"BlackTrace_Report_{timestamp}.html"
    output_path = os.path.join(OUTPUT_DIR, report_name)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"<html><head><title>BlackTrace Report - {timestamp}</title></head><body>")
        f.write("<h1 style='color:#2E86C1;'>🛡️ BlackTrace - Threat Intelligence Report</h1>")
        f.write(f"<p><b>Generated on:</b> {timestamp}</p><hr>")

        f.write("<h2>🚨 Detected IOCs:</h2><ul>")
        for ioc in report_data["ioc_detected"]:
            f.write(f"<li>{ioc}</li>")
        f.write("</ul>")

        f.write("<h2>🎯 Suspected Threat Actors:</h2><ul>")
        for actor in report_data["actors"]:
            f.write(f"<li>{actor}</li>")
        f.write("</ul>")

        f.write("<h2>🔔 Alerts:</h2><ul>")
        for alert in report_data["alerts"]:
            f.write(f"<li>{alert}</li>")
        f.write("</ul>")

        f.write("</body></html>")

    print(f"✅ Report saved as: {output_path}")

# =======================
# Main Menu
# =======================

def main():
    while True:
        print("\n🛡️  BlackTrace - Cyber Threat Intel Recon Engine")
        print("1. Analyze IOC")
        print("2. Track Threat Actor")
        print("3. Scan Dark Web")
        print("4. Check Real-time Alerts")
        print("5. Generate Threat Report")
        print("6. Exit")

        choice = input("\nEnter your choice (1-6): ").strip()

        if choice == "1":
            ioc = input("Enter IOC (IP, Domain, Hash): ").strip()
            analyze_ioc(ioc)

        elif choice == "2":
            keyword = input("Enter actor keyword or TTP: ").strip()
            track_actor(keyword)

        elif choice == "3":
            query = input("Enter keyword to scan dark web: ").strip()
            scan_darkweb(query)

        elif choice == "4":
            check_alerts()

        elif choice == "5":
            generate_report()

        elif choice == "6":
            print("👋 Exiting BlackTrace. Stay safe!")
            break

        else:
            print("❌ Invalid choice. Please enter a number from 1 to 6.")

if __name__ == "__main__":
    main()

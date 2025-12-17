import os

ALERTS = []

def detect_sysmon(log):
    if "EncodedCommand" in log or "unknown.exe" in log:
        ALERTS.append("Suspicious process detected (Sysmon)")

def detect_zeek(log):
    if log.count("HTTP POST") >= 3:
        ALERTS.append("Possible brute-force or scanning activity (Zeek)")

def detect_suricata(log):
    if "Malware" in log or "Brute Force" in log:
        ALERTS.append("Network attack detected (Suricata)")

def read_logs():
    for file in os.listdir("../logs"):
        with open(f"../logs/{file}", "r") as f:
            lines = f.readlines()
            for line in lines:
                if "sysmon" in file:
                    detect_sysmon(line)
                elif "zeek" in file:
                    detect_zeek(line)
                elif "suricata" in file:
                    detect_suricata(line)

if __name__ == "__main__":
    read_logs()
    print("=== Security Alerts ===")
    for alert in set(ALERTS):
        print(alert)

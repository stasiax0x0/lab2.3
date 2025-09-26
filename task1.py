# lab2.3_starter.py
import json
from collections import defaultdict
from datetime import datetime

LOGFILE = "sample_auth_small.log"

def top_n(counts, n):
    return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:n]

def parse_auth_line(line):
    """
    Parse an auth log line and return (timestamp, ip, event_type)
    Example auth line:
    Mar 10 13:58:01 host1 sshd[1023]: Failed password for invalid user admin from 203.0.113.45 port 52344 ssh2
    We will:
     - parse timestamp (assume year 2025)
     - extract IP (token after 'from')
     - event_type: 'failed' if 'Failed password', 'accepted' if 'Accepted password', else 'other'
    """
    parts = line.split()
    # timestamp: first 3 tokens 'Mar 10 13:58:01'
    ts_str = " ".join(parts[0:3])
    try:
        ts = datetime.strptime(f"2025 {ts_str}", "%Y %b %d %H:%M:%S")
    except Exception:
        ts = None
    ip = None
    event_type = "other"
    if "Failed password" in line:
        event_type = "failed"
    elif "Accepted password" in line or "Accepted publickey" in line:
        event_type = "accepted"
    if " from " in line:
        try:
            idx = parts.index("from")
            ip = parts[idx+1]
        except (ValueError, IndexError):
            ip = None
    return ts, ip, event_type

if __name__ == "__main__":
    per_ip_timestamps = defaultdict(list)
    with open(LOGFILE) as f:
        for line in f:
            ts, ip, event = parse_auth_line(line)
            if ts and ip and event == "failed":   # checks that ts and ip are not null, and that event=="failed"
                per_ip_timestamps[ip].append(ts)
    
    
    # quick print
    for ip, times in per_ip_timestamps.items():
        formatted_times = [t.strftime("%b %d %H:%M:%S") for t in times]  # Format as 'Mar 10 13:45:01'
        print(f'  "{ip}": [')
        for ft in formatted_times:
            print(f'      "{ft}",')
        print('  ], ')


# task2.py
from datetime import timedelta

incidents = []
window = timedelta(minutes=10)
for ip, times in per_ip_timestamps.items():
    times.sort()
    n = len(times)
    i = 0
    while i < n:
        j = i
        while j + 1 < n and (times[j+1] - times[i]) <= window:
            j += 1
        count = j - i + 1
        if count >= 5:
            incidents.append({
                "ip": ip,
                "count": count,
                "first": times[i].isoformat(),
                "last": times[j].isoformat()
            })
            # advance i past this cluster to avoid duplicate overlapping reports:
            i = j + 1
        else:
            i += 1
# print incidents
print(f'Detected {len(incidents)} brute-force incidents {incidents}')


for incident in incidents:
    count_incidents +=1

#task3


top_failed_ips = top_n(incidents, 10)

print("Top 10 IPs with most failed attempts:")
for ip, count in top_failed_ips:
    print(f"{ip}, {count}")

with open("bruteforce_incidents.txt", "w")as file:
        file.write("Top 10 IPs with most failed attempts:\n")        #write hearder
        for ip, count in top_failed_ips():
            file.write(f"{ip}, {len(incidents)}\n")
import random
from datetime import datetime, timedelta

# ------------------------
# CONFIG
# ------------------------
users = ["john.doe", "alice", "bob", "emma", "david"]
ips = [f"192.168.1.{i}" for i in range(10, 60)]
domains = ["google.com", "linkedin.com", "acme.com", "youtube.com"]

start_time = datetime(2026, 4, 1, 8, 0, 0)

web_logs, windows_logs, dns_logs, email_logs = [], [], [], []
auth_logs, cloud_logs, file_logs = [], [], []

# ------------------------
# HELPER
# ------------------------
def rand_time(i):
    return start_time + timedelta(seconds=i * 5)

def pick_user():
    return random.choice(users)

def pick_ip():
    return random.choice(ips)

# ------------------------
# BASELINE (NOISE)
# ------------------------
for i in range(300):
    t = rand_time(i)
    user = pick_user()
    
    web_logs.append(f"timestamp={t} index=web user={user} url=http://{random.choice(domains)} action=allowed")
    windows_logs.append(f"EventCode=4688 index=windows User={user} ProcessName=chrome.exe ParentProcess=explorer.exe")
    auth_logs.append(f"timestamp={t} index=auth user={user} action=login status=success src_ip={pick_ip()}")

# ------------------------
# CASE 1: PHISHING
# ------------------------
for i in range(300, 400):
    t = rand_time(i)
    user = pick_user()
    
    email_logs.append(f"timestamp={t} index=email sender=it-support@secure-login.com recipient={user} attachment=reset.docm")
    web_logs.append(f"timestamp={t} index=web user={user} url=http://secure-login-acme.com action=allowed")
    windows_logs.append(f"EventCode=4688 index=windows User={user} ParentProcess=winword.exe ProcessName=powershell.exe CommandLine='-enc XYZ'")
    dns_logs.append(f"timestamp={t} index=dns src_ip={pick_ip()} query=data.exfil.evil.com bytes_out={random.randint(1000000,50000000)}")

# ------------------------
# CASE 2: WEB ATTACK
# ------------------------
for i in range(400, 500):
    t = rand_time(i)
    
    web_logs.append(f"timestamp={t} index=web url=/login.php?id=1' OR '1'='1 status=500")
    web_logs.append(f"timestamp={t} index=web url=/upload.php file=shell.php")
    web_logs.append(f"timestamp={t} index=web url=/shell.php?cmd=whoami")

# ------------------------
# CASE 3: INSIDER
# ------------------------
for i in range(500, 600):
    t = rand_time(i)
    user = "alice"
    
    file_logs.append(f"timestamp={t} index=file user={user} file=finance.xlsx bytes={random.randint(10000000,80000000)}")
    auth_logs.append(f"timestamp={t} index=auth user={user} login_time=02:30")

# ------------------------
# CASE 4: BRUTE FORCE
# ------------------------
for i in range(600, 700):
    t = rand_time(i)
    
    auth_logs.append(f"timestamp={t} index=auth user=admin action=login status=failed src_ip={pick_ip()}")
    auth_logs.append(f"timestamp={t} index=auth user=admin action=login status=success src_ip={pick_ip()}")

# ------------------------
# CASE 5: RANSOMWARE
# ------------------------
for i in range(700, 800):
    t = rand_time(i)
    user = pick_user()
    
    file_logs.append(f"timestamp={t} index=file user={user} file=document.docx.encrypted action=rename")
    windows_logs.append(f"EventCode=4688 index=windows User={user} ProcessName=ransomware.exe")

# ------------------------
# CASE 6: C2
# ------------------------
for i in range(800, 900):
    t = rand_time(i)
    
    dns_logs.append(f"timestamp={t} index=dns query=malicious-c2.com interval=60s")
    
# ------------------------
# CASE 7: PRIV ESC
# ------------------------
for i in range(900, 1000):
    t = rand_time(i)
    
    windows_logs.append(f"EventCode=4672 index=windows user=admin privilege=SeDebugPrivilege")

# ------------------------
# CASE 8: CLOUD
# ------------------------
for i in range(1000, 1100):
    t = rand_time(i)
    
    cloud_logs.append(f"timestamp={t} index=cloud action=PutObject bucket=external-data bytes={random.randint(10000000,90000000)}")

# ------------------------
# CASE 9: LOLBins
# ------------------------
for i in range(1100, 1200):
    t = rand_time(i)
    
    windows_logs.append(f"EventCode=4688 index=windows ProcessName=certutil.exe CommandLine='download evil.com'")

# ------------------------
# CASE 10: APT
# ------------------------
for i in range(1200, 1400):
    t = rand_time(i)
    
    web_logs.append(f"timestamp={t} index=web url=http://phish-apt.com")
    windows_logs.append(f"EventCode=4688 index=windows ProcessName=powershell.exe")
    dns_logs.append(f"timestamp={t} index=dns query=apt-c2.com")
    file_logs.append(f"timestamp={t} index=file file=secret.zip bytes=90000000")

# ------------------------
# WRITE FILES
# ------------------------
def write_file(name, data):
    with open(name, "w") as f:
        f.write("\n".join(data))

write_file("web.log", web_logs)
write_file("windows.log", windows_logs)
write_file("dns.log", dns_logs)
write_file("email.log", email_logs)
write_file("auth.log", auth_logs)
write_file("cloud.log", cloud_logs)
write_file("file.log", file_logs)

# Combined
all_logs = web_logs + windows_logs + dns_logs + email_logs + auth_logs + cloud_logs + file_logs
write_file("combined.log", all_logs)

print("✅ Dataset generated successfully!")

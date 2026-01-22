def analyze_log(line):
    suspicious_keywords = ["failed", "error", "attack", "unauthorized"]
    for word in suspicious_keywords:
        if word in line.lower():
            return True
    return False


with open("logs/auth.log", "r") as f:
    for line in f:
        if analyze_log(line):
            print("[SUSPICIOUS]", line.strip())
        else:
            print("OK:", line.strip())
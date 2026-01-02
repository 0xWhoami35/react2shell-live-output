import time
import os
import requests

# =========================
# CONFIG
# =========================
BOT_TOKEN = "8312617820:AAF0sXB-yZdZ1efYPJOOHhOAfDDxbnixkGY"
CHAT_ID = "6975542904"

FILE_PATH = "vulnerable_targets.txt"
CHECK_INTERVAL = 1  # seconds

# =========================
# TELEGRAM SEND FUNCTION
# =========================
def send_telegram(message):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": CHAT_ID,
        "text": message,
        "disable_web_page_preview": True
    }
    try:
        requests.post(url, data=data, timeout=10)
    except Exception as e:
        print(f"[!] Telegram error: {e}")

# =========================
# FILE MONITOR
# =========================
def monitor_file():
    print("[+] Monitoring vulnerable_targets.txt ...")

    # Open file and move to EOF (do not read old lines)
    with open(FILE_PATH, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                time.sleep(CHECK_INTERVAL)
                continue

            line = line.strip()
            if not line:
                continue

            # Format message
            message = (
                "🔥 *NEW VULNERABLE TARGET FOUND*\n\n"
                f"`{line}`"
            )

            send_telegram(message)
            print(f"[+] Sent: {line}")

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    if not os.path.exists(FILE_PATH):
        print("[!] vulnerable_targets.txt not found")
        exit(1)

    monitor_file()

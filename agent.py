import win32evtlog
import win32evtlogutil
import json
import requests
import time

SERVER_URL = "http://127.0.0.1:5000/api/logs"  # ✅ صح

def read_logs(log_type):
    logs = []
    handle = None
    try:
        handle = win32evtlog.OpenEventLog("localhost", log_type)
        flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                 win32evtlog.EVENTLOG_SEQUENTIAL_READ)

        while True:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break

            for event in events:
                try:
                    msg = win32evtlogutil.SafeFormatMessage(event, log_type)
                except:
                    msg = "No message"

                entry = {
                    # ✅ للعرض والحفظ
                    "source": log_type,
                    "event_id": int(event.EventID & 0xFFFF),
                    "time": str(event.TimeGenerated),
                    "computer": event.ComputerName,
                    "message": msg,
                    # ✅ للنموذج - أرقام فقط
                    "EventID": int(event.EventID & 0xFFFF),
                    "EventType": int(event.EventType),
                }
                logs.append(entry)

                if len(logs) >= 3000:
                    return logs

    except Exception as e:
        print(f"Error reading {log_type}: {e}")

    finally:
        if handle:  # ✅ يغلق دايماً
            win32evtlog.CloseEventLog(handle)

    return logs


def detect_threats(logs):
    alerts = []
    failed_logins = 0

    for log in logs:
        if log["event_id"] == 4625:
            failed_logins += 1
            log["alert"] = "Failed Login Attempt"
            alerts.append(log)

        elif log["event_id"] == 4624:
            log["alert"] = "Successful Login"

        elif log["event_id"] == 3:
            log["alert"] = "Network Connection Detected"
            alerts.append(log)

    if failed_logins > 5:
        alerts.append({
            "EventID": 9999,  # ✅ رقم للنموذج
            "EventType": 2,
            "type": "Brute Force Attack",
            "count": failed_logins
        })

    return alerts


def save_logs(logs, alerts):
    with open("logs.json", "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=4, ensure_ascii=False)

    with open("alerts.json", "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=4, ensure_ascii=False)

    print("💾 تم الحفظ في logs.json و alerts.json")


def send_to_server(alerts):
    success = 0
    for alert in alerts:  # ✅ كل alert لوحده
        try:
            r = requests.post(SERVER_URL, json=alert, timeout=3)
            if r.status_code == 200:
                result = r.json()
                if result.get('threat'):
                    print(f"🚨 السيرفر كشف تهديد: EventID {alert.get('EventID')}")
                success += 1
        except:
            print("⚠️ السيرفر مو شغال")
            break

    print(f"📤 تم إرسال {success}/{len(alerts)} تنبيه")


def main():
    print("🚀 Agent شغال - يتحقق كل 30 ثانية")

    while True:  # ✅ يشتغل باستمرار
        print("\n🔍 جمع السجلات...")

        security_logs = read_logs("Security")
        sysmon_logs = read_logs("Microsoft-Windows-Sysmon/Operational")
        all_logs = security_logs + sysmon_logs

        print(f"✅ جمع {len(all_logs)} سجل")

        alerts = detect_threats(all_logs)
        print(f"⚠️ {len(alerts)} تنبيه")

        save_logs(all_logs, alerts)
        send_to_server(alerts)

        print("⏳ انتظار 30 ثانية...\n")
        time.sleep(30)  # ✅ ينتظر وما يوقف


if __name__ == "__main__":
    main()
import json
import os
import re
from collections import defaultdict
from datetime import datetime # Zaman damgası için eklendi

# --- Konfigürasyon ve Yardımcı Fonksiyonlar ---

def load_config(config_path='config.json'):
    """
    Yapılandırma dosyasını (config.json) yükler.
    """
    if not os.path.exists(config_path):
        print(f"[HATA] Konfigürasyon dosyası bulunamadı: {config_path}")
        exit()
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, Exception) as e:
        print(f"[HATA] Konfigürasyon dosyası okunurken bir hata oluştu: {e}")
        exit()

# --- Log Ayrıştırıcı Fonksiyon ---

def parse_log_line(line):
    """
    Tek bir log satırını Regex kullanarak yapılandırılmış verilere ayırır.
    """
    log_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>.+?)\] '
        r'"(?P<method>\S+) (?P<url>\S+) \S+" '
        r'(?P<status_code>\d{3}) (?P<response_size>\S+)'
    )
    match = log_pattern.match(line)
    if match:
        data = match.groupdict()
        data['status_code'] = int(data['status_code'])
        return data
    return None

# --- Adım 5: Raporlama Fonksiyonu ---

def write_alerts_to_file(alerts, file_path):
    """
    Tespit edilen uyarıları, başına zaman damgası ekleyerek belirtilen dosyaya yazar.
    Dosyaya ekleme modunda (append) yazar.
    """
    if not alerts:
        return # Yazacak uyarı yoksa fonksiyondan çık

    try:
        with open(file_path, 'a', encoding='utf-8') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"\n--- Analiz Raporu: {timestamp} ---\n")
            for alert in alerts:
                f.write(alert + '\n')
        print(f"[BİLGİ] {len(alerts)} adet uyarı '{file_path}' dosyasına başarıyla yazıldı.")
    except Exception as e:
        print(f"[HATA] Uyarılar dosyaya yazılırken bir hata oluştu: {e}")

# --- Ana Analiz Fonksiyonu ---

def analyze_logs():
    """
    Log analizi için ana fonksiyon.
    """
    print("="*50)
    print("PyLogSentry - Log Analiz Aracı Başlatılıyor...")
    print("="*50)
    
    config = load_config()
    print("[BİLGİ] Konfigürasyon dosyası başarıyla yüklendi.")
    
    log_file = config.get("log_file_path")
    rules = config.get("rules", {})
    
    if not log_file or not os.path.exists(log_file):
        print(f"[HATA] Yapılandırmada belirtilen log dosyası bulunamadı: {log_file}")
        return

    print(f"[BİLGİ] Analiz edilecek log dosyası: {log_file}")
    print("\n[BİLGİ] Analiz başlıyor...")
    
    ip_request_counts = defaultdict(int)
    ip_error_counts = defaultdict(lambda: defaultdict(int))
    alerts = []
    
    high_request_threshold = rules.get("high_request_threshold", 100)
    error_code_threshold = rules.get("error_code_threshold", 10)
    suspicious_patterns = rules.get("suspicious_url_patterns", [])
    monitored_error_codes = rules.get("monitored_error_codes", [])

    line_count = 0
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                
                line_count += 1
                parsed_data = parse_log_line(line)
                
                if not parsed_data: continue

                ip, url, status_code = parsed_data['ip'], parsed_data['url'], parsed_data['status_code']

                ip_request_counts[ip] += 1
                if status_code in monitored_error_codes:
                    ip_error_counts[ip][status_code] += 1
                
                for pattern in suspicious_patterns:
                    if pattern in url:
                        alert_msg = f"[UYARI - Şüpheli URL] IP: {ip}, URL: {url}, Tespit Edilen Desen: '{pattern}'"
                        alerts.append(alert_msg)
                        break

    except Exception as e:
        print(f"[HATA] Analiz sırasında bir hata oluştu: {e}")
        return
        
    for ip, count in ip_request_counts.items():
        if count > high_request_threshold:
            alerts.append(f"[UYARI - Yüksek İstek Sayısı] IP: {ip}, İstek Sayısı: {count} (Eşik: {high_request_threshold})")

    for ip, error_codes in ip_error_counts.items():
        for code, count in error_codes.items():
            if count > error_code_threshold:
                alerts.append(f"[UYARI - Çok Sayıda Hata Kodu] IP: {ip}, Hata Kodu: {code}, Sayı: {count} (Eşik: {error_code_threshold})")

    # --- Sonuçları Raporlama ---
    print("\n[BİLGİ] Analiz tamamlandı.")
    print("\n--- Tespit Edilen Uyarılar ---")
    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("Herhangi bir şüpheli aktivite tespit edilmedi.")
    print("--- Uyarılar Sonu ---\n")

    # Adım 5: Uyarıları dosyaya yaz
    alerts_log_file = config.get("alerts_log_path")
    if alerts_log_file:
        write_alerts_to_file(alerts, alerts_log_file)
    else:
        print("[UYARI] Konfigürasyonda uyarı log dosyası yolu belirtilmemiş.")

    print(f"\nToplam {line_count} satır log incelendi, {len(alerts)} adet uyarı bulundu.")
    print("="*50)

if __name__ == "__main__":
    analyze_logs()

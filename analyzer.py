import json
import os
import re # Regular Expressions modülünü dahil ediyoruz

# --- Konfigürasyon ve Yardımcı Fonksiyonlar ---

def load_config(config_path='config.json'):
    """
    Yapılandırma dosyasını (config.json) yükler.
    Dosya bulunamazsa veya JSON formatı bozuksa programı sonlandırır.
    """
    if not os.path.exists(config_path):
        print(f"[HATA] Konfigürasyon dosyası bulunamadı: {config_path}")
        exit()
        
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        print("[BİLGİ] Konfigürasyon dosyası başarıyla yüklendi.")
        return config
    except json.JSONDecodeError:
        print(f"[HATA] Konfigürasyon dosyası ({config_path}) hatalı JSON formatına sahip.")
        exit()
    except Exception as e:
        print(f"[HATA] Konfigürasyon dosyası okunurken bir hata oluştu: {e}")
        exit()

# --- Adım 3: Log Ayrıştırıcı Fonksiyon ---

def parse_log_line(line):
    """
    Tek bir log satırını Regex kullanarak yapılandırılmış verilere ayırır.
    Örnek log satırı: 192.168.1.1 - - [10/Mar/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 503
    """
    # Apache'nin yaygın log formatına uygun Regex deseni
    # Bu desen IP, tarih, metod, URL, durum kodu ve boyutu yakalar.
    log_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>.+?)\] '
        r'"(?P<method>\S+) (?P<url>\S+) \S+" '
        r'(?P<status_code>\d{3}) (?P<response_size>\S+)'
    )
    
    match = log_pattern.match(line)
    if match:
        # Eşleşme başarılı olursa, verileri bir sözlük (dictionary) olarak döndür
        return match.groupdict()
    
    # Satır desene uymuyorsa None (boş) döndür
    return None

# --- Ana Analiz Fonksiyonu ---

def analyze_logs():
    """
    Log analizi için ana fonksiyon.
    """
    print("="*50)
    print("PyLogSentry - Log Analiz Aracı Başlatılıyor...")
    print("="*50)
    
    config = load_config()
    log_file = config.get("log_file_path")
    
    if not log_file or not os.path.exists(log_file):
        print(f"[HATA] Yapılandırmada belirtilen log dosyası bulunamadı: {log_file}")
        return

    print(f"[BİLGİ] Analiz edilecek log dosyası: {log_file}")
    print("\n[BİLGİ] Analiz başlıyor...")
    
    line_count = 0
    parsed_count = 0
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                line_count += 1
                
                # Her satırı ayrıştırıcı fonksiyona gönder
                parsed_data = parse_log_line(line)
                
                if parsed_data:
                    # Başarıyla ayrıştırılan veriyi ekrana yazdır
                    print(f"Ayrıştırıldı: {parsed_data}")
                    parsed_count += 1
                else:
                    # Ayrıştırılamayan satırları bildir
                    print(f"[UYARI] Bu satır standart formata uymuyor: {line}")

    except FileNotFoundError:
        print(f"[HATA] Log dosyası bulunamadı: {log_file}")
        return
    except Exception as e:
        print(f"[HATA] Log dosyası okunurken bir hata oluştu: {e}")
        return
    
    print("\n[BİLGİ] Analiz tamamlandı.")
    print(f"Toplam {line_count} satır okundu, {parsed_count} satır başarıyla ayrıştırıldı.")
    print("="*50)

# --- Betiğin Başlangıç Noktası ---

if __name__ == "__main__":
    analyze_logs()

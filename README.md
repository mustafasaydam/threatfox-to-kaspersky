# ThreatFox to Kaspersky IOC Sync

Bu repository, ThreatFox API’sinden otomatik olarak IOC (indicator of compromise) çekip Kaspersky uyumlu XML formatına dönüştürür. Anlaşılır ve basit bir şekilde hazırlanmıştır.

## Özellikler

- Her gün ThreatFox’tan IOC çekme
- Kaspersky uyumlu XML çıktısı oluşturma
- Oluşturulan dosyaları `iocs/` klasöründe saklama
- Manuel olarak da çalıştırabilme

## Kurulum

1. Repository’yi fork edin veya klonlayın.

2. GitHub Secrets ayarlayın:
   - Repository Settings → Secrets and variables → Actions
   - Yeni secret ekleyin: `THREATFOX_API_KEY`
   - Değer olarak ThreatFox hesabınızdan aldığınız API key’i girin

3. Workflow’u etkinleştirin:
   - Actions sekmesine gidin
   - "ThreatFox IOC Sync" workflow’unu etkinleştirin
   - İlk çalıştırmayı manuel başlatabilirsiniz

## Kullanım

### Otomatik Çalıştırma
- Workflow her gün UTC 00:00'da çalışır
- IOC dosyaları `iocs/` klasöründe saklanır

### Manuel Çalıştırma
- Actions → ThreatFox IOC Sync → "Run workflow"
- Gün sayısını isteğe bağlı olarak seçebilirsiniz

## Çıktılar

- `iocs/kaspersky_threatfox_YYYYMMDD_HHMMSS.xml` — Zaman damgalı dosya  
- `iocs/kaspersky_threatfox_latest.xml` — En son dosyaya sembolik link

## Güvenlik

- API anahtarı yalnızca GitHub Secrets’ta saklanır
- IOC’ler opsiyonel olarak public repository’de saklanmayabilir
- Tüm işlemler GitHub Actions’ın güvenli ortamında çalışır

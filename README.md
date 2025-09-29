# ThreatFox to Kaspersky IOC Sync

Bu repository, ThreatFox API'ından otomatik olarak IOC'leri çeker ve Kaspersky uyumlu XML formatına dönüştürür.

## Özellikler

- 🔄 24 saatte bir otomatik senkronizasyon
- 🛡️ Kaspersky uyumlu XML çıktısı
- 📊 Detaylı istatistikler
- 🔐 Güvenli API anahtar yönetimi
- 🎯 Malware gruplandırmalı IOC'ler

## Kurulum

1. **Repository'yi fork edin** veya clone layın

2. **GitHub Secrets ayarlayın:**
   - Repository Settings → Secrets and variables → Actions
   - Yeni secret ekle: `THREATFOX_API_KEY`
   - Değerini ThreatFox hesabınızdan aldığınız API key ile doldurun

3. **Workflow'u etkinleştirin:**
   - Actions tab'ına gidin
   - "ThreatFox IOC Sync" workflow'unu etkinleştirin
   - İlk çalıştırmayı manuel olarak başlatın

## Kullanım

### Otomatik Çalıştırma
- Workflow her gün UTC 00:00'da otomatik çalışacak
- Oluşturulan IOC dosyaları `iocs/` dizininde saklanacak

### Manuel Çalıştırma
- Actions → ThreatFox IOC Sync → "Run workflow"
- İsteğe bağlı gün sayısı seçebilirsiniz

## Çıktı

- `iocs/kaspersky_threatfox_YYYYMMDD_HHMMSS.xml` - Zaman damgalı dosya
- `iocs/kaspersky_threatfox_latest.xml` - En son dosyaya sembolik link

## Güvenlik

- API anahtarı GitHub Secrets'ta güvenle saklanır
- IOC'ler public repository'de saklanmaz (opsiyonel)
- Tüm işlemler GitHub'ın güvenli ortamında çalışır

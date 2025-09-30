import requests
import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime, timedelta
import uuid
import os
import sys

class ThreatFoxToKasperskyConverter:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://threatfox-api.abuse.ch/api/v1/"
        self.headers = {
            "Content-Type": "application/json",
            "Auth-Key": self.api_key
        }
        
        self.threat_type_mapping = {
            "botnet_cc": "Botnet Command & Control",
            "payload_delivery": "Malware Payload Delivery",
            "skimming": "Credit Card Skimming"
        }

    def get_iocs_from_threatfox(self, days=1):
        """ThreatFox API'ından IOC'leri çek"""
        print(f"🔍 ThreatFox'tan son {days} günün IOC'leri çekiliyor...")
        
        payload = {
            "query": "get_iocs",
            "days": days
        }
        
        try:
            response = requests.post(
                self.base_url,
                headers=self.headers,
                json=payload,
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"📊 API Response: {result.get('query_status')}")
                
                if result.get("query_status") == "ok":
                    iocs = result.get("data", [])
                    print(f"✅ {len(iocs)} IOC başarıyla alındı")
                    return iocs
                else:
                    print(f"❌ API hatası: {result.get('query_status')}")
                    return []
            else:
                print(f"❌ HTTP hatası: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"❌ ThreatFox API bağlantı hatası: {e}")
            return []

    def _get_context_for_ioc_type(self, ioc_type, threat_type):
        """IOC tipine göre context bilgisi döndür"""
        context_map = {
            "domain": {
                "document": "DnsEntryItem",
                "search": "DnsEntryItem/RecordName",
                "content_type": "string"
            },
            "ip:port": {
                "document": "PortItem", 
                "search": "PortItem/remoteIP",  
                "content_type": "string"
            },
            "url": {
                "document": "DnsEntryItem",  
                "search": "DnsEntryItem/RecordName", 
                "content_type": "string"
            },
            "sha256_hash": {
                "document": "FileItem",
                "search": "FileItem/Sha256sum",
                "content_type": "sha256"
            },
            "md5_hash": {
                "document": "FileItem",
                "search": "FileItem/Md5sum",
                "content_type": "md5"
            },
            "sha1_hash": {
                "document": "FileItem",
                "search": "FileItem/Sha1sum", 
                "content_type": "sha1"
            }
        }
    
        return context_map.get(ioc_type)

    def create_advanced_ioc_xml(self, iocs, output_path):
        """Gelişmiş IOC XML'i oluştur"""
        print("🛠️ Gelişmiş Kaspersky XML formatı oluşturuluyor...")
        
        ioc_element = ET.Element("ioc")
        ioc_element.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
        ioc_element.set("xmlns:xsd", "http://www.w3.org/2001/XMLSchema")
        ioc_element.set("id", str(uuid.uuid4()))
        ioc_element.set("last-modified", datetime.now().strftime("%Y-%m-%dT%H:%M:%S"))
        ioc_element.set("xmlns", "http://schemas.mandiant.com/2010/ioc")

        # Metadata
        short_desc = ET.SubElement(ioc_element, "short_description")
        short_desc.text = f"ThreatFox IOC Collection - {datetime.now().strftime('%Y-%m-%d')}"
        
        description = ET.SubElement(ioc_element, "description")
        description.text = "Automated IOC import from ThreatFox API via GitHub Actions"
        
        authored_by = ET.SubElement(ioc_element, "authored_by")
        authored_by.text = "ThreatFox-GitHub-Actions"
        
        authored_date = ET.SubElement(ioc_element, "authored_date")
        authored_date.text = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        definition = ET.SubElement(ioc_element, "definition")
        main_indicator = ET.SubElement(definition, "Indicator")
        main_indicator.set("operator", "OR")
        main_indicator.set("id", str(uuid.uuid4()))

        # IOC'leri malware ve threat type'a göre grupla
        malware_threat_groups = {}
        for ioc_data in iocs:
            malware = ioc_data.get("malware_printable") or ioc_data.get("malware", "Unknown")
            threat_type = ioc_data.get("threat_type_desc") or ioc_data.get("threat_type", "Unknown")
            
            key = f"{malware}|{threat_type}"
            if key not in malware_threat_groups:
                malware_threat_groups[key] = []
            malware_threat_groups[key].append(ioc_data)

        # Her grup için ayrı Indicator oluştur
        processed_count = 0
        for group_key, group_iocs in malware_threat_groups.items():
            if len(group_iocs) == 0:
                continue
                
            malware, threat_type = group_key.split("|")
            
            group_indicator = ET.SubElement(main_indicator, "Indicator")
            group_indicator.set("operator", "OR")
            group_indicator.set("id", str(uuid.uuid4()))
            
            # Grup açıklaması için Comment ekle
            # comment = ET.SubElement(group_indicator, "Comment")
            # comment.text = f"Malware: {malware} | Threat: {threat_type} | Count: {len(group_iocs)}"
            
            for ioc_data in group_iocs:
                ioc_value = ioc_data.get("ioc", "").strip()
                ioc_type = ioc_data.get("ioc_type", "")
                
                if not ioc_value:
                    continue
                    
                context_info = self._get_context_for_ioc_type(ioc_type, ioc_data.get("threat_type", ""))
                if not context_info:
                    continue
                    
                indicator_item = ET.SubElement(group_indicator, "IndicatorItem")
                indicator_item.set("id", str(uuid.uuid4()))
                indicator_item.set("condition", "is")
                
                context = ET.SubElement(indicator_item, "Context")
                context.set("document", context_info["document"])
                context.set("search", context_info["search"])
                context.set("type", "mir")
                
                content = ET.SubElement(indicator_item, "Content")
                content.set("type", context_info["content_type"])
                content.text = ioc_value
                
                processed_count += 1

        # XML'i kaydet
        if processed_count > 0:
            rough_string = ET.tostring(ioc_element, 'utf-8')
            reparsed = minidom.parseString(rough_string)
            formatted_xml = reparsed.toprettyxml(indent="  ")
            formatted_xml = formatted_xml.replace('<?xml version="1.0" ?>', '<?xml version="1.0" encoding="us-ascii"?>')
            
            with open(output_path, 'w', encoding='us-ascii') as f:
                f.write(formatted_xml)
            
            print(f"✅ Gelişmiş IOC XML oluşturuldu: {output_path} ({processed_count} IOC)")
            return True
        else:
            print("❌ İşlenebilir IOC bulunamadı!")
            return False

    def print_statistics(self, iocs):
        """İstatistikleri yazdır"""
        print("\n" + "="*60)
        print("📊 THREATFOX IOC İSTATİSTİKLERİ")
        print("="*60)
        print(f"📈 Toplam IOC sayısı: {len(iocs)}")
        
        type_count = {}
        malware_count = {}
        
        for ioc in iocs:
            ioc_type = ioc.get("ioc_type", "unknown")
            type_count[ioc_type] = type_count.get(ioc_type, 0) + 1
            
            malware = ioc.get("malware_printable") or ioc.get("malware", "unknown")
            malware_count[malware] = malware_count.get(malware, 0) + 1
        
        print(f"\n🔧 IOC Tip Dağılımı:")
        for ioc_type, count in sorted(type_count.items(), key=lambda x: x[1], reverse=True):
            print(f"  {ioc_type:15}: {count:4d}")
        
        print(f"\n🐛 En çok IOC içeren Malware'ler:")
        for malware, count in sorted(malware_count.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {malware:30}: {count:4d}")

def main():
    """GitHub Actions için ana fonksiyon"""
    print("🚀 ThreatFox to Kaspersky IOC Converter - GitHub Actions")
    print("=" * 60)
    
    # API anahtarını environment variables'dan al
    api_key = os.getenv('THREATFOX_API_KEY')
    
    if not api_key:
        print("❌ HATA: THREATFOX_API_KEY environment variable bulunamadı!")
        print("📝 Lütfen GitHub Repository Settings -> Secrets altında THREATFOX_API_KEY ekleyin")
        sys.exit(1)
    
    # Converter'ı başlat
    converter = ThreatFoxToKasperskyConverter(api_key)
    
    # IOC'leri al
    iocs = converter.get_iocs_from_threatfox(days=1)
    
    if not iocs:
        print("❌ IOC bulunamadı, işlem sonlandırılıyor...")
        sys.exit(1)
    
    # İstatistikleri göster
    converter.print_statistics(iocs)
    
    # Çıktı dizinini oluştur
    output_dir = "iocs"
    os.makedirs(output_dir, exist_ok=True)
    
    # XML dosyasını oluştur
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"kaspersky_threatfox_{timestamp}.xml"
    output_path = os.path.join(output_dir, output_filename)
    
    success = converter.create_advanced_ioc_xml(iocs, output_path)
    
    if success:
        print(f"\n🎉 BAŞARILI: {output_path} dosyası oluşturuldu!")
        
        # Latest symlink oluştur (opsiyonel)
        latest_path = os.path.join(output_dir, "kaspersky_threatfox_latest.xml")
        if os.path.exists(latest_path):
            os.remove(latest_path)
        os.symlink(output_filename, latest_path)
        print(f"🔗 Latest symlink güncellendi: {latest_path}")
        
        # Commit mesajı için summary oluştur
        print(f"::set-output name=total_iocs::{len(iocs)}")
        print(f"::set-output name=output_file::{output_filename}")
        
    else:
        print("\n💥 HATA: XML dosyası oluşturulamadı!")
        sys.exit(1)

if __name__ == "__main__":
    main()

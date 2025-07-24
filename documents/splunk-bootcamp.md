<!-- markdownlint template -->
<!-- markdownlint-disable MD033 -->

# SPL, Report, Dashboard, Alert, Log Forwarding ve Use-Case Bazlı Korelasyon Yazımıyla Splunk Dünyasına Uygulamalı Giriş

<p align="center">
    <img src="../assets/splunk-bootcamp/Splunk_logo.png" width="500" alt="Splunk Logo">
</p>

Bu doküman, Seyfullah ALVER tarafından hazırlanmış olan "Sıfırdan Uzmanlığa : Uygulamalı Splunk Eğitimi" adlı Udemy eğitimi sırasında tuttuğum notları içermektedir.

## Table of Contents

- [SPL, Report, Dashboard, Alert, Log Forwarding ve Use-Case Bazlı Korelasyon Yazımıyla Splunk Dünyasına Uygulamalı Giriş](#spl-report-dashboard-alert-log-forwarding-ve-use-case-bazlı-korelasyon-yazımıyla-splunk-dünyasına-uygulamalı-giriş)
  - [Table of Contents](#table-of-contents)
  - [Bölüm 1: Temel Kavramlar ve Splunk Ortamının Hazırlanması](#bölüm-1-temel-kavramlar-ve-splunk-ortamının-hazırlanması)
    - [Kursta Neler Öğreneceksiniz?](#kursta-neler-öğreneceksiniz)
    - [SIEM (Security Information and Event Management)](#siem-security-information-and-event-management)
      - [SIEM Nasıl Çalışıyor?](#siem-nasıl-çalışıyor)
    - [Splunk Best Practice](#splunk-best-practice)
      - [Splunk Best Practice (Sadeleştirilmiş)](#splunk-best-practice-sadeleştirilmiş)
        - [Search Head Cluster](#search-head-cluster)
        - [Indexer Cluster](#indexer-cluster)
        - [Cluster Master](#cluster-master)
      - [Veri Toplama Katmanı](#veri-toplama-katmanı)
        - [Universal Forwarder (UF)](#universal-forwarder-uf)
        - [Heavy Forwarder (HF)](#heavy-forwarder-hf)
        - [Deployment Server](#deployment-server)
      - [Yönetim ve İzleme Katmanı](#yönetim-ve-i̇zleme-katmanı)
        - [License Master](#license-master)
        - [Monitoring Console (MC)](#monitoring-console-mc)
        - [Deployer](#deployer)
      - [Bilgi ve Uygulama Katmanı](#bilgi-ve-uygulama-katmanı)
        - [Knowledge Objects](#knowledge-objects)
        - [Apps \& Add-ons](#apps--add-ons)
      - [Splunk Primary Functions of Splunk](#splunk-primary-functions-of-splunk)
    - [Splunk Kurulumu](#splunk-kurulumu)
      - [Linux Üzerinde Kurulum](#linux-üzerinde-kurulum)
      - [Windows Üzerinde Kurulum](#windows-üzerinde-kurulum)
      - [Web Arayüzü Port Değiştirme (Opsiyonel)](#web-arayüzü-port-değiştirme-opsiyonel)
    - [Splunk HTTPS Yapılandırma Kılavuzu](#splunk-https-yapılandırma-kılavuzu)
      - [1. Kendinden İmzalı Sertifika Oluşturma](#1-kendinden-i̇mzalı-sertifika-oluşturma)
      - [2. Web Konfigürasyonunu Düzenleme](#2-web-konfigürasyonunu-düzenleme)
      - [3. Sertifika Dosyası İzinlerini Ayarlama](#3-sertifika-dosyası-i̇zinlerini-ayarlama)
      - [4. PYTHONHTTPSVERIFY Ayarını Güncelleme](#4-pythonhttpsverify-ayarını-güncelleme)
      - [5. Splunk'ı Yeniden Başlatma](#5-splunkı-yeniden-başlatma)
      - [6. HTTPS Üzerinden Web Arayüzüne Erişim](#6-https-üzerinden-web-arayüzüne-erişim)
      - [7. Olası Hatalar İçin Log Kontrolü](#7-olası-hatalar-i̇çin-log-kontrolü)
    - [Splunk Uygulama Aşamasında Kullanılan Materyaller Hakkında Bilgilendirme](#splunk-uygulama-aşamasında-kullanılan-materyaller-hakkında-bilgilendirme)
    - [Log Dosyalarının Splunk'a Import Edilmesi](#log-dosyalarının-splunka-import-edilmesi)
      - [1. Veri Ekleme Adımları](#1-veri-ekleme-adımları)
      - [2. Örnek Dosyalar ve Sourcetype Ayarları](#2-örnek-dosyalar-ve-sourcetype-ayarları)
      - [Kavramlar](#kavramlar)
    - [Splunk Field Extraction Yöntemleri](#splunk-field-extraction-yöntemleri)
      - [1. Index-Time Field Extraction](#1-index-time-field-extraction)
      - [2. Search-Time Field Extraction](#2-search-time-field-extraction)
        - [Yaygın Yöntemler](#yaygın-yöntemler)
  - [Bölüm 2: SPL ile Veri Analizi](#bölüm-2-spl-ile-veri-analizi)
    - [SPL Komutlarına Giriş](#spl-komutlarına-giriş)
    - [Temel SPL Komutları ve Örnekler](#temel-spl-komutları-ve-örnekler)
      - [1. Anahtar Kelime (Keyword) Bazlı Arama](#1-anahtar-kelime-keyword-bazlı-arama)
      - [2. `fields` ve `table` Komutları](#2-fields-ve-table-komutları)
      - [3. `rename` Komutu](#3-rename-komutu)
      - [4. `sort` Komutu](#4-sort-komutu)
      - [5. `dedup` Komutu](#5-dedup-komutu)
      - [6. `top` Komutu](#6-top-komutu)
      - [7. `rare` ve `by` Komutları](#7-rare-ve-by-komutları)
      - [8. `stats` Komutu: `count()` ve `dc()`](#8-stats-komutu-count-ve-dc)
      - [9. `where` Komutu](#9-where-komutu)
      - [10. `stats sum()` Kullanımı](#10-stats-sum-kullanımı)
      - [11. `avg()`, `max()`, `min()` Kullanımı](#11-avg-max-min-kullanımı)
      - [12. `stats list()` ve `values()` Kullanımı](#12-stats-list-ve-values-kullanımı)
      - [13. `eval` Kullanımı](#13-eval-kullanımı)
      - [14. `if` ve `case` Kullanımı](#14-if-ve-case-kullanımı)
      - [15. `timechart` ve `span` Kullanımı](#15-timechart-ve-span-kullanımı)
      - [16. `iplocation` Kullanımı](#16-iplocation-kullanımı)
      - [17. `eventstats` Kullanımı](#17-eventstats-kullanımı)
      - [18. `transaction` ve `contingency` Kullanımı](#18-transaction-ve-contingency-kullanımı)
      - [19. subsearch Kullanımı](#19-subsearch-kullanımı)
      - [20. `geom` Kullanımı](#20-geom-kullanımı)
  - [Bölüm 3: Report, Dashboard, Alert Yönetimi](#bölüm-3-report-dashboard-alert-yönetimi)
    - [Report](#report)
    - [Dashboard](#dashboard)
      - [Data Input Örneği](#data-input-örneği)
    - [Alerts](#alerts)
      - [Uyarı Oluşturma Adımları](#uyarı-oluşturma-adımları)
        - [Admin Failed Login Attempts](#admin-failed-login-attempts)
        - [Açıklama](#açıklama)
        - [Splun User Create Detection](#splun-user-create-detection)
  - [Bölüm 4: Workflow, Lookups, Regex](#bölüm-4-workflow-lookups-regex)
    - [Workflow](#workflow)
    - [Lookups](#lookups)
    - [Regex](#regex)
  - [Bölüm 5: Log Forwarding](#bölüm-5-log-forwarding)
  - [Bölüm 6: Use-Case](#bölüm-6-use-case)
    - [Windows Audit Log Tampering Detection](#windows-audit-log-tampering-detection)
    - [Detecting Brute Force Attack](#detecting-brute-force-attack)
    - [A User Account was Created and Deleted in 24 Saat](#a-user-account-was-created-and-deleted-in-24-saat)
      - [Komut Satırı Örnekleri](#komut-satırı-örnekleri)
      - [Örnek Event Log](#örnek-event-log)
      - [Splunk Sorgusu](#splunk-sorgusu)
      - [Açıklamalar](#açıklamalar)
    - [Schedule Task was Created Detection](#schedule-task-was-created-detection)
    - [CMD ve PowerShell Komutlarının Loglanması](#cmd-ve-powershell-komutlarının-loglanması)
      - [Komut Satırı Argümanlarını Loglama](#komut-satırı-argümanlarını-loglama)
      - [Process Creation Alt Kategorisinin Açılması](#process-creation-alt-kategorisinin-açılması)
      - [Group Policy Güncelleme](#group-policy-güncelleme)
    - [Powershell ile Şüpheli Dosya İndirme Aktivitelerinin Tespiti](#powershell-ile-şüpheli-dosya-i̇ndirme-aktivitelerinin-tespiti)
      - [Örnek Komutlar](#örnek-komutlar)

## Bölüm 1: Temel Kavramlar ve Splunk Ortamının Hazırlanması

### Kursta Neler Öğreneceksiniz?

Dijital dünyada her hareket ve işlem bir iz bırakır. Bu izler doğru analiz edildiğinde sistemlerimizi koruyabilir, tehditleri önceden tespit edebilir ve güçlü savunmalar oluşturabiliriz.

Splunk yalnızca bir log toplama aracı değil; verilere anlam kazandıran, tehditleri görünür kılan ve sistemlerimize canlılık veren bir platformdur.

1. **Splunk'a Hızlı Başlangıç:** SIEM kavramı ve temel özellikler, Splunk kurulumu
2. **Uygulamalı Log Analizi:** Web sunucu ve uygulama loglarının güvenlik analizi
3. **SPL (Search Processing Language) ile Güçlü Aramalar:** Search, stats, eval, timechart vb. temel SPL komutları
4. **Dashboard, Report ve Alarm Yönetimi:** Dashboard oluşturma, rapor ve alarm sistemleri
5. **Log Forwarding ve Veri Kaynaklarının Entegrasyonu:** Windows event, powershell, cmd loglarının Splunk'a aktarılması
6. **Güvenlik Use-Case'leri ve Kural Yazımı:** Brute Force, schedule task, suspicious Powershell aktivitelerinin tespiti

### SIEM (Security Information and Event Management)

Kurumların sistemlerindeki güvenlik olaylarını merkezi olarak toplamak, analiz etmek ve bu olaylara zamanında müdahale etmek için kullanılan bir çözümdür.

![SIEM Puzzle](/assets/splunk-bootcamp/siem_puzzle.png "SIEM Puzzle")

*SIEM (Security Information and Event Management) kavramının bileşenlerini ve işleyişini özetleyen görsel.*

Çeşitli kaynaklardan (Firewall, Server, IPS, Router, Switch, Workstation) logları toplayan, normalize eden ve korelasyon kurallarıyla şüpheli aktiviteleri tespit ederek gerekli durumlarda alarm üreten, böylece hızlı yanıt vermemizi sağlayan bir güvenlik çözümü.

#### SIEM Nasıl Çalışıyor?

1. **Step 1:** Collect data from various sources, including network devices, servers, domain controllers and more.
2. **Step 2:** Normalize and aggregate the collected data.
    > **Normalizasyon:** SIEM sistemine farklı kaynaklardan gelen loglar ve veriler, standart bir yapıda olmadığı için çeşitlilik gösterir. SIEM, bu verileri analiz edilebilir ve tutarlı bir standart yapıya dönüştürür.
3. **Step 3:** Analyze the data to discover and detect threats.
4. **Step 4:** Pinpoint security breaches and enable organizations to investigate alerts.

### Splunk Best Practice

!["Splunk Best Practice"](/assets/splunk-bootcamp/splunk_best_practice.png "Splunk Best Practice")

*Splunk mimarisi ve en iyi uygulama (best practice) önerilerini özetleyen diyagram.*

#### Splunk Best Practice (Sadeleştirilmiş)

##### Search Head Cluster

- **İşlev**: Kullanıcı arayüzü ve sorgu işleme.
- **Özellikler**:
  - Sorgular (SPL) yazılır ve çalıştırılır.
  - Dashboard, rapor ve uyarılar oluşturulur.
  - Web arayüzü sağlar.
  - Yüksek erişilebilirlik için cluster.
- **Öneri**: En az 3 Search Head ile load balancer kullan.

##### Indexer Cluster

- **İşlev**: Log verilerini depolar ve indeksler.
- **Özellikler**:
  - Veriler işlenir ve saklanır.
  - Sorguları işler, sonuç döndürür.
  - Veriler bucket’larla saklanır.
  - Replication factor ile veri güvenliği.
- **Öneri**: En az 3 indexer, replication factor 2.

##### Cluster Master

- **İşlev**: Indexer cluster yönetim.
- **Özellikler**:
  - Indexer’ları koordine eder.
  - Replikasyonu yönetir.
  - Cluster sağlığını izler.
  - Arıza durumlarında devreye girer.

#### Veri Toplama Katmanı

##### Universal Forwarder (UF)

- **İşlev**: Hafif veri toplama ajanı.
- **Özellikler**:
  - Az kaynak kullanır.
  - Sadece veri gönderir.
  - Load balancing ve SSL desteği.
- **Öneri**: Basit veri toplama için kullan.

##### Heavy Forwarder (HF)

- **İşlev**: Gelişmiş veri işleme.
- **Özellikler**:
  - Veri ayrıştırma, filtreleme ve yönlendirme.
  - Daha fazla kaynak gerektirir.
- **Öneri**: Karmaşık veri işleme için tercih et.

##### Deployment Server

- **İşlev**: Forwarder’ların merkezi yönetimi.
- **Özellikler**:
  - Konfigürasyonları dağıtır.
  - Binlerce forwarder’ı yönetir.
  - Gruplu yönetim ve standartlaşma.
- **Öneri**: Otomatik yönetim için kullan.

#### Yönetim ve İzleme Katmanı

##### License Master

- **İşlev**: Lisans yönetimi.
- **Özellikler**:
  - Veri limitlerini kontrol eder.
  - Kullanım raporları sunar.
  - Kota aşımı uyarısı.
- **Öneri**: Lisans takibini düzenli yap.

##### Monitoring Console (MC)

- **İşlev**: Splunk altyapı izleme.
- **Özellikler**:
  - Tüm bileşenlerin sağlığını izler.
  - Performans verileri sağlar.
  - Sorunları önceden tespit eder.
- **Öneri**: Proaktif izleme için kullan.

##### Deployer

- **İşlev**: Search Head Cluster konfigürasyon yönetimi.
- **Özellikler**:
  - Uygulama ve bilgi nesnelerini dağıtır.
  - Search Head’leri senkronize eder.
- **Öneri**: Düzenli senkronizasyon yap.

#### Bilgi ve Uygulama Katmanı

##### Knowledge Objects

- **Bileşenler**:
  - **Field Extractions**: Verilerden alan çıkarma.
  - **Lookups**: Harici veri ile zenginleştirme.
  - **Macros**: Yeniden kullanılabilir sorgular.
  - **Tags/Event Types**: Veri sınıflandırma.
  - **Data Models**: Pivot tabloları.
  - **Workflows**: Dış sistem entegrasyonu.

##### Apps & Add-ons

- **Splunk Apps**:
  - Enterprise Security (ES)
  - IT Service Intelligence (ITSI)
  - User Behavior Analytics (UBA)
  - Machine Learning Toolkit (MLTK)
- **Technology Add-ons (TA)**:
  - Windows, Linux, Unix.
  - Network cihazları (Cisco, F5).
  - Cloud platformları (AWS, Azure, GCP).
  - Veritabanları (Oracle, MSSQL, MySQL).

![Splunk Architecture](/assets/splunk-bootcamp/splunk_architecture.png "splunk_architecture")

*Splunk platformunun genel mimarisini ve bileşenlerini gösteren diyagram.*

#### Splunk Primary Functions of Splunk

> Collect and Index -> Search and Investigate -> Add Knowledge -> Report and Visualize -> Monitor and Alert

### Splunk Kurulumu

#### Linux Üzerinde Kurulum

```bash
chmod 644 splunk_package_name.rpm
rpm -i splunk_package_name.rpm
/opt/splunk/bin/splunk start
```

> `splunk_package_name.rpm` yerine indirilen Splunk RPM paket adını yazmalısınız.

#### Windows Üzerinde Kurulum

```bash
msiexec /i splunk-*.msi
```

> Kurulum sırasında gelen sihirbazı takip ederek kurulumu tamamlayabilirsiniz. `splunk-*.msi` ifadesi, indirdiğiniz Splunk MSI paketini temsil eder.

#### Web Arayüzü Port Değiştirme (Opsiyonel)

Splunk varsayılan olarak 8000 portu üzerinden web arayüzü sağlar. Bu portu değiştirmek için aşağıdaki komutları kullanabilirsiniz:

```bash
/opt/splunk/bin/splunk set web-port 5000
/opt/splunk/bin/splunk restart
```

### Splunk HTTPS Yapılandırma Kılavuzu

#### 1. Kendinden İmzalı Sertifika Oluşturma

```bash
mkdir -p /opt/splunk/certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
-keyout /opt/splunk/certs/splunk.key \
-out /opt/splunk/certs/splunk.crt
```

#### 2. Web Konfigürasyonunu Düzenleme

`/opt/splunk/etc/system/local/web.conf` dosyasını oluşturun veya aşağıdaki şekilde düzenleyin:

```ini
[settings]
enableSplunkWebSSL = true
privKeyPath = /opt/splunk/certs/splunk.key
serverCert = /opt/splunk/certs/splunk.crt
```

#### 3. Sertifika Dosyası İzinlerini Ayarlama

```bash
chmod 600 /opt/splunk/certs/splunk.key
chmod 644 /opt/splunk/certs/splunk.crt
```

#### 4. PYTHONHTTPSVERIFY Ayarını Güncelleme

`/opt/splunk/etc/splunk-launch.conf` dosyasına şu satırı ekleyin veya mevcutsa güncelleyin:

```ini
PYTHONHTTPSVERIFY=1
```

#### 5. Splunk'ı Yeniden Başlatma

```bash
/opt/splunk/bin/splunk restart
```

#### 6. HTTPS Üzerinden Web Arayüzüne Erişim

Tarayıcınızdan aşağıdaki adrese giderek erişimi test edin:

```text
https://sunucu_adresi:8000
```

> **Not:** Kendinden imzalı sertifika kullanıyorsanız, tarayıcı sertifika uyarısı verebilir. Erişime devam etmek için uyarıyı kabul edin.

#### 7. Olası Hatalar İçin Log Kontrolü

Aşağıdaki log dosyalarını kontrol ederek yapılandırma sorunlarını tespit edebilirsiniz:

```bash
cat /opt/splunk/var/log/splunk/splunkd.log
cat /opt/splunk/var/log/splunk/web_service.log
```

### Splunk Uygulama Aşamasında Kullanılan Materyaller Hakkında Bilgilendirme

| Log Türü                    | Açıklama                                                             |
| --------------------------- | -------------------------------------------------------------------- |
| **Access Combined - Wcookie** | Çerez (cookie) içeren detaylı web erişim log formatı.                |
| **DB Audit**                | Veritabanı erişim ve denetim loglarını içerir.                       |
| **Linux Secure**            | `/var/log/secure` içeriğindeki SSH, sudo ve diğer güvenlik olayları. |

Not: Ağınıza yönelik **User-Agent** güvenlik taramaları, genellikle özel **User-Agent** bilgileri içerir. Splunk ile bu tür taramalar kolayca tespit edilebilir (Nikto, Nessus, Acunetix vb.).

`index=main useragent="Nikto" | table _time, host, useragent`

### Log Dosyalarının Splunk'a Import Edilmesi

#### 1. Veri Ekleme Adımları

- Splunk arayüzünde **Settings > Add Data** adımlarını takip ederek veri ekleme işlemine başlanır.
- Manuel olarak dosya yükleneceği için **Upload** seçeneği tercih edilir.

#### 2. Örnek Dosyalar ve Sourcetype Ayarları

**access\_30Day.log**

- Splunk bu dosyanın sourcetype'ını otomatik olarak `access_combined_wcookie` olarak tanımlar.
- Host değeri olarak `web_application` belirlendi.

**linux\_s\_30DAY.log**

- Splunk bu dosyanın sourcetype'ını otomatik tanımlayamaz.
- Manuel olarak **Operating System > linux\_secure** seçilir.
- Host değeri olarak `web_server` seçildi.

**db\_audit\_30DAY.csv**

- Splunk bu dosyanın sourcetype'ını varsayılan olarak `csv` olarak tanımlar, ancak bu değiştirilmek istenir.
- **Save As** seçeneği ile özel bir sourcetype tanımlanır:

  - Sourcetype adı: `db_audit`
  - Description: `Postgre`
  - Category: `Database`
  - App context: `System` (varsayılan olarak kalabilir)
  - Host değeri: `database`

#### Kavramlar

- Splunk, indeks belirtilmediği sürece logları varsayılan olarak **main** indeksine kaydeder.
- Spesifik bir indeks belirtilmediğinde, aramalar yalnızca **main** indeksi üzerinden gerçekleşir.
- `ìndex=*`, * ifadesine wildcard deniliyor. Buda bütün indekslerdeki logları getiriyor.

| Alan Adı        | Açıklama                                                                             |
| --------------- | ------------------------------------------------------------------------------------ |
| `_time`         | Olayın gerçekleştiği zaman (timestamp).                                              |
| `host`          | Olayın geldiği sistemin adı veya IP’si.                                              |
| `source`        | Logun geldiği dosya, port, uygulama veya komut dosyası.                              |
| `sourcetype`    | Verinin formatını tanımlar (örneğin: `access_combined`, `json`, `wineventlog`).      |
| `index`         | Verinin yazıldığı Splunk indeksi.                                                    |
| `_raw`          | Logun ham (orijinal) |

### Splunk Field Extraction Yöntemleri

#### 1. Index-Time Field Extraction

- Veriler indekslenirken alanlar çıkarılır.
- Örnek: `INDEXED_EXTRACTIONS=json`
- Yalnızca JSON, CSV, TSV gibi yapılandırılmış veriler için önerilir.
- Dezavantaj: Disk kullanımı artar, değiştirilemez.

#### 2. Search-Time Field Extraction

- Arama sırasında alanlar çıkarılır (en çok kullanılan yöntem).
- Esnek, performans dostu ve değiştirilebilir.

##### Yaygın Yöntemler

- **rex**: Regex ile alan çıkartılır.
  `... | rex "User:\s(?<username>\w+)"`
- **spath**: JSON veriler için kullanılır.
  `... | spath input=data.user.id`
- **extract / kv**: `key=value` şeklindeki verilerde otomatik alan çıkarımı.
  `... | extract`
- **Interactive Field Extractor**: Arayüzden tıklayarak alan oluşturma.
- **props.conf + transforms.conf**: Kalıcı ve özel regex ile field extraction tanımlanır.
- **Field Alias**: Mevcut alanlara alternatif ad tanımlanır.
- **Calculated Fields**: Eval ile dinamik alan oluşturulur.
  `... | eval fullname=user."-".domain`

## Bölüm 2: SPL ile Veri Analizi

### SPL Komutlarına Giriş

Splunk'un **Search Processing Language (SPL)**, veri filtreleme, dönüştürme ve analiz etme süreçlerinde kullanılan güçlü bir sorgu dilidir. Bu bölümde, temel SPL komutları ve örnek kullanımları açıklanarak veri analizi süreçlerinizi kolaylaştıracak bilgiler sunulmaktadır.

### Temel SPL Komutları ve Örnekler

#### 1. Anahtar Kelime (Keyword) Bazlı Arama

Anahtar kelimelerle arama yaparak belirli olayları (event) filtreleyebilirsiniz. Esnek aramalar için wildcard (`*`) kullanılabilir.

```spl
index=main error OR fail*
```

**Açıklama:** `main` indeksinde `error` veya `fail` ile başlayan kelimeleri içeren olayları listeler.

```spl
index=main sourcetype=access_combined_wcookie action=purchase file="success.do" status=40* OR status=50*
```

**Açıklama:** `success.do` dosyasını içeren ve başarısız satın alma işlemlerine (`status=40*` veya `status=50*`) ait olayları filtreler.

#### 2. `fields` ve `table` Komutları

**`fields`**: Belirtilen alanları seçerek veri setini daraltır ve performansı artırır.  
**`table`**: Sonuçları düzenli bir tablo formatında görüntüler.

```spl
index=main sourcetype=access_combined_wcookie action=purchase
| fields clientip, action, file, status
| table clientip, action, file, status
```

**Notlar:**

- `fields` komutu kullanılmadığında, Splunk varsayılan olarak yalnızca gerekli alanları getirir (smart mode). Ancak, performans optimizasyonu için gerekli alanları açıkça belirtmek önerilir.
- `table` komutu kullanılmazsa, veriler ham (raw) formatta görüntülenir.

#### 3. `rename` Komutu

Alan isimlerini daha anlaşılır veya kullanıcı dostu hale getirmek için kullanılır.

```spl
index=main sourcetype=access_combined_wcookie *76.169.7.252*
| table _time, clientip, JSESSIONID, status, file, uri, uri_path, useragent
| rename JSESSIONID AS UserSessions, clientip AS IPs
```

**Açıklama:** `JSESSIONID` alanı `UserSessions`, `clientip` alanı ise `IPs` olarak yeniden adlandırılır.

#### 4. `sort` Komutu

Sonuçları belirli bir alana göre artan (`+`) veya azalan (`-`) sırayla sıralar.

```spl
index=main sourcetype=access_combined_wcookie "76.169.7.252"
| table _time, clientip, JSESSIONID, status, file, uri, uri_path, useragent
| rename JSESSIONID AS UserSessions, clientip AS IP
| sort uri
```

**Açıklama:** Sonuçlar `uri` alanına göre artan sırayla sıralanır.

```spl
| sort -uri
```

**Açıklama:** Sonuçlar `uri` alanına göre azalan sırayla sıralanır.

#### 5. `dedup` Komutu

Tekrar eden kayıtları kaldırır ve yalnızca benzersiz kayıtları listeler.

```spl
index=main sourcetype=access_combined_wcookie
| dedup clientip
| table clientip
| rename clientip AS IPs
| sort -IPs
```

**Açıklama:** Her `clientip` için yalnızca bir kayıt tutulur, sonuçlar `IPs` olarak yeniden adlandırılır ve azalan sırayla sıralanır.

#### 6. `top` Komutu

Bir alanda en sık tekrar eden değerleri, sayıları ve yüzdelik oranlarıyla listeler.

```spl
index=main sourcetype=access_combined_wcookie
| top clientip
```

**Açıklama:** Varsayılan olarak en sık tekrar eden 10 `clientip` değerini listeler.

```spl
index=main sourcetype=access_combined_wcookie
| top clientip limit=5
```

**Açıklama:** En sık tekrar eden 5 `clientip` değerini getirir.

```spl
index=main sourcetype=access_combined_wcookie
| top clientip limit=500 showperc=false showcount=false
```

**Açıklama:** Yüzde ve sayı bilgisi olmadan 500 `clientip` değerini listeler.

```spl
index=main sourcetype=access_combined_wcookie action=purchase status=200 file=success.do
| top productId
```

**Açıklama:** Başarılı satın alma işlemlerinde en çok satılan ürünleri listeler.

#### 7. `rare` ve `by` Komutları

`top` komutunun tersine, en az tekrar eden değerleri listeler.

```spl
index=main sourcetype=access_combined_wcookie
| rare file
```

**Açıklama:** En az ziyaret edilen 10 sayfayı listeler.

```spl
index=main sourcetype=access_combined_wcookie action=purchase status=200 file=success.do
| rare productId
```

**Açıklama:** En az satılan ürünleri listeler.

```spl
index=main sourcetype=access_combined_wcookie action=purchase status=200 file=success.do
| rare productId by date_month
```

**Açıklama:** Ürünleri aylara göre gruplayarak en az satılanları listeler.

```spl
index=main sourcetype=access_combined_wcookie action=purchase status=200 file=success.do
| rare productId by date_month, date_mday limit=1
```

**Açıklama:** Aylara ve günlere göre gruplayarak her grup için en az satılan 1 ürünü listeler.

#### 8. `stats` Komutu: `count()` ve `dc()`

Veriler üzerinde istatistiksel özetler oluşturur. Gruplama ve sayım işlemleri için kullanılır.

```spl
index=main sourcetype=access_combined_wcookie
| stats count
```

**Açıklama:** Toplam olay (event) sayısını döndürür.

```spl
index=main
| stats count by sourcetype
```

**Açıklama:** Her `sourcetype` için olay sayısını listeler.

```spl
index=main
| stats dc(clientip)
```

**Açıklama:** Benzersiz `clientip` sayısını (`distinct count`) döndürür.

```spl
index=main sourcetype=access_combined_wcookie
| stats dc(JSESSIONID) AS Logins by clientip
| sort -Logins
```

**Açıklama:** Her `clientip` için benzersiz oturum (`JSESSIONID`) sayısını hesaplar ve azalan sırayla sıralar.

#### 9. `where` Komutu

Sonuçları belirli bir koşula göre filtreler.

```spl
index=main sourcetype=access_combined_wcookie status!=200
| stats count by clientip
| where count > 100
```

**Açıklama:** Başarısız giriş denemesi (`status!=200`) sayısı 100’den fazla olan `clientip` adreslerini listeler.

#### 10. `stats sum()` Kullanımı

```spl
index=main sourcetype="access_combined_wcookie"
| stats sum(bytes) as TotalBytes
```

**Açıklama:** Toplam trafik boyutunu bayt cinsinden gösterir.

```spl
index=main sourcetype="access_combined_wcookie"
| stats sum(bytes) as TotalBytes by file
```

**Açıklama:** Her sayfa için toplam bayt boyutlarını listeler.

```spl
index=main sourcetype="access_combined_wcookie"
| stats sum(bytes) as TotalBytes by file
| where TotalBytes > 100000
| sort -TotalBytes
```

**Açıklama:** Toplam bayt boyutu 100.000’den büyük olan sayfaları azalan sırayla listeler.

#### 11. `avg()`, `max()`, `min()` Kullanımı

```spl
index=main sourcetype="access_combined_wcookie"
| stats avg(bytes) by file
```

**Açıklama:** Sayfalara göre ortalama bayt boyutunu hesaplar.

```spl
index=main sourcetype="access_combined_wcookie"
| stats avg(bytes) as "Ortalama Trafik" sparkline(avg(bytes)) as "Trafik Eğilimi" min(bytes) as "Minimum Trafik" max(bytes) as "Maximum Trafik" by file
```

**Açıklama:** Sayfalara göre ortalama, minimum, maksimum trafik değerlerini ve trafik eğilimini sparkline ile gösterir.

!["Sparkline"](/assets/splunk-bootcamp/splunk_sparkline_usage.png)

*SPL sorgularında sparkline fonksiyonunun kullanımıyla elde edilen mini grafiklerin Splunk dashboard’unda nasıl göründüğünü gösterir.*

#### 12. `stats list()` ve `values()` Kullanımı

```spl
index=main sourcetype="access_combined_wcookie" 217.23.14.61
| stats list(useragent) by clientip
```

**Açıklama:** Belirtilen `clientip` için tüm `useragent` değerlerini tekrarlı şekilde listeler.

```spl
index=main sourcetype="access_combined_wcookie" 217.23.14.61
| stats values(useragent) by clientip
```

**Açıklama:** Belirtilen `clientip` için benzersiz `useragent` değerlerini listeler.

#### 13. `eval` Kullanımı

`eval` komutu, veri üzerinde matematiksel veya mantıksal hesaplamalar yapmayı sağlar.

```spl
index=main sourcetype="access_combined_wcookie"
| stats sum(bytes) as TotalBytes
| eval MB=TotalBytes / (1024*1024)
| eval GB=TotalBytes / (1024*1024*1024)
```

**Açıklama:** Toplam bayt boyutunu megabayt (MB) ve gigabayt (GB) cinsine çevirir.

#### 14. `if` ve `case` Kullanımı

```spl
index=main sourcetype="access_combined_wcookie"
| eval http_status = if(status!=200, "Error", "Success")
| stats count by http_status
```

**Açıklama:** HTTP durum koduna göre olayları "Error" veya "Success" olarak sınıflandırır ve sayar.

```spl
index=main sourcetype="access_combined_wcookie"
| eval httpStatusCategory = case(status==200, "Success", status>=400 AND status<500, "Client Error", status>=500, "Server Error")
| stats count by httpStatusCategory
```

**Açıklama:** HTTP durum kodlarını "Success", "Client Error" ve "Server Error" kategorilerine ayırır ve her kategorideki olay sayısını listeler.

#### 15. `timechart` ve `span` Kullanımı

```spl
index=main sourcetype="access_combined_wcookie"
| timechart avg(bytes)
```

**Açıklama:** Uygulamanın günlük ortalama trafik hacmini gösterir (varsayılan olarak 1 günlük).

```spl
index=main sourcetype="access_combined_wcookie"
| timechart span=1hr avg(bytes)
```

**Açıklama:** Uygulamanın saatlik ortalama trafik hacmini gösterir.

```spl
index=main sourcetype="access_combined_wcookie" action="purchase" status=200 file=success.do
| timechart span=1d count by categoryId
```

**Açıklama:** Günlük bazda her kategoriden satılan ürün sayısını gösterir.

**Not:** `timechart` komutundan sonra `stats` komutu kullanılamaz.

#### 16. `iplocation` Kullanımı

Splunk, IP adresleriyle ilgili coğrafi bilgileri (örneğin, enlem ve boylam) dahili veritabanından çeker.

```spl
index=main sourcetype="access_combined_wcookie"
| iplocation clientip
| stats dc(clientip) by Country
```

**Açıklama:** Ülkelere göre benzersiz `clientip` sayısını listeler.

```spl
index=main sourcetype="access_combined_wcookie"
| iplocation clientip
| top Country
```

**Açıklama:** En fazla trafik üreten ülkeleri listeler.

```spl
index=main sourcetype="access_combined_wcookie"
| iplocation clientip
| stats sum(bytes) as TotalBytes by clientip, Country
| sort TotalBytes
| head 1
```

**Açıklama:** En fazla trafik üreten IP adresini ve ülkesini gösterir.

```spl
index=main sourcetype="access_combined_wcookie"
| iplocation clientip
| stats dc(clientip) values(clientip) by Country
```

**Açıklama:** Her ülkeden gelen benzersiz IP adreslerini ve sayısını listeler.

#### 17. `eventstats` Kullanımı

`eventstats`, `stats` ile benzer istatistiksel hesaplamalar yapar ancak olayların detaylarını korur.

```spl
index=main sourcetype="access_combined_wcookie"
| head 10
| eventstats sum(bytes) as TotalBytes by clientip
| table _time, bytes, TotalBytes, clientip
| sort clientip
```

**Açıklama:** İlk 10 olayın her `clientip` için toplam bayt boyutunu hesaplar ve detaylarıyla birlikte sıralar.

#### 18. `transaction` ve `contingency` Kullanımı

`transaction` komutu, birden fazla olayı mantıksal bir işlem olarak birleştirir.

```spl
index=main sourcetype="access_combined_wcookie"
| transaction JSESSIONID
```

**Açıklama:** Aynı `JSESSIONID` değerine sahip olayları birleştirir ve kullanıcının uygulamada geçirdiği süreyi (`duration`) hesaplar.

```spl
index=main sourcetype="access_combined_wcookie" SD5SL2FF9ADFF4966
| transaction JSESSIONID
| stats avg(duration)
```

**Açıklama:** Belirtilen `JSESSIONID` için ortalama oturum süresini saniye cinsinden hesaplar.

**Alternatif ve Daha Performanslı Yöntem:**

```spl
index=main sourcetype="access_combined_wcookie" SD5SL2FF9ADFF4966
| stats min(_time) as start_time max(_time) as end_time by JSESSIONID
| eval duration=end_time - start_time
| stats avg(duration)
```

**Açıklama:** Daha performanslı bir şekilde oturum süresini hesaplar.

```spl
index=main sourcetype="access_combined_wcookie"
| contingency file status
```

**Açıklama:** `file` ve `status` arasındaki ilişkiyi bir tablo halinde gösterir.

#### 19. subsearch Kullanımı

Sorgu içinde sorgu çalıştırarak daha spesifik sonuçlar elde edilir.

```spl
index=main sourcetype="access_combined_wcookie" action=purchase file="success.do" status=200 
    [search index=main sourcetype="access_combined_wcookie" action=purchase file="success.do" status=200
    | top clientip limit=1
    | table clientip]
```

**Açıklama:** En çok satın alma yapan `clientip` adresine ait başarılı satın alma işlemlerini listeler.

```spl
index=main sourcetype="access_combined_wcookie" action=purchase file="success.do" status=200 
    [search index=main sourcetype="access_combined_wcookie" action=purchase file="success.do" status=200
    | top clientip limit=1
    | table clientip]
| stats count as "Toplam Satın Alınan", dc(productId) as "Toplam Farklı Ürün Sayısı", values(productId) as "Ürünler" by clientip
| rename clientip as "Top 1 Müşteri"
```

**Açıklama:** En çok satın alma yapan müşterinin toplam satın alma sayısını, farklı ürün sayısını ve ürünlerini listeler.

#### 20. `geom` Kullanımı

Coğrafi verileri görselleştirmek için kullanılır.

```spl
index=main sourcetype="access_combined_wcookie"
| iplocation clientip
| stats sum(bytes) by Country
| geom geo_countries featureIdField=Country
```

**Açıklama:** Ülkelere göre toplam trafik hacmini coğrafi bir harita üzerinde görselleştirir.

## Bölüm 3: Report, Dashboard, Alert Yönetimi

### Report

Splunk'ta rapor, bir arama sorgusunun kaydedilerek paylaşılabilir ve zamanlanabilir bir formata dönüştürülmesini sağlayan bir özelliktir. Raporlar, belirli bir veri setini analiz etmek ve düzenli olarak sonuç üretmek için kullanılır.

**Örnek Arama Sorgusu:**

```spl
index=main sourcetype="access_combined_wcookie" status=403
| iplocation clientip
| stats count as attempts by clientip, Country
| where attempts > 10
```

**Not:** Raporlar genellikle "Everyone" için okuma (read) yetkisiyle paylaşılırken, yalnızca "admin" rolüne düzenleme (write) yetkisi verilir.

!["Report Edit Permissions"](/assets/splunk-bootcamp/splunk_edit_report_permissions.png)

*Splunk’ta bir raporun paylaşım ve izin ayarlarını düzenleme ekranı.*

### Dashboard

Birden fazla arama sonucunu görselleştirerek verileri daha anlaşılır, takip edilebilir ve etkileşimli bir şekilde sunmayı amaçlar. Temel hedef, karmaşık verileri kullanıcı dostu bir formatta görselleştirmektir.

Coğrafi verileri görselleştirmek için kullanılan bir pano örneği:

!["Choropleth Map"](/assets/splunk-bootcamp/splunk_choropleth_map.png)

*Splunk’ta coğrafi verilerin choropleth (renkli bölge) haritası üzerinde görselleştirilmesini gösteren dashboard paneli.*

```spl
index=main sourcetype="access_combined_wcookie"
| iplocation clientip
| stats sum(bytes) by Country
| geom geo_countries featureIdField=Country
```

**Açıklama:** Bu sorgu, ülkelere göre toplam trafik hacmini coğrafi bir harita üzerinde görselleştirir.

**Dashboard Oluşturma:**

Dashboard, mevcut raporlardan beslenebilir.
Yeni bir dashboard eklemek için: Edit > Add Panel > New from Report.

#### Data Input Örneği

1. Dashboard için sorgunun oluşturulması

    Önceklikle dashboard oluşturan sorguyu yazıyorum. visualizations kısmında gelip linechart yapıyorum.

    ```spl
    index=main sourcetype="access_combined_wcookie" action=purchase status=200 file=success.do categoryId=*
    | timechart count as "Unit Sold" by productId usenull=false useother=false
    ```

    usenull=false kullandığımızda productId alanı olmayanlar dahil edilmez. (satılmayan ürünleri getirme)
    useother=false (çok az satılan product varsa onları other olarak işaretlmeyecek)

2. DataInput içerisinde değişken olarak değerleri değiştirmek için uygun panel ekleme

    Add Input içerisinde Time sonrasında Dropdown ekledik.

    **Time Kısmı İçin**

    !["DataInput Dashboard Add Time"](/assets/splunk-bootcamp/splunk_dashboard_data_input_add_time.png)

    **Dropdown Kısmı İçin**

    !["DataInput Dashboard Add Dropdown"](/assets/splunk-bootcamp/splunk_dashboard_data_input_add_dropdown.png)

    Tüm category'leri getirecek.
    !["DataInput Dashboard Add Dropdown Static Options"](/assets/splunk-bootcamp/splunk_dashboard_data_input_add_dropdown_static_options.png)

    !["DataInput Dashboard Add Dropdown Dynamic Options"](/assets/splunk-bootcamp/splunk_dashboard_data_input_add_dropdown_dynamic_options.png)

  ```spl
  index=main sourcetype="access_combined_wcookie"
  | dedup categoryId
  | table categoryId
  ```

  spl sorgusu

  !["Search String"](/assets/splunk-bootcamp/splunk_dashboard_data_input_add_dropdown_search_string.png)

### Alerts

`index=_` dediğimizde Splunk üzerinde ön tanımlı indexlere ulaşabilirsiniz.

Aşağıda, Splunk'ta verdiğin arama sorgusunu (`index="_audit" user=admin action="login attempt" info=failed`) temel alarak basit ve dökümante edilecek şekilde bir uyarı (alert) oluşturma adımlarını açıklıyorum:

#### Uyarı Oluşturma Adımları

##### Admin Failed Login Attempts

1. **Ayarlar (Settings):**
   - **Alert:** `Admin Failed Login Attempts` (Admin Başarısız Giriş Denemeleri)
   - **Description:** `Bu uyarı, admin kullanıcısının başarısız giriş denemelerini izler.`
   - **Permissions:** `Private` olarak ayarlanırsa sadece alarmı oluşturan kişi görebilir; `Shared in App` olarak ayarlanırsa diğer Splunk kullanıcıları da bu uyarıyı görebilir.
   - **Alert Type:** `Real-time` (Gerçek Zamanlı) seçeneği anlık izleme için uygundur; `Scheduled` ise belirli zaman aralıklarında çalıştırmak için mantıklıdır.
   - **Expires:** `2400 days` (2400 gün) ile alarmın geçerlilik süresi belirlenir.

2. **Trigger Conditions (Tetikleme Koşulları):** Bu bölüm, alarmın ne zaman tetikleneceğini tanımlar.
   - **Trigger alert when:** `Number of Results` (Sonuç Sayısı)
   - **is greater than:** `5` (5'ten fazla)
   - **in:** `1 minute` (1 dakikada)
   - **Trigger:** `Once` (Bir Kez)
   - **Throttle?:** `Yes` (Evet) - Örneğin, bir saldırgan 1 dakika içinde 100 başarısız giriş denemesi yaparsa ve throttle yoksa 100 uyarı tetiklenebilir; bu da gereksiz tekrarlara yol açar. Throttle ile bu engellenir.
   - **Suppress triggering for:** `1 minute` (1 dakika) - Uyarı, 1 dakika boyunca tekrar tetiklenmez.

3. **Trigger Actions (Tetikleme Eylemleri):**
   - **When triggered:** `Add to Triggered Alerts` (Tetiklenen Uyarılara Ekle)
   - **Severity:** `High` (Yüksek)

4. **Kaydetme:**
   - Değişiklikleri kaydetmek için `Save` (Kaydet) butonuna bas.

##### Açıklama

- **Arama Sorgusu:** `index="_audit" user=admin action="login attempt" info=failed` ile audit loglarında admin kullanıcısının başarısız giriş denemeleri aranır.
- **Uyarı Mantığı:** Son 1 dakikada 5'ten fazla başarısız giriş denemesi olduğunda uyarı bir kez tetiklenir ve 1 dakika boyunca tekrar tetiklenmez.
- **Amaç:** Admin hesabındaki şüpheli etkinlikleri tespit etmek ve hızlı müdahale sağlamak.

!["Splunk Alert Definition"](/assets/splunk-bootcamp/splunk_alert_definition.png)

*Splunk’ta bir alarm (alert) tanımının nasıl yapıldığını gösteren ekran görüntüsü.*

**Not:** Alarmlara kural, korelasyon, use-case diyoruz.

Tetiklendiğinde Activity > Trigger Alert içerisinde görebilirsiniz.

Sayfaya girdiğinizde App kısmını All Apps yapabilirsiniz.

##### Splun User Create Detection

```spl
index="_audit" action=create_user info=succeeded
```

!["Splunk Alert Definition 2"](/assets/splunk-bootcamp/splunk_alert_definition2.png)

*Splunk’ta kullanıcı oluşturma alarmı (alert) tanımının ekran görüntüsü.*

## Bölüm 4: Workflow, Lookups, Regex

### Workflow

**Workflow**, Splunk kullanıcılarının arama sonuçları üzerinden hızlı aksiyon almasını veya bağlamsal geçiş yapmasını sağlar. Örneğin, bir IP adresi ya da kullanıcı adı üzerinden başka bir aramaya geçiş yapılabilir veya harici bir aksiyon (örneğin, bir IP adresini tehdit istihbaratı veritabanında sorgulama) tetiklenebilir. Bu özellik, kullanıcıların analiz süreçlerini hızlandırır ve operasyonel verimliliği artırır.

**Erişim Yolu**: Splunk arayüzünde **Settings > Workflows** menüsünden yapılandırılır.

**Örnek Kullanım**: Bir IP adresine tıklayarak AbuseIPDB gibi harici bir tehdit istihbaratı servisinde sorgulama başlatılabilir.

![Splunk Workflow Ekran Görüntüsü](/assets/splunk-bootcamp/splunk_workflow_abuse_ip.png)

*Splunk Workflow özelliğiyle bir IP adresinin AbuseIPDB gibi harici bir tehdit istihbarat servisiyle sorgulanmasını gösteren ekran.*

### Lookups

**Lookups**, Splunk'ta arama sonuçlarını zenginleştirmek veya belirli alanları harici verilerle eşleştirmek için kullanılır. Bu işlem, veri zenginleştirme (data enrichment) olarak adlandırılır ve analiz sonuçlarını daha anlamlı hale getirir. Örneğin, bir IP adresini coğrafi konum bilgisiyle eşleştirmek için lookup tabloları kullanılabilir.

**Yapılandırma Adımları**:

1. **Lookup Table Files**: Harici veri dosyanızı (ör. CSV formatında) yüklemek için **Settings > Lookups > Lookup table files > Add New** seçeneğini kullanın.
2. **Lookup Definitions**: Yeni bir lookup tanımı oluşturmak için **Settings > Lookups > Lookup definitions > Add New** seçeneğine tıklayın ve lookup dosyanıza bir isim verin.
3. **Automatic Lookups**: Otomatik lookup'ları etkinleştirmek için **Settings > Lookups > Automatic lookups > Add New** seçeneğini kullanın. Bu, belirli alanların otomatik olarak harici verilerle eşleşmesini sağlar.

**Örnek Kullanım**: Bir IP adresi alanını, coğrafi konum bilgileri içeren bir CSV dosyasıyla eşleştirerek şehir veya ülke bilgisi ekleyebilirsiniz.

![Splunk Lookups Ekran Görüntüsü](/assets/splunk-bootcamp/splunk_lookup.png)

*Splunk’ta lookup tablosu oluşturma ve yapılandırma adımlarını gösteren arayüz ekranı.*

### Regex

Splunk'ta düzenli ifadeler (regex), ham log verilerinden belirli bilgileri çıkarmak için kullanılır. Aşağıda sık kullanılan regex kalıpları ve açıklamaları verilmiştir:

- `\s`: Boşluk karakterlerini seçer (boşluk, tab, newline vb.).
- `\w`: Alfanümerik karakterleri seçer (`a-z`, `A-Z`, `0-9` ve `_`).
- `\d`: Sayı karakterlerini seçer (`0-9`).
- `\d{1,3}`: 1 ile 3 arasında tekrar eden sayı karakterlerini seçer (ör. `5`, `12`, `999`).
- `\d+`: Bir veya daha fazla sayı karakterini seçer.
- `\d*`: Sıfır veya daha fazla sayı karakterini seçer (boş string de eşleşebilir).

**Örnek Log**:

```text
Mon Dec 27 2021 22:56:31 www1 sshd[1389]: Failed password for invalid user ubuntu from 223.213.255.255 port 4411 ssh2
```

**Regex Kullanım Örnekleri**:

1. **Port Bilgisi Çıkarma**:

   ```spl
   index="main" sourcetype=linux_secure
   | rex field=_raw "port\s(?<port_number>\d+)"
   ```

   *Açıklama*: Bu arama, logdaki `port` kelimesinden sonraki sayı dizisini `port_number` adıyla bir alan olarak çıkarır.

2. **IP Bilgisi Çıkarma**:

   ```spl
   index="main" sourcetype=linux_secure
   | rex field=_raw "port\s(?<port_number>\d+)"
   | rex field=_raw "(?<clientip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
   | table clientip, port_number
   | where isnotnull(clientip)
   | where isnotnull(port_number)
   ```

   *Açıklama*: IP adresini `clientip` adıyla çıkarır ve yalnızca geçerli IP ve port bilgilerini tablo olarak listeler.

3. **Kullanıcı Adı ve Port 22 Filtresi**:

   ```spl
   index="main" sourcetype=linux_secure
   | rex field=_raw "port\s(?<port_number>\d+)"
   | rex field=_raw "(?<clientip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
   | rex field=_raw "user\s(?<username>\w*)"
   | table clientip, port_number, username
   | where isnotnull(clientip)
   | where isnotnull(port_number)
   | where isnotnull(username)
   | where port_number = 22
   | stats count by clientip
   ```

   *Açıklama*: IP, port ve kullanıcı adı çıkarılır; yalnızca port 22'ye yapılan bağlantılar filtrelenir ve IP adresine göre bağlantı sayısı hesaplanır.

4. **En Sık Bağlantı Yapan  geval 5 IP**:

   ```spl
   index="main" sourcetype=linux_secure
   | rex field=_raw "port\s(?<port_number>\d+)"
   | search port_number = 22
   | rex field=_raw "(?<clientip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
   | rex field=_raw "user\s(?<username>\w*)"
   | stats count as ssh_connection_number by clientip
   | sort -ssh_connection_number
   | head 5
   ```

   *Açıklama*: Port 22'ye yapılan bağlantılar için en sık bağlanan 5 IP adresini listeler.

## Bölüm 5: Log Forwarding

Splunk Universal Forwarder, log verilerini Splunk sunucusuna iletmek için kullanılır. Log forwarding yapılandırması, Splunk arayüzü ve forwarder ayarları üzerinden gerçekleştirilir.

**Yapılandırma Adımları**:

1. **Log Alma Ayarları**:
   - Splunk arayüzünde **Settings > Forwarding and Receiving > Receive Data** seçeneğine gidin.
   - Yeni bir port eklemek için **Configure receiving** kısmına tıklayın ve Splunk'ın dinlemesini istediğiniz portu (ör. 9997) belirtin.

2. **Forwarder Yapılandırması**:
   - Splunk Universal Forwarder'ın kurulu olduğu dizinde (ör. `C:\Program Files\SplunkUniversalForwarder\etc\apps\SplunkUniversalForwarder\default`) `inputs.conf` dosyasını düzenleyin.
   - Örnek `inputs.conf` yapılandırması:

     ```xml
     [WinEventLog://Security]
     index=wineventlog
     ```

     *Açıklama*: Bu ayar, Windows Güvenlik Olay Günlüklerini (Security Event Logs) `wineventlog` indeksine iletir.

3. **Yeni İndeks Oluşturma**:
   - Splunk arayüzünde **Settings > Indexes** menüsünden yeni bir indeks oluşturun (ör. `wineventlog`).
   - İndeksin adını ve diğer ayarları (ör. veri saklama süresi) yapılandırın.

**Not**: Forwarder'ın düzgün çalıştığından emin olmak için, forwarder ile Splunk sunucusu arasındaki ağ bağlantısını ve port erişimini kontrol edin.

## Bölüm 6: Use-Case

### Windows Audit Log Tampering Detection

Windows loglarının silinmesi veya kapatılması tespit edilir.

```spl
index="wineventlog" EventCode=1100 OR EventCode=1102
```

- `1100`: Event Logging Service kapatıldı.
- `1102`: Güvenlik logları temizlendi.

!["Windows Audit Log Tampering Detection"](/assets/splunk-bootcamp/Windows_Audit_Log_Tampering_Detection.png)

*Windows loglarının silinmesi veya kapatılması gibi log manipülasyonlarını tespit eden Splunk dashboard veya arama sonucu.*

### Detecting Brute Force Attack

Çok sayıda başarısız oturum açma denemesi algılanır.

```spl
index="wineventlog" EventCode=4625
```

- `4625`: Failed Logon (başarısız oturum açma)

!["Detecting Brute Force Attack"](/assets/splunk-bootcamp/Detecting_Brute_Force_Attack.png)

*Splunk’ta brute force saldırılarını tespit etmeye yönelik bir dashboard veya arama sonucunun görseli.*

### A User Account was Created and Deleted in 24 Saat

#### Komut Satırı Örnekleri

```cmd
net user                             :: Sistemdeki kullanıcıları listeler  
net user test123 test123 /add       :: Yeni kullanıcı oluşturur  
net user test123 /delete            :: Kullanıcıyı siler  
```

#### Örnek Event Log

```xml
Subject:
    Security ID:        S-1-5-21-...
    Account Name:       test
    Account Domain:     DESKTOP-X
    Logon ID:           0x753D38
```

#### Splunk Sorgusu

```spl
index="wineventlog" EventCode=4720 OR EventCode=4726
| rex "Subject:\s+\w+\s\S+\s+\S+\s+\S+\s+\S+\s+(?<Source_Account>\S+)"
| rex "New Account:\s+\w+\s\S+\s+\S+\s+\S+\s+\S+\s+(?<New_Account>\S+)"
| rex "Target Account:\s+\w+\s\S+\s+\S+\s+\S+\s+\S+\s+(?<Delete_Account>\S+)"
| eval SuspectAccount = coalesce(Delete_Account, New_Account)
| transaction SuspectAccount startswith="EventCode=4720" endswith="EventCode=4726"
| where duration <= 86400
```

#### Açıklamalar

- `Source Account`: İşlemi gerçekleştiren kullanıcı
- `New Account`: Oluşturulan kullanıcı
- `Delete Account`: Silinen kullanıcı
- `duration <= 86400`: İşlemlerin 24 saat içinde gerçekleşip gerçekleşmediği kontrol edilir (86400 saniye)

### Schedule Task was Created Detection

Zararlı amaçla zamanlanmış görev oluşturulması tespiti.

```cmd
schtasks /create /tn "windowsUpdate" /tr "win32calc.exe" /sc daily /st 13:29
```

```spl
index="wineventlog" EventCode=4698
```

- `4698`: Yeni bir zamanlanmış görev oluşturuldu.

Process işlemlerinin loglanmasını açmak için "Local Security Policy" aşağıdaki değerleri açıyoruz.

!["Windows Policy Audit Process Creation"](/assets/splunk-bootcamp/Windows_Policy_Audit_Process_Creation.png)

*Windows’ta process (işlem) oluşturma olaylarının loglanmasını sağlayan güvenlik politikası ayar ekranı.*

Schecule Task loglanması için

!["Windows Policy Audit Other Object Access Events"](/assets/splunk-bootcamp/Windows_Policy_Audit_Other_Object_Access_Events.png)

*Windows’ta diğer nesne erişim olaylarının loglanmasını etkinleştiren güvenlik politikası ekranı.*

### CMD ve PowerShell Komutlarının Loglanması

cmd üzerinden whoami dye bir komutu çalıştığında 4688 olarak loglanıyor. Ama uzun betikler çalıştırıldığında bu komutlar loglanmıyor. Loglanması için aşağıdaki scripti çalıştırabiliriz.

#### Komut Satırı Argümanlarını Loglama

```cmd
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

#### Process Creation Alt Kategorisinin Açılması

```cmd
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

#### Group Policy Güncelleme

```cmd
gpupdate /force
```

Bu yapılandırmalarla birlikte, çalıştırılan komutlar `EventCode=4688` loglarında görünmeye başlar.

Bu logun loglanmasını bekliyorum.

net user deneme deneme /add

Ayrıca powershell loglamasınıda açmamız gerekmektedir

!["Windows Powershell Logging"](/assets/splunk-bootcamp/Windows_Policy_Powershell_Logging.png)

*PowerShell komutlarının ve aktivitelerinin loglanmasını sağlayan genel Windows güvenlik politikası ekranı.*

Veya content kaldırıp *'da koyabilirsiniz. Tüm logları alır.

!["Windows_Policy_Powershell_Logging_Contents"](/assets/splunk-bootcamp/Windows_Policy_Powershell_Logging_Contents.png)

!["Windows_Policy_Powershell_Script_Block_Logging"](/assets/splunk-bootcamp/Windows_Policy_Powershell_Script_Block_Logging.png)

!["Windows_Policy_Powershell_Script_Execution](/assets/splunk-bootcamp/Windows_Policy_Powershell_Script_Execution.png)

!["Windows_Policy_Powershell_Transcription"](/assets/splunk-bootcamp/Windows_Policy_Powershell_Transcription.png)

Eventcode=4104 olaylarına bakabiliriz.

### Powershell ile Şüpheli Dosya İndirme Aktivitelerinin Tespiti

#### Örnek Komutlar

```powershell
New-Item -Path "C:\Data" -ItemType Directory -Force Invoke-WebRequest -Uri "https://live.sysinternals.com/Autoruns.exe" -OutFile "C:\Data\Autoruns.exe"
```

```cmd
bitsadmin /transfer "DownloadAutoruns" https://live.sysinternals.com/Autoruns.exe C:\Data\Autoruns.exe
```

```spl
index="wineventlog" sourcetype="WinEventLog:Microsoft-Windows-Powershell/Operational" EventCode=4104 "*bitsadmin*" AND ("http" OR "https")
```

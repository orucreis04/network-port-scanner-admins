# Network Port Scanner for Admins

## 1. Overview

Network Port Scanner for Admins, sistem yoneticileri ve guvenlik ekipleri icin gelistirilen Python tabanli bir TCP port tarama aracidir. Proje; yalnizca yetkili sistemlerde kullanilmak uzere tasarlanmis, sade bir CLI arayuzu ve JSON/CSV raporlama destegi sunar.


## 2. Features

- IPv4, IPv6, domain ve CIDR hedef destegi
- TCP connect scan yaklasimi
- Port listesi ve port araligi destegi
- Paralel port tarama
- Worker sinirlandirmasi ile kontrollu kaynak kullanimi
- Rich tabanli terminal tablosu
- JSON rapor cikti destegi
- CSV rapor cikti destegi
- Sadece acik portlari veya tum sonuclari gosterme secenegi
- Anlasilir hata mesajlari
- Pytest test kapsami

## 3. Tech Stack

- Python 3.11+
- argparse
- socket
- ipaddress
- concurrent.futures
- dataclasses
- json
- csv
- rich
- pytest

## 4. Project Structure

```text
network-port-scanner-admins/
├── portscanner/
│   ├── __init__.py
│   ├── cli.py
│   ├── scanner.py
│   ├── models.py
│   ├── validators.py
│   ├── reporters.py
│   └── services.py
├── tests/
│   ├── __init__.py
│   ├── test_validators.py
│   ├── test_services.py
│   ├── test_scanner.py
│   └── test_reporters.py
├── examples/
│   └── sample_report.json
├── main.py
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

## 5. Installation on Fedora 42+

Python surumunu kontrol edin:

```bash
python3 --version
```

Sanal ortam olusturun:

```bash
python3 -m venv .venv
```

Sanal ortami aktif edin:

```bash
source .venv/bin/activate
```

Paketleri yukleyin:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

CLI yardimini goruntuleyin:

```bash
python main.py --help
```

## 6. Usage Examples

Lokal hedefte belirli portlari tarama:

```bash
python main.py -t 127.0.0.1 -p 22,80,443
```

CIDR hedefte port araligi tarama:

```bash
python main.py -t 192.168.1.0/24 -p 1-100 --timeout 0.5 --workers 50
```

Domain tarayip JSON rapor kaydetme:

```bash
python main.py -t example.com -p 80,443 --json report.json
```

Kapali portlari da gosterip CSV rapor kaydetme:

```bash
python main.py -t 127.0.0.1 -p 1-1024 --csv report.csv --show-closed
```

## 7. Sample Output

Asagidaki ornek, `--show-closed` kullanildiginda terminalde gorulebilecek sade ciktiyi temsil eder.

```text
Notice: Use only on systems you own or have explicit permission to test.
Scan: hosts=1, ports=3, timeout=1.0s, workers=100

                         Network Port Scan Results
┏━━━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Host      ┃ Port ┃ Status ┃ Service ┃ Error              ┃ Response (ms) ┃
┡━━━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ 127.0.0.1 │   22 │ OPEN   │ SSH     │                    │         1.420 │
│ 127.0.0.1 │   80 │ closed │ HTTP    │ Connection refused │         0.870 │
└───────────┴──────┴────────┴─────────┴────────────────────┴───────────────┘

Done: open=1, closed=2, total=3, displayed=3, duration=0.032s
```

## 8. JSON Report Example

```json
[
  {
    "host": "127.0.0.1",
    "port": 22,
    "is_open": true,
    "service": "SSH",
    "error": null,
    "response_time_ms": 1.42
  },
  {
    "host": "127.0.0.1",
    "port": 80,
    "is_open": false,
    "service": "HTTP",
    "error": "Connection refused",
    "response_time_ms": 0.87
  }
]
```

## 9. CSV Report Example

```csv
host,port,is_open,service,error,response_time_ms
127.0.0.1,22,True,SSH,,1.42
127.0.0.1,80,False,HTTP,Connection refused,0.87
```

## 10. Responsible Usage

- Bu arac yalnizca sahibi oldugunuz veya yazili izin aldiginiz sistemlerde kullanilmalidir.
- Yetkisiz aglarda port taramasi hukuki ve etik sorunlara yol acabilir.
- Varsayilan ayarlar agresif degildir.
- Bu proje egitim, sistem yonetimi ve guvenlik dogrulama amaciyla gelistirilmistir.

## 11. Running Tests

Testleri calistirmak icin:

```bash
pytest
```

## 12. Roadmap

- UDP scan optional support
- HTML report
- Web dashboard
- Docker/Podman support
- Scheduled internal scans
- Basic vulnerability hints by service

## 13. License

Bu proje MIT lisansi ile lisanslanmistir. Ayrintilar icin [LICENSE](LICENSE) dosyasina bakabilirsiniz.

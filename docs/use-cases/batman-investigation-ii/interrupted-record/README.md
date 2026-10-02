# Kesilmiş koşunun tam kayıt arşivi

`s421201` başarılı bitmedi: **10 recorded established /4 unresolved**; Q1 partial, Q12–Q14 not_determinable. Flag/gold/all14 doğrulanmadı. Son trace2 Ekim18:59:20UTC, son mirror19:24:58UTC.10 VM Stopped; registry running, controller/geçici preparation dizini yok. Duruş nedeni bilinmiyor; gözlemci ajanları durdurmadı veya yeniden başlatmadı.

## Korunan kayıtlar

- Mevcut sandbox'ın **153.236 dosyası /18.032.011.433 byte** ayrı özel snapshot'a kopyalandı; özgün dosya ve kopya bütünüyle SHA256 ile karşılaştırıldı. Başlangıç/son envanter ve stat bilgileri aynı. Snapshot dosyaları salt okunur yapıldı.
- Repo paketi **3.891 özgün kayıt /2.127.840.997 byte** taşır: bütün retained trace,10 Pi oturumu, pano post'ları, ledger/review/lead/finish/question/request kayıtları, bütün job metadata/stdout/stderr, tam text outputs, tools/history/catalog/VM metadata ve çalışma metinleri. **İçerik kesilmedi veya redacted gövdeyle değiştirilmedi.**
- Input link'i izlenmedi;4.8GB ham delil ve VM diskleri Git'e alınmadı.149.344 türetilmiş binary/content-blob dosyası ve1 dedicated auth-secret dosyası özel snapshot'ta bütünüyle tutuluyor. Her dış dosyanın SHA256/boyut/disposition bilgisi tam şifreli kaynak envanterindedir.
- Paylaşılan registry/audit ve3 dış anchor bütünüyle özel tutuldu; [provenance](external-source-custody.json). Önceki özel checkpoint sürümleri/selected-prefix asılları da korunuyor.

## Biçim ve yeniden kurma

Okunabilir projection, redactor'ın son kontrolünde17.538 reported hit ile reddedildi; bütün hit'ler gerçek secret leak diye sınıflandırılmadı. Başarısız projection özel tutuldu ve yayımlanmadı. Tam özgün kayıtlar **kayıpsız gzip + AES-256-GCM** ile korundu:19 sıralı parça, toplam315.574.003 byte; parça başına en çok16MiB. Anahtar Git'te değildir:

`/Users/halilozturkci/DFIR/Private/dfirswarm-run-observer/s421201/interrupted-20261002T200442Z/record-archive-key.json`

[Manifest](archive-verification.json) nonce/tag, parça sırası ve hashleri, ciphertext hashini ve source inventory commitment'ını taşır. [Geri açma aracı](../preparation/restore-encrypted-record.py) önce parçaları ve GCM authentication'ı doğrular; yalnız güvenli regular-file yollarını yeni özel dizine çıkarıp her SHA256'yı karşılaştırır. Arşiv programlarını çalıştırmaz:

```sh
python3 docs/use-cases/batman-investigation-ii/preparation/restore-encrypted-record.py \
  docs/use-cases/batman-investigation-ii/interrupted-record \
  /Users/halilozturkci/DFIR/Private/dfirswarm-run-observer/s421201/restored-copy
```

Python `cryptography` gerekir; arşivleme44.0.0 ile yapıldı. Gerçek paket iki kez geri açıldı;3891 dosyanın hashleri eşleşti. Ayrı bozulmuş-ciphertext kontrolü InvalidTag ile reddedildi. Mevcut Pi/Codex/hub kaynaklarındaki10 uzun literal/20 raw-JSON-UTF16 formu, bütün2.127GB boyunca tarandı:0 hit/değer basılmadı. Bu geçmişteki bilinmeyen sırlar için global secrecy hükmü değildir.

## Custody sınırı

[Snapshot](snapshot-verification.json) · [Koruma tamamlanması](preservation-completion.json) · [Zincir/custody denetimi](chain-verification.json) · [Son yöntem kaynakları](late-technique-source-index.json).

LF ile23082 trace satırı ve387 ledger kaydı hash zincirlerine/anchor'a uyuyor. Leads1537, finish156, questions93, requests13 ve journal2835 zincirleri sağlam.8 trace kaydı sender attribution açısından unverified; enrolled/signed examiner veya analitik doğruluk iddiası yok.

Resmi stop custody yok. Read-only custody verifier literal Unicode separator'ları nedeniyle sağlam trace'i847'de broken raporluyor; [gerçek/sentetik ayrım testi](unicode-line-reader-probe.json). VM finish/snapshot receipts yok;2 operator line audit ile eşleşmiyor. Geçici controller/UI log dosyaları artık yok: mevcut dosyaların tam korunması kayıp dış kayıtları geri getirmiyor. Agent final answers.json/report.md/timeline.md yok; agent adına sonuç üretilmedi. Solution okunmadı.

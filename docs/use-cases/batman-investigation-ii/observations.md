# Batman Investigation II — canlı gözlem notları

## Hazırlık

- Orijinal arşivin beklenen SHA256 değeri doğrulandı. Yalnız iki handout delili, solution ağacından ayrı bir salt okunur dizine çıkarıldı. Solution içerikleri okunmadı.
- Önceki 3 model testi gerçek VM içinde başarılıydı. Bu koşunun her 10 ajanının gerçek çağrıları ayrıca doğrulanacak.
- Sembol hazırlığı: `dfirswarm-memory:symbols-arm64`, digest `d0f618ec45c24c57184dbab45a8f04bf2d2ac362bd2e44fb5f65d6b74a97ffa7`, bu dökümün `ntkrnlmp.pdb/81BC5C377C525081645F9958F209C5271` tablosunu içermiyor. Gerçek çevrimdışı Windows.info gereksinim hatası verdi. Katalogdaki geniş sembol paketi tek başına bu vaka için hazır oluşu kanıtlamıyor. Eksik tablo Microsoft'tan tam kimlikli olarak alınarak ayrı, hashli araç referansı olarak sağlanıyor.
- Özel ön testin ilk denemesinde `bash -lc` imaj PATH'ini sıfırladığı için `vol` bulunmadı; tam araç yoluyla düzeltildi. Bu operatör ön test hatası, swarm ajan hatası sayılmıyor. İki ön test sonucu da saklanıyor.

## Koşu

Aktif koşu `s421201`, 2026-10-02 09:56:19 UTC'de başladı. Bulgular ajan/iş/trace kimlikleri ve zamanlarıyla aşağıda saklanıyor; nihai çözüm ve custody henüz yok.

### Başlatma bulgusu — s5e1edd

10 gerçek VM oluşturuldu; hepsinin başlangıç probunda `inputs_exec=exec` çıktı. `--inputs-copy` kopyasının `inputs/` yolu salt okunur run montajının içinde kalıyor; ayrı no-exec delil montajı oluşmuyor. Başlatma fail-closed davranarak ajanlara ilk analitik mesajı göndermeden tüm VM'leri kaldırdı. Kaynak: failed-copy-start-s5e1edd.log ve run vm kayıtları.

Etki: belgelerde canlı koşular için önerilen `--inputs-copy` bu VM başlangıcında çalışmıyor. Öneri: kopya delil dizininin VM spec içinde ayrı RO+noexec montajı; kopya/bind, tek/çoklu set yollarında gerçek VM kabul testi. Bu koşuda yalnız iki dosyadan oluşan, önceden hashlenmiş ve chmod ile salt okunur hazırlanmış ayrı dizin bind edilecek; orijinal vaka/solution ağacı monte edilmeyecek. Platform kodu değişmeden aynı commit ile tekrar başlatılıyor.

### 09:57–10:02 UTC — gerçek çalışma ve araç çağrı hataları

- 10/10 ek VM izolasyon probu geçti (isolation-proof.json): deliller var; Solution, repo use-cases, özel cache ve host auth dosyaları görünmüyor. Yazım EROFS (errno30) ile reddediliyor; GitHub/raw/search/host console köklerine erişilemiyor. Ek prob yalnız yol varlığını kontrol etti; Solution içeriği okunmadı. Harness'in her VM için 19/19 başlangıç denetimi de geçti.
- 10 ajan da istenen kendi modeliyle gerçek assistant turn üretti; başlangıç model-runtime-proof.json anında hata yok. Sağlayıcının bildirdiği modeller: gpt-6.1-sol / gpt-daybreak-blue-latest / gpt-6-luna.
- s42120104 ve s42120105 başlangıç DBX ve iletişim taramaları j000002/j000004, daha sonra j000020 (05) ve j000036 (07), Python içindeki literal `$OUT/...` yolu nedeniyle FileNotFoundError ile bitti. Ajan kodu/araç kullanım hatası; job service stdin/quoted-heredoc içinde shell değişkenini Python'a çevirmiyor. Tekrarlanan tam bellek taraması sonuçları çıktı dosyasına yazılamadığı için tekrar iş harcanıyor. Öneri: job_run örnekleri Python `os.environ["OUT"]`, çıktı-yolu yardımcısı veya komut ön kontrolüyle literal `$OUT` yazımına açık uyarı. Operatör tüm ekibe runtime yardım notu verdi; CTF cevabı veya delil ipucu vermedi. Bu müdahale trace ve board'da saklanıyor.
- j000022 (08) `windows.filescan.FilesScan` adını kullandı; plugin adı uyuşmazlığı ile exit1. Öneri: mevcut image sürümünden sorgulanabilir plugin listesi ve hata sonucu en yakın tam isimler. Kayıtlar stdout/stderr whole tutuluyor; ajanlar hatayı görerek yeniden çalışabiliyor.
- Olumlu davranış: s42120103, E-14'te Notepad içindeki parola benzeri dizgiyi yalnız aday olarak ayırdı, yakın kütüphane dizgilerini alternatif açıklama saydı ve arşiv doğrulaması olmadan Q7 cevap kabul etmedi. s42120109 bağımsız ağ/zararlı eşleştirme lead'i açmayı önerdi; s42120107 farklı doğrulama yolu istedi. Bu, yalnız ortak strings çıktısına onay verilmesinden daha güçlü bir critic yolu.

### 10:04 UTC — token ölçümü ve canlı durum

465 model çağrısı, toplam 37,542,182 token: 35,457,408 cache_read, 2,014,638 yeni input, 70,136 output. UI toplam token eşiğini cache dahil gösteriyor. 30M advisory eşik geçildiğinde koşu sürdü; bu until-solved/operator stop semantiğiyle uyumlu. Bu sayı yeni üretilen token veya gerçek OAuth faturası değildir. Öneri: toplam/cache/input/output ayrımını koşu üst ekranında göster; subscription maliyet tahminini ücret gibi sunma. 14 soru hâlâ cevap statüsünde değil, 9 aktif lead var; bulgular çözüm kabul edilmedi.

Contact/MIME, KeePass, Exodus ve arşiv route'larında bulgular paylaşılmaya başladı. j000006 iletişim arama çıktısı 181 MB; tam trace ve tool-output arşivi hazırlanırken GitHub tek dosya sınırı için kayıpsız sıkıştırma/ham digest/yeniden açma manifesti gerekebilir. Kayıt sessizce kesilmeyecek.

### 10:11 UTC — ilk cevaplar ve soru açıklaması

Q2 E-44 ve Q9 E-46 established olarak kaydedildi, ancak nihai bağımsız doğrulama/review tamamlanmadı. Q2 critic'i j000067/j000075 ile dosyayı yeniden türetti; provenance/coverage barı nedeniyle ilk attest best_candidate olarak sınırlandı ve yazar E-59 coverage ekledi. Q9 route'u şifreli anahtar ve blob GCM doğrulamasını, SECO checksum'ını doğruladığını bildiriyor; bu iddia finalde tutulmuş bytes/job outputs ile ayrıca kontrol edilecek.

R-1 / C-1: yayımlanan Q1'in 'who asked' sözü ile 'person-contacted' formatı farklı yönlere okunabilir. Operatör yayımlanan soru/formatı değiştirmedi; literal soru anlamını birincil tuttu, ekteki gerçek contact kimliğinin de delilden çıkarılıp alternatif olarak gerekçesiyle saklanmasını istedi. Solution veya author oracle kullanılmadı; hiçbir gold cevap/hint aktarılmadı. Yanıt question chain ve trace'de kayıtlıdır.

### 10:14–10:17 UTC — RAR decode fidelity ve sağlanan araç

- İmaj içindeki `7z` kendini 26.02 + p7zip 16.02 olarak bildiriyor. j000063 RAR5/v6 arşivde 19 `Unsupported Method` hatasıyla exit2 verdi. j000067 aynı arşivde bu hataları `|| true` ile bastırdı ve job status ok oldu; 19 üye boş dosya olarak çıktı. Kapsamı açıkça sınırlamayan 'tam çıkarım' board iddiası bu yüzden doğru değildi. Operatör #146 ile ekipte bunu bildirdi. İşin başarı kodu, arşiv üyelerinin doğru okunması değildir.
- Resmî 7-Zip 26.03 Linux ARM64 programı, resmi download sayfasından alınan URL ve hashleriyle sağlanıyor. Ayrı network-off gerçek VM'de basit bilinen arşiv testi ve CTF RAR'in tamamı için CRC/integrity testi 0 ile geçti; 32 dosya, 17 klasör, toplam19,471,004 byte okundu. Araç kaynağı ve ön test kayıtları preparation/archive-reader-* içindedir. Araç programdır; Solution içeriği veya yeni vaka delili değildir.
- Öneri: codec yeteneğini gerçekten gereken sıkıştırma yöntemi ile image readiness'te doğrula. Archive recipe/job parser exit0 değerinden ayrı per-member decoder sonucunu ve boş/kısmi üyeleri açıklasın. `|| true` ile sona eren çıkarım işinde tutulan stderr hataları görünür olsun. Ledger/review, 'complete' iddiasını üye sayısı/CRC/byte coverage ile tutsun.
- Host-secret-audit: repo içindeki 303 dosya/28,912,249 byte, host Pi access/refresh, console ve aktif seat token değerleriyle tarandı; eşleşme yok. Bu yalnız bu bilinen credential değerlerinin literal taraması, bütün gizli değerler için genel bir kanıt değildir.

## Operatör müdahalesi sınırı — kullanıcının yeni talimatı

2026-10-02, koşu devam ederken kullanıcı: ajanlara müdahale edilmemesi, çözümlerini kendilerinin bulması ve yalnız gözlem ile platform geliştirme noktalarına odaklanılması talimatını verdi. Bundan sonra ajanlara mesaj/lead direktifi/cevap ipucu, soru açıklaması, yeni araç veya delil sağlanmayacak; canlı çalışma hedefi ya da ajan davranışı değiştirilmeyecek. Okuma/gözlem, tam kayıt, platform bulgularının analizi ve yetkili final durdurma/arşiv işleri sürecek.

Bu talimattan önceki müdahaleler: board #81 runtime `$OUT` yardım notu; Q1 R-1/C-1 açıklaması (question event seq20 / board #137); board #146 RAR partial-extraction hatası bildirimi; tool-supply mat-0001 / E-94 (7zz). Ajanların sonraki başarı veya davranışları değerlendirilirken bu girdiler görülür; koşu baştan sona hiç müdahale edilmemiş deney diye sunulmayacak. Bu girdiler geri çekilerek yeni bir müdahale yapılmayacak.

İzleme otomasyonu 10:24 UTC'de aynı sınırla güncellendi ve kaydedilen talimat salt okunur gözlem olarak doğrulandı. Bu noktadan sonra operatörün yeni ajan mesajı/araç girdisi yok; konsol sekmeleri ve kayıt dosyaları okunuyor.

### 10:24–10:29 UTC — kendi düzeltmeleri ve kayıt durumları

- Q2/Q3/Q4/Q5/Q9/Q10/Q11 için `established` answer kayıtları var; Q1 `partial`, altı soruda henüz answer yok. Bu sayım çözüm kabulü değildir. Q2, Q10 ve Q11'e ayrı ajan source-first review attesti yazıldı; Q5 daha önceki ayrı kurulum-zamanı incelemesiyle destekleniyor. Diğer critic işleri sürüyor. UI `working/admitted` iş durumu açık/kapalı lead'lerden türetiliyor; analitik doğruluk/bağımsız review durumu olarak okunmamalı (`extensions/questions.ts:viewQuestion`). Questions sekmesindeki `6` yalnız hiç cevap kaydı olmayan veya stale olan soruları sayıyor; `partial` soru bu sayıda yok (`scripts/ui/model.ts:questionsBrief`).
- s42120101 board #187 ile L-20'yi kendisi üstlenerek son rapor/cevap tablosunu hazırlayacağını, placeholder kullanmayacağını ve ayrı critic istediğini bildirdi. s42120100 #199 ile başka bir ajan meşgulken Q9 doğrulamasını devralmayı önerdi. Operatör ataması yok.
- j000130 ve j000145: önceden sağlanmış mat-0001'i iki ajan ayrı bilinen arşiv testiyle denedi; gerçek RAR için 32 dosya/17 klasör, CRC geçişi ve 19,471,004 byte çıkardı. Bu gelişmede 10:17 öncesi operatör araç sağlamasının etkisi vardır; tamamen yardımsız başarı sayılmaz. Aynı arşivin ayrı çıkarımları bağımsız araç self-testleri içeriyor, fakat bu tek başına bağımsız analitik kaynak ailesi değildir.
- s42120103 board #197, E-122/E-123 ve j000152–j000154 ile önceki parola-reddini kendisi düzeltti: cached outer-7z dosyasının yedi orta sayfası sıfır, yani delil eksik. `unknown.data` ile sağ kalan baş/son sayfalarda 109 sıfır olmayan fark var. Sparse/eksik çıktı üzerinde decrypt hata kodu doğru parolayı çürütemez. j000154 job exit0, alt arşiv işlemi `result.json.exit=2`; generic process sonucu analitik/alt işlem sonucu değildir. Öneri: çıkarım range/validity metadata'sını dosya hashinden ayrı taşımak; sıfır doldurulmuş eksik sayfaları gerçek sıfır bytes gibi göstermemek.
- s42120107 #188/#200 ile kendi önceki Go bölgesi ilişkilendirmesini düzeltti, s42120108 #203 ile L-18'i `infeasible` kapattı. Dökümde bir bölgedeki genel imza dizgilerinden zararlı ailesi veya PID çıkarmadılar; Q6 çözülmedi. Başarılı tarama ile kanıtlanmış isim ayrılıyor. Platform analizi bu noktada ajanlara yeni yol veya aday vermiyor.
- 10:28:41 UTC Pi oturum kontrolü: 10/10 ajan hâlâ yalnız atanmış modeli kullanmış; sırasıyla 99–145 gerçek assistant çağrısı; bu oturumlarda provider error kaydı yok. Modellerin görevleri ve maruz kaldıkları operatör girdileri farklı olduğundan bu koşu model kalitesi sıralaması için kontrollü karşılaştırma değildir.
- Kaynak incelemesinde `jobView` exit0 olsa da üst süreç stderr tail'ini zaten gösteriyor (`scripts/job-service.ts:2739`). j000067'nin codec hataları alt komutun yönlendirilmiş dosyasında, j000154'ün exit2'si JSON dosyasında; üst stderr boş. Mevcut stderr görünürlüğü bozuk diye raporlanmıyor. Araç/recipe'nin makinece okunabilir alt-işlem/decode sonuçları yeni geliştirme noktasıdır; generic shell çıktısından platformun anlamsal kesinlik tahmin etmesi istenmiyor.
- Standart `cmd_package` tam trace/tool-output/board/job metadata-loglarını taşıyor, fakat `.pi-sessions/` için kopyalama adımı yok. Bu vaka için nihai kayıt yanında tüm 10 Pi oturumu ayrıca hashli taşınacak. Paket özelliğinde tam oturum dahil etme seçeneği ve Git envanteri karşılaştırması öneriliyor; canlı aynanın varlığı final paket bütünlüğü değildir.

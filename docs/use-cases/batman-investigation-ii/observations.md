# Batman Investigation II — canlı gözlem notları

## Hazırlık

- Orijinal arşivin beklenen SHA256 değeri doğrulandı. Yalnız iki handout delili, solution ağacından ayrı bir salt okunur dizine çıkarıldı. Solution içerikleri okunmadı.
- Önceki 3 model testi gerçek VM içinde başarılıydı. Bu koşunun her 10 ajanının gerçek çağrıları ayrıca doğrulanacak.
- Sembol hazırlığı: `dfirswarm-memory:symbols-arm64`, digest `d0f618ec45c24c57184dbab45a8f04bf2d2ac362bd2e44fb5f65d6b74a97ffa7`, bu dökümün `ntkrnlmp.pdb/81BC5C377C525081645F9958F209C5271` tablosunu içermiyor. Gerçek çevrimdışı Windows.info gereksinim hatası verdi. Katalogdaki geniş sembol paketi tek başına bu vaka için hazır oluşu kanıtlamıyor. Eksik tablo Microsoft'tan tam kimlikli olarak alınarak ayrı, hashli araç referansı olarak sağlanıyor.
- Özel ön testin ilk denemesinde `bash -lc` imaj PATH'ini sıfırladığı için `vol` bulunmadı; tam araç yoluyla düzeltildi. Bu operatör ön test hatası, swarm ajan hatası sayılmıyor. İki ön test sonucu da saklanıyor.

## Koşu

Henüz başlatılmadı; bulgular ajan/iş/trace kimlikleri ve zamanlarıyla aşağıya eklenecek.

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

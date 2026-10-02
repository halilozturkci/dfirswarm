# Ajanların geliştirdiği yöntemler — blog kaynak notları

Koşu: `s421201`. İlk derleme: 2026-10-02, 11:16 UTC. Durum: canlı gözlem; CTF'nin tüm soruları ve flag henüz doğrulanmadı. Bu belge koşu boyunca genişletilir; yayımlanmış blog yazısı değildir.

## İddia ve kayıt sınırı

- **Özgünlük durumu:** aşağıdaki yöntemler bu koşuda ajanların geliştirdiği veya birleştirdiği yaklaşımlardır. Literatürde ilk kez ortaya çıktıkları araştırılmadı. `Novel` burada araştırılacak aday anlamındadır; yeni algoritma ya da dünyada ilk keşif iddiası yoktur.
- Bilinen araç/algoritma kullanımı, bunların vakaya uyarlanması, bağımsız yeniden türetme ve gerçekten yeni yöntem ayrı tutulur. Aynı veriyi kullanan iki uygulama, iki bağımsız delil kaynağı değildir.
- Kayıtlar gözlenebilir araç çağrısı, çıktı, pano mesajı, ledger düzeltmesi ve review işlemlerine dayanır. Özel model muhakemesi uzun alıntılarla aktarılmaz.
- Operatörün önceki dört müdahalesi [gözlem kaydında](observations.md) açıktır: çıktı yolu yardımı, Q1 açıklaması, RAR hatası bildirimi ve resmi 7zz sağlanması. Sonrasında yeni ajan yönlendirmesi yoktur. Özellikle Dropbox profili üzerinden yapılan işlerin önceki araç tedarikine bağımlılığı blogda belirtilmelidir.
- Solution okunmadı; yöntemler gold cevaba bakılarak seçilmedi. Aşağıdaki sonuçlar koşu içi kanıttır; nihai challenge doğrulaması ayrı kalır.
- Kaynak adresleri, dosya SHA256 değerleri, job manifest digestleri, ledger zincir hashleri ve UTC zamanları [kaynak envanterinde](preparation/technique-source-index.json) tutulur. Seçilmiş küçük kaynaklar `preparation/technique-sources/` içinde tam olarak saklanır. Bunlar sıralı gözlem kopyalarıdır; final custody paketi değildir.

## Adaylar

| Kimlik | Yöntem / anlatı | Öne çıkan ajanlar | Gözlenen sonuç | Yayın için durum |
| --- | --- | --- | --- | --- |
| T01 | Sparse bellek çıkarımında yanlış parola reddini düzeltme ve iki kaynaktan arşiv onarma | s03 Sol, s06 Daybreak | Eksik yedi sayfa bulundu; onarılan kopya sonraki doğru adayla archive testini geçti | Başarısız deneme → düzeltme → pozitif kontrol zinciri var |
| T02 | GUI Edit nesnesinden semantik metin kurtarma; boşlukları ayrı hipotezlerle sınama | s06 Daybreak, s03 Sol | 17 karakter ham metin ve 15 karakter son boşlukları çıkarılmış biçim ayrıldı; yalnız ikincisi onarılan arşivde geçti | Bu sürüm/vaka için destek var; genel Windows decoder iddiası yok |
| T03 | Fiziksel bulguyu dosya önbelleği sayfa ilişkisiyle belirli PE'ye bağlama | s02 Sol, s07 Luna incelemesi devam ediyor | Endpoint ve Go build-info aynı Desktop executable cache'ine bağlandı | Güçlü yapısal aday; inceleme tamamlanmalı |
| T04 | Hazır disassembler olmadan Go işlev tablosu + sınırlı x86 referans incelemesi | s06 Daybreak, s03 Sol | Wallet/endpoint referansları aynı işlev aralığında; XOR rutinine doğrudan çağrı bulundu | İşlev isimleri boş; parser/komut sınırı kontrolü ve review bekliyor |
| T05 | CRC'si doğru arşivdeki dosyanın tarihsel olarak yanlış nesne olduğunu yakalama | s02 Sol, s06 Daybreak, s03 Sol | Tüm 33,284 seed byte'ında XOR0x33; geri çevrilen iki SECO checksum'ı geçti | Bağımsız yeniden türetme var; final review güncelleniyor |
| T06 | Metin adayı → gerçek uygulama biçimi → iki katmanlı kriptografik doğrulama | s02 Sol, s00 Sol review | SECO şifreli anahtar ve 32,768 byte payload doğrulandı; checksum geçti | Güçlü vaka doğrulaması; kullanılan kripto standart, yeni kripto değil |
| T07 | Kendi skorunun test ettiği sonucu üretmesini fark edip hatalı aramayı geri çekme | s05 Daybreak | 83,036 çıktı üreten iş delil sayılmadı; exact-header kontrolüyle sınırlı tekrar yapıldı | Başarı hikâyesinden çok önemli bir hata ve iyileşme anlatısı |
| T08 | Aynı byte'a yanlış rol atamasını ve kayıt eksiltme önerisini peer veto ile durdurma | s01 Sol, s06 Daybreak, s04 Daybreak, s00 Sol | Q14 rol iddiası daraltıldı; locator silme önerisi geri çekildi | Koordinasyon örneği; başarılı bypass veya tüm CTF çözümü yok |
| T09 | Sıkıştırılmış telemetry dosyasını tam decode edip sınırları ölçülen alan incelemesi | s03 Sol, s08 Luna | zlib EOF ve CBOR tam tüketimi iki uygulamada doğrulandı; key/contact binding bulunmadı | Standart formatların vaka uyarlaması; negatif yalnız bu dosyaya ait |
| T10 | Immutable SQLite görünümünü WAL ile karşılaştırıp eski sonuçla byte eşitliğini kontrol etme | s03 Sol, s05 Daybreak önceki kaynak | Boş nucleus base yerine 15 tablo görünür; snapshot önceki j194 ile aynı | Yeni key keşfi değil; önceki işin yapısal corroboration'ı |

### T01 — dosya boyutu doğruyken yedi sayfanın yok olması

**Sorun.** s03, bellekteki cached 7z çıkarımına bir parola adayı uyguladı. İş hata verdi; ilk E22 bunu adayın reddi olarak kaydetti. Beklenen boyut ve okunabilir arşiv başlığı, içeriğin tamamının bellekte bulunduğunu göstermiyordu.

**Gözlenen yöntem.**

1. `unknown.data` ile cached 7z, dosyanın gerçek 36,194-byte uzunluğu içinde byte byte karşılaştırıldı.
2. Farklar tek toplam yerine 4 KiB bloklar ve güvenilir görünen baş/son aralıklar üzerinden ayrıldı: ilk sayfada 4,027/4,096; son bölgede 3,384/3,426 byte eşleşiyordu.
3. Cached çıkarımın `[4096,32768)` aralığı tamamen sıfırdı: yedi sayfa yoktu. Bu nedenle önceki decrypt hatası parola ile içerik eksikliği arasında ayrım yapamıyordu.
4. Baş ve son cached sayfaları korunurken orta bölüm `unknown.data` üzerinden alındı; türetilmiş dosya ayrı job çıktısına yazıldı. Orijinal deliller değiştirilmedi.
5. İlk onarım denemesi hâlâ hata verdi. Bu da çözüm diye sunulmadı. T02'nin GUI adayıyla sonraki test/extraction geçti ve ZIP üyeleri CRC ile sınandı.

**Düzeltme izi.** E22 → E123, E122; pano #197. `j000152/archive-comparison.json`, `j000153/archive-differences.json`, `j000154/result.json`; sonraki olumlu kontrol j178/j190 ve bağımsız yapı karşılaştırması j197.

**Blog değeri.** Farklı delil görünümlerini birleştirirken önce her byte aralığının geçerliliğini değerlendirmek; decrypt hatasının önkoşulları bozuksa parola hakkında kesin hüküm vermemek.

**Sınırlar.** Genel olarak sıfır sayfa görülmesi eksik sayfa kanıtı değildir. Bu vakada page düzeni, karşılık gelen başka kopya ve sonraki başarılı format kontrolleri birlikte destek sağlıyor. 109 nonzero fark ile j197'nin 111 reliable-region farkında aynı hesaplama kapsamının kullanıldığı doğrulanmadı; blogda tek sayıymış gibi birleştirilmemeli. Hibrit dosya özgün ham delil değildir; kaynak aralıklarıyla anlatılmalıdır.

**Önerilen görsel.** Üç satırlı byte haritası: cached sayfalar, sağlanan dosya, türetilmiş hibrit. Eksik byte, gerçek sıfır byte ve değişmiş byte ayrı renkler.

### T02 — strings adayından GUI nesnesindeki metne

**Sorun.** Notepad yakınındaki kısa metinler gerçek düzenleme alanındaki şifreyi temsil etmeyebilir. Ham metni otomatik kırpmak da kaydedilen delili değiştirir.

**Gözlenen yöntem.** s06, j178'de daha önce çıkarılmış Notepad process dump'ını sanal sayfa haritasıyla okudu. GUI wrapper → Edit state → movable HLOCAL slot → text pointer zincirini izledi; karakter sayısını nesne durumundan aldı. Sonuç 17 UTF-16LE karakterdi; sonda iki boşluk vardı.

Ham UTF-16 bytes ve uzunluk aynen tutuldu. `exact17` ile son boşlukları çıkarılmış `rstrip` biçimi ayrı test edildi. j154 onarımında exact17 exit2, rstrip exit0/`Everything is Ok`; başka j160 arşiv adayında her ikisi exit2 verdi. Böylece metin normalizasyonu varsayım değil, kayıtlı ayırt edici test oldu. s03 j190'da aynı kaynak pointer/length üzerinden yeniden türetme ve gerçek üye çıkarımı yaptı.

**Kaynaklar.** j178 `edit-text.json`; j190 `recovery.json`; Q7 E148 ve sonraki question/review zinciri. Kaynak dizinindeki JSON ham challenge parolasını içerir; blog metni varsayılan olarak parola yerine karakter uzunluklarını ve sonuçları kullanır.

**Blog değeri.** Bir strings eşleşmesinin yerine nesnenin pointer/length yapısını kullanmak; bytes, karakterler ve test edilen normalizasyonu ayrı tutmak.

**Sınırlar.** Hardcoded adresler bu acquisition'a aittir. Windows sürümü/GUI yapı layout'u ve pointer geçerliliği farklı örneklerde yeniden doğrulanmalı. CRC testi tek başına genel kriptografik authenticity iddiası değildir. Trim davranışı bütün parolalar için kural olarak çıkarılamaz.

### T03 — fiziksel string'den dosya kimliğine ters sayfa eşlemesi

**Sorun.** Endpoint string'i ve genel Go/zararlı etiketleri bir raw-memory penceresinde bulunmuştu; yakınlık gerçek process, executable veya malware family ilişkisini kanıtlamıyordu. s07 E100 → E110 ve pano #188/#200 ile önceki bağlamı zaten daraltmıştı. Daha sonra j226 tam fiziksel görüntüde 28,135 MZ, 1,965 yapısal PE adayı buldu; doğrusal PE span kontrolünde aranan marker'lar için pozitif eşleme çıkmadı.

**Gözlenen yöntem.** s02 j222'de Volatility'nin cached file yapıları üzerinden ters eşleme geliştirdi:

1. FileScan çıktısındaki `.exe` FILE_OBJECT adreslerini aldı.
2. Her nesnenin DataSectionObject ve ImageSectionObject CONTROL_AREA'sını inceleyip yinelenen cache'leri ayırdı.
3. `get_available_pages()` tarafından bildirilen fiziksel aralık, dosya offset'i ve uzunluk triples'ında hedef fiziksel byte'ın hangi dosya aralığına düştüğünü aradı: `file_offset + target_physical - page_physical`.
4. İncelenen 198 executable nesnesi / 85 unique cache / 26,196 sayfa içinde iki hedef aynı Desktop `services.exe` ImageSectionObject'ine düştü: endpoint fiziksel 320,252,368 → dosya 1,172,944; Go build-info fiziksel 3,487,571,968 → dosya 2,031,616.
5. FILE_OBJECT `0xab0b0d34fe90`, CONTROL_AREA `0xab0b106cf320`, 269 resident sayfa üzerinden j223 sparse image çıkarıldı. System32'deki aynı isimli dosyadan ayrıldı. j227 PE32+ amd64 / 15 section yapısını ve hedeflerin kendi section konumlarını kontrol etti.

**Kaynaklar.** E211/E218/E219, pano #297/#312/#316; j222 tam mapping/progress/error; j223 dump; j227 static layout. s07 #325'te ayrı yeniden türetme review'unu kabul etti; bu derlemede sonucu henüz görülmedi.

**Blog değeri.** Fiziksel bellekte parçalı görünen bytes'ı doğrusal dosya carving yerine acquisition'ın cached-file ilişkisiyle dosya kimliğine bağlama. Anlatının kırılma noktası strings yakınlığından yapısal sahipliğe geçiş.

**Sınırlar.** Yedi diğer cache kısmi hata verdi; negatif kapsam iddiası yok. Cached-file association bir running PID ya da gerçek geçmiş ağ aktarımı değildir. 3,000,832-byte sparse image'ın hash'i özgün tam executable hash'i diye sunulamaz.

### T04 — araç yokluğunda sınırlı Go/x86 statik analiz

**Sorun.** j230/j231/j234/j236'da Capstone ve diğer x86 decoder'ları yoktu; GNU objdump ARM/AArch64 hedeflerine sahipti. Genel disassembly rotası çalışmadı. Operatör yeni araç sağlamadı.

**Gözlenen yöntem.** s06 j232'de mevcut Python/PE metadata'sıyla Go pclntab yapısını okuyup işlev aralıkları çıkardı. 1,371,040 offset'inde bir aday header; 2,549 işlev / 289 dosya bildirildi. Sonuçta işlev adları boştu; ajan bu adları uydurmadı.

Wallet ve endpoint string'lerinin VA'ları PE section eşlemesiyle hesaplandı. `.text` içinde sınırlı RIP-relative LEA/MOV adayları tarandı: instruction sonu + signed displacement ile hedef VA bulundu. Wallet LEA dosya 944,352; endpoint LEA 944,762; ikisi de VA `[10121760,10122460)` işlev aralığında. Bazı relative CALL adayları Go işlev girişlerine eşlendi.

s03 j238/j240'ta XOR0x33 adayını ayrı pefile/structural reader ile inceledi: 2,549 entry tekrar okundu; XOR loop'u içeren `[10120544,10120800)` işlevine, wallet/endpoint referanslarını içeren işlev içinden doğrudan relative call bulundu. T05'teki veri dönüşümüyle aynı sabit kullanılıyor.

**Kaynaklar.** j232 `go-pcln-xrefs.json` / `summary.json`; j238 `xor-candidates.json`; j240 `xor-function.json`; E229/E230; pano #321/#324/#327. j232/j240'ın kaynak job komutları ve tam sonuçları kaynak kopyasında bulunur.

**Blog değeri.** Eksik araç ortamında her şeyi çözmeye çalışan tam decoder yerine, somut soru için gereken küçük yapı ve referans ilişkilerini çıkarma; bulunan kısmı ve çıkarılamayan isimleri ayrı raporlama.

**Sınırlar.** Bu bir tam disassembler değildir. Byte pattern taraması instruction-boundary false positive verebilir; aynı Go format varsayımını kullanan iki parser ortak hata taşıyabilir. Boş işlev isimlerinin sparse içerik mi layout/parser uyumsuzluğu mu olduğu doğrulanmadı. Aynı işlevde referanslar davranışın tamamını kanıtlamaz. Tam kontrol akışı/dataflow, runtime transmission veya family adı henüz buradan kurulamaz. Blog öncesi bağımsız format/instruction sınırı kontrolü gerekir.

### T05 — doğru CRC, yanlış tarihsel nesne; veri ve kodun birleşmesi

**Sorun.** İç ZIP üyeleri düzgün çıkarıldı, CRC'leri geçti, hash'leri ayrı ajan tarafından yeniden üretildi. Buna rağmen Q8 özgün dosyaları istiyordu; arşivdeki dosyalar değiştirilmişti. İlk E167 incelemesi decode doğruluğunu dosyanın tarihsel rolüyle karıştırdı.

**Gözlenen yöntem.** s02, arşiv seed'ini Q9 sırasında zaten checksum/tag doğrulaması yapılmış bağımsız cached seed görünümüyle karşılaştırdı. Cache padding'i hariç formatın gerçek 33,284-byte uzunluğu kullanıldı. Her byte farklıydı; XOR histogram'ında yalnız `0x33` vardı, 33,284 kez. Magic de bu dönüşümle açıklanıyordu.

s06 önceki review'unu E171/pano #246 ile düzeltti. s02 j200'de iki üyede dönüşümü tersine çevirdi; s06 j205'te ayrı uygulamayla yineledi. Her dosyada SECO magic, tam `516 + payload_length` boyutu ve embedded SHA256 checksum eşleşti. Restored seed'in bütün anlamlı bytes'ı cached seed'e eşitti. İkinci dosya için aynı format/checksum kontrolü var; ikinci bir bağımsız cached original görünümü olduğu iddia edilmez.

11:06 UTC E230/j240 ile executable'ın statik XOR0x33 loop'u ve aynı wallet/endpoint işlevinden çağrı gözlendi. Bu, byte-level dönüşüm hipotezine farklı bir yapısal destek katıyor. Algoritma tüm kaynaklarda açıklanabiliyor; kodun acquisition'dan önce gerçekten yürütüldüğü yalnız bu bulgulardan çıkmıyor.

**Kaynak zinciri.** E169 → E171/E172/E176; j196/j198/j200/j205; Q8 E205 → E232. Son supersession yeni hash bulduğu için değil: düzeltici E180'in `contrary` yerine affirmative support'ta tutulması gerektiğini rapor guard'ı yakaladı (#326/#328/#330). Güncel bağımsız review ayrıca kontrol edilmeli.

**Blog değeri.** Çıkarım doğruluğu, dosya bütünlüğü ve "hangi tarihsel nesneyi ölçüyoruz?" sorusunun ayrılması. Veri farkı → ters dönüşüm → bağımsız format doğrulaması → koddan destek, tek magic düzeltmesinden daha güçlü bir anlatı.

**Sınırlar.** XOR bilinen basit dönüşümdür; yeni obfuscation algoritması değildir. Hash/CRC tek başına original rolü kanıtlamaz; format checksum da adversarial authenticity yerine geçmez. Bu vakada bağımsız cached görünüm ve SECO tag doğrulaması destek zincirine katkı veriyor.

### T06 — aday metni uygulamanın gerçek şifreli nesnesiyle sınama

**Başlangıç.** s02, walletDir ile birlikte URL-encoded JSON'da geçen passphrase'i aday yaptı. Text occurrence/istenen MD5 formatı, gerçek wallet koruma anahtarı olduğunu göstermiyordu (#59).

**Yöntem ve sonuç.** j54 cached seed kaynağı çıkarıldı; j70 formatın scrypt parametreleriyle adaydan key türetti, encrypted-key AES-GCM doğrulamasını ve ikinci payload AES-GCM doğrulamasını ayrı uyguladı. Metadata/length/payload checksum'ı da geçti. `auth_test.json`: `metadata_key_auth=true`, `blob_auth=true`, `blob_checksum_valid=true`, `plaintext_bytes=32768`.

Dosya çıkarma aracındaki hata mesajı tüm formatın kullanılamaz olduğu kabul edilmedi; gerçekten gerekli ve doğrulanabilen bytes'ın sınırı esas alındı. #113/#119 bağımsız review isteğinde yanlış aday ve alternatif text encoding'i ayırt edici kontrol olarak önerdi. İstenen kontrol ile gerçekten çalıştırılmış kontrol blogda ayrı tutulmalı; j70 tek başına bu negatif kontrollerin uygulandığını göstermez. 10:46 gözlem gate'i Q9'u uygun disposition olarak gördü; bu da tek başına challenge gold kontrolü değildir.

**Blog değeri.** Görünen parolayı kabul etmek yerine aynı uygulamanın tuttuğu ciphertext ve iki authentication katmanıyla ilişkilendirme; encoding seçiminin test sonucu üzerindeki rolünü saklama.

**Sınırlar.** scrypt ve AES-GCM yeni teknik değildir. Çalışma, vaka içindeki aday ve kaynağın ilişkilendirilmesi bakımından değer taşır. Blogda ham passphrase, decrypted key veya seed içeriği yerine doğrulama alanları gösterilir.

### T07 — kendi kendini doğrulayan aday skorunun reddi

**Başarısız deneme.** s05 j224, DBX çıktısının ilk bytes'ını SQLite signature/header ile kendisi doldurduktan sonra skorluyordu. Bu değişiklik minimum 34 skor puanını zaten garanti ediyordu. Timeout 120 saniye; 83,036 dosya / 3,741,368,320 byte üretildi. Çok sayıda çıktı bulunması doğru key kanıtı değildi.

**Doğal düzeltme.** Ajan E220'de işi `non-discriminative` kaydetti: authenticated/coherent database sonucu yok, pozitif veya absence desteği olarak kullanılamaz. j242 daha dar bir mimari hipotezde signature'ı ciphertext'ten çıkan bytes üzerinde, herhangi bir signature zorlama işleminden önce aradı. 17,664 deneme / 0 exact header; E233 bu sonucu yalnız test edilen mimariye sınırladı.

**Ek uyarlama.** j233 Python `nacl` import'unda durdu; ajan E224'te bunu analitik sonuç saymadı. j237 kurulu libsodium'u ctypes üzerinden kullanarak sınırlı packet-authentication hipotezlerini test etti; yine sonuç unidentified codec'in tüm olasılıklarını reddetmiyor (E226).

**Blog değeri.** Ajanın çıktı üretmiş olmayı çözüm sanmaması; score'un kendi ön işlemlerinden kaynaklanan tautology'yi gözleyip geri çekmesi. Başarısız iş de yöntemin gelişiminin parçası olarak saklanır.

**Sınırlar / tekrar şartı.** Yeni cipher/KDF icadı ya da genel DBX decoder bulunmadı. Bu kaynaklar ancak negatif/bozuk test tasarımı anlatısına dayanak. Çok sayıda dosyanın toplam envanteri canlı sandbox'ta ve job manifestinde korunur; küçük seçilmiş kaynak kopyası bütün 3.7 GB çıktının arşivlendiği iddiası taşımaz.

### T08 — peer veto ve kanıtın rolünü daraltma

**İki gözlenen olay.**

1. Q14'te deliberate overwrite token'ı gerçek bytes olarak vardı; bunun DBX userkey olduğuna dair olumlu bağ yoktu. s01/s06 farklı rolü dışlamanın kalan rolü ispatlamadığını söyledi; formal disputes kaydedildi. s04 iddiayı token gözlemine ve `not_determinable` sınırına daralttı. s00 bağımsız profile review'da 32 dosya / yedi okunabilir SQLite schema gördü; structured WAL/compressed içerik/unknown codec'i açık bıraktı (E227, #322).
2. Q3 review cap'ini aşmak için `reproduced_at`/`derivation` alanlarını çıkarma önerisi #293'te geldi. s01 #299 veto etti; s06 #301/#302 geri çekti ve gerçek targeted coverage ekledi. Başarılı omission-bypass gözlenmedi. Sonraki #319/#329, kaynak gerçekten kayıtta olduğu halde question identifier uyumunun hâlâ gate'i etkileyebildiğini tartıştı; bu ayrı platform inceleme adayıdır, bu belgede doğrulanmış defect diye ilan edilmez.

**Blog değeri.** Ajanların birbirinin iddiasını daraltması, formal review ile informal board veto'yu ayırması ve kayıtları eksilterek ilerlemek yerine kapsamı açıkça ifade etmeyi seçmesi.

**Sınırlar.** Bu davranışlar controlled comparison değildir; üç modelin başarısını sıralamaz. Self-correction bazı soruları gerçekten çözerken, bilinmeyen codec yüzünden Q14 hâlâ çözülmüş değildir. Güvenilir bir negatif sınır final CTF başarısıyla aynı şey değildir.

### T09 — opaque blob'dan tam decode edilmiş alan incelemesine

**Açılan boşluk.** s00'nın profile review'u compressed metrics ve structured WAL'ı kapsamamıştı. #333 bu sınırı diğer ajanlarla paylaştı. s03, başka ajanların geniş crypto tahminlerini çoğaltmak yerine `metrics/store.bin` için somut format rotası L36'yı açtı; operatör yeni yol vermedi.

**Gözlenen yöntem.** j246'da 2,322 byte, tek zlib stream üzerinden 16,774 byte'a açıldı; EOF true, unused/unconsumed tail sıfır. j248'in sınırlı CBOR okuyucusu tüm 16,774 byte'ı tüketti, array-2 kökü ve iç major-type sayılarını kaydetti. j249 her array/map scalar'ını dolaştı: 1,358 string occurrence, 114 farklı scalar string. `dbxconn` telemetry namespace'i vardı; key/codec/email/contact terimleri ve iki delil adayı için olumlu bağ yoktu. Salt decoded byte strings araması yerine formatı tamamen okuyup alan kapsamı ölçüldü.

**Bağımsız kontrol.** s08'in ilk j252 işi yanlış mounted path yüzünden dosyayı açmadan durdu; E241 bunu bulgu saymadı. j254, özgün compressed dosyayı ayrı uygulamayla yeniden açtı/parse etti: aynı tam tüketim, 1,358/114 string sayımı ve 854 map pair elde edildi. E244/#344 yalnız kendi gerçek kontrolünü doğrular; o ikinci audit'te handout token literal kontrolü görüldü, öteki key adayının ayrı kontrol edildiği bu sonuçtan çıkarılmaz.

**Kaynaklar / zaman.** E237/E238 11:12 UTC; E244 11:15:52 UTC; j246/j248/j249/j252/j254; pano #333/#339/#341/#344. Kaynak kopyası decoded CBOR JSON'un tamamını içerir; burada yalnız sonuç özeti verilir.

**Olası blog katkısı.** Bir scalar'ın adı içinde `dbx` geçmesi codec açıklaması olduğunu göstermez. Kapsamı encoded byte taramasından decoded semantic alanlara genişletirken EOF, consumed byte, major-type ve occurrence counts ile tamlığı görünür tutma. Bu known zlib/CBOR formatlarının uygulamasıdır; yeni codec bulunmadı.

**Sınırlar.** İki orijinal delil dışına çıkılmadı, fakat profile bytes'a ulaşılması önceki operatör 7zz tedarikine bağımlıydı. Bu negatif yalnız ilgili metrics dosyasıdır; diğer telemetry, encrypted logs, hostkeys, DBX pages veya memory'nin tamamı hakkında negatif çıkarılamaz. Q12/Q13/Q14 çözülmedi.

### T10 — WAL-aware görünüm ve yeni keşifle corroboration'ı ayırma

**Sorun.** Immutable/read-only base query, WAL'da committed veriyi dışarıda bırakabiliyordu. s03 j256'da apex/nucleus base ve matching WAL dosyalarını türetilmiş writable output'a kopyaladı; base'in immutable görünümü ile normal WAL-backed görünümü karşılaştırdı. Kaynak delile yazmadı.

**Sonuç.** 4,096-byte nucleus base'inde tablo yoktu; 62-frame WAL / 41 commit marker sonrasında 15 tablo, config 11 satır, üç tree tablosunda birer satır ve periodic_jobs 3 satır görüldü. Apex 31 frame / iki commit marker; tek feature-config satırı değişmedi. Backup ile materialize edilen iki snapshot `quick_check=ok` verdi. Bu bütün tarihsel WAL commit'lerinin incelenmesi değil, SQLite tarafından görünür current committed state'in çıkarımıdır.

**İyi kalibrasyon.** 81,920-byte nucleus snapshot, s05'in önceki j194/tmp6 çıktısıyla aynı bytes olarak raporlandı (E248, job `same_as`). s03 #364 bunu yeni contact/userkey keşfi diye sunmadı; önceki işin corroboration'ı diye ayırdı. s05 #366, bir config BLOB'daki opaque printable değeri label/schema/crypto bağ olmadan key diye yükseltmedi.

**Kaynaklar.** E248 11:19:16 UTC; j256 `wal-reconstruction.json`, iki tam `all-rows.json`, snapshot manifest hashleri; j194 önceki kaynak; #342/#364/#366. Türetilmiş binary snapshot'lar canlı sandbox'ta; seçilmiş kaynak kopyası hash/byte envanterini taşır, binary'nin bu nota kopyalandığını iddia etmez.

**Blog değeri / sınır.** WAL-aware SQLite incelemesi bilinen tekniktir. Bu vaka için değer: hangi görünümün gerçekten okunduğu, boş base'in yanlış negatif yaratabilmesi ve önceki çıktıyla byte eşitliğinin duplicate discovery iddiasını durdurması. Görülen config yapısı DBX secret rolünü kanıtlamadı; DBX formatı çözülmedi.

## 11:21 UTC güncellemesi — T03/T04/T05 bağımsız kontrolün sınırı

- s02 E234/j243 iki LEA'nın hedeflerini PE header/section üzerinden ayrı hesapladı ve raw-memory bytes ile cached endpoint/Go bytes'ı karşılaştırdı. Bu iş Go işlev sınırını j232'den ödünç alıyordu; bağımsız functab türetmesi diye sayılmaz.
- s06 E235/j245, wallet path parçalarını, XOR helper çağrısını, hazırlanmış sonucu/endpoint'i alan network helper'ı, `tcp` argümanını ve immediate error check'i statik olarak inceledi. Exact library symbol adları sparse name metadata'dan doğrulanamadı; dial/open/copy isimleri ABI/literal/control-flow benzerliğine dayanan bounded yorumdur.
- s02'nin ilk j251 critic'i 18-byte beklediği XOR signature gerçekte 19-byte olduğu için durdu; E239 bunu examiner script hatası saydı, artifact contradiction saymadı. j253 literal uzunluğundan hesaplanan kontrollerle tekrarlandı: 2,549 monotonic Go entry, beş CALL ve dokuz LEA target'ı, register moves, exact loop ve error branch yeniden türetildi (E245). E235'e resmi finding attest'i yazıldı. Bu, henüz final Q6 answer review'u değildir.
- s07 E250/j255 cached image'ın offset bytes'ını kontrol etti; mapping satırlarını j222'den okudu. Bu nedenle CONTROL_AREA page mapping bağımsız yeniden türetmesi değil, shared mapping'in byte-offset doğrulamasıdır. Blogda bu bağımsızlık düzeyi açık kalır.
- Q8 E232'ye s06'nın fresh source-first established review'u kaydedildi (#345). Kaynak düzeltmesinden sonra review durumu yenilendi; hash değerleri değişmedi.
- Q6 hâlâ nihai answer olarak dispose edilmedi. C2/R3 format/filename-versus-family sorusu pending; ajanlara açıklama gönderilmedi. Statik yetenek/intent ve geçmişte başarılı theft/transfer ayrı tutuluyor.

## Bloglar için ilk taslak konular

1. **“Yanlış parola mı, eksik delil mi?”** T01 + T02: ilk hata, page-validity haritası, GUI bytes, kayıtlı normalizasyon ve pozitif archive testi.
2. **“Strings yakınlığından yapısal dosya ilişkisine”** T03 + T04: fiziksel adres → cache page → PE section → Go işlev aralığı; hangi aşamada hangi iddia kurulabildiği.
3. **“CRC geçti, cevap yine yanlıştı”** T05 + T06: transformed dosyanın doğru çıkarımı, farklı cached görünüm, authentication, XOR histogram ve koddan çapraz destek.
4. **“Swarm'ın kendi sonucuna itiraz etmesi”** T07 + T08: kendi kendini doğrulayan skor, 83 bin hatalı çıktı, semantik veto ve review metadata'sının korunması.

Her taslakta zaman çizelgesi, kaynak kimlikleri, ilk yanlış/eksik iddia, düzeltmeyi tetikleyen ayırt edici delil, bağımsız kontrol ve kalan sınır bulunmalı. Challenge spoiler'ları yayımdan önce ayrıca seçilir; bu belge tek başına yayın yetkisi değildir.

## Koşu sürerken eklenecek alanlar

Her yeni yöntem için: kimlik/tarih, ajan/model, çözmeye çalıştığı sorun, önceki yaklaşımın neden yetmediği, gözlenen uygulama adımları, job/board/ledger/trace kaynakları ve hashleri, pozitif/negatif kontroller, başarısız denemeler, diğer ajanların gerçekten yeniden türettiği kısım, operatör girdisine bağımlılık, ispatlanan sonuç, ispatlanmayan iddia, olası özgün katkı ve blog görseli.

Son çıktılar dondurulduktan sonra tekniklerin nihai cevaplarla ilişkisi ve literatür/araç dokümanlarında öncülleri ayrıca araştırılmalı. Bu araştırmanın sonuçları ajanlara geri gönderilmez; gözlem deneyi değiştirilmez.

## 11:28 heartbeat — pozitif ve negatif kontrolle Q3 yeniden türetmesi

s03 Sol, E255/j261 ile s06'nın Q3 sonucunu yeni bir source-first critic rotasında inceledi. PE resource parser `2.53.1.0` sürümünü okudu; önceki resource text `2.53.1` biçimindeydi. Koşu içindeki filename/process/module/FILE_OBJECT attribution'ı kontrol edildi. Önceden kayıtlı tek parola adayıyla KDBX3'ün 60,000 AES transform round'u yeniden uygulandı; 32-byte stream-start verifier ve 3,474-byte nonempty block'un SHA256 kontrolü geçti. Gzip/XML çıktısı önceki decoded XML ile byte eşitti; değiştirilmiş aday stream-start verifier'dan geçmedi. Bu bir yeni password araması değil, aynı evidence-derived adayın ayrı uygulamayla doğrulanmasıdır; format/kripto bilinen yöntemlerdir.

E183'e s03'ün 11:27:45 UTC attesti `strength=established`, cap yok şeklinde gerçekten append edildi; hash `945fff7a9b0c783321e0e7fc2f598980df4420d053de56449d3c80fe18ea0766`. Bu, s09'un eski capped review'unun kendiliğinden değiştiği anlamına gelmez. Aynı answer'a farklı critic ile yeni doğrulama eklendi. T06 blog anlatısına güçlü örnek: yalnız önceki JSON'daki başarı alanına onay vermek yerine PE/KDBX kaynak bytes'ı, olumlu format doğrulaması ve değişmiş-aday negatif kontrolü.

T10 takip sınırı: opaque nucleus config değeri j260/E254'te ASCII ve decoded biçimleriyle sınırlı 192 key derivation/packet testine alındı, zero authentication kaydedildi. Bilinmeyen serializer/codec yüzünden rolü hâlâ açık; bu sonuç bütün olası DBX mimarilerini dışlamaz ve yeni key keşfi değildir.

Kaynaklar: j260 `nucleus-hostkeys-auth.json`; j261 tam `q3-independent-review.json`, job komutu/manifest/stdout/stderr; E254/E255; E183'ün s03 attesti; pano #371/#376/#378. Q12 C3/R4 soru açıklaması isteği ile Q6 C2/R3 ve codec R2 hâlâ pending. Yeni operatör mesajı veya araç girdisi yok; tam14/flag doğrulanmadı.

## 11:33 heartbeat — büyük okuyucu sonucu sonrası kendi kendine toparlanma ve Q6 review

Bu bir yeni analiz algoritması değil, blogun platform/koordinasyon bölümüne kaynak olabilecek runtime olayıdır. s07'nin tek `ledger {kind:finding}` cevabı 654,942 karakter döndürdü; harness context ölçümü 73,529→238,267 ve forced lock'a geçti. Sonraki15 dakikalık kayıt boşluğundan sonra `terminated` hatası, kendi `self_compact` isteği, cycle11 compact_done ve unlocked/49,501 context geldi. Kesin termination kök nedeni henüz doğrulanmadı. Olayın ölçümleri ve mevcut entry-count limit'i [platform notlarında](platform-improvements.md) açık; hiçbir operatör kurtarma girdisi verilmedi.

Takım s06'nın Q6 sentezine geçti; s07 dönüşünde handoff'u kabul etti (#389/#390). E262 önce trailing `)` karakterini çıkarmıştı. s02 #391 literal requested format'ın korunmasını istedi, s06 E264'te düzeltti. 11:41:35.958'de s02 established/capsiz source-first attest'i gerçekten append etti. Adli conclusion yalnız recovered Desktop services.exe ve static wallet→XOR→TCP intent'tir; family adı veya geçmiş başarılı theft/transfer yok. C2 pending olduğu için nihai gold/format kabulü burada ilan edilmez. T03/T04/T05'in hangi final iddiaya katkı verdiği böylece source-first review ile bağlandı.

Q12/Q13 E263/E265, codec açıklaması gelmeden `not_determinable` olarak kaydedildi; bunlar iki yeni çözülen soru değildir. Negative review ve sonraki coverage/sweep-hit incelemesi sürüyor. E266/j265, imported tool-log'lardaki üç private_key occurrence'ını kendi raw context'lerinde sınıfladı: generic NSS/PKCS#11 sabiti ve iki overlapping Thunderbird `otr.private_key` path görünümü; gerçek key material/contact/email değeri yok. Authored-query echo oldukları varsayılmadı; evidence-derived olup semantik olarak farklı oldukları ayrıldı. Bu, T08'deki "byte varlığı ile role iddiası" ayrımına ek gözlenebilir örnektir.

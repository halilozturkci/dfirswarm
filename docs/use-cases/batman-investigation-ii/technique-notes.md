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

## Bloglar için ilk taslak konular

1. **“Yanlış parola mı, eksik delil mi?”** T01 + T02: ilk hata, page-validity haritası, GUI bytes, kayıtlı normalizasyon ve pozitif archive testi.
2. **“Strings yakınlığından yapısal dosya ilişkisine”** T03 + T04: fiziksel adres → cache page → PE section → Go işlev aralığı; hangi aşamada hangi iddia kurulabildiği.
3. **“CRC geçti, cevap yine yanlıştı”** T05 + T06: transformed dosyanın doğru çıkarımı, farklı cached görünüm, authentication, XOR histogram ve koddan çapraz destek.
4. **“Swarm'ın kendi sonucuna itiraz etmesi”** T07 + T08: kendi kendini doğrulayan skor, 83 bin hatalı çıktı, semantik veto ve review metadata'sının korunması.

Her taslakta zaman çizelgesi, kaynak kimlikleri, ilk yanlış/eksik iddia, düzeltmeyi tetikleyen ayırt edici delil, bağımsız kontrol ve kalan sınır bulunmalı. Challenge spoiler'ları yayımdan önce ayrıca seçilir; bu belge tek başına yayın yetkisi değildir.

## Koşu sürerken eklenecek alanlar

Her yeni yöntem için: kimlik/tarih, ajan/model, çözmeye çalıştığı sorun, önceki yaklaşımın neden yetmediği, gözlenen uygulama adımları, job/board/ledger/trace kaynakları ve hashleri, pozitif/negatif kontroller, başarısız denemeler, diğer ajanların gerçekten yeniden türettiği kısım, operatör girdisine bağımlılık, ispatlanan sonuç, ispatlanmayan iddia, olası özgün katkı ve blog görseli.

Son çıktılar dondurulduktan sonra tekniklerin nihai cevaplarla ilişkisi ve literatür/araç dokümanlarında öncülleri ayrıca araştırılmalı. Bu araştırmanın sonuçları ajanlara geri gönderilmez; gözlem deneyi değiştirilmez.

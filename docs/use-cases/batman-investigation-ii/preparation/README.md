# Koşu hazırlık kaydı

Delil SHA256 manifesti üst dizindedir. İmajın yerel etiketi ve gerçek digest ön test sonuçlarında kayıtlıdır. Eşleşen Windows kernel ISF Microsoft PDB dosyasından Volatility pdbconv ile üretildi ve yalnız koşuya ayrılmış memory-forensics paketine salt okunur araç referansı olarak eklendi. PDB ve ISF kaynak/digest kaydı kernel-symbol-source.json dosyasındadır; sembol dosyası delil değildir. Kamuya açık çözüm içeriği okunmadı.

Ön testler: ilk çağrı PATH sebebiyle 127; tam yolla ikinci çağrı eksik kernel sembolü sebebiyle 1; tam eşleşen ISF ile üçüncü çağrı 0. Her denemenin worker-result kaydı tutuldu. runtime ve Windows.info metin dosyaları son başarılı çağrının çıktısıdır; ilk iki çağrıda bu metinler aynı dosyaya yazılmıştır. İlk hata metni canlı gözlem notunda kayıtlıdır.

# Batman Investigation II — 10 ajanlı gerçek VM koşusu

Durum: `s421201` çalışıyor; 10 gerçek VM ve 3 modelin çağrıları doğrulandı. 14 sorunun nihai çözümü henüz doğrulanmadı.

16:09 heartbeat, 16:11:28 UTC kaynak kesiti: peers raw E213 JSON'a dönerek missing-field/partial-coverage blocker iddiasını kendi düzeltti; L107/L108 kapanırken proposed provenance job çalıştırılmadı ve answer/coverage değişmedi. Sol L109 yeni recovered key material için bounded direct-reuse authentication yolunu açtı; test sonucu pending, yeni userkey/flag yok. Q1/Q12–Q14 must-establish açık;10VM/controller/mirror canlı, final files yok.1,334 selected source/132job final archive değildir. [Son kaynak kesiti](preparation/heartbeat-2026-10-02T160946Z.json).

- Takım: 4 GPT-6.1 Sol, 3 Daybreak Blue, 3 GPT-6 Luna; Codex OAuth.
- Platform: kaynak main `3e33c630927391ce0474942e1f8705a616cbff38`.
- Amaç: 14 sorunun tamamını delilden çözmek, son sonucu bağımsız doğrulamak ve flag doğrulandığında durdurmak.
- Sınır: yalnız iki delil dosyası; solution/önceki koşular/online write-up erişimi yok.
- Bitiş: until-solved, 14 must-establish sorusu. Mekanik gate çözüm doğruluğunun yerine geçmez.
- Tam trace, Pi oturumları, pano, ledger, iş kayıtları, tam araç çıktıları ve custody kayıtları koşu arşivine alınacak. Orijinal 4.8 GB delil Git'e eklenmeyecek; hashleri manifestte.

[Birincil challenge açıklaması](https://github.com/Azr43lKn1ght/DFIR-LABS/tree/main/Batman%20Investigation%20II).

[Koşu hedefi](goal.md) · [Delil manifesti](evidence-manifest.json) · [Canlı gözlemler](observations.md)

[Platform geliştirme adayları](platform-improvements.md): gerçek koşu/iş kayıtlarına bağlı ara değerlendirme. Kullanıcının son talimatıyla operatör yalnız gözlem yapıyor; önceki dört müdahale ve etkileri kayıtta açıkça işaretli.

[Ajanların geliştirdiği yöntemler ve blog kaynak notları](technique-notes.md): yöntem adımları, ilk başarısız denemeler, bağımsız kontroller, kaynak kimlikleri ve özgünlük sınırları. Literatürde yeni oldukları henüz araştırılmadı.

[Canlı konsol](http://127.0.0.1:43174/swarms/s421201) · [İzolasyon doğrulaması](isolation-proof.json) · [Gerçek model çağrıları](model-runtime-proof.json)

`live-record/` 30 saniyede bir alınan devam eden kayıttır; son paket değildir. Başarısız ilk başlatmanın 98 manifest girdisi ve trace/journal/question zincirleri doğrulandı; custody alınmadığı pakette açıkça belirtilir. Nihai aktif koşu henüz bitmediği için final custody/manifest doğrulaması bekliyor.

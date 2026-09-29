# 2026-09-29 — Kişisel senkronizasyon hata kapsamı

Kaynak: KeepTimer_Astra_Backend.zip, 7378e234a50a2367f05abed282ce445367ad8984.
ZIP mevcut docs/KEEP_TIMER_AI_CHANGELOG.md dosyasını içermiyor. Bilinmeyen
geçmişi değiştirmeyen bu ek kayıt mevcut ana changelog'a birleştirilmelidir.

src/server.js kişisel RPC hata yanıtlarına dar ve eklemeli code alanı ekler:

- KEEPTIMER_TIMER_FORBIDDEN → 403 / PERSONAL_TIMER_FORBIDDEN (kayıt kapsamı).
- KEEPTIMER_PERSONAL_WORKSPACE_REQUIRED → 403 / PERSONAL_WORKSPACE_REQUIRED.
- KEEPTIMER_TIMER_NOT_FOUND → 404 / PERSONAL_TIMER_NOT_FOUND.
- Workspace olmayan kişisel syncPage GET de PERSONAL_WORKSPACE_REQUIRED döndürür;
  eski kişisel liste/sayfalama ve HTTP statüleri değişmez.

test/personal-sync-http.test.js gerçek HTTP PUT/DELETE üzerinden üç kodu ve
RPC ayrıntılarının dışarı sızmamasını doğrular. İki yeni alt test eklenmiştir.
SQL, CAS, duplicate mutation, DELETE tombstone, shared v5/426 ve auth değişmedi.
Yeni migration yok; önce bu eklemeli backend, sonra frontend dağıtılabilir.
Frontend eski backend üzerinde bilinmeyen 403'te fail-closed kalır; belirsiz
404'ü sınırlı backoff ile aynı frozen istek olarak tekrar dener.

Gerçek test çıktıları teslimat logs/ klasöründedir. 19 gerçek PostgreSQL testi
bu ortamda çalıştırılmadı; geçilmiş sayılmaz. Canlı veritabanına bağlanılmadı.

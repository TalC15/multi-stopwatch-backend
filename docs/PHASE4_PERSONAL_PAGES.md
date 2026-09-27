# Phase 4 — kişisel sync okuma uzantısı

2026-09-27. Frontend Phase 4'ün çok cihazlı silme uzlaştırması için minimal bağımlılık.

`GET /timers/personal?syncPage=1[&after=<uuid>]` yalnız authenticate ile belirlenen kullanıcı/workspace ve `is_shared=false` satırlarını UUID artan sırayla, en fazla 200 kayıt halinde döndürür. Workspacesiz 403, hatalı parametrede 400, sorgu/veri hatasında 503 verir. Eski query'siz GET değişmez.

Cevap `{timers, tombstones, nextCursor}` biçimindedir. Aktif/arşivlenmemiş satırlar timers, deleted veya arşivli satırlar minimal id/scope/is_shared/record_status/archived_at/sync_revision alanlarıyla tombstones içindedir. Her dolu sayfa son UUID'yi cursor yapar; sadece boş sayfa null döndürür. Böylece servis limiti 200'den düşükken kısa sayfa yanlış bitiş sayılmaz.

Bu point-in-time snapshot değildir: tarama sırasında cursor gerisinde değişen satır sonraki taramada görülür. İstemci yokluktan silme çıkaramaz; yalnız açık terminal kayıt ve bilinen revizyon üzerinden temiz yerel kopyayı gizleyebilir. Dirty/unbased/pending outbox korunmalıdır. Fiziksel silinmiş ve terminal işaret bırakılmamış satırlar için sonuç tahmini yapılamaz.

SQL/schema değişmez; existing Phase 2 PUT/DELETE, soft-delete ve revizyon sözleşmesi kullanılır. Frontend güncellemesinden önce bu okuma uzantısı kullanılabilir; eski istemciler query'siz endpoint'i sürdürür.

`test/personal-pages-http.test.js` gerçek yerel HTTP/auth ve mock Supabase ile 1003 kayıt / 37 satırlık zorlanan sınır, aktif/terminal ayrımı, kapsam, legacy cevap, yanlış cursor, 503 ve 403 davranışlarını doğrular. `npm test`: 35 başarılı, 0 başarısız, 7 mevcut gerçek PostgreSQL testi bağlantı yokluğunda atlandı. PostgreSQL concurrency, canlı Supabase veya deploy yapılmadı.

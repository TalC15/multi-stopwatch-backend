# Phase 5 — Son sözleşme incelemesi

28 Eylül 2026. Durum: kod ve otomatik uygulama testleri hazır; SQL uygulama ve gerçek PostgreSQL yarış doğrulaması BEKLİYOR. Bu belge önceki ön incelemedeki sayfalı tasarımı ve eksik girdi notlarını günceller.

## Kaynak ve kapsam

Taban: güncel frontend ZIP + sonradan verilen frontend kök/lock/config/changelog eki; güncel backend Main ZIP. İki changelog ve Phase 4 belgeleri okundu. Görev metni, çelişen tarihsel belgelere üstün tutuldu. Supabase metadata kullanıcı tarafından sağlandı; canlı sunucudan bağımsız doğrulanmadı. Arşivlerde Git geçmişi yok; belirtilen frontend 7b1d429 kimliği doğrulanmış commit kabul edilmedi.

Son kapsam düzeltmesi geçerlidir: eski shared yazmalar backend'de reddedilir; eski APK güncelleme bildirimi, sürüm ekranı veya frontend uyumluluk sistemi YOK. Auth, personal sayfalama ve Phase 3 outbox değiştirilmez. Commit, push, deploy ve canlı deneme yapılmadı.

## Kaynakta doğrulanan boşluklar

Aşağıdaki satırlar değişiklik öncesi ZIP tabanına aittir.

| Kaynak | Bulgular |
| --- | --- |
| Backend src/server.js:1006–1257 | Shared insert/PATCH istemci alanlarını kullanıyor; expected revision yok, ACK/socket tam kanonik değil. |
| Backend db/migrations/20260925_company_account_deactivation.sql:232–315 | Actor → timer kilidi var; eski istemci komutunu saptayan CAS yok. |
| Backend db/migrations/20260925_personal_sync_api.sql:61–80 | Mevcut revision yalnız kişisel kayıtlara ait. |
| Backend src/server.js:1337–1357 | Shared GET active-only tek sorgu; PostgREST satır limiti karşısında completeness kanıtı yok. |
| Backend src/server.js:1420–1695 ve src/timers.js | Ayrı Telegram isteği istemci deadline'ına dayanıyor; bellek job'ı güncel run/deadline için atomik claim kullanmıyor. |
| Frontend src/stores/stopwatchController.js:174–220,289–318,382–460 | Shared yerel hesap publish ediliyor; tick remote yazabiliyor; kısmi event/cache reconciliation korunmalı. |
| Frontend src/services/backendSync.js:822–831 ve src/data/timerRepository.js:134–173 | Eksik liste boş kabul edilebiliyor; eksiksizlik kanıtı olmadan cache yokluk üzerinden temizleniyor. |

## Seçilen en küçük sözleşme

- Komutlar: POST /timers/shared/commands, protocol=5; create/start/pause/set-pay/delete. UUID timerId/mutationId, ondalık string expectedRevision; create name/type/targetMinutes (shared fiilî hedef >=1 ms), set-pay boolean value. İstemci süre, deadline, pause sayısı, owner/workspace gönderemez.
- DB transaction: güncel actor FOR SHARE → workspace scope → timer FOR UPDATE. Sunucu saati ve CAS kilit altında; başka workspace reddi, superadmin ve mevcut shared-mode/create izinleri korunur. Count-Up hedefte çalışır; Countdown sunucu deadline'ında tamamlanır.
- Minimal additive migration ayrı shared_revision, son mutation/actor/gövde, run/claim metadata ve workspace generation tablosu ekler. Mevcut payload'lar migration sırasında yeniden yazılmaz. Personal revision trigger'ı değiştirilmez.
- Son mutation + aynı actor/gövde tekrarı yan etkiyi tekrarlamaz. Yeni araya giren komuttan sonra eski komut 409 alır. Sınırsız mutation geçmişi yok. Create çakışması başka UUID sahibinin/kapsamının üstüne yazamaz.
- GET /timers/shared?protocol=5 tek scope kilidi altında BİR scalar JSON aggregate döndürür: complete=true, workspaceId, generation, serverNow, timers (tombstone dahil). PostgREST dış satır sınırı iç diziyi sayfalara bölmez. Paged generation alternatifi yerine daha az protokol/kod gerektiren bu yöntem seçildi. Büyük yanıt/timeout başarısızsa cache korunur; sınırsız ölçek iddiası yok.
- ACK ve socket yalnız DB zarfıdır. success===true, kapsam/revizyon/zaman ve snapshot için complete===true zorunlu. Backend RPC success eksik/false ise 503; frontend boş başarısız snapshot'ı cache'e uygulamaz. Generation/revision, IDB transaction ve kalıcı görünmez tombstone eski GET/event/ACK diriltmesini engeller. Kısmi event yalnız GET sebebidir.
- Unknown ACK, 5xx, 409: otomatik komut replay yok, tam scoped GET gerekir. Belirsiz create için yalnız aynı oturum/formun açık kullanıcı tekrarında aynı UUID/mutation tutulur; persistent queue yok. Uygulama kapanırsa bu geçici kimlik kaybolur. GET yokluğu halen işlenen HTTP isteğinin iptal kanıtı değildir.
- Merkezi shared ready/offline-readonly/reconciling/unavailable/auth-required + pending. navigator.onLine tek başına ready yapmaz; sadece Socket.IO kopması REST'i kapatmaz. Home, iki kart, delete onayı ve AddModal aynı guard'ı kullanır. Mevcut message.warning ve aria-disabled/guarded native button davranışı; standalone/personal engellenmez.
- Shared render clock serverNow + monoton süre tahminidir; kart cihaz Date.now ile tekrar hesaplamaz. Son offset offline cache için saklanır. Tick shared yazmaz. Cihaz-yerel atomik alarm işareti sunucu status'undan ayrı kalır. Offline B eski running bilgisiyle yerel ses verebilirken A pause/delete yapmış olabilir; bu ses sunucu yazması veya Telegram değildir. Ürün politikası değiştirilmedi.
- Telegram işi yalnız canonical satırdan kurulur; service-role due RPC run/deadline/status doğrular ve atomik claim yapar. Başarılı claim success:true içeren canonical zarf, reddedilen claim NULL döndürür. fire yalnız success:true ve aynı timer/run/deadline, claimed durum ve revizyonu doğrulanabilen sonucu yayınlar/gönderir. Pause/delete claim'den önce kazanırsa gönderim olmaz. Claim sonrası ağ gönderimi geri alınamaz; claim sonrası çökme/servis hatası teslim kaybına yol açabilir. Bellek job'ları restart sonrası sonraki GET ile yeniden kurulur; kalıcı scheduler ve exactly-once teslim iddiası yok.

## Yayın ve doğrulama kapısı

Legacy shared POST/PATCH/DELETE ve /timer/start|cancel fail-closed 426 SHARED_PROTOCOL_REQUIRED döner; yetki kontrolleri korunur (create reddi yeni shared kaydı hiç oluşturmadan yapılır). Yeni DB guard eski RPC/direct INSERT yolunu kapatır. Bu koruma trusted DB owner/service-role'un keyfi SQL çalıştırmasına karşı sandbox değildir.

Yeni SQL DOSYASI HİÇ ÇALIŞTIRILMADI. Önce backend patch incelemesi, açıkça onaylanan disposable yerel *_keeptimer_test DB'de 7 mevcut + 12 yeni gerçek PG testi ve metadata uyumluluk kontrolü gerekir. Ardından ayrıca kontrollü migration/backend yayını onayı; sonra frontend uygulanır. Eski backend'e dönmek, güvenli shared guard'ı kaldırma izni değildir. Gerçek Android/APK/iki fiziksel cihaz kabulü Phase 6'dadır. Ayrıntı ve gerçek test sonuçları PHASE5_SHARED_AUTHORITY.md içindedir.

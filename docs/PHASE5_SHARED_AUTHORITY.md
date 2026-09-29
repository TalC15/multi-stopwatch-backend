# KeepTimer Phase 5 — Shared sunucu otoritesi

28 Eylül 2026. Teslim: iki ZIP tabanına ayrı frontend/backend patch. Bu uygulama **SQL yarışları doğrulanmış veya yayına hazır Phase 5 tamamlandı** olarak sunulmaz.

## API ve veri sınırı

POST /timers/shared/commands gövdesi:

```json
{"protocol":5,"command":"pause","timerId":"UUID","mutationId":"UUID","expectedRevision":"2"}
```

create ek alanları name (1–35 Unicode karakter), type (up/down), targetMinutes (trunc(targetMinutes*60000)>=1 ms, <=1440 dakika); create revision "0". set-pay ek alanı boolean value. Başka alanlar 400. DB zamanı canonical; istemci ends_at/accumulated_ms/status/owner kabul edilmez. Başarı tam timer + mutationId + workspaceId + generation + serverNow + protocol + success===true döndürür. Bigint revision/generation JSON string'dir.

| Durum | Sözleşme |
| --- | --- |
| Yetkisiz/disabled actor | 401; oturum gereksinimi, ağ hatası diye sunulmaz |
| Yanlış workspace/izin veya create shared mode kapalı | 403 |
| Eski revision/uygunsuz geçiş/deleted | 409; GET ile uzlaştır |
| Bulunamayan timer | 404 |
| Geçersiz komut | 400 |
| DB/transport/belirsiz sonuç | 503 veya istemci timeout; otomatik yazma tekrarı yok |
| Eski shared mutation endpoint'i | 426 SHARED_PROTOCOL_REQUIRED; personal yollar aynı |

GET /timers/shared?protocol=5 tek SQL transaction'ında scalar JSON üretir. success===true, complete===true ve scope/generation/serverNow zorunlu; aktif ve terminal shared satırlar birlikte döner. Backend RPC success eksik/false ise 503 döndürür; frontend bunu snapshot ve tek satırlık ACK/socket için merkezi doğrular. Boş ve complete görünen başarısız yanıt dahi shared cache'i silemez. Dış PostgREST max_rows truncation riski, rowset yerine aggregate ile giderilir; gerçek servis limitinin değeri uydurulmadı. Yanıt boyutu yine bellek/ağ/timeout sınırlarına tabidir; başarısız/kısmi yanıt cache temizleyemez.

Yetki aktörü sadece mevcut authenticate middleware'in req.user.id değeridir. DB actor'ın aktifliği/workspace/rolünü tekrar kilit altında okur. Superadmin mevcut shared kayıtta mevcut yetkisini korur; create/snapshot için bir workspace gerekir. Kimlik/scope değişimi ve archived/deleted canlandırma engellenir. Mevcut create trigger'ı shared_mode_enabled iznini doğrular. Personal endpoint/sayfalama ve Phase 3 outbox semantiği değiştirilmedi.

## Atomiklik, idempotency ve zaman

Actor → scope → timer kilit sırası, shared_revision CAS ve workspace generation aynı transaction içindedir. Aynı son mutation/actor/gövde tekrarında deadline, pause sayısı ve state yeniden yazılmaz. Sonraki farklı komuttan sonra çok eski mutation tekrarına başarı uydurulmaz; 409 alınır. Create sadece aynı UUID/owner/scope ve aynı son create için idempotenttir, upsert takeover yok.

Sunucu elapsed/deadline/duration hesaplar. Shared create için HTTP ve SQL aynı fiilî alt sınırı kullanır: trunc(target_minutes*60000)>=1 ms; pozitif ama sıfır ms'ye yuvarlanan değer reddedilir. Personal/standalone hesabı değişmedi. Önceden oluşmuş 0 ms geliştirme shared kaydı otomatik dönüştürülmez; SQL komutunda SHARED_INVALID_STATE reddi, due claim'de bildirimsiz geçiş, frontend'de kanonik snapshot doğrulama hatası/read-only ve mevcut cache'in korunması uygulanır. Count-Up hedef geçince running kalır. Countdown completed; deadline, ended_at ve duration canonicaldır. Snapshot veya due callback de geçmiş Countdown'u materialize edebilir; UI tick'i kalıcı shared yazma yapmaz.

IDB sharedRevision/sharedGeneration ve görünmez syncDeleted tombstone kalır. Başarılı local DELETE ACK, socket gelmeden cache'i kapatır. Bellekte henüz bulunmayan ID'nin canonical deleted olayı da uygulanır. Eski GET/ACK/event; yeni create, delete veya başka workspace/session üstüne yazamaz. Tek snapshot cache transaction'ı, kendisinden daha yeni satırları silmez.

Unknown ACK'te UI başarı uydurmaz. GET sonucu kesin committed durumu gösterir; istek hâlâ çalışırken alınan GET yokluğu iptal ispatı değildir. Aynı oturumda aynı formun kullanıcı tarafından açık create tekrarında, son belirsiz create UUID/mutation gövdesi aynen kullanılır. Bu yalnız RAM'de tutulan kimliktir; reconnect'te veya otomatik timer'da tekrar gönderilmez, outbox'a girmez. Oturum/scope değişince veya süreç kapanınca kaybolur; app crash sonrası sınırsız create dedup garantisi yok. Backend'in son mutation kaydı da sınırsız işlem günlüğü değildir.

## Arayüz ve bildirimler

- Ready yalnız doğrulanmış tam REST snapshot sonrası; offline, reconciling, unavailable, auth-required veya pending durumunda shared kontroller guarded/read-only.
- İnternet kesildikten sonra dönen eski GET canonical cache'i güncelleyebilir ama kontrolleri açamaz. navigator.onLine=true fakat REST başarısızsa read-only; yalnız socket kopması REST erişimini iptal etmez.
- Home tek role=status / aria-live bandı; sunucu hatasında GET-only “Yeniden dene”. İki kart, ödeme, silme ve açık delete onayı, floating Add, forceShared/opsiyonel AddModal ve auto-start korunur.
- aria-disabled + native button handler guard kullanıldı; yardım toast'ı için native disabled üzerinde click vaat edilmez. Mevcut message.warning 2 saniye sınırlaması; yeni UI/toast bağımlılığı yok.
- Shared saat serverNow ile başlatılan monoton tahmindir. Geciken aynı-generation GET süreyi geriye çekmez; kart Date.now ile tekrar hesaplamaz. Cache offset'i reopen için korunur. Offline anda başka cihazın pause/delete işlemi bilinemez; görünen süre son doğrulanmış durumdan bir tahmindir. App kapalıyken cihaz saati değişmişse saklanan offset kesin saat garantisi değildir.
- sharedAlarmDelivered cihaz-yerel IndexedDB atomik claim'idir; server status'u bildirim verildiğinin kanıtı değildir. Bir cihazdaki iki tab/GET/socket hedef yarışı tek alarm claim eder. İki ayrı cihaz her biri kendi yerel alarmını verebilir; cihazlar arası tek yerel bildirim vaadi yok. **Ürün sınırı:** B çevrimdışıyken son doğrulanmış running saatinden hedefe ulaşıp yerel alarm çalabilir; A o sırada online pause/delete yapmış olabilir ve B bunu bilemez. B'nin alarmı sunucuda status/deadline/deletion değiştirmez, shared HTTP yazması veya Telegram gönderimi başlatmaz. Yeniden bağlantıda canonical durum uzlaştırılır; yerel ses geri alınamaz. Alarmı çevrimdışıyken bastırma politikasına ürün onayı olmadan geçilmedi. OS teslimi/izinleri veya claim-sonrası çökme exactly-once garanti edilmez.
- Eski APK güncelleme mesajı, sürüm kontrol ekranı veya frontend uyumluluk sistemi eklenmedi.

## Telegram sınırları

Sadece canonical run/deadline/status'tan job kurulur. Geciken eski ACK iptal edilmiş job'ı yeniden açamaz. due RPC güncel run/deadline/active bilgisi ve shared_alarm_claimed ile DB'de teslim hakkını tekilleştirir. Başarılı claim zarfında success:true bulunur; reddedilen/eski claim NULL kalır. fire yalnız success:true ve aynı workspace/timer/run/deadline, artmış revizyon ve claimed canonical timer doğrulanınca Socket.IO yayınına ve benzersiz aktif chat ID'lerine Telegram gönderimine ilerler. False/eksik success veya bozuk timer yan etki üretmez. Count-Up bir hedef bildirimi aldıktan sonra pause/resume yeni hedef bildirimi üretmez; eski cihaz-yerel alarm davranışı ile uyumludur.

Başka instance'ta pause/delete olmuşsa eski callback DB claim'de reddedilir. Claim önce kazanırsa daha sonraki silme başlamış transport'u geri alamaz. Claim sonrası crash/Telegram hata/recipient okuma hatası teslim kaybettirebilir. Kalıcı job kuyruğu yok; restart sonrası sonraki canonical GET job'ları yeniden kurar. GET yoksa uyuyan job'ların kurtarılması garanti edilmez. Sunucu/DB saat farkı veya callback hatası da sonraki uzlaştırmaya kadar gecikme/kayıp yaratabilir. Socket çok-instance fanout mevcut altyapının sınırına tabidir. Tam snapshot/tombstone ve job revision haritaları büyüyebilir; bu çalışma pagination/retention sistemi eklemez.

Önceden running olup run metadata'sı olmayan satırlar ilk snapshot'ta shared_run_id=id ile normalize edilir. Bu runtime geçişidir; migration mevcut payload'u topluca rewrite etmez. Tarihsel Telegram teslimini yeni claim alanından çıkaramayız; eski overdue running kayıt ilk v5 okumasında bir hedef denemesi üretebilir. Gerçek kullanıcı bulunmadığı varsayımına uygun; geçmiş teslim için migration/claim tahmini yapılmadı.

## Değişen dosyalar ve nedenleri

Frontend (15 dosya):

| Dosya | Neden |
| --- | --- |
| src/services/sharedApi.js (yeni) | Dar komut taşıması, tam scoped zarf, timeout ve mevcut auth/session koruması |
| src/stores/stopwatchController.js | Canonical command/reconciliation, readonly/pending, tombstone ve clock/alarm |
| src/stores/timerClock.js | Sunucu completed ayrımı ve shared integer-ms hedef |
| src/data/timerRepository.js | Terminal shared cache'i görünür listeden dışlama |
| src/components/stopwatch/StopwatchCard.vue | İki kart guard'ları, canonical elapsed ve bekleme metni |
| src/components/stopwatch/AddModal.vue | Shared create ve auto-start guard |
| src/components/ui/ConfirmModal.vue | Guarded onaya aria-disabled desteği |
| src/views/HomeView.vue | Ortak bağlantı bandı, Add guard ve GET-only retry |
| src/stores/stopwatchController.test.js | Mevcut Phase 4 senaryolarını v5 fixture/tombstone sözleşmesine uyarlama |
| src/sync/testSupport/sharedFixture.js (yeni) | Sadece testlerde eski IO kancalarını v5 envelope'a uyarlama |
| src/stores/sharedAuthority.test.js (yeni) | 40 canonical/offline/ACK/scope/saat regresyonu; başarısız snapshot/cache, 0 ms geçmiş kayıt ve offline A/B alarmı |
| src/components/sharedControls.test.js (yeni) | 6 gerçek derlenmiş Vue component giriş testi |
| docs/PHASE5_CONTRACT_REVIEW.md (yeni) | Kaynak ve tasarım kararı |
| docs/PHASE5_SHARED_AUTHORITY.md (yeni) | API, dosya gerekçeleri, test ve yayın kapıları |
| docs/KEEP_TIMER_AI_CHANGELOG.md | Tarihli Phase 5 kaydı |

Backend (11 dosya):

| Dosya | Neden |
| --- | --- |
| db/migrations/20260928_shared_authority.sql (yeni) | UYGULANMAMIŞ additive shared CAS/snapshot/claim RPC ve legacy DB guard |
| src/sharedTimers.js (yeni) | Komut/GET HTTP ve canonical Telegram job uzlaştırma |
| src/server.js | Yeni endpoint'leri bağlama, legacy shared mutation reddi |
| test/shared-http.test.js (yeni) | 21 gerçek lokal HTTP + DB fixture testi; success, 1 ms ve due false/eksik/bozuk zarf sınırı |
| test/shared-concurrency.test.js (yeni) | 12 onay-gated gerçek PostgreSQL testi; çalıştırılmadı |
| test/personal-sync-http.test.js | Legacy shared 426, personal davranışları ve RPC yan etkisi korunması |
| test/deactivation-guards.test.js | Shared legacy cancel 426; kapalı/yanlış yetki 403 guard'larını koruma |
| test/notification-race.test.js | Legacy shared start 426; önceki kabul edilmiş job fixture'ıyla eski 5 kapanış yarışı korunur |
| docs/PHASE5_CONTRACT_REVIEW.md (yeni) | Sözleşme/karar |
| docs/PHASE5_SHARED_AUTHORITY.md (yeni) | Bu belge |
| docs/KEEP_TIMER_AI_CHANGELOG.md | Tarihli Phase 5 kaydı |

Auth/token refresh, socket session modülü, personal sync/outbox dosyaları, mevcut iki migration, mevcut test/concurrency.test.js, package.json/lock/config değişmedi. Frontend test fixture dosyasının sync altında bulunması üretim outbox değişikliği değildir.

## Gerçek doğrulama sonuçları

Node v24.19.0. Bağımlılıklar mevcut kurulu ortamdan kullanıldı; iki supplied package/lock JSON'u kurulu tabanla semantik eşit doğrulandı. Yeni npm ci yapılmadı, yeni bağımlılık yok.

| Komut / çalışma | Sonuç |
| --- | --- |
| Frontend taban npm test | 137 pass, 0 fail, 0 skip |
| Frontend son npm test | 183 pass, 0 fail, 0 skip (137 mevcut + 40 yeni controller + 6 Vue) |
| Backend taban sıralı test/*.test.js | 35 pass, 0 fail, 7 skip |
| Backend son node --test --test-concurrency=1 test/*.test.js | 75 toplam: 56 pass, 0 fail, 19 skip |
| Backend JavaScript node --check | src ve test JS dosyaları geçti; backend build script'i yok |
| Frontend normal npm run build | Vite bundle üretildi; PWA Workbox/Terser renderChunk aşamasında exit 1 |
| Frontend ortam yardımcısıyla npm run build | exit 0; PWA sw.js + workbox ve 19 precache entry üretildi |

Ortam os.cpus()=0 döndürüyor. Sadece doğrulama sürecine yüklenen cpu-build-shim.cjs bu durumda bir CPU tanımı verir; proje/config/patch'e dahil edilmedi. Yardımcı teslim test kanıtlarında bulunur. Normal build'i geçmiş saymıyoruz; normal CPU sağlayan geliştirici/CI ortamında yeniden npm run build gereklidir.

Mevcut 137 frontend testi silinmedi veya skip edilmedi. Shared mock IO kanonik v5'e uyarlandı; tombstone assertion'ları güçlendirildi, stale GET yarışı ready iken başlayan komutla yeni protokole uygun kuruldu. Backend mevcut 35 normal testin shared legacy 200 beklentileri izin verilen fail-closed 426'ya çevrildi; closure/foreign-scope yan etki assertion'ları korunarak fixture güncellendi. Bunlar byte-for-byte değişmemiş test iddiası değildir.

Somut kırmızı → yeşil kanıtlar: shared DELETE sonrası ghost görünüm eski controller testinde; gecikmiş GET'in clock'u geri çekmesi (clock-red); kartın cihaz saatinden süre hesaplaması (ui-clock-red); online başlayan GET'in offline durumda ready açması (offline-race-red). Hedefli yeni kırmızı koşumda frontend üç success doğrulaması ve backend dört success/ACK + bir 0 ms hedef testi başarısızdı; düzeltilmiş hedefli ve son tam koşumlar geçirir. Yeni offline alarm testleri davranış sınırını doğrular. İlk test harness/fixture kurulum hataları üretim açığı diye sayılmadı.

Son due sözleşme testi: test/shared-http.test.js, mock RPC'de false/eksik success ile yanlış ID için Socket.IO ve Telegram yan etkisini reddeder (3 kırmızı → yeşil). test/shared-concurrency.test.js mevcut atomik claim yarışında başarılı **gerçek PG** sonucunun success:true, protocol:5, timer ID, run ve shared_alarm_claimed alanlarını doğrular; bu PG testi henüz çalıştırılmadığı için passed sayılmaz. Değişmeyen frontend src/services/sharedApi.js validatörü, SQL zarfı biçimindeki test fixture'ını kabul eder ve false/eksik success'i reddeder: teslimdeki due-envelope-frontend-check.mjs çıktısı. Bu son koşum gerçek PostgreSQL'in ürettiği byte'ları doğrulamış değildir; onaylı PG kapısı saklıdır. Frontend patch SHA-256, önceki teslimle aynıdır.

19 skip = 7 mevcut + 12 yeni gerçek PostgreSQL yarışı. Onaylı disposable local DB ve çalışan PostgreSQL ortamı yok; yeni migration hiçbir DB'de, PGlite dahil, çalıştırılmadı. SQL syntax/trigger/runtime/concurrency doğrulandı iddiası YOK. HTTP DB mock ve önceki migration'ları kullanan normal PGlite testleri bunu kanıtlamaz.

UI testleri gerçek SFC'leri mevcut Vite/Vue ile derler, custom renderer'da gerçek button handler'larını çalıştırır; yeni dependency yok. Gerçek browser/klavye/Android/iki fiziksel cihaz E2E testi değildir. 1005 satır client ve HTTP fixture'da test edildi; gerçek SQL aggregate >1000 testi hazır ama skip.

## Zorunlu sonraki kapı

1. Backend patch'i ve migration'ı gözden geçirin; provided metadata ile gerçek hedef şemasını karşılaştırın.
2. Ayrı açık onayla disposable **yerel**, restore/canlı olmayan *_keeptimer_test DB adını belirleyin. Yeni test host'u localhost/127.0.0.1/::1 ve PHASE5_DISPOSABLE_DB_APPROVED değerini tam DB adıyla doğrular; fixture public şemasını SİLER. TEST_DATABASE_URL genel/üretim ortamında ayarlı bırakılmamalıdır.
3. Yalnız onaylı ortamda, TEST_DATABASE_URL ve PHASE5_DISPOSABLE_DB_APPROVED sağlandıktan sonra backend kökünde:
   `node --test --test-concurrency=1 test/concurrency.test.js test/shared-concurrency.test.js`
   Mevcut `npm run test:concurrency` sadece eski 7 testi içerir; package script değiştirilmedi.
4. 19 gerçek PG testi + normal testler + standart frontend build geçmeden migration/backend yayını yapmayın. Sonra ayrıca kontrollü yayın onayı; frontend patch sonrasında uygulanır. APK/iki fiziksel cihaz matrisi Phase 6'da kalır.

Bu teslimde migration, commit, push, merge, deploy veya canlı Telegram işlemi yapılmadı.

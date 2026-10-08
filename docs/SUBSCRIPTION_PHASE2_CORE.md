# KeepTimer Faz 2 — Backend Subscription / Entitlement Core

Tarih: 8 Ekim 2026. Taban: gönderilen `KEEPTİMER GÜNCEL BACKEND(1).zip`.
Bu teslim mevcut güncel backend üzerine incremental patch'tir. Önceki Faz 1 veya
güvenlik revision patch'ini tekrar içermez. Production/Supabase bağlantısı, deploy,
commit/push veya kullanıcının gerçek projesine patch uygulaması yapılmadı.

## 1. Mevcut durum ve kapsam

Güncel ZIP'teki iki önceki patch ve `pg_catalog.host(pg_catalog.inet_server_addr())`
düzeltmesi taban kabul edildi. `test/support/subscriptionDatabase.js`, 54 güvenlik
guard testi ve önceki dört migration byte-byte korundu. Frontend/Android ve auth
modülleri değiştirilmedi. Kullanıcının bildirdiği önceki gerçek PostgreSQL PASS
sonuçları bu çalışmanın kendi doğrulaması olarak sayılmadı.

Faz 2 yalnız karar çekirdeğini, mevcut endpoint'lerde ücretli kapsamın yanlış bir
legacy yola düşmesini engelleyen sınırı ve transaction içinde kullanılacak assertion'ı
ekler. Agent satış/customer/renewal/cancel API'si veya private provisioning yoktur.

## 2. Değişen dosyalar

| Dosya | Değişiklik |
| --- | --- |
| `db/migrations/20261008_subscription_entitlement_core.sql` | Yeni forward-only karar/transaction function'ları ve insert kilit trigger'ı |
| `src/subscriptions.js` | Merkezi RPC istemcisi, sonuç doğrulama, error contract, guard ve minimal durum yanıtı |
| `src/server.js` | Mevcut resource authentication sonrası scope guard; self-status endpoint; Socket.IO giriş kontrolü |
| `test/subscription-phase2.test.js` | DB durum, history seçimi, yetki, expiry/veri koruma testleri |
| `test/subscription-phase2-http.test.js` | Gerçek Express/auth + PGlite otoritesi; forged input, stale JWT, cookie/refresh, socket testleri |
| `test/subscription-phase2-concurrency.test.js` | Altı gerçek PostgreSQL yarış senaryosu |
| `test/support/subscriptionPhase2.js` | Güvenli mevcut DB helper'ının üzerine Faz 2 fixture |
| `test/support/subscriptionHttp.js` | Legacy regresyonların yeni RPC için açık boş-history cevabı |
| `test/support/database.js` | Mevcut company/personal DB regresyon fixture'ına yeni migration |
| `test/concurrency.test.js` | Eski yarış fixture'ına yeni migration |
| `test/shared-concurrency.test.js` | Shared yarış fixture'ına yeni migration |
| `test/subscription-concurrency.test.js` | Önceki beş senaryo korunarak Faz 2 fixture'ına geçiş |
| `test/account-ui-telegram.test.js` | Yeni RPC için legacy mock cevabı |
| `test/deactivation-guards.test.js` | Aynı mock uyarlaması |
| `test/http-disabled.test.js` | Aynı mock uyarlaması |
| `test/notification-disabled.test.js` | Aynı mock uyarlaması |
| `test/notification-race.test.js` | Aynı mock uyarlaması |
| `test/personal-pages-http.test.js` | Aynı mock uyarlaması |
| `test/personal-sync-http.test.js` | Aynı mock uyarlaması |
| `test/web-auth.test.js` | Aynı mock uyarlaması |
| `docs/SUBSCRIPTION_PHASE2_CORE.md` | Bu teknik rapor ve sonuçlar |

Sekiz eski HTTP fixture'ında yalnız import + açık yeni RPC cevabı eklenir; mevcut
assertion'lar gevşetilmedi. Beklenmeyen/bozuk RPC cevabında production kodu legacy
erişime fallback yapmaz. Dependency veya package-lock değişikliği yoktur.

## 3. Entitlement mimarisi

Otorite `public.keeptimer_resolve_entitlement(user_id)` function'ıdır. Backend
`createSubscriptionCore(db).resolveSubscriptionEntitlement(userId)` yalnız bu RPC'yi
çağırır. Kullanıcı kimliği doğrulanmış `req.user.id` kaynağındandır. Body, query,
client clock, localStorage veya JWT içindeki plan/expiry claim'leri RPC'ye aktarılmaz.

Resolver tek DB transaction'ında user, katalog ve history satırlarını kilitler;
kilit beklemelerinden SONRA `clock_timestamp()` ile bir karar zamanı alır. Durum,
plan enabled ve history seçimi bu aynı zamana göre yapılır. Node `Date.now()` veya
transaction başındaki `now()` entitlement otoritesi değildir. JS'de Date.parse
yalnız RPC yanıtının tarih biçimi ve starts<ends tutarlılığını kontrol eder.

Resolver'ın internal sonucu:

```text
planCode, status, startsAt, endsAt, isEntitled, requiresSubscription, code
```

`requiresSubscription` yalnız kapsam sınıflandırmasıdır: users.plan_code doluysa,
herhangi bir subscription history varsa veya mevcut workspace private türündeyse
true olur. Bu alan erişim VERMEZ. Örneğin sadece users.plan_code='individual' ve
history yoksa SUBSCRIPTION_REQUIRED çıkar. users.plan_code null'a çekilse de history
varlığı ücretli kapsamı korur. Team sınıflandırması altında geçerli Individual
history varsa entitlement kararı history'deki Individual dönemden verilir.

Aktif olmayan/olmayan hesap hata durumunda legacy geçişe izin verilmez. Normal
legacy hesapta plan null + history yok + workspace private değilse eski resource
davranışı devam eder. Böylece mevcut standalone/team/shared kullanımı Faz 2 ile
topluca ücretli hale getirilmez. Bu ayrım entitlement yerine sınıflandırma kullanmak
değildir: paid entitlement her durumda history/katalog/zaman ile hesaplanır.

## 4. Dört subscription durumu

| Öncelik | Koşul | Durum |
| --- | --- | --- |
| 1 | cancelled_at dolu | cancelled |
| 2 | serverNow < starts_at | pending |
| 3 | starts_at <= serverNow < ends_at | active |
| 4 | serverNow >= ends_at | expired |

SQL içindeki koşul sırası cancellation → future → expired → active şeklinde
eşdeğer sınır koşullarını uygular. Tam starts_at anı active, tam ends_at anı expired.
İptal edilmiş gelecek dönem de cancelled'dır. `keeptimer_subscription_state` saf
internal helper'ı sabit timestamp ile mikro-saniye sınır testlerine izin verir;
anon/authenticated/service_role bu helper'ı doğrudan çağıramaz. Public resolver'ın
client tarafından belirlenebilir bir zaman parametresi yoktur.

History yoksa veya birden fazla aktif dönem nedeniyle tek authoritative dönem
seçilemiyorsa status null'dır ve code açıklama taşır. Bunlar beşinci bir subscription
durumu değildir; seçilmiş bir dönem bulunmaması/anomali durumudur.

## 5. Birden fazla history satırı seçimi

1. Kullanıcının bütün iptal edilmemiş, zaman aralığı şu anı kapsayan satırları sayılır.
   Birden fazlaysa, planları farklı/kapalı olsa bile SUBSCRIPTION_CONFLICT; erişim yok.
2. Tek active varsa bu satır seçilir; daha yüksek sequence'li pending yenileme bunu
   gölgelemez. Daha yüksek sequence'li iptal satırı da diğer active dönemi iptal etmez.
3. Active yoksa iptal edilmemiş en yakın starts_at'a sahip future/pending dönem
   seçilir. Aynı starts_at halinde sequence_no DESC deterministik tie-break'tir.
4. Active ve iptal edilmemiş pending yoksa en yüksek sequence_no seçilir; bu satır
   cancelled veya expired olabilir. Tarih sırası yerine tarihçenin satış/yenileme
   sıra numarası burada son kayıt göstergesidir.
5. Hiç history yoksa SUBSCRIPTION_REQUIRED.

İş kuralı: cancellation dönem-bazlıdır; "en yeni dönem iptal edildi" bütün hesabın
ve önceki geçerli dönemlerin iptal edildiği anlamına gelmez. Hesabı tamamen kapatma
ayrı disabled_at işlemidir. Gelecek iki dönem birbiriyle çakışıyorsa henüz entitlement
verilmez; zamanı geldiğinde iki aktif dönem görülürse fail-closed olur. Faz 3 satış
transaction'ı gelecekteki çakışmaları oluşturmayı da önlemelidir.

## 6. Enabled plan ve kullanıcı kuralları

Yalnız `subscription_plans.enabled=true` olan ve code='individual' olan geçerli
active satır paid entitlement sağlar. Team/enterprise flag'leri ileride yanlışlıkla
true yapılsa bile bu fazın sabit destek kapsamı onları PLAN_DISABLED ile reddeder.
Unknown plan FK/CHECK ile DB'ye giremez; bilinmeyen plan içeren bozuk RPC cevabı
JS tarafından SUBSCRIPTION_UNAVAILABLE olarak reddedilir.

Technical RBAC rolü worker kalır. History bulunan worker dışı hesap Individual
entitlement alamaz. Hata önceliği: disabled/missing account; uygun olmayan teknik
rol; aktif dönem çakışması; missing history; kapalı/desteklenmeyen plan; dönem durumu.
users.disabled_at expiry sırasında yazılmaz. Backend/sunucu input'una güvenmek,
istemciden gelen plan_code veya JWT rol/plan claim'ine güvenmek anlamına gelmez;
mevcut auth kimliği/rolü DB'den tekrar doğrulamayı sürdürür.

## 7. HTTP / Socket.IO entegrasyonu ve error contract

Yeni `GET /account/subscription`, mevcut identity/session authenticate ile korunur.
Yalnız kendi aboneliğini döndürür. Expired/pending/cancelled/missing subscription
durumları profil gösterilebilsin diye 200 + isEntitled=false + code döndürür:

```json
{
  "subscription": {
    "planCode": "individual",
    "status": "expired",
    "startsAt": "2026-10-01T00:00:00+00:00",
    "endsAt": "2026-11-01T00:00:00+00:00",
    "isEntitled": false
  },
  "code": "SUBSCRIPTION_EXPIRED"
}
```

Yanıt Cache-Control:no-store kullanır; yalnız açıkça seçilen beş alan ve code
dışarı çıkar. Subscription/user/actor ID, sequence, amount, email, hash, token,
private workspace veya internal scope flag'i gösterilmez. Kullanıcı farklı bir
userId/plan/time query'si gönderse de kendi doğrulanmış kimliği kullanılır.

Mevcut protected route'larda authenticateIdentity sonrasına merkezi account-scope
guard eklenir. Shared route mount'u da aynı wrapper'ı alır. Socket.IO bağlantıları
user/workspace odalarına katılmadan aynı scope kararından geçer. Login/refresh/logout
credential handler'ları ve validateAccessToken değiştirilmez.

| Code | Protected operation HTTP | Anlam |
| --- | ---: | --- |
| SUBSCRIPTION_REQUIRED | 403 | Paid kapsam için history yok |
| SUBSCRIPTION_PENDING | 403 | Dönem başlamadı |
| SUBSCRIPTION_EXPIRED | 403 | Bitiş sınırına ulaşıldı |
| SUBSCRIPTION_CANCELLED | 403 | Seçilen dönem iptal |
| PLAN_DISABLED | 403 | Kapalı veya bu fazda desteklenmeyen plan |
| SUBSCRIPTION_FORBIDDEN | 403 | Technical role Individual için uygun değil |
| SUBSCRIPTION_CONFLICT | 409 | Birden fazla aktif dönem; veri uyuşmazlığı |
| INDIVIDUAL_SCOPE_NOT_READY | 403 | Entitlement var, private kaynak kapsamı henüz açılmadı |
| ACCOUNT_DISABLED | 401 | Identity doğrulaması sonrası eşzamanlı disable veya missing account |
| SUBSCRIPTION_UNAVAILABLE | 503 | RPC/DB hatası veya bozuk/tutarsız yanıt |

403 abonelik reddini credential invalidity'den ayırır; refresh cookie/token silinmez.
Mevcut authenticate'in daha önce yakaladığı disabled/session hataları kendi 401
sözleşmesini korur. Status endpoint'inde conflict=409, account disabled=401 ve
DB/malformed=503; diğer abonelik durumları yukarıdaki açıklamayla 200'dür.
Socket error.data status/code alanları aynı kararı taşır. SQL assertion, reddi P0001
ve aynı sabit domain code mesajıyla yükseltir; gelecek mutation endpoint'leri bunu
aynı HTTP eşlemesine çevirmelidir. Ham DB hata mesajı istemciye/loga aktarılmaz.

## 8. Private scope kararı ve expiry

Bu faz private workspace'i KULLANIMA AÇMAZ. `isEntitled=true` ürünün abonelik hakkını
ifade eder; membership/resource authorization yerine geçmez. Mevcut group/standalone
endpoint'leri active Individual için INDIVIDUAL_SCOPE_NOT_READY ile kapalıdır.
Bu bilinçli release sınırı sayesinde henüz cross-table owner/member güvenliği
kurulmamış bir workspace ya da workspace-null standalone fallback ücretli veri yolu
olamaz. Private marker'ı olan ancak history'si olmayan hesap da legacy yola geçemez.

Faz 3 önkoşulları: owner/member uyumu, tek üye, membership giriş/çıkışının DB koruması,
kind transition güvenliği, invite/shared kapalı olması, mevcut shared kayıt ve
workspace üyelerinin kontrolü, atomik provisioning. Sonrasında mevcut scope guard'ın
"not ready" sınırı gerçek private resource authorization ile değiştirilmelidir;
sadece bu hata kodunu kaldırmak yeterli değildir.

Faz 2 private kayıt oluşturmaz, var olan workspace'i dönüştürmez, frontend mode
conversion veya UI gizleme yapmaz. Status endpoint'i private detaylarını göstermez;
login yanıtının mevcut workspace_id sözleşmesi aynen kalır. Bu yüzden Phase 3
tamamlanmadan gerçek Individual müşteri açmak desteklenmez.

Expiry cron'a bağlı değildir; karar anında ends_at<=DB clock yeterlidir. Hiçbir user,
timer, session veya subscription satırı expiry yüzünden değiştirilmez/silinmez.
Yeni resolver read/lock yapar, veri update etmez. Kayıtlar standalone'a çevrilmez.
Auth TTL/absolute lifetime, PIN, password ve refresh token yapısı korunur. Mevcut
legacy standalone cascade riski ve frontend Android arşiv eksikliği kapsam dışıdır.
Geçmiş legacy hesabın sonradan paid'e dönüştürülmesi ve açık socket/job'ların bu
dönüşümde ele alınması bu fazda uygulanmış değildir; Faz 3 böyle bir dönüşümü
destekleyecekse ayrıca güvenli yaşam döngüsü kurmalıdır.

## 9. Transaction / TOCTOU ve migration gerekçesi

Sadece Node'da ardışık Supabase SELECT'ler; tutarlı history/catalog snapshot'ı,
bekleme sonrası DB saati ve mutation ile aynı transaction garantisi sağlayamaz.
Bu nedenle önceki migration'a dokunmadan yeni forward-only SQL gereklidir.

Yeni SQL dört function ve bir BEFORE INSERT trigger ekler. Tablo/kolon/plan seed/
eski history/index/FK/RLS modeli yeniden tasarlanmaz; veri rewrite yoktur.
BEGIN/COMMIT, local lock_timeout=5s, idempotent CREATE OR REPLACE ve yalnız kendi yeni
trigger'ını DROP/CREATE etme kullanılır. Geçmiş tablolara DROP/TRUNCATE yoktur.

Resolver kilit sırası: user FOR SHARE → katalog code sırasıyla FOR SHARE → user'ın
history satırları sequence sırasıyla FOR SHARE → clock_timestamp → karar.
Bu, aynı transaction boyunca disable, katalog flag update ve mevcut satırın
cancellation update'iyle çatışır. Yeni INSERT trigger'ı user FOR UPDATE alır;
resolver'ın kilidi tutulurken görünmeyen yeni history satırı eklenmesini de engeller.
Trigger satırı değiştirmez; yalnız lock alır. Customer başına history serileştirilir.

`keeptimer_require_individual_entitlement(user_id)` merkezi resolver'ı çağırıp
entitlement yoksa exception verir. Gelecekteki paid mutation RPC'si bunu **aynı DB
transaction'ında**, resource/timer kilitleri ve mutation'dan önce çağırmalıdır.
Önceden yapılmış HTTP resolver/guard çağrısı, ayrı sonraki Supabase mutation için
atomik garanti sağlamaz; bu doküman böyle bir iddiada bulunmaz.

Faz 3 sales/cancel/renewal işlemleri user → catalog → history → resource lock sırasını
izlemeli; çok hesaplı batch veya ters lock sırasıyla deadlock üretmemelidir. Gerekirse
40P01/40001 için tüm transaction güvenli retry edilir. DB assertion yalnız entitlement
denetimidir; actor RBAC ve hedef kaynağın ownership kontrolü ayrıca gereklidir.

READ COMMITTED zorunludur; daha yüksek isolation'daki eski snapshot'ın, user lock
beklemesinden sonra yeni history INSERT'ini kaçırması ihtimaline karşı resolver
SUBSCRIPTION_ISOLATION_UNSUPPORTED ile fail-closed olur (HTTP katmanında 503).
Karar zamanı lock beklemelerinden sonradır; long-running transaction başındaki
now() kullanılmaz. Yetki doğrulama anı operation'ın yetkilendirme noktasıdır;
HTTP cevabı ulaştığı ana kadar veya keyfi sonraki transaction'lar için yetki vaadi
değildir. Future mutation, assertion'dan sonra uzun bağımsız bekleme yapmamalıdır.

Yeni RPC'ler yalnız service_role'a EXECUTE verir. Internal status/trigger function
EXECUTE PUBLIC/anon/authenticated/service_role'dan kaldırılır. SECURITY DEFINER
function'ların search_path'i boş, isimler schema-qualified'dır. Yeni tablo privilege,
RLS policy, global ALTER ROLE veya BYPASSRLS genişletmesi yapılmaz. Güvenilir service
anahtarı yine yalnız backend'dedir; raw RPC actor parametresi istemciye emanet edilmez.

Dağıtım sırası inceleme sonrası yeni migration, sonra yeni backend sürümü olmalıdır.
Migration eksikse yeni RPC çağrısı 503 verir; sessiz legacy fallback yoktur. Bu çalışma
bu dağıtımı yapmamıştır. Katalog üç satır ve user history üzerinde alınan read locks
her protected HTTP isteğinde ek DB turu/maliyet oluşturur; stale cache kullanılmaz.

## 10. Test sonuçları

| Çalıştırma | Toplam | PASS | FAIL | SKIP |
| --- | ---: | ---: | ---: | ---: |
| Gönderilen güncel backend tabanı | 202 | 178 | 0 | 24 |
| İlk Faz 2 DB çekirdeği | 26 | 26 | 0 | 0 |
| Son focused core çalıştırması (son ek HTTP senaryosundan önce) | 41 | 41 | 0 | 0 |
| Son tam backend regresyonu | 250 | 220 | 0 | 30 |
| Son PostgreSQL suite envanteri, ayrı çalıştırma | 30 | 0 | 0 | 30 |

Tam final çalıştırmanın yeni Faz 2 kısmı: DB 26 + HTTP 16 = 42 PASS, PG concurrency
6 SKIP. Önceki 54 security guard ve 21 Faz 1 DB testi final suite içinde geçti.
Eski account closure, auth/session, web/native auth, personal sync/pages, shared,
Telegram ve notification regresyonları korundu. Aynı testlerin farklı çalıştırma
satırları tekrar içerir; sayılar bağımsız testler olarak toplanmamalıdır.

Yeni DB testleri: sekiz exact/cancelled/boundary durumu; expired+active,
active+pending, expired+pending, multiple expired, cancelled newest+active older,
cancelled newest+no active, earliest pending; cross-plan aktif overlap; sınıflandırma
otorite ayrımı; team/enterprise enabled=true yapılsa bile ret; unknown FK/plan;
disabled/missing/no-history/non-worker; expiry'de tüm veri değerlerinin korunması;
private marker; service-only ACL ve tablolarda grant genişlememesi; yüksek isolation
reddi; migration replay ve eski append-only korumaları.

Yeni HTTP testleri gerçek Express server/auth handler'larını kullanır; Supabase
transportu PGlite DB resolver'a yönlendirilir. Paid status'ların sekiz farklı legacy
route girişinde reddi; legacy standalone'ın korunması; DB kararı karşısında stale
imzalı JWT ve forged user/plan/status/time; minimal no-store own response; malformed
RPC/unknown plan; expired login + HttpOnly cookie + geçerli refresh + paid ret;
anlık katalog/iptal/overlap değişiklikleri; paid socket giriş reddi ve reusable guard
üzerinde cancellation sonrası cache kullanılmadığı doğrulanır.

İlk yeni HTTP testinde test fixture'ının X-KeepTimer-CSRF başlığı eksikti; mevcut
auth guard doğru olarak 403 verdi. Auth kodu gevşetilmedi, fixture'a zorunlu başlık
eklendi. İlk focused HTTP ve ilk toplu deneme bu nedenle iki FAIL (alt + üst test)
içeriyordu; son focused ve final toplu çalıştırmada hata yoktur. Ham dökümde denemeler
ayrı isimlerle bulunur. Son tam çalıştırmadan sonra yalnız eski PostgreSQL fixture'ları
yeni migration ile çalışacak şekilde güncellendi; bu suite'lerin son halleri ayrıca
çalıştırılıp beklenen 30 SKIP doğrulandı. Üretim kodu son toplu testten sonra değişmedi.

Komutlar inceleme kopyasının backend kökündedir:

```sh
env -u SUBSCRIPTION_TEST_DATABASE_URL -u SUBSCRIPTION_TEST_CLUSTER_NAME \
  -u TEST_DATABASE_URL -u PHASE5_DISPOSABLE_DB_APPROVED \
  node --test --test-reporter=tap test/*.test.js

env -u SUBSCRIPTION_TEST_DATABASE_URL -u SUBSCRIPTION_TEST_CLUSTER_NAME \
  node --test --test-reporter=tap test/subscription-phase2.test.js test/subscription-phase2-http.test.js

env -u SUBSCRIPTION_TEST_DATABASE_URL -u SUBSCRIPTION_TEST_CLUSTER_NAME \
  -u TEST_DATABASE_URL -u PHASE5_DISPOSABLE_DB_APPROVED \
  node --test --test-reporter=tap test/concurrency.test.js test/shared-concurrency.test.js \
  test/subscription-concurrency.test.js test/subscription-phase2-concurrency.test.js
```

Gerçek PostgreSQL bu ortamda çalıştırılamadı: UID=0; docker/podman/system postgres
yok; root olmayan süreç denemesi `runuser: cannot set groups: Operation not permitted`
ile reddedildi. Erişim kısıtı aşılmadı, mevcut/production cluster aranmadı. Yeni
altı PG testi PASS olarak raporlanmaz:

1. Assertion önceyse concurrent cancellation bekler.
2. Cancellation önceyse sonraki assertion reddedilir.
3. Assertion boyunca yeni INSERT history phantom oluşturamaz.
4. Catalog enabled ve user disabled update'leri bekler.
5. Bekleme sırasında biten dönem, transaction-start now yerine gerçek karar saatiyle expired olur.
6. INSERT önceyse user lock beklemesi sonrası yeni dönem görülür.

Kullanıcının bildirdiği önceki 5/5 PostgreSQL ve 54/54 security sonuçları tarihsel
girdidir. Bu yeni migration'ın multi-connection davranışının bu ortamda test edildiği
anlamına gelmez. Güvenli isolated cluster mevcutsa, önceki güvenlik raporundaki
provision/cluster marker/role koşullarıyla yalnız disposable DB'de:

```sh
SUBSCRIPTION_TEST_CLUSTER_NAME="$test_cluster" \
SUBSCRIPTION_TEST_DATABASE_URL=postgres://postgres:local_test_only@127.0.0.1:55432/subscription_keeptimer_test \
  node --test --test-concurrency=1 test/subscription-phase1.test.js \
  test/subscription-concurrency.test.js test/subscription-phase2.test.js \
  test/subscription-phase2-concurrency.test.js
```

Helper koruması gevşetilmedi. `host(inet_server_addr())`, exact cluster marker,
DB envanteri, rollerin pre-provision kontrolü ve external ALTER ROLE yasağı aynıdır.
Bu suite'ler public schema reset yapar; değerli DB ve paralel schema-reset suite kullanmayın.

## 11. Faz 3'e ve sonraki mevcut fazlara bırakılanlar

- Satış/customer/renewal/cancel API'leri, agent RBAC, audit üretimi ve sequence ayırma.
- Calendar-month hesaplama, gelecek dönem overlap önleme ve users.plan_code uyumu.
- Private workspace atomik provisioning, tek üye/owner, kind geçiş güvenliği ve
  resource mutasyonlarının SQL assertion ile aynı transaction'a alınması.
- Mevcut legacy hesabın paid'e dönüştürülmesi desteklenecekse in-flight request,
  socket ve scheduled notification yaşam döngüsünün ayrıca güvenli hale getirilmesi.
- Individual profil UI, account-scope açma/kapatma ve expiry UX; standalone 10 timer
  limiti; Telegram/TTS ürün gating'i; MFA/OTP/password reset; Team/Enterprise satışları.

8 faz planı değiştirilmedi. Bu çekirdek, membership ve kaynak yetkisiyle birlikte
tamamlanmadan paid resource kullanımını açmıyor. Gerçek PG yarış doğrulaması ve
bağımsız güvenlik incelemesi halen release önkoşuludur.

## 12. Patch kontrolü ve kaynaklar

Patch yolları güncel ZIP'in `multi-stopwatch-backend-main` backend köküne göredir.
`git diff --check` ve temiz güncel ZIP tabanında `git apply --check` sonuçları teslim
raporunda kaydedilir. Patch uygulanmaz; yalnız inceleme kopyası dosyaları düzenlenir.
SHA-256 ayrı teslim dosyasındadır. Kaynak ZIP dosyaları değişmemiştir.

Tasarım doğrulaması için resmî kaynaklar:

- [PostgreSQL 16 explicit locking](https://www.postgresql.org/docs/16/explicit-locking.html):
  FOR SHARE/UPDATE uyumsuzluğu ve transaction sonuna kadar tutulan row lock'lar.
- [PostgreSQL 16 date/time](https://www.postgresql.org/docs/16/functions-datetime.html):
  transaction zamanı ile gerçek clock_timestamp farkı.

Bu kaynaklar tasarım dayanağıdır; çalıştırılmamış concurrency testinin yerine geçmez.

# KeepTimer ücretli bireysel abonelik — Faz 1 teknik raporu

Tarih: 7 Ekim 2026. Kapsam: yalnız PostgreSQL veri modeli ve temel invariantlar.
Frontend, backend `src/`, Android ve mevcut auth/session davranışı değiştirilmedi.
Deploy, production bağlantısı, production migration, git commit veya push yapılmadı.
Çalışma, gönderilen arşivlerin ayrı bir kopyasında yapıldı.

## 1. İncelenen taban ve değişen dosyalar

Taban: `KEEPTİMER BACKEND GÜNCEL(4).zip` içindeki
`multi-stopwatch-backend-main/`; ayrıca frontend ZIP ve gönderilen schema snapshot.
Patch yolları backend köküne göredir. Arşivler ve kullanıcının gerçek projesi değiştirilmedi.

| Dosya | Değişiklik |
| --- | --- |
| `db/migrations/20261007_subscription_phase1.sql` | Yeni, transaction içindeki incremental migration |
| `test/subscription-phase1.test.js` | Yeni DB invariant, yetki, replay ve veri koruma testleri |
| `test/subscription-concurrency.test.js` | Yeni, ayrı PostgreSQL bağlantılarıyla beş yarış testi |
| `test/support/subscriptionDatabase.js` | Güncel şemaya uyarlanmış PGlite/yerel PostgreSQL fixture |
| `test/support/database.js` | Mevcut DB regresyon fixture'ına Faz 1 migration'ı eklenir |
| `test/concurrency.test.js` | Mevcut yarış fixture'ına Faz 1 migration'ı eklenir |
| `test/shared-concurrency.test.js` | Mevcut shared yarış fixture'ına Faz 1 migration'ı eklenir |
| `docs/SUBSCRIPTION_PHASE1.md` | Bu açıklama, sonuçlar ve sınırlar |

Paket/dependency dosyaları değiştirilmedi. Test için indirilen PostgreSQL binary'si,
node_modules, kaynak ZIP'ler, schema kopyaları ve geçici dosyalar patch'e dahil değildir.

## 2. Gerçek şema ve kod hakkında bulgular

- Snapshot: 5 tablo, 51 kolon, 17 constraint, 10 index, 7 trigger, 18 function;
  enum ve RLS policy yok. Beş tabloda RLS açık, FORCE RLS kapalı.
- `users.role` enum değil, `users_role_check` ile sınırlanan `text`.
  Önceki roller `worker`, `manager`, `superadmin`.
- `users.disabled_at` mevcut. Aktiflik `disabled_at IS NULL` demek.
  Mevcut trigger disable edilmiş hesabın değiştirilmesini ve yeniden açılmasını engelliyor.
  Workspace'e bağlı worker/manager rolleri ve üyelikleri de korunuyor.
- `pin_hash text NOT NULL` mevcut; backend bcrypt/PIN doğrulaması kullanıyor.
  `password_hash`, `mfa_email`, plan alanı ve abonelik/audit tabloları yok.
  Snapshot'ta plaintext password/PIN kolonu bulunmuyor; bu bir veri satırı taraması değildir.
- `workspaces.owner_id` nullable ve users FK'si var. `invite_code` nullable/unique.
  `shared_mode_enabled` gerçek snapshot'ta nullable, varsayılan false.
  Tarihsel test fixture'ı bu ayrıntılarda farklıydı; yeni fixture bu farkları düzeltiyor.
- Ayrı membership tablosu yok; üyelik `users.workspace_id` üzerinden tutuluyor.
  Bu nedenle tek sahip ile tek üye aynı invariant değildir.
- Backend `SUPABASE_SERVICE_KEY` ile çalışıyor. Mevcut güvenilir RPC'lerde
  SECURITY DEFINER + sabit/boş search_path kullanılıyor. Uygulama rolü `users.role`,
  PostgreSQL `authenticated` veya `service_role` rolüyle aynı şey değil.
- Frontend `standalone`, `workspace-personal`, `shared` ayrımı yapıyor.
  `workspace-personal` verisi user/workspace sahipliğine bağlı. Bu yapı korundu.
- Frontend auth yanıt denetimi şu an yalnız üç eski rolü kabul ediyor.
  DB'ye agent eklemek agent login/panel desteği anlamına gelmiyor.
- Superadmin bootstrap kodu `.single()` ile disabled filtresi olmadan sorguluyor;
  birden fazla tarihsel superadmin oluştuğunda bu davranış Faz 2'de ele alınmalı.

Snapshot tablo/function ACL'lerini, owner'ları, PostgreSQL rol üyeliklerini,
event-trigger bağlamalarını ve gerçek veri satırlarını içermiyor. Bunlar canlı
ortamdan doğrulanmış kabul edilmedi. `rls_auto_enable()` function'ı mevcut;
event-trigger bağlantısı snapshot'tan çıkarılamıyor. Yeni tablolarda RLS açıkça açılıyor.

## 3. Migration davranışı

### Paketler, roller ve users

`subscription_plans` merkezi katalogdur. Kod CHECK'i yalnız `individual`, `team`,
`enterprise` kabul eder. İlk uygulamada individual açık, diğer ikisi kapalıdır.
`enabled` boolean NOT NULL; default false. Tekrar uygulama mevcut katalog tercihlerini
ON CONFLICT DO NOTHING ile korur; her çalıştırmada değerleri sıfırlamaz.

`users.plan_code` nullable FK'dir. Var olan hesaplara otomatik plan atanmaz;
privileged hesaplarda null kalabilir. Paket kodları rol değildir.
`password_hash` ve `mfa_email` nullable; `must_change_password` NOT NULL default false.
PIN hash kolonu ve NOT NULL koşulu korunur. Böylece mevcut backend yazmaları devam eder.
Password-only hesap üretimi için PIN zorunluluğunun kontrollü geçişi sonraki fazdadır.
Hash formatı/doğrulama, email doğrulama ve zorunlu parola değiştirme akışı uygulanmadı.

`users_role_check` agent ile genişletilir. İki partial unique index,
`disabled_at IS NULL` durumunda role başına en fazla bir superadmin ve bir agent sağlar.
Kontrol INSERT, rol UPDATE ve disabled durum değişikliklerinde DB tarafından uygulanır.
Sıfır aktif yetkiliye izin verilir; tam olarak bir tane olma zorunluluğu yoktur.
Eski yetkili disable edildikten sonra başka hesap aktif yetkili olabilir.
Disabled hesabın geri açılması mevcut trigger gereği hâlâ yasaktır.
Session `revoked_at` hesabın aktiflik ölçütü değildir; logout singleton kotasını boşaltmaz.
Aktif hesabın role değerini düşürmek de ilgili partial index kotasını boşaltır;
yetki devri/revoke API'si bu fazda yoktur.

### Abonelik tarihçesi

`subscriptions`: UUID id, user/plan FK, pozitif integer sequence_no, timestamptz
starts_at/ends_at, 1–12 smallint term_months, negatif olmayan bigint amount_minor,
üç büyük ASCII harfli currency (default TRY), oluşturan kullanıcı ve zaman,
iptal zamanı/kullanıcısı/isteğe bağlı en çok 1000 karakter neden.
Tarihler sonlu olmalı ve ends_at > starts_at olmalı.
`(user_id, sequence_no)` unique; sequence kullanıcı bazındadır, paket bazında değildir.

Yeni yenileme INSERT'tir. Ekonomik/sahiplik alanları UPDATE edilemez; DELETE/TRUNCATE
trigger ile engellenir. Yalnız iptal alanları birlikte bir kez doldurulabilir;
iptal edilmiş satır değiştirilemez. Aynı değere yapılan idempotent UPDATE mümkündür.
service_role yalnız iptal kolonlarında UPDATE yetkisine sahiptir.
`created_by_user_id` zorunludur; iptal zamanı varsa iptal eden de zorunludur.
Aktörün agent/superadmin olmasını bu faz henüz uygulamaz; güvenilir API'nin sonraki
transaction'ında role/disabled doğrulaması gereklidir.

Stored status veya expiry scheduler yoktur:

```sql
CASE WHEN cancelled_at IS NOT NULL THEN 'cancelled'
     WHEN ends_at <= now() THEN 'expired'
     ELSE 'active' END
```

Bu, istenen üçlü durum kuralıdır; gelecekte başlayacak dönem için ayrıca pending
durumu tanımlamaz. Takvim ayı hesaplama, dönemlerin çakışma/ardışıklık politikası,
sequence ayırma/retry ve güncel users.plan_code güncellemesi Faz 2 transaction'ına kalır.
term_months tarih farkından otomatik türetilmez. Currency ISO biçimini denetler;
tam ISO kod kataloğu değildir. Ücret yalnız haricen alınan bedelin küçük para
birimindeki kaydıdır; hiçbir tahsilat altyapısı yoktur.

FK, kapalı bir planın tarihçede referans edilmesini engellemez. Satış izni için
`subscription_plans.enabled` kontrolü ileride backend transaction'ında yapılmalıdır.
Eski team workspace'lerin çalışması bu katalog flag'leriyle değiştirilmedi.

### Audit ve yetki sınırı

`admin_audit_log` UUID, actor, action, isteğe bağlı target, JSONB metadata ve zaman tutar.
İstenen yedi action CHECK ile tanımlıdır. Metadata yalnız `subscription_id` (UUID
biçimli metin), `sequence_no` (pozitif integer aralığı) ve `plan_code` (paket enumu)
anahtarlarını kabul eder. Boş object geçerlidir; nested payload ve keyfi metin reddedilir.
Password/PIN/OTP/hash/access token/refresh token/MFA email ve request dump anahtarları
saklanamaz. Yeni metadata veya action gereksinimi kontrollü migration ister.
Bu bir içerik sınıflandırıcısı değildir; üretici API hiçbir secret'ı farklı bir
anahtar/kimlik alanına da kodlamamalıdır. İptal nedenine de secret yazılmaması sözleşmedir.

Yeni üç tabloda RLS açık; anon/authenticated policy yok. PUBLIC, anon, authenticated
ve service_role üzerindeki geniş tablo grant'leri temizlenir. Sonrasında:

| PostgreSQL rolü | İzin |
| --- | --- |
| anon / authenticated / PUBLIC | Yeni tablolarda hiçbir tablo izni yok |
| service_role | Katalog SELECT; subscription/audit SELECT ve INSERT; yalnız subscription iptal kolonlarında UPDATE |
| migration/table owner | Katalog yönetimi; history trigger'ları normal SQL'de UPDATE/DELETE/TRUNCATE korumasını uygular |

Audit UPDATE/DELETE/TRUNCATE ayrıca statement trigger ile reddedilir. Yeni trigger
function'ları SECURITY INVOKER, search_path boş; dış EXECUTE grant'i yok. Yeni RPC,
SECURITY DEFINER satış function'ı, policy veya email log trigger'ı eklenmedi.
DB owner/superuser trigger'ı kaldırabilir; bu DDL yetkisine karşı kurcalanamaz arşiv
iddiası değildir. BYPASSRLS, tablo ACL'sini veya trigger'ı otomatik atlatmaz.
Gerçek service_role BYPASSRLS/rol üyelikleri ve miras grant'leri deployment öncesi
ayrıca incelenmelidir; snapshot bunları sunmuyor.

### Private workspace hazırlığı

`workspaces.kind`: NOT NULL default `team`; alternatif `individual_private`.
Mevcut workspaces team olarak kalır. Private satırın owner_id'si dolu, invite_code'u
null ve shared_mode_enabled değeri kesin false olmak zorundadır. Bir owner için
en fazla bir private workspace partial unique index ile korunur.

Bu yalnız yerel satır kuralları ve discriminator hazırlığıdır. Başka user'ın o
workspace_id'ye bağlanması, mevcut üyeli bir workspace'in private'a çevrilmesi,
mevcut shared kayıtların dönüştürme öncesi kontrolü ve UI gizleme bu fazda
tam enforce edilmez. Shared oluşturma normal mevcut RPC'de false flag nedeniyle
engellenir; bu tüm cross-table geçişlerin korunduğu anlamına gelmez.
Private workspace/account oluşturma migration'ı yoktur. Hesaplar açılmadan önce
Faz 2'de üyelik, sahiplik ve tür geçişi transaction kuralları tamamlanmalıdır.

## 4. FK ve timer veri kaybı sonucu

Yeni subscriptions/audit user FK'leri ve plan FK'leri ON DELETE RESTRICT kullanır.
Oluşturan/iptal eden/audit aktörünün silinmesi tarihçeyi anonimleştirmez veya silmez;
silme işlemi reddedilir. Normal hesap yaşam döngüsü fiziksel silme değildir.

Mevcut `sessions.user_id`, `timers.user_id`, `timers.workspace_id` CASCADE ilişkileri
bu küçük patch'te değiştirilmedi. `timers.created_by` NO ACTION FK'sidir.
Workspace/company user/timer koruma trigger'ları mevcut workspace tarihçesini korur;
testler user ve workspace silmesinin reddedildiğini doğrular.

**Mevcut açık risk:** workspace_id null, herhangi bir subscription/audit/owner
referansı olmayan bir user'ın created_by=null standalone timer'ı, user fiziksel
olarak silinince CASCADE ile silinebilir. Bu senaryo testte gerçekten yeniden üretildi.
created_by başka bir kullanıcıysa da benzer risk vardır; kendi user'ına olan
NO ACTION referansı bazı durumlarda silmeyi engelleyebilir.
Patch bu riski sessizce düzeltilmiş gibi sunmaz; kapsamı büyütmemek için eski
FK/cleanup davranışını değiştirmez. Mevcut admin delete yolu bu açıdan incelenmelidir.
Yeni abonelik tarihçesi olan user'ın silinmesi RESTRICT yüzünden atomik olarak
reddedilir; aynı statement içinde timer cascade denense bile rollback ile timer kalır.

Migration timer satırlarına INSERT/UPDATE/DELETE/TRUNCATE yapmaz. Expiry job'ı yok;
expiry kullanıcı/workspace/timer silmez, disabled_at yazmaz, session süresini değiştirmez.
Snapshot yeniden kurulumunda migration öncesi/sonrası tüm mevcut timer kolon değerleri
eşit kaldı. Üretimde hiçbir timer veya hesap üzerinde işlem yapılmadı.

## 5. Transaction, tekrar çalıştırma ve uygulama öncesi kontrol

Sıra: mevcut üç 202609 migration'ından sonra `20261007_subscription_phase1.sql`.
BEGIN/COMMIT ile atomiktir. users/workspaces üzerinde ACCESS EXCLUSIVE lock,
preflight ile index kurulumu arasında yarış bırakmaz. Lock timeout 5 saniyedir;
uzun süre bloklamak yerine başarısız olur. Bu nedenle bakım penceresi ve normal
migration serialization prosedürü kullanılmalıdır; CONCURRENTLY index kullanılmadı.

Birden fazla aktif superadmin/agent varsa isim/email yazmadan rol ve adet ile
`KEEPTIMER_PHASE1_ACTIVE_ROLE_CONFLICT` hatası verir. Kimseyi seçmez, disable etmez,
silmez. Önceden incelemek için yalnız read-only sorgu:

```sql
SELECT id, role, disabled_at FROM public.users
WHERE role IN ('superadmin', 'agent') AND disabled_at IS NULL
ORDER BY role, id;
```

Hangi hesabın korunacağı operatör kararıdır; patch otomatik temizlik yapmaz.
Duplicate testi transaction rollback sonrası iki hesabın da durduğunu ve yeni
tablo/kolonların oluşmadığını doğrular.

Tekrar uygulama aynı şemada desteklenir: kolon/tablo/index IF NOT EXISTS,
function CREATE OR REPLACE, adlandırılmış trigger/check yenileme, seed ON CONFLICT.
Replay tarihçeyi, timer değerlerini ve sonradan kapatılmış katalog tercihlerini korur.
Bu, başka bir migration'ın aynı isimlerle farklı nesneler oluşturduğu şema sapmasını
iyileştirme sistemi değildir; böyle bir ortam önce incelenmelidir.
Hata halinde transaction rollback; client transaction'ı açık bırakırsa ROLLBACK
gerekir. `psql -v ON_ERROR_STOP=1` gibi stop-on-error araç kullanılmalıdır.
Başarılı uygulama sonrası history oluşmuşsa tabloları DROP eden otomatik down
migration önerilmez; düzeltme ileri migration ile yapılır.

Patch kontrolü, ayrı temiz güncel backend tabanında `git apply --check` ile yapıldı.
Gerçek projeye patch uygulanmadı. Kullanıcı backend kökünde önce aynı kontrolü yapabilir:

```sh
git apply --check /path/to/keeptimer-phase1.patch
```

## 6. Çalıştırılan testler ve tam sonuç özeti

| Çalıştırma | Toplam | Geçen | Hata | Atlanan |
| --- | ---: | ---: | ---: | ---: |
| Orijinal backend `npm test` | 122 | 103 | 0 | 19 |
| Faz 1 DB `node --test --test-reporter=tap test/subscription-phase1.test.js` | 21 | 21 | 0 | 0 |
| Faz 1 eklenmiş backend regresyon çalıştırması | 143 | 124 | 0 | 19 |
| Yeni çok bağlantılı `subscription-concurrency.test.js` | 5 | 0 | 0 | 5 |
| Değiştirilmemiş frontend `npm test` | 469 | 467 | 2 | 0 |
| Gönderilen snapshot'ın yeniden kurulumu + migration/RPC/replay kontrolleri | Ayrı doğrulama | Başarılı | 0 | — |

Backend regresyon komutu `node --test --test-reporter=tap test/*.test.js` idi.
Bu çalıştırma yeni concurrency dosyası eklenmeden başlatıldı; beş yarış testi sonra
ayrı komutla çalıştırıldı ve skip edildi. Son patch'te tek toplu çalıştırmada
beklenen birleşik envanter 148 test / 124 pass / 24 skip'tir; bu son sayı ayrı
çalıştırmaların toplamıdır, yapılmamış bir ek çalıştırmanın sonucu değildir.

21 DB testi, 19 alt senaryo + iki üst testten oluşur. Kapsanan senaryolar:

1. Plan kod whitelist'i ve üç başlangıç enabled değeri.
2. Nullable plan/password/MFA, false must-change ve eski PIN insert uyumu.
3. term=0 reddi.
4. term=13 reddi.
5. Eşit başlangıç/bitiş reddi.
6. Başlangıçtan önce bitiş reddi.
7. Sonsuz bitiş reddi.
8. Negatif/ondalıklı ücret, sıfır sequence, currency biçimi, FK ve büyük bigint doğruluğu.
9. Aynı user/sequence reddi, 1/3/12 aylık üç satırın korunması, overwrite/delete/truncate reddi.
10. İkinci aktif superadmin insert/update reddi, disable sonrası yeni yetkili, reactivation reddi.
11. Aynı kuralların agent için doğrulanması.
12. Birlikte iptal alanları ve iptal sonrası değişmezlik.
13. Hesabı/timer'ı değiştirmeden derived expiry ve subscription FK'siyle user delete reddi.
14. Private discriminator, owner, invite, nullable shared flag ve owner tekilliği.
15. Geniş default grant'lere rağmen ordinary role ACL/RLS koruması; service_role grant sınırları.
16. Audit append-only; yedi action; secret/nested metadata ve user delete reddi.
17. Mevcut company/workspace cascade korumaları.
18. Eski workspace-null user cascade veri kaybının açık reproduksiyonu.
19. Replay'in katalog tercihi, satır sayıları ve timer değerlerini koruması.
20. Ana invariant üst testi.
21. İki mevcut aktif superadmin halinde atomik preflight hatası; hesaplar korunur.

Snapshot doğrulaması PGlite üzerinde gönderilen 5 tablo, 51 kolon, 17 constraint,
10 index, 18 function ve 7 trigger'dan yeniden kuruldu. Migration, mevcut timer
değerleri eşitliği, `keeptimer_sync_personal`, `keeptimer_shared_request` create
ve migration replay kontrolü geçti. ACL/owner/event-trigger bağlantıları snapshot'ta
olmadığı için birebir production yetki kopyası olduğu iddia edilmez.

PGlite, projenin mevcut PostgreSQL tabanlı test motorudur; SQL constraint/trigger/RLS
testleri mock değildir. Ancak ayrı sunucu bağlantılarındaki lock yarışlarını doğrulamaz.
Gerçek PostgreSQL binary'si geçici ortama indirildi, fakat ortam root olmayan süreç
başlatmaya izin vermedi (`runuser: cannot set groups: Operation not permitted`).
İzin kısıtı aşılmadı, production bağlantısı denenmedi. Eski 19 ve yeni 5 server
yarış testi bu yüzden doğrulanmış sayılmaz.

Frontend'deki iki başarısız test değişiklik öncesi arşiv eksikliğidir:

- `native credential directory is excluded from both Android backup formats and transfer`:
  `android/app/src/main/AndroidManifest.xml` yok (ENOENT).
- `native registration keeps fixed transport, no global HTTP/cookies, and disables bridge argument logs`:
  `android/app/src/main/assets/capacitor.config.json` yok (ENOENT).

Android üretimi/tamiri veya frontend değişikliği yapılmadı. Tüm backend sonuçları,
frontend hataları ve snapshot çıktılarını içeren ayrı test dökümü teslim edilir.

### Yerel PostgreSQL'de kalan testleri çalıştırma

Bu bölümün önceki yalnız localhost/DB adı kontrolüyle çalışan yönergesi, incremental
güvenlik revizyonuyla değiştirilmiştir. Artık ayrı ve yeni oluşturulmuş disposable
cluster, doğrulanan server `cluster_name` işareti ve önceden hazırlanmış roller gerekir.
Query/fragment içeren URL'ler yasaktır; gerçek DB/IP, cluster envanteri ve rol ayarları
doğrulanmadan `public` şeması silinmez. Kurulum ve çalıştırma adımları için
[Faz 1 güvenlik revizyonu](SUBSCRIPTION_PHASE1_SECURITY_REVISION.md) belgesini kullanın.
Yeni ve eski schema-reset suite'lerini aynı DB üzerinde paralel çalıştırmayın.

## 7. Bilinen sınırlar ve Faz 2

Üretim için tüm testler geçti iddiası yoktur: PostgreSQL yarış doğrulaması ve gerçek
ACL incelemesi eksik; frontend Android dosyaları eksiktir. Veri kaybı riski yukarıda
açıkça sınırlandırılmıştır. Snapshot gerçek veri içermediği için production'da kaç
aktif superadmin bulunduğu bilinmiyor.

Faz 2'ye bırakılanlar: agent/superadmin işlem yetkileri, audit üretimi, satışta
enabled-plan kontrolü, eşzamanlı sequence/yenileme transaction'ı, users.plan_code
eşlemesi, parola/PIN geçişi, must-change/reset ve MFA email/OTP akışları; private
workspace otomatik oluşturma, tek üye/owner tutarlılığı ve tür geçişlerinin DB
koruması; admin fiziksel silme yolunun gözden geçirilmesi; bootstrap'ın tarihsel
superadmin kayıtlarıyla uyumu.

İleriki ilgili fazlar: agent paneli, frontend rol gösterimi/router/drawer,
subscription gating ve expiry logout, TTS/Telegram/standalone limitleri, Android
entegrasyonu. Bu patch team/enterprise kullanımını açmaz; shared/workspace API
entitlement davranışını veya session/token mimarisini değiştirmez.

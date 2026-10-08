# KeepTimer Faz 1 — test altyapısı incremental güvenlik revizyonu

Tarih: 7 Ekim 2026. Bu patch, mevcut Faz 1 patch'inin ÜZERİNE uygulanır.
Tam Faz 1 patch'inin yerine geçmez. Production bağlantısı, Supabase erişimi, deploy,
git commit/push veya kullanıcının gerçek projesinde değişiklik yapılmadı.

## Taban ve değişen dosyalar

Önceki `keeptimer-phase1.patch` SHA-256:

```text
f04fb7103e3f79ca60a5a0253e79ef4aa5314a671100b4f1e50570f9f6f87009
```

| Dosya | Değişiklik |
| --- | --- |
| `test/support/subscriptionDatabase.js` | URL/config, runtime hedef/cluster/rol ön kontrolleri; external rol mutasyonu kaldırıldı |
| `test/subscription-database-safety.test.js` | 54 yeni güvenlik regression testi |
| `docs/SUBSCRIPTION_PHASE1.md` | Eski PostgreSQL çalıştırma yönergesi yeni güvenli yönergeye yönlendirildi |
| `docs/SUBSCRIPTION_PHASE1_SECURITY_REVISION.md` | Bu teknik açıklama, kurulum, sonuçlar ve sınırlar |

Migration SQL ve bütün veri modeli byte-byte aynı kaldı. Değişmeyen
`db/migrations/20261007_subscription_phase1.sql` SHA-256:

```text
c6fae30464463d81424ee30580a5ef6ae75586e09e4f0123bd3f0290e9427973
```

`subscription_plans`, `users.plan_code`, `subscriptions`, `admin_audit_log`,
`workspaces.kind`, aktif agent/superadmin index'leri ve password/MFA hazırlığı
değiştirilmedi. Frontend, Android, backend `src/`, paket bağımlılıkları, production
FK'leri ve mevcut beş subscription concurrency senaryosu değiştirilmedi.

## 1. URL guard bypass düzeltmesi

`localTestUrl()` artık orijinal connection string yerine doğrulanmış, sabitlenmiş
`pg.Client` seçeneklerini döndürür. Mevcut isim çağıranların boolean kontrolünü korur;
helper'ın string döndürme davranışı bilinçli olarak kaldırılmıştır.

- Yalnız `postgres:` / `postgresql:` kabul edilir.
- Host allowlist'i `localhost`, `127.0.0.1`, `[::1]`; IPv6 sürücüye `::1` olarak verilir.
- `localhost`, DNS'e bırakılmadan `127.0.0.1` adresine sabitlenir. IPv6-only yerel
  sunucu için URL'de `[::1]` kullanılmalıdır.
- Path kesin olarak `/[a-zA-Z0-9_]+_keeptimer_test` biçimindedir. Kodlanmış path,
  başka DB, ilave path parçası ve Unix socket host'u kabul edilmez.
- `url.search` boş değilse reddedilir. Boş `?` işareti de reddedilir; hiçbir query
  key'i istisna tutulmaz. Fragment, ham whitespace/control karakterleri de reddedilir.
- Port 1–65535; verilmemişse 5432. Username/password standart percent encoding ile
  çözülür. Hatalı URL/encoding mesajları connection string'i veya parolayı yazdırmaz.
- Sürücüye `connectionString` gönderilmez. Host, port ve DB açık alanlardır;
  ikinci parser üzerinden host/hostaddr/service/dbname override mümkün değildir.
- `PGHOST`, `PGPORT`, `PGDATABASE` ve `PGOPTIONS` hedefi/başlangıç seçeneklerini
  değiştirmez. Kullanıcı verilmezse postgres; parola verilmezse boş parola seçilir.
  Parola callback'i boş değerin `PGPASSWORD` fallback'ine düşmesini önler.
  Yerel test için SSL false ve bağlantı timeout'u 5 saniyedir.

URL reddinde `pg.Client` constructor'ı, `connect()` ve SQL çağrısı çalışmaz.

## 2. Bağlantı sonrası ve DROP öncesi doğrulama

Her gerçek `connect()` çağrısında aşağıdaki read-only kontroller tamamlanır;
admin fixture bağlantısında da aynı sıra geçerlidir:

1. `pg_catalog.current_database()`, `pg_catalog.inet_server_addr()` ve
   `pg_catalog.current_setting('cluster_name')` sorgulanır.
2. DB adı yalnız suffix ile değil, URL'de doğrulanmış DB adıyla birebir eşleşir.
3. Server address kesin `127.0.0.1` veya `::1` olur. NULL, IPv4-mapped IPv6 ve başka
   adresler fail-closed reddedilir. Unix socket taşımaya izin yoktur.
4. Server `cluster_name`, `SUBSCRIPTION_TEST_CLUSTER_NAME` ile aynı olmalıdır.
   Format `keeptimer_disposable_` + 32 küçük hexadecimal karakterdir. Bu ortam
   değişkeni eksik/hatalıysa bağlantı dahi kurulmaz.
5. `pg_catalog.pg_database` envanterinde yalnız template0, template1, postgres ve
   beklenen test DB'si olabilir. Başka test DB'si veya custom template de reddedilir.
6. `pg_catalog.pg_roles` ile gerekli rollerin tamamı aşağıdaki sözleşmeyle doğrulanır.

Ancak bütün kontroller başarılıysa `DROP SCHEMA IF EXISTS public CASCADE; CREATE
SCHEMA public` başlar. Yanlış kimlik, eksik metadata, rol hatası veya sorgu hatası
bağlantıyı kapatır; schema/rol DDL'si çalışmaz. Katalog sorguları schema-qualified'dır.

`inet_server_addr()` PostgreSQL'de Unix socket için NULL döner. NULL'u loopback
varsaymak yerine reddetmek, bu suite'in yalnız TCP taşımasını desteklediğini açık
kılar. `cluster_name` yalnız sunucu başlangıcında ayarlanabilen bir parametredir;
helper bu işareti kendisi SET/ALTER etmez.

## 3. Cluster genelindeki service_role etkisinin kaldırılması

Gerçek PostgreSQL yolunda helper hiçbir `CREATE ROLE`, `ALTER ROLE` veya `DROP ROLE`
çalıştırmaz. Gerekli roller, yeni ve disposable cluster provision edilirken ayrı
olarak hazırlanır. Böylece yanlış mevcut rolü "düzeltme" davranışı tamamen kaldırılır.

| Rol | BYPASSRLS | SUPERUSER | LOGIN |
| --- | --- | --- | --- |
| anon | false | false | false |
| authenticated | false | false | false |
| service_role | true | false | false |

Örneğin `service_role.rolbypassrls=false` ise hata verilir; rol aynı kalır ve schema
DROP yapılmaz. Rol yoksa da helper oluşturmaz, fail eder. Bu politika istenen
"yalnız doğrulanmış disposable cluster'da kontrollü oluşturulabilir" seçeneğinden
daha dardır: external role creation tamamen provision aşamasına bırakılmıştır.

PGlite yolu farklıdır: helper her seferinde kendi yeni in-memory instance'ını yaratır.
Bu instance içinde roller ilk yaratıldıklarında uygun attribute ile tanımlanır;
`ALTER ROLE service_role BYPASSRLS` burada da kaldırılmıştır. Paylaşılan cluster'a
veya başka veritabanındaki role dokunulmaz.

## 4. Regression testleri ve sonuçlar

| Çalıştırma | Toplam | PASS | FAIL | SKIP |
| --- | ---: | ---: | ---: | ---: |
| Güvenlik guard testleri, son dosya hali | 54 | 54 | 0 | 0 |
| Güvenlik + mevcut Faz 1 PGlite testleri | 75 | 75 | 0 | 0 |
| Tam backend regresyonu | 202 | 178 | 0 | 24 |
| Beş subscription PostgreSQL concurrency testi, ayrı çalıştırma | 5 | 0 | 0 | 5 |

75 test = 54 güvenlik + mevcut 21 Faz 1 DB testi. Tam regresyondaki 24 SKIP,
önceki 19 PostgreSQL testi ve yeni beş concurrency testidir. Ayrı çalıştırmalar
aynı testleri tekrar içerir; sayılar bağımsız test sayısı olarak toplanmamalıdır.

Güvenlik testlerinin tamamında gerçek `pg.Client` giriş noktasına kontrollü harness
yerleştirilir; socket açılmaz. Bir test ayrıca gerçek pg sürücüsünün config parser'ını
bağlantı kurmadan denetler. PostgreSQL kimlik/rol cevapları harness tarafından sağlanır;
bu sonuç gerçek sunucu concurrency doğrulaması gibi sunulmaz.

54 testin kapsamı:

- 11 URL suffix testi: host, hostaddr, service, dbname, port, sslmode, options,
  application_name query'leri, boş query, dolu/boş fragment. Kullanıcının üç örneği
  doğrudan kapsanır. Constructor/connect/SQL sayısı sıfır olarak doğrulanır.
- 12 diğer URL reddi: uzak host, yanlış DB/path/encoded path, yanlış protocol,
  farklı 127.* adresi, mapped IPv6, socket path, 0/65536 port, newline, libpq string.
- 1 bozuk credential encoding testi; 3 geçerli localhost/IPv4/IPv6 bağlantı seçeneği.
- 1 gerçek sürücü config testi: PG* ortam override'larına direnç ve encoded credentials.
- 3 eksik/hatalı cluster opt-in testi; bağlantıdan önce ret.
- 8 runtime kimlik reddi: yanlış DB ve farklı doğru-suffix DB, uzak/null/eksik/mapped
  IP, yanlış/boş cluster marker; hepsi DROP öncesinde.
- 1 eksik identity sonucu; 3 fazladan cluster DB/custom-template; 1 boş envanter.
- 1 mevcut NOBYPASSRLS service_role testi: attribute değişmez, ALTER ROLE/DROP yok.
- 3 eksik rol; 3 uygunsuz rol attribute testi; hiçbiri cluster'ı yeniden yapılandırmaz.
- 1 doğru hazırlanmış cluster harness'i: identity → inventory → roles → DROP sırası
  ve fixture devamı, hiçbir external role DDL'si olmadığı doğrulanır.
- 2 bağlantı/sorgu hatasında temiz kapanış ve schema değişmediği testleri.

Çalıştırılan komutlar backend kopyasının kökündedir. External DB ortam değişkenleri
bilinçli olarak kaldırılmıştır; regression komutu mevcut başka suite'leri yanlış
bir DB'ye yönlendiremez:

```sh
env -u SUBSCRIPTION_TEST_DATABASE_URL -u SUBSCRIPTION_TEST_CLUSTER_NAME \
  -u TEST_DATABASE_URL -u PHASE5_DISPOSABLE_DB_APPROVED \
  node --test --test-reporter=tap test/subscription-database-safety.test.js test/subscription-phase1.test.js

env -u SUBSCRIPTION_TEST_DATABASE_URL -u SUBSCRIPTION_TEST_CLUSTER_NAME \
  -u TEST_DATABASE_URL -u PHASE5_DISPOSABLE_DB_APPROVED \
  node --test --test-reporter=tap test/*.test.js

env -u SUBSCRIPTION_TEST_DATABASE_URL -u SUBSCRIPTION_TEST_CLUSTER_NAME \
  node --test --test-reporter=tap test/subscription-concurrency.test.js

env -u SUBSCRIPTION_TEST_DATABASE_URL -u SUBSCRIPTION_TEST_CLUSTER_NAME -u TEST_DATABASE_URL \
  node --test --test-reporter=tap test/subscription-database-safety.test.js
```

Son komut, ilk query örneğinin host'unu kullanıcının tam `127.0.0.1` örneğine
uyarladıktan sonra guard dosyasının son halini doğrular; helper değişmemiştir.

Gerçek PostgreSQL concurrency çalışmadı. Ortam UID=0; docker/podman ve sistem
postgres/initdb komutları yok. Önceki teslimde indirilen binary olsa da root olmayan
süreç başlatma denemesi `runuser: cannot set groups: Operation not permitted`
ile reddediliyor. Bu sınır aşılmadı; mevcut cluster aranmadı/bağlanılmadı. Güvenli
isolated cluster erişimi olmadığından beş test SKIP; production doğrulaması yok.
Tam TAP çıktıları ve ortam kontrolü ayrı teslim dosyasındadır.

## 5. Güvenli disposable PostgreSQL çalıştırma yönergesi

Bu Linux Docker örneği **yeni container ve yeni tmpfs data directory** oluşturur;
mevcut cluster yeniden etiketlenmez, mevcut volume/restore kullanılmaz. Host network
ve loopback-only PostgreSQL dinlemesi NAT/bridge adresi belirsizliğini önler.
Komutlar bu ortamda çalıştırılmadı; host-network destekli Linux Docker makinede
testler için verilmiştir. Desteklenmeyen platformda ayrı native cluster kullanın.

```sh
# Backend kökünde; yalnız yeni, atılabilir cluster için. Hata varsa ilerlemeyin.
set -e
test_token=$(node -e "process.stdout.write(require('node:crypto').randomBytes(16).toString('hex'))")
test_cluster="keeptimer_disposable_${test_token}"
test_container="keeptimer-phase1-${test_token}"

docker run --rm -d --name "$test_container" \
  --network host \
  --tmpfs /var/lib/postgresql/data \
  -e POSTGRES_PASSWORD=local_test_only \
  -e POSTGRES_DB=subscription_keeptimer_test \
  -e PGPORT=55432 \
  postgres:16 -p 55432 -c listen_addresses=127.0.0.1 -c "cluster_name=$test_cluster"

# Hazır olmadan ilerlemeyin; başarısızsa aynı yeni container için tekrar kontrol edin.
docker exec "$test_container" pg_isready -h /var/run/postgresql -p 55432 -U postgres -d subscription_keeptimer_test

# Yalnız az önce yaratılmış bu container'da provision edilir; ALTER ROLE yoktur.
docker exec -i "$test_container" \
  psql -h /var/run/postgresql -p 55432 -U postgres -d subscription_keeptimer_test -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE anon NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE authenticated NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE service_role NOLOGIN NOSUPERUSER BYPASSRLS;
SQL

SUBSCRIPTION_TEST_CLUSTER_NAME="$test_cluster" \
SUBSCRIPTION_TEST_DATABASE_URL=postgres://postgres:local_test_only@127.0.0.1:55432/subscription_keeptimer_test \
  node --test --test-concurrency=1 test/subscription-phase1.test.js test/subscription-concurrency.test.js

# Yalnız bu çalışma için yaratılan container'ı durdurun; tmpfs verisi atılır.
docker stop "$test_container"
```

Provision adımı yalnız yeni container'ın kendi filesystem'indeki Unix socket'i
kullanır; host namespace'inde aynı portu kullanan başka sunucuya rol DDL'si göndermez.
Test helper ise yalnız TCP kullanır ve server kimliğini ayrıca doğrular.
Port doluysa sunucu başlangıcı başarısız olur. Teste devam etmeyin; başka port
seçilirse bütün port değerlerini ve URL'yi birlikte değiştirin. Var olan başka
sunucuya yanlışlıkla bağlantı kurulsa bile yeni rastgele cluster marker'ı eşleşmez;
schema reset başlamaz. NAT/bridge kurulumuna geçerseniz server address kontrolü
bridge IP'sini reddeder; allowlist'i genişletmeyin.

Roller önceki çalışmadan varsa CREATE ROLE hatasını ALTER ROLE ile geçiştirmeyin;
bu yeni-cluster yönergesine uyulmadığını gösterir. Cluster'ı paylaşmayın; fixture
schema reset yaptığı için suite dosyalarını `--test-concurrency=1` ile seri çalıştırın.

## 6. Bilinen sınırlar ve inceleme notları

- Cluster marker + tam DB envanteri kazara yanlış cluster seçimine karşı ek
  kapılardır; verinin değersiz olduğunu SQL ile matematiksel olarak kanıtlamaz.
  Yönetici değerli bir cluster'ı bilerek bu marker ile yeniden başlatıp izin verilen
  adlara değerli veri koyarsa bu sözleşme ihlal edilir. Helper bunu yapmaz.
- `postgres` bakım DB'sinin boş olduğu veya default template'lerin hiçbir kullanıcı
  nesnesi içermediği araştırılmıyor. Bu nedenle yeni disposable cluster provision
  şartı zorunludur; mevcut paylaşılan cluster'a marker eklemek desteklenmez.
- Provision dışında eşzamanlı bir yöneticinin cluster/rol yapılandırmasını
  değiştirmediği varsayılır. Yeni fixture mevcut role attribute'larını hiçbir zaman
  mutate etmediği için böyle bir durumda da rol değişikliği kaynaklı zarar üretmez.
- Server-reported identity güvenilir yerel PostgreSQL sunucusunu varsayar; kötü niyetli
  bir PostgreSQL protokol proxy'sine karşı kriptografik attestation tasarımı değildir.
- Unix socket, mapped IPv6, diğer 127/8 adresleri ve Docker bridge adresleri bu
  destructive suite için desteklenmez; otomatik gevşetme veya sessiz fallback yoktur.
- Rol attribute testleri ve başarılı reset sırası harness ile doğrulandı; gerçek
  PG rol/concurrency doğrulaması halen yapılmalıdır.
- Eski `test/concurrency.test.js` ve `test/shared-concurrency.test.js` kendi ayrı
  helper/guard yollarını kullanır. Bu revision bunları yeniden tasarlamaz. Yukarıdaki
  güvenlik garantileri subscriptionDatabase yoluna aittir; eski suite'ler tümünün
  aynı guard'a taşındığı şeklinde yorumlanmamalıdır.
- Legacy standalone timer cascade riski ve frontend Android arşiv eksiklikleri
  önceki bilinen durumlardır; bu revision bunları değiştirmez veya yeni bulgu saymaz.

## 7. Patch doğrulama ve kaynaklar

`git diff --check` ve temiz **güncel Faz 1 tabanına** incremental revision için
`git apply --check` kontrolleri teslimde yapılır; sonuçlar teslim raporunda bulunur.
Uygulama sırası: önce mevcut Faz 1 patch'i, sonra bu revision. Kullanıcının gerçek
projesine ikisi de bu çalışma kapsamında uygulanmadı.

Bağımsız incelemeye mevcut Faz 1 patch + revision patch + bu rapor ve test dökümü
birlikte verilmelidir. Revision patch'in SHA-256 değeri ayrı `.sha256` dosyasındadır.

Resmî PostgreSQL kaynakları (7 Ekim 2026 erişimi):

- [System Information Functions](https://www.postgresql.org/docs/16/functions-info.html):
  current_database ve Unix socket'te NULL dönen inet_server_addr sözleşmesi.
- [Database Roles](https://www.postgresql.org/docs/16/database-roles.html):
  roller database-local değil, cluster genelindedir.
- [Process Title / cluster_name](https://www.postgresql.org/docs/16/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-PROCESS-TITLE):
  cluster_name yalnız server startup'ta ayarlanır.
- Connection-string precedence ve seçenek davranışı ayrıca projenin kurulu
  `pg/lib/connection-parameters.js` kaynak kodundan incelendi.

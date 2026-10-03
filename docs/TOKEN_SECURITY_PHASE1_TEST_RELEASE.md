# KeepTimer — Aşama 1 test ve yayın talimatları

## Patch'i uygulama

Orijinal güncel backend'in kökünde, mevcut çalışmalarınızı ayrı bir branch veya
commit ile koruyun. Patch önceki patch'lerin uygulanmış kopyasına göre üretilmedi.

```sh
git switch -c backend-token-phase1
git apply --check /dosyanin/yolu/keeptimer-backend-token-phase1.patch
git apply /dosyanin/yolu/keeptimer-backend-token-phase1.patch
git diff --check
npm ci --no-audit --no-fund
env -u TEST_DATABASE_URL -u PHASE5_DISPOSABLE_DB_APPROVED npm test
```

İlk `git apply --check` hata verirse zorlayarak uygulamayın; kaynak sürümünü
kontrol edin. Paket veya lockfile değişikliği yoktur. Gerçek PostgreSQL
değişkenlerinin bu genel çalıştırmada kaldırılması canlı/yanlış DB'ye test
gitmesini ve iki destructive test dosyasının aynı şemada eşzamanlı çalışmasını
önler. Shell örnekleri Ubuntu/bash içindir.

## Gerçekten çalıştırılan komutlar ve sonuçlar

Node v24.19.0 / npm 11.9.0 kullanıldı.

```sh
npm ci --no-audit --no-fund
node --test --test-reporter=tap test/web-auth.test.js test/http-disabled.test.js test/auth-log.test.js
env -u TEST_DATABASE_URL -u PHASE5_DISPOSABLE_DB_APPROVED npm test
```

- Lockfile kurulumu: 134 paket; ek bağımlılık yok.
- Son hedefli auth testleri: 28 test, 28 başarılı, 0 başarısız, 0 atlanan.
- İlk tüm-suite çalıştırması: 103 test, 84 başarılı, 0 başarısız, 19 atlanan.
  Bundan sonra genel auth istisna işleyicisi için bir test daha eklendi.
- Temiz orijinal ZIP kopyasında son patch sonrası tüm-suite: 104 test, 85 başarılı, 0 başarısız, 19 atlanan.
- Patch kontrolü: Başarılı; temiz orijinale uygulanabilir, test edilen kodla aynı.

Önceki başarısız ortam denemeleri test başarısı olarak sayılmadı: offline npm
kurulumunda eksik cache; normal ağda EPERM; sandbox testlerinde listen EPERM.
İzinli kurulum ve yerel port erişiminden sonra yukarıdaki testler çalıştırıldı.

HTTP/Socket.IO testleri gerçek yerel sunucu ve polling handshake kullanır.
Supabase/PostgREST yanıtları kontrollü test doubles ile sağlanır. Proxy testi
yerel reverse proxy üzerinden Origin, dış/iç yol, Cookie ve Set-Cookie
aktarımını doğrular. Cookie kabulünü Node testlerinde gerçek browser jar'ı
doğrulamaz; Cookie başlığı test tarafından eklenir.

Mevcut PGlite DB testleri genel suite'e dahildir. 19 gerçek PostgreSQL
ayrı-bağlantı testi çalıştırılmadı; bunlar aşağıdaki 7 + 12 testtir.

## Gerçek PostgreSQL testleri — yalnız silinebilir yerel DB

Bu mevcut testler `public` şemasını silip yeniden oluşturur. Canlı Supabase,
restore kopyası, geliştirme verilerinizin bulunduğu DB veya müşteri verisi
kullanmayın. Ürün sahibi bunları kendi Ubuntu ortamında çalıştıracaktır.

İzole örnek:

```sh
docker run --rm --name keeptimer-token-phase1-db \
  -e POSTGRES_PASSWORD=keeptimer_local_only \
  -e POSTGRES_DB=phase1_keeptimer_test \
  -p 127.0.0.1:55432:5432 -d postgres:16

docker exec keeptimer-token-phase1-db \
  pg_isready -U postgres -d phase1_keeptimer_test
```

Hazır yanıtı gelmeden testleri başlatmayın. Ardından backend kökünde şu iki
komutu **sırayla**, önceki tamamlandıktan sonra çalıştırın:

```sh
TEST_DATABASE_URL=postgres://postgres:keeptimer_local_only@127.0.0.1:55432/phase1_keeptimer_test \
  node --test test/concurrency.test.js

TEST_DATABASE_URL=postgres://postgres:keeptimer_local_only@127.0.0.1:55432/phase1_keeptimer_test \
PHASE5_DISPOSABLE_DB_APPROVED=phase1_keeptimer_test \
  node --test test/shared-concurrency.test.js
```

İlk dosyada 7, ikincide 12 test beklenir. İkincideki approval değişkeni tam
silinmesine izin verilen DB adını belirtir. Bu iki dosyayı aynı DB üzerinde
paralel çalıştırmayın; iki değişkeni export edip tüm `npm test` komutunu
başlatmayın. İş bitince yalnız bu örnek konteyneri durdurun:

```sh
docker stop keeptimer-token-phase1-db
```

Bu patch yeni migration eklemez; testler mevcut migration'ları izole test
şemasına kendileri uygular. Canlı migration veya veri değişikliği bu aşamanın
parçası değildir.

## Otomatik test kapsamı

| Zorunlu beklenti | Test / kanıt |
|---|---|
| Login ve güvenli cookie, JWT süreleri | `web-auth.test.js`: login; HttpOnly/Secure/Lax/Path/Expires, claim ve DB hash kontrolü |
| JSON refresh sızıntısı olmaması | Login ve refresh yanıt anahtarlarının tam karşılaştırılması |
| Bearer API ve Socket.IO | Üretilen access ile korumalı çağrı ve gerçek Socket.IO handshake; eksik/refresh/revoked token reddi |
| Geçerli refresh, hatalı/eksik/expired cookie | Refresh testleri; yanlış imza/tür ve duplicate cookie dahil |
| Logout yalnız ilgili session | DB filtreleri, diğer session'ın korunması, gerçek socket disconnect |
| Revoked ve disabled session | Refresh/API/socket reddi; mevcut `http-disabled` testi ve DB testleri |
| Hesap kapatma / force-logout | Manager ve superadmin closure; superadmin force-logout; manager force-logout 403 korunur |
| Yanlış PIN ve limitler | Kullanıcı lockout ve değişen sahte en-sol XFF/X-Real-IP ile aynı IP limiti |
| CSRF ve CORS | Eksik/null/foreign origin, prefix saldırısı, özel header, form/text, preflight |
| Cookie silme scope'u | Oluşturma/silme attribute eşitliği, geçmiş Expires |
| Cache ve güvenli hata yanıtı | Başarı/hata/preflight no-store; bozuk/oversized JSON ve beklenmeyen auth hatası |
| Altyapı kesintisi | Login/refresh/logout DB hatalarında 503, cookie silmeme ve sahte başarı vermeme |
| Eski oturum isteği | A sessionId + B cookie 409; DB değişikliği ve Set-Cookie yok |
| Gecikmiş logout sınırı | A iptal edilir, B DB session'ı korunur; gecikmiş silme cookie'sinin varlığı açıkça test edilir |
| Proxy | Gerçek yerel HTTP reverse proxy ile dış `/api/auth` → iç `/auth`, Origin ve cookie header aktarımı |
| PIN log'u | Gerçek bootstrap hashleme yolu; PIN/hash/secret/service-key console.log'da bulunmaz |

## Koordineli yayın ve eski sürümler

Bu backend eski frontend'le auth bakımından uyumlu değildir; bu bilinçli bir
sözleşme değişikliğidir. Eski JSON refresh fallback'i ve çift auth endpoint'i
yoktur. Önce backend kodu gözden geçirilip ayrı commit olarak hazırlanabilir;
frontend tamamlanmadan üretime tek başına yayınlanması önerilmez.

1. Backend patch'ini inceleyin ve yerel testleri tamamlayın. Gerçek PostgreSQL
   sonuçlarını alın. AUTH_ALLOWED_ORIGINS ve mevcut sırları doğru tanımlayın;
   loglara cookie/PIN/Authorization veya env değerlerini dökmeyin.
2. Sonraki aşamada frontend sözleşmesini uygulayın. Access yalnız bellekte;
   gizli olmayan session marker; cookie taşıması; çok sekmeli sıralama;
   başarılı logout sonrası yerel scope kapatma; online/offline başlangıç.
3. İzole test ortamında Vite/HTTPS localhost ve Vercel → Render akışını browser
   ile test edin. Auth header'ları, rate-limit IP davranışı, cookie silme,
   CDN/SW cache dışlaması ve race senaryoları doğrulanmadan yayına çıkmayın.
4. Bu geliştirme projesinde test kullanıcılarının yeniden giriş yapması kabul
   edildi. Yeni frontend eski accessToken/refreshToken anahtarlarını bilinçli
   olarak kaldırıp yeni login akışını kullanmalı; user cache ve IndexedDB
   outbox/timer kayıtlarını topluca silmemelidir. Marker olmayan eski profile
   cookie'den otomatik hesap keşfi yapılmaz.
5. PWA güncellemesinin tüm açık sekmelere ulaştığını doğrulayın. Eski service
   worker kaldırıldı diye çalışan eski JS sekmeleri anında yeni koda dönüşmez.
   Yeni sürümü alma/yeniden açma yönlendirmesi ve sürüm geçişi testi gerekir.
   Browser site verisini topluca temizlemeyi varsayılan çözüm yapmayın; offline
   kişisel outbox'ın henüz gönderilmemiş verilerini kaybettirebilir.
6. Eski APK güncellenmeden yeni auth sözleşmesiyle çalışmayacaktır. Vercel'de
   frontend yayınlamak APK içindeki paketi güncellemez. Android güvenli taşıma
   ve gerçek cihaz testleri bitmeden eski APK'yı destekleniyormuş gibi
   dağıtmayın; kullanıcı/test ekibine güncelleme gerekliliğini bildirin.
7. Backend ve yeni frontend'i planlı aynı yayın penceresinde devreye alın.
   Geçiş esnasındaki eski istemciler 400/403/401 görebilir; middleware kapatıp
   wildcard origin veya JSON token fallback'i ekleyerek bunu gizlemeyin.
8. Geri alma gerekirse frontend/backend sözleşmesini birlikte değerlendirin.
   Yeni frontend'i eski backend'le veya eski frontend'i yeni backend'le bırakmak
   auth'u düzeltmez. Cookie hataları nedeniyle veri tabanını silmeyin.

Mevcut JWT/session doğrulaması korunduğu için daha önce verilmiş geçerli access
token'lar session iptal edilmedikçe 15 dakikalık sürelerinin sonuna kadar
Bearer API'lerde çalışabilir. Eski frontend'ler yeni token yenileme
sözleşmesini kullanamaz. Koordineli yayın, eski token veya açık socket'lerin
kendiliğinden iptali anlamına gelmez. İhtiyaç varsa test session'ları mevcut
yetkili yönetim işlemleriyle ayrı yayın kararı kapsamında kapatılır; bu
teslimatta canlı toplu iptal yapılmadı ve bir SQL reset önerilmiyor.

## Gerçek ortam kabul testleri

- Chrome/Firefox/Safari hedefleri ve kurulu PWA: login, reload, yeni sekme,
  access expiry, refresh cookie expiry, logout, browser geri/ileri dönüşü.
- Aynı origin'de A/B hesap değişimi, iki eşzamanlı login, refresh–logout,
  gecikmiş A logout, request abort, response loss ve sekme kapanması.
- Offline sıcak/soğuk açılış, timer çalışması, outbox birikimi ve reconnect;
  internet yokken logout'un başarılı gösterilmemesi.
- Başarılı logout ve kesin session iptali sonrası önceki kişisel timer'ların
  standalone görünmemesi; doğru hesapla yeniden girişte doğru scoped outbox.
- Yönetici kapatma ve superadmin force-logout; HTTP reddi ve socket disconnect.
- Gerçek Vite/Vercel proxy'de Origin/Set-Cookie aktarımı, auth yanıtının cache'e
  alınmaması, API için index.html dönmemesi ve limit anahtarının doğru olması.
- Gerçek Android cihazda frontend sözleşmesindeki native kontrol listesi.

Bu manuel/canlı/Android kontrolleri bu teslimatta yapılmadı. Backend testlerinin
geçmesi bunların geçtiği anlamına gelmez; tam uygulama yayına hazır ilan edilmedi.

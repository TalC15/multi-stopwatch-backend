# KeepTimer — Backend token güvenliği, Aşama 1

Tarih: 2 Ekim 2026. Bu teslimat yalnızca backend aşamasıdır.

## Sonuç ve kapsam

Web/PWA giriş, refresh ve logout işlemleri mevcut `/auth/login`,
`/auth/refresh`, `/auth/logout` endpoint'lerinde cookie sözleşmesine geçirildi.
Refresh token JSON'dan alınmıyor ve JSON yanıtında döndürülmüyor. Access token
JWT olarak dönmeye devam ediyor. Frontend henüz değiştirilmedi; eski frontend
ve APK'nın bu auth sözleşmesiyle çalışması beklenmemelidir.

Temel kaynak: `KEEPTİMER BACKEND GÜNCEL(1).zip` içindeki
`multi-stopwatch-backend-main/`.

ZIP SHA-256:
`c0be5408ae63f9ef19390c9c01f9603e15acdcb81ed41d3dd397ac5f3c3d2107`

Önceki patch'ler kullanılmadı. Frontend/APK dosyaları değiştirilmedi. Canlı
Render/Vercel/Supabase üzerinde işlem, git push veya dağıtım yapılmadı.
Yeni SQL migration, kullanıcı tablosu, authentication sistemi, token rotasyonu,
offline logout kuyruğu veya geçiş endpoint'i eklenmedi.

## Değiştirilen dosyalar ve fonksiyonlar

| Dosya | Değişiklik |
|---|---|
| `src/server.js` | Üç auth yoluna özel middleware; `webRefreshSession` ile cookie ve beklenen session kontrolü; login JSON'undan refresh kaldırılması; başarılı logout'ta cookie silme; auth altyapı hatalarını geçici hata olarak döndürme |
| `src/webAuth.js` — yeni | Origin yapılandırması, CSRF/content-type/method kontrolleri, route'a özel CORS, cookie okuma/yazma/silme, hassas yanıtlar için no-store ve genel hata işleyicisi |
| `src/auth.js` | Yalnızca superadmin oluşturma mesajındaki açık PIN log'u kaldırıldı; JWT/session doğrulama fonksiyonları değiştirilmedi |
| `test/http-disabled.test.js` | Mevcut hesap kapatma beklentileri yeni cookie/Origin/sessionId sözleşmesine uyarlandı |
| `test/web-auth.test.js` — yeni | Gerçek yerel HTTP ve Socket.IO sunucusu, sahte PostgREST yanıtları ve yerel reverse proxy ile sözleşme testleri |
| `test/auth-log.test.js` — yeni | Superadmin oluştururken PIN, hash, JWT secret ve servis anahtarının console.log'a yazılmaması |
| `docs/TOKEN_SECURITY_PHASE1*.md` — yeni | Bu rapor, frontend sözleşmesi, test/yayın talimatları |

`package.json` ve `package-lock.json` değişmedi. **Yeni bağımlılık yok.** Cookie
yazımı için mevcut Express `res.cookie`/`res.clearCookie`, CORS için mevcut
`cors` kullanıldı. Tek cookie okuyan küçük parser, duplicate ve bozuk cookie
değerlerini reddediyor; genel amaçlı cookie-parser eklenmedi.

## Yeni token ve cookie akışı

1. Browser `/api/auth/login` adresine aynı-origin POST gönderir; proxy bunu
   Render `/auth/login` adresine iletir.
2. Mevcut PIN doğrulaması, kullanıcı aktiflik kontrolü ve session insert'i
   çalışır. Başarılı insert sonrasında refresh JWT `Set-Cookie` ile yazılır.
3. JSON `{accessToken, sessionId, user}` içerir. Access token 15 dakika,
   refresh token 30 gün geçerlidir; JWT claim yapısı değişmedi.
4. Refresh, cookie ve JSON `{sessionId}` ile yapılır. Cookie JWT imzası/süresi,
   tipi, session sahibi, hash, revoked durumu ve mevcut
   `keeptimer_refresh_session` RPC kontrolü korunur.
5. Refresh yalnızca `{accessToken, sessionId}` döndürür. Cookie tekrar
   yazılmaz; süresi uzatılmaz ve refresh rotasyonu yapılmaz.
6. Logout aynı cookie/sessionId kontrolünden geçer. Yalnızca ilgili session
   iptal edilir, o session'ın socket'leri kapatılır; sonra cookie silinir ve
   `{success:true, sessionId}` döner. Zaten iptal edilmiş ama cookie'si hâlâ
   geçerli session için işlem idempotenttir.

Cookie adı `__Secure-keeptimer-refresh`; `HttpOnly; Secure; SameSite=Lax;
Path=/api/auth`; Domain yok. Expires, JWT'nin mutlak `exp` zamanıdır. Browser
yolu ile Express yolu bilinçli olarak farklıdır. Silme aynı cookie seçenekleri
ile yapılır. Hata yanıtları cookie oluşturmaz/silmez.

`sessionId` gizli bir token veya yetki kanıtı değildir. İstek gövdesindeki
sessionId yalnızca cookie ile doğrulanmış kimlikle eşleşmek zorundadır.
Frontend user/role/workspace cache'i backend yetkisi olarak kullanılmaz.

## Güvenlik önlemleri ve sınırları

### CSRF, Origin, CORS

`AUTH_ALLOWED_ORIGINS` virgülle ayrılmış tam origin listesi olarak okunur.
HTTPS zorunludur; HTTP yalnızca localhost/127.0.0.1/[::1] için kabul edilir.
Path, kullanıcı bilgisi veya wildcard içeren değerler geçersizdir. Eksik/boş
yapılandırmada yalnızca web auth yolları 503 ile kapalı kalır. Hatalı URL
yapılandırması başlangıç hatasıdır; otomatik wildcard fallback yoktur.

Üç auth endpoint'inin POST isteklerinde izin verilen `Origin`,
`Content-Type: application/json`, `X-KeepTimer-CSRF: 1` zorunludur.
Bu sabit başlık bir sır değildir; Origin kontrolüyle birlikte tarayıcıların
çapraz-origin istek kurallarından yararlanır. HTML form içerik türleri,
Origin eksik/null/uygunsuz olduğunda istekler reddedilir. Referer/Host veya
istemci kaynaklı forwarded-host üzerinden izin üretilmez.

CORS auth yollarında yalnızca tanımlı origin, POST ve belirtilen başlıklara
izin verir. OPTIONS güvenlik kontrollerini atlayıp login yapmaz. Diğer Bearer
HTTP yolları, Socket.IO CORS'u ve Telegram webhook'u mevcut davranışını korur.
SameSite veya CORS tek başına CSRF çözümü olarak kullanılmadı.

### Önbellek, hata ve log davranışı

Auth middleware, gövde parse edilmeden önce `Cache-Control`,
`CDN-Cache-Control` ve `Vercel-CDN-Cache-Control` değerlerini `no-store`
yapar. Başarılı/hatalı yanıtlar ve preflight bu kapsamda; Pragma no-cache
ve Vary Origin de eklenir. Frontend SW/CDN kurallarının bu başlıkları
bozmaması sonraki aşamanın sorumluluğudur.

Eksik/bozuk cookie 401, farklı sessionId 409, hatalı gövde 400, yanlış içerik
türü 415, CSRF/Origin hatası 403 döner. Altyapı hataları 503 olarak ayrılır.
Login kullanıcı sorgusunun altyapı hatası artık yanlış PIN sayılmaz;
başarısız session insert'i de cookie yazmaz. Bilinmeyen auth istisnaları
ham hata/stack/request döndürmez. Auth işlemlerindeki ham DB hata log'ları
yerine sabit mesajlar kullanıldı; mevcut açık bootstrap PIN log'u kaldırıldı.

Bu çalışma uygulamanın tüm log noktalarını veya bütün XSS yüzeylerini
denetleyen kapsamlı bir güvenlik incelemesi değildir.

### Rate limit ve proxy güveni

Login hâlâ tek endpoint ve aynı loginLimiter üzerinden geçer: IP başına
15 dakikada 10 deneme; kullanıcı adına 15 dakikada 5 başarısız deneme.
Sayaçların mevcut süreç içi yapısı değişmedi. Yeni bypass login yolu yoktur.

Mevcut `trust proxy: 1` korundu. Kod keyfî X-Real-IP'yi veya XFF'nin en sol
değerini seçmez. Testte saldırganın en soldaki XFF/X-Real-IP değerlerini
değiştirmesi, sabit en yakın ingress değerine uygulanan limiti aşamıyor.
**Bu, Render'ın gerçek zincirini doğrulayan bir test değildir.** Numeric hop
güveni, uygulamaya tüm yolların güvenilir ingress üzerinden ulaştığı ve
ingress'in XFF'yi doğru eklediği/yenilediği varsayımına dayanır.

Vercel → Render zincirinde `req.ip` gerçek kullanıcı yerine proxy adresi
olabilir; kullanıcılar aynı rate-limit kotasında toplanabilir. Doğrudan
backend erişimi ve proxied erişim farklı uzunluktaysa sırf kullanıcı IP'sini
elde etmek için trust proxy değerini 2/true yapmak güvenli değildir. Yayın
öncesi iki giriş yolu, sahte forwarded başlıklar ve gerçek ingress davranışı
doğrulanmalıdır. Bu belirsizlik nedeniyle yeni bir IP başlığına güvenen kod
eklenmedi. Login kimlik bilgileri bu kontrollerden bağımsız doğrulanır.

### Rotation kararı

Refresh rotasyonu eklenmedi. Çalınan refresh token mevcut 30 günlük mutlak
süre veya session iptaline kadar kullanılabilir. HttpOnly bunu geçmişte
çalınmış kopyalar için düzeltmez; JavaScript'in kalıcı refresh token'ını
okuyabilmesi riskini azaltır. Bellek access token'ı ve HttpOnly cookie aktif
XSS'nin kullanıcı adına istek yapmasını tamamen engellemez.

Rotation ve reuse detection, çalınmış bir refresh token'ın yeniden kullanımını
tespit etme ve oturumu iptal etme avantajı sunabilir. Bunun doğru uygulanması
atomic hash değişimi, birden fazla sekmede eşzamanlı refresh, kayıp yanıt,
tekrar deneme ve gerekirse önceki-token toleransı/oturum zinciri kararları
gerektirir. Mevcut tek hash/RPC sistemini yalnız token taşımasını değiştirmek
için genişletmedim. JWT doğrulama, hash karşılaştırma, DB session iptali ve
aktiflik kontrolleri korunuyor; rotasyon ayrı değerlendirilmesi gereken bir
iyileştirmedir, bu patch'in sağladığı bir özellik değildir.

### Logout ve yarış koşulları

Ürün kararına uygun olarak offline logout kuyruğu yoktur. Frontend 200 ve
eşleşen sessionId/success sonucu görmeden kullanıcıya başarılı logout
bildirmemelidir. Ağ hatası/503 doğrulanmış çıkış değildir.

Backend'in çözdüğü: A sekmesinin sessionId'siyle B cookie'si gönderilirse 409
gelir; B iptal edilmez ve cookie silinmez. Eski A cookie'siyle doğrulanmış
logout yalnızca A session'ını iptal eder. Hata/refresh yanıtlarında cookie
yazılmaması ek yarış kaynaklarını azaltır.

Backend'in çözemediği: A logout yanıtı B login yanıtından sonra browser'a
ulaşırsa A'nın silme Set-Cookie'si aynı isimli B cookie'sini silebilir.
Test bu durumu bilerek görünür kılar; çözüldüğü iddia edilmez. Login,
refresh ve logout frontend'de sekmeler arasında sıralanmalı; beklenen session
ve generation her await sonrasında kontrol edilmelidir. Lock yalnız JSON'u
state'e yazarken değil ağ isteği ve yanıtını kapsamalıdır. Timeout/abort veya
sekme kapanmasıyla bir cookie-mutating isteğin sonucu belirsiz kaldıysa bunu
başarı sayıp yeni login'i serbest bırakmak yeterli değildir. Ayrıntılı
uzlaşma/sıralama sözleşmesi frontend belgesindedir.

## Korunan sistemler

- `src/auth.js` access doğrulaması JWT yanında güncel kullanıcı role,
  workspace, disabled_at ve session revoked_at bilgilerini okumaya devam eder.
- Access token HTTP Bearer ve Socket.IO handshake.auth.token için korunur.
- `/users/:id/force-logout` mevcut şekilde **yalnız superadmin** içindir.
  Manager'ın yetkisi genişletilmedi. Manager ve superadmin'ın mevcut çalışan
  hesap kapatma yolu korunur; ilgili session/socket iptali test edilir.
- Timer API'leri, personal mutation/revision/ACK ve shared v5 kodları,
  Telegram/notification işleri ve veritabanı migration'ları değiştirilmedi.
- Standalone/kişisel/ortak kayıtların depolanması, offline kişisel outbox ve
  local user cache yeni sunucu yetkisi olarak kullanılmaz; frontend aşaması
  bunların mevcut kapsam sınırlarını korumalıdır.

## Test sonuçları

Ortam: Node v24.19.0, npm 11.9.0. Orijinal lockfile ile `npm ci --no-audit
--no-fund`: 134 paket kuruldu; dependency dosyaları değişmedi. İlk offline
kurulum denemesi eksik npm cache'i nedeniyle, sandbox içi test denemeleri
yerel listen EPERM nedeniyle tamamlanamadı. Yetkilendirilmiş ağ/yerel port
erişimiyle aşağıdaki gerçek test çalıştırmaları yapıldı.

| Çalıştırma | Sonuç |
|---|---|
| İlk hedefli HTTP/cookie testleri | 25 test, 25 başarılı, 0 başarısız |
| İlk tüm backend testi | 103 test, 84 başarılı, 0 başarısız, 19 atlandı |
| Son hedefli auth/log testleri | 28 test, 28 başarılı, 0 başarısız, 0 atlanan |
| Temiz ZIP'e patch uygulandıktan sonraki tüm backend testi | 104 test, 85 başarılı, 0 başarısız, 19 atlanan |
| `git diff --check` ve temiz kopyada `git apply --check` | Başarılı; temiz orijinale uygulanabilir, test edilen kodla aynı |

Kesin komutlar ve gerçek PostgreSQL yönergeleri:
`TOKEN_SECURITY_PHASE1_TEST_RELEASE.md`.

HTTP testleri gerçek yerel Express/Socket.IO çalıştırır; Supabase yanıtları
test doubles ile sağlanır. Mevcut DB iş kuralı testleri PGlite üzerinde çalışır.
19 ayrı-bağlantılı gerçek PostgreSQL testi bu ortamda çalıştırılmadı. Yerel
reverse proxy testi header/path aktarımını sınar, gerçek Vercel/Render veya
tarayıcı cookie politikalarının doğrulanması anlamına gelmez.

## Doğrulanmamış noktalar ve bilinen riskler

1. Gerçek Vite/Vercel/Render Set-Cookie aktarımı, CDN ayarları, Origin taşıma
   ve rate-limit IP çözümlemesi henüz test edilmedi.
2. Android APK/WebView cookie jar, third-party cookie kabulü, native bridge
   erişimi ve uygulama yaşam döngüsü test edilmedi. Native token endpoint'i
   veya yeni depolama sistemi eklenmedi. Cookie-only Lax web sözleşmesi
   cross-site APK isteklerinde doğrudan çalışacak diye kabul edilmemelidir.
3. Bu API JWT/session çekirdeğini native desteğe kapatmaz. Ancak Android için
   ileride cookie dışı güvenli taşıma seçilirse ayrı, açıkça tasarlanmış bir
   taşıma sözleşmesi gerekecektir; bugün body refresh fallback'i yoktur.
4. Eski PWA cache'leri ve APK paketleri otomatik dönüşmez. Koordineli sürüm,
   zorunlu güncelleme/re-login ve veri kaybını önleyen geçiş testi gereklidir.
5. Offline cihaz sunucu iptalini bağlantı kurmadan öğrenemez. Mevcut socket
   doğrulaması handshake sırasında yapılır; açık socket sırf access süresi
   doldu diye kapanmaz. Force-logout yolları aktif disconnect yapar; doğrudan
   DB değişikliği aynı uygulama olayını otomatik üretmez.
6. Mevcut superadmin bootstrap kodu, SUPERADMIN_PIN eksikse bilinen `1234`
   varsayılanını kullanıyor. PIN log'u kaldırıldı; varsayılan değiştirilmedi.
   Yetkisiz erişim riski nedeniyle yayın yapılandırmasında güçlü bir
   SUPERADMIN_PIN zorunlu kabul edilmeli ve mevcut test admin hesabı ayrıca
   kontrol edilmelidir. Env değiştirmek var olan hesabın PIN'ini değiştirmez.
7. Backend geneli için sıfır açık veya üretim güvenliği garantisi verilmez.
   Yeni patch bir token taşıma ve web auth koruması iyileştirmesidir.

## Teknik kaynaklar

Proje kaynakları yukarıdaki dosya/fonksiyon tablosunda verilmiştir. Platform
davranışları için 2 Ekim 2026 tarihinde kontrol edilen resmi belgeler:

- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [MDN Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)
- [Express behind proxies](https://expressjs.com/en/guide/behind-proxies/)
- [Vercel external rewrites](https://vercel.com/docs/routing/rewrites)
- [Vercel external-origin cache değişikliği, 30 Mart 2026](https://vercel.com/changelog/vercels-cdn-now-respects-cache-control-headers-from-external-origins-by-default)
- [Vercel cache başlıkları](https://vercel.com/docs/caching/cache-control-headers)
- [Vite server.proxy](https://vite.dev/config/server-options)
- [Capacitor config](https://capacitorjs.com/docs/config)
- [Android CookieManager](https://developer.android.com/reference/android/webkit/CookieManager)

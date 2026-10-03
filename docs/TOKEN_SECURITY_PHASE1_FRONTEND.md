# KeepTimer — Frontend entegrasyon sözleşmesi

Bu belge backend Aşama 1'in uygulanmış sözleşmesidir. Frontend, Vite, Vercel
ve APK dosyaları bu teslimatta değiştirilmemiştir. Aşağıdaki frontend örnekleri
sonraki aşamada kullanılmak üzere belgedir; kurulmuş bir proxy değildir.

## Adresler ve zorunlu istek özellikleri

| Browser'ın gördüğü URL | Render'ın gördüğü URL |
|---|---|
| `/api/auth/login` | `/auth/login` |
| `/api/auth/refresh` | `/auth/refresh` |
| `/api/auth/logout` | `/auth/logout` |

Üç işlem de POST ve JSON'dur. Browser frontend origin'ine göreli URL kullanır.
Her birinde `Content-Type: application/json` ve `X-KeepTimer-CSRF: 1` zorunlu.
`Origin` browser tarafından gönderilir; frontend JS bu forbidden header'ı
elle ayarlamaya çalışmamalıdır. Proxy gerçek Origin'i korumalıdır.
`credentials: 'same-origin'`, `cache: 'no-store'` kullanılmalıdır.
Cookie başlığı frontend JS tarafından oluşturulmaz; refresh JWT okunmaz.

Backend env:

```dotenv
AUTH_ALLOWED_ORIGINS=https://YOUR-PRODUCTION-FRONTEND.example,http://localhost:5173
```

Yer tutucuyu gerçek frontend origin'iyle değiştirin. Sondaki slash, path,
wildcard veya bütün `*.vercel.app` domain'lerini kabul eden kural kullanmayın.
Gerekirse her test/preview origin'ini ayrı ekleyin; güvenilmeyen preview
deployment'larına production auth izni vermeyin. Origin listesi başlangıçta
okunur; değişiklik backend restart gerektirir. Localhost portu listeyle aynı
olmalıdır. Mevcut JWT_SECRET, Supabase ve diğer backend env'leri korunur.

## Login

```http
POST /api/auth/login
Content-Type: application/json
X-KeepTimer-CSRF: 1
Origin: https://YOUR-PRODUCTION-FRONTEND.example

{"username":"worker","pin":"1234"}
```

PIN örneği yalnız test içindir. İki değer de dolu string olmalıdır. Login
gövdesine userId, role, workspace, refreshToken veya başka alan eklemeyin.

200 yanıtının yapısı:

```json
{
  "accessToken": "<access-JWT>",
  "sessionId": "<session-UUID>",
  "user": {
    "id": "<user-UUID>",
    "username": "worker",
    "role": "worker",
    "workspace_id": "<workspace-UUID veya null>"
  }
}
```

`workspace_id` workspace yoksa JSON `null` değeridir, string "null" değildir.
Backend ayrıca aşağıdaki refresh cookie'sini yazar. JSON'da refresh token yoktur.

Frontend access token'ı yalnız bellekte saklamalıdır. User cache'i mevcut UI
ve yerel kapsam amaçlarıyla devam edebilir. Yeni `sessionId` gizli değildir;
reload ve sekme koordinasyonu için kalıcı bir session işareti içinde
saklanabilir. Kimlik doğrulama kanıtı olarak kullanılmaz.

## Refresh

```http
POST /api/auth/refresh
Content-Type: application/json
X-KeepTimer-CSRF: 1
Origin: https://YOUR-PRODUCTION-FRONTEND.example
Cookie: __Secure-keeptimer-refresh=<browser otomatik ekler>

{"sessionId":"<bu sekmenin beklediği session-UUID>"}
```

200 yanıtı:

```json
{"accessToken":"<yeni-access-JWT>","sessionId":"<aynı-session-UUID>"}
```

Refresh token dönmez; Set-Cookie yazılmaz; cookie'nin 30 günlük mutlak ömrü
uzatılmaz. Dönen token'ın süresi 15 dakikadır. JSON gövdesi tam olarak tek
`sessionId` alanı içermelidir. Eski `{refreshToken: ...}` yöntemi desteklenmez.

SessionId zorunludur; cookie var ama yerel session işareti kayıpsa bu API
anonim bir bootstrap/hesap keşif endpoint'i değildir. Kullanıcı tekrar giriş
yapar. Geliştirme hesapları için bu davranış kabul edilen yeniden giriş
kararıyla uyumludur; eski localStorage refresh token'ını yeni endpoint'e
aktaracak migration köprüsü yoktur.

## Logout

Refresh ile aynı başlıklar ve `{sessionId}` gövdesi kullanılır.

200 yanıtı:

```json
{"success":true,"sessionId":"<iptal edilen-session-UUID>"}
```

Cookie aynı name/Path/Domain kapsamında, geçmiş Expires ile silinir.
200, doğrulanmış bu session'ın iptal edildiği veya zaten iptal edilmiş
olduğunun doğrulandığı anlamındadır. Cookie hâlâ istemcideyse aynı session
logout isteği tekrarlanabilir. Cookie silindikten sonra tekrar gönderilen
istek 401 alır; cookiesiz isteğe doğrulanmış logout başarısı verilmez.

**Ürün kararı:** internet ve eşleşen sunucu sonucu olmadan başarılı logout
gösterilmez. Ağ hatası/timeout/503 geldiğinde yerel user/session/cache'i
silip standalone'a geçmiş gibi davranmayın. Yeni offline logout kuyruğu yoktur.
İşlem sürerken hesap değiştiren auth işlemleri sıraya alınmalıdır.

401, session'ın artık kullanılamadığını gösteren ayrı bir sonuçtur; mevcut
oturumun sona ermesini UI'da işlemek mümkündür, fakat bunu başarılı kullanıcı
logout cevabı diye sunmayın. İstek başladıktan sonra session değişmişse eski
401 veya 200 yeni hesabın yerel verisini temizlememelidir.

## Cookie ayrıntıları

| Alan | Değer |
|---|---|
| Name | `__Secure-keeptimer-refresh` |
| HttpOnly | `true` |
| Secure | `true`, ortamdan bağımsız |
| SameSite | `Lax` |
| Domain | Yok; browser'ın gördüğü frontend host'una özgü |
| Path | `/api/auth`; upstream `/auth` değildir |
| Expires | İmzalı refresh JWT exp zamanı; login'den yaklaşık 30 gün |
| Max-Age | Ayrıca ayarlanmıyor; mutlak Expires kullanılıyor |
| Refresh yanıtında değiştirme | Yok |
| Hata yanıtında temizleme | Yok |
| Başarılı logout | Aynı seçeneklerle geçmiş Expires |

Örnek login başlığı:

```http
Set-Cookie: __Secure-keeptimer-refresh=<JWT>; Path=/api/auth; Expires=<JWT exp>; HttpOnly; Secure; SameSite=Lax
```

Dar Path kullanıldığı için `__Host-` yerine `__Secure-` seçildi. Path bir
yetkilendirme sınırı değildir. Proxy Set-Cookie'yi iletmeli; Domain=Render veya
Path=/auth eklememeli ve JSON'a çevirmemelidir. Browser JS Set-Cookie başlığını
okumaya ihtiyaç duymaz. Host-only cookie portlara göre ayrılmaz; aynı localhost
host'undaki farklı portlarda çalışan geliştirme uygulamalarında cookie isim
çakışmasına dikkat edin. Test için ayrı browser profili kullanılabilir.

HTTP localhost Secure cookie istisnası browser'a bağlı doğrulanmalıdır.
localhost, 127.0.0.1 ve LAN IP erişimlerini eşdeğer saymayın. Sorunu çözmek
için production Secure'ı kapatmayın; gerekirse HTTPS local geliştirme kullanın.

## Hata sözleşmesi

Bütün uygulama auth hatalarında `{error: string}` bulunur; aşağıdaki yeni
korumalarda `code` de bulunur. Eski DB/PIN hata mesajlarının tümüne yeni code
eklenmedi; frontend metin karşılaştırmak yerine HTTP durumunu esas almalıdır.

| HTTP | Durum / varsa code | Frontend davranışı |
|---|---|---|
| 200 login | accessToken/sessionId/user | Yalnızca hâlâ güncel login işleminin sonucunu uygula |
| 200 refresh | accessToken/sessionId | Belleği güncelle; kullanıcı/workspace kapsamını kendiliğinden değiştirme |
| 200 logout | success:true/sessionId | Güncel bağlamı doğrula; yerel logout olaylarını/temizliğini uygula |
| 400 | Gövde bozuk, eksik/uygunsuz sessionId veya ek alan; `AUTH_BODY_INVALID` | İstemci sözleşme hatası; refresh döngüsü yapma |
| 401 login | Yanlış PIN, bilinmeyen veya disabled kullanıcı; ortak hata mesajı | Login başarısız; başka mevcut session'ı silme |
| 401 refresh | Eksik/bozuk/expired cookie, JWT türü/imza hatası, session yok/revoked, hash uyumsuz veya hesap disabled | Yalnız güncel session için oturum sona ermesini işle |
| 401 logout | Cookie/session doğrulanamadı | Başarılı logout sayma; güncel session'ın geçersizliğini ayrı işle |
| 403 | `AUTH_ORIGIN_REJECTED` veya `AUTH_CSRF_REJECTED` | Yapılandırma/güvenlik hatası; yeniden login deneme döngüsü yok |
| 405 | `AUTH_METHOD_REJECTED` | POST/OPTIONS dışında yöntem desteklenmiyor |
| 409 | `AUTH_SESSION_CHANGED` | Eski sekme/istek; başka session cookie'sini veya global user cache'ini silme |
| 413 | Çok büyük JSON gövdesi; `AUTH_BODY_INVALID` | İstemci hatası; tekrar deneme yok |
| 415 | Yanlış Content-Type (`AUTH_CONTENT_TYPE_REJECTED`) veya gövde kodlaması (`AUTH_BODY_INVALID`) | İstek biçimini düzelt |
| 429 login | Mevcut IP veya kullanıcı-adı limiti | Bekleme göster; yeni auth yolu deneyerek aşma |
| 503 | DB/geçici auth hatası; bazı genel hatalarda `AUTH_UNAVAILABLE`; eksik env'de `AUTH_NOT_CONFIGURED` | Otomatik logout yok; geçici hata ile yanlış yapılandırmayı ayır |
| HTTP yanıtı yok | Offline, timeout, proxy/network sorunu | İşlemin sonucunu varsayma; logout başarısı bildirme |

Gövde doğrulaması cookie kontrolünden önce gelir: boş `{}` ile refresh
gönderilirse cookiesiz olsa bile 400 alınır; doğru sessionId gövdesiyle cookie
yoksa 401 alınır. Geçerli cookie başka session'a aitse 409 gelir. Backend
503/401/409 yanıtlarında cookie'ye müdahale etmez.

Her auth yanıtında `Cache-Control: no-store`, `CDN-Cache-Control: no-store`,
`Vercel-CDN-Cache-Control: no-store` ve `Pragma: no-cache` bulunur.
Preflight izinli origin için 204'tür; Access-Control-Allow-Origin tam origin,
Allow-Credentials true, Allow-Methods POST, Allow-Headers Content-Type ve
X-KeepTimer-CSRF'dir. Eksik/yanlış preflight Origin reddedilir; desteklenmeyen
istenen yöntem 405'tir. İlave header'lara browser CORS izni verilmez.

## Vite örneği — yalnız dokümantasyon

Mevcut `vite.config.js` plugins/PWA/alias bölümlerini koruyarak server alanına
aşağıdaki ayarlar eklenebilir. Bu dosya backend patch'iyle oluşturulmaz.

```js
server: {
  port: 5173,
  strictPort: true,
  proxy: {
    '^/api/auth(?:/|$)': {
      target: 'https://multi-stopwatch-backend.onrender.com',
      changeOrigin: true,
      secure: true,
      rewrite: path => path.replace(/^\/api\/auth(?=\/|$)/, '/auth'),
    },
  },
}
```

`changeOrigin` upstream Host içindir; browser Origin'ini Render origin'iyle
değiştiren ek kod yazmayın. TLS doğrulamasını devre dışı bırakmayın. Standart
Vite geliştirmesinde `AUTH_ALLOWED_ORIGINS` içinde `http://localhost:5173`
bulunmalıdır. HTTPS veya farklı port kullanılırsa tam origin'i güncelleyin.

## Vercel örneği — yalnız dokümantasyon

Mevcut proje routing/header ayarlarıyla birleştirin. Auth rewrite, SPA fallback
kuralından önce gelmelidir. Aşağıdaki örnekte backend hedefi mevcut Render'dır.

```json
{
  "rewrites": [
    {
      "source": "/api/auth/:path*",
      "destination": "https://multi-stopwatch-backend.onrender.com/auth/:path*"
    },
    { "source": "/(.*)", "destination": "/index.html" }
  ],
  "headers": [
    {
      "source": "/api/auth/:path*",
      "headers": [
        { "key": "Cache-Control", "value": "no-store" },
        { "key": "CDN-Cache-Control", "value": "no-store" },
        { "key": "Vercel-CDN-Cache-Control", "value": "no-store" },
        { "key": "x-vercel-enable-rewrite-caching", "value": "0" }
      ]
    }
  ]
}
```

Dashboard'daki routing/CDN kuralları da kontrol edilmeli; auth yolu için cache
etkinleştiren bir kural bırakılmamalıdır. Vercel'in external-origin cache
varsayılanlarının her projede aynı olduğu varsayılmamalıdır. Gerçek login,
refresh ve logout üzerinde Set-Cookie, Origin, HTTP durum kodu ve no-store
aktarımı browser Network panelinden doğrulanmalıdır.

Diğer REST API ve Socket.IO Render'a doğrudan bağlanmaya devam edebilir.
Auth prefix'i için yapılan değişiklik bütün `BASE_URL` kullanımını topluca
aynı-origin'e çevirme gerekçesi değildir. Socket.IO cookie auth'a geçirilmez.

## Başlangıç, reload, offline ve yeniden bağlantı

1. Hesapsız/standalone mod ağ isteği veya login gerektirmeden çalışır.
2. Daha önce giriş yapılmışsa user cache ve gizli olmayan session işaretiyle
   yerel kişisel sayaç kapsamı açılabilir. Bellekte access olmaması kendi
   başına logout nedeni değildir. Local veriler backend yetkisi değildir.
3. Online başlangıçta aynı session için tek bir koordineli refresh yapılır.
   API gönderimleri, personal outbox flush ve ilk socket bağlantısı access
   hazır olana kadar bekler. Uygulama kabuğu/yerel sayaçlar gereksiz yere
   network yanıtına kilitlenmez.
4. Başlangıç offline ise timer/IndexedDB kullanımı sürer; yeni offline profil
   doğrulama mekanizması eklenmez. Başarısız refresh=logout eşitliği kurulmaz.
5. Ağ geri gelince session/generation kontrolü, refresh ve ardından scoped
   outbox/shared reconcile/socket akışı çalışır. Aynı mutationId/revision/body
   tekrar kullanma ve ACK kuralları korunur.
6. 401 veya server revocation kesinleşince sadece güncel scope kapatılır.
   Geçici ağ/503 bu sonuca dönüştürülmez. Role/workspace yetkisi backend'in
   güncel DB kontrolünde kalır.

Frontend'deki başlıca uyarlama yerleri `src/services/backendSync.js`,
`workspaceSession.js`, `sharedApi.js`, `socket.js`,
`src/sync/personalSyncApi.js`, `src/stores/stopwatchController.js`,
`src/main.js`, `src/App.vue`, `src/router/index.js`'dir. Raw refresh string'i
ile yapılan snapshot/storage karşılaştırmaları gizli olmayan session işaretine
taşınmalı; cookie değişiminin `storage` olayı üretmediği unutulmamalıdır.

## Sekmeler, gecikmiş yanıtlar ve cookie mutasyonlarının sıralanması

- Aynı browser origin'i için login/refresh/logout ortak auth kilidi kullanmalı.
  Mevcut Web Locks tabanı uygun bir başlangıçtır; kilit fetch gönderimi,
  response/header işleme, JSON okuma ve yerel commit tamamlanana kadar tutulur.
  Yalnız token state'i yazarken kilitlemek yeterli değildir.
- Kilit içinde gönderimden önce beklenen session/user/tab/generation yeniden
  kontrol edilir. İstek sonrası ve JSON parse sonrası tekrar kontrol edilir.
  Eski sekme otomatik olarak yeni hesabın sessionId'sini alıp işlem yapmamalıdır.
- Login cevabındaki `sessionId` tüm aktif oturum işaretinin parçası olur.
  Sekmelerin sessionStorage bağları ve localStorage/storage bildirimleri
  korunur; kalıcı access/refresh token tekrar eklenmez.
- Refresh yanıtında Set-Cookie olmaması stale refresh'in yeni cookie'yi
  değiştirmesini önler. Yine de eski access yanıtını B hesabına uygulamamak
  frontend'in sorumluluğudur.
- Logout A cookie'si ile başladıktan sonra B login'i sıraya girmelidir.
  HTTP 200 gövdesi okunmadan ve A bağlamı doğrulanmadan B login gönderilmez.
  Logout sonucunun kullanıcıya uygulanması da session kontrollü olmalıdır.
- Timeout/abort, browser'ın Set-Cookie'yi uygulamadığını veya backend'in
  işlemi yapmadığını kanıtlamaz. Cookie-mutating login/logout belirsizse yeni
  hesap geçişi otomatik açılmamalı; "oturum işlemi doğrulanamadı" durumu
  saklanmalı ve sonraki adım aynı session altında koordineli doğrulama/tekrar
  giriş akışıyla ele alınmalıdır. Yeni bir offline logout kuyruğu oluşturmayın.
- Mevcut kilidin Web Locks desteklenmeyen ortamda doğrudan callback çalıştıran
  fallback'i gerçek bir sekmeler arası kilit değildir. Native tek WebView
  varsayımını çok sekmeli web'e genellemeyin. Bu ortam için güvenilir sıralama
  veya destek sınırı frontend aşamasında seçilmeli ve test edilmelidir.
- Sekme kapanması/çökmesi, kilidin düşmesi ve sonucu belirsiz login/logout gibi
  durumlarda yalnız kilit/sessionId ile bütün Set-Cookie yarışlarının bittiği
  ileri sürülemez. Sabit isimli tek cookie kullanılan bu backend, response
  browser'a ulaştığında conditional compare-and-set yapamaz. Bu sınır test ve
  ürün akışıyla açıkça ele alınmalıdır; backend'in çözdüğü şey DB session
  kapsamı ve stale isteği reddetmedir.

## Sayaçlar, PWA ve bildirimler

Başarılı logout veya güncel session'ın kesin geçersizliği sonrasında
workspace-personal ve shared görünüm scope'u kaldırılmalı; önceki kişisel iş
sayaçları **asla standalone'a dönüştürülmemelidir**. Mevcut explicit dataMode,
userId/workspaceId sorguları, outbox sahipliği ve stale response kontrolleri
korunur. Gerçek standalone kayıtlar ve workspace'i olmayan kullanıcıların
mevcut standalone davranışı değişmez. Veritabanını topluca silmeyin.

Logout pending aşamasında başarılı local logout olayını erken yayınlamayın;
bu ürün kararı eski frontend'deki ilk await öncesi local temizlemeden farklıdır.
Başarı/oturum iptali kesinleşince socket, scoped görünüm ve hesaba bağlı
yerel ses/bildirim temizliği birlikte uygulanmalıdır.

Auth yolları service worker runtime cache veya precache'e eklenmez. SPA
navigation fallback için `/api/auth` kapsamı denylist'e alınmalıdır; API yerine
index.html dönmesi engellenir. Uygulama kabuğunun offline cache'i korunur.
Service worker içinde ayrı token depolama/refresh sistemi kurulmaz.
Telegram webhook adresi Render üzerinde kalır; web Origin/CSRF kontrolüne
tabi tutulmaz. Sunucu timer işlerinin anlamı değiştirilmez.

## Android — sonraki aşamada gerçek cihaz doğrulaması

Mevcut Capacitor yapılandırmasının beklenen Android origin'i `https://localhost`;
üretilmiş APK ve native yapılandırma bu aşamada doğrulanmadı. Yerel paket
içindeki `/api/auth` isteği Vercel'e gitmez. SameSite=Lax web cookie'si,
WebView → Render cross-site akışının hazır çözümü değildir. Android origin'ini
allowlist'e eklemek tek başına cookie sorununu çözmez.

Test edilmesi gerekenler:

1. Gerçek Origin, WebView/Android sürümü, cookie kabulü ve third-party politikası.
2. Set-Cookie sonrası cookie'nin tekrar gönderilmesi; SameSite/Secure/Path
   davranışı ve credentials/CORS koşulları.
3. Uygulama kapatma/açma, force-stop, cihaz restart ve APK güncellemesi.
4. HttpOnly token'ın document.cookie veya kullanılan native API'lerden
   JavaScript'e açılmaması; native ve WebView cookie jar tutarlılığı.
5. Online logout, response loss, hesap değişimi, offline açılış ve reconnect.
6. Socket.IO, request abort/timeout, personal outbox ve bildirim yaşam döngüsü.
7. Web Locks/tek WebView varsayımı ve başka WebView/process olasılığı.

CapacitorHttp/CapacitorCookies'i bütün fetch/document.cookie davranışını
değiştirecek şekilde test etmeden etkinleştirmeyin. Native güvenli depolama
seçilirse aynı JWT/session çekirdeği kullanılabilir; bu backend'de geçici
güvensiz JSON refresh endpoint'i veya native fallback bulunmuyor.

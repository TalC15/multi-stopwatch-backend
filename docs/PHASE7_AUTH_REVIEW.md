# Faz 7 revizyonu — auth, owner ve geçiş

İnceleme yamasıdır; canlı SQL/deploy/commit/push yapılmadı. Auth ve sales release false kalır. Gerçek PostgreSQL 18, staging, Android build/cihaz ve bağımsız SOL-6.1 kabulü olmadan Faz 7 tamamlanmış sayılmaz. Önceki Faz 1–6 migration'ları değişmez.

## SQL sırası

16 Ekim teslim durumu: activation ve management production’da zaten uygulanmış kabul edilir; bu dosyalar değiştirilmez/yeniden çalıştırılmaz. Yeni `20261016_mfa_device_context.sql` kapılar false/false iken mevcut doğrulanmış owner ile, backend güncellemesinden önce hazırlanır. Cutover henüz uygulanmadı; bu görevde çalıştırılmaz. Aşağıdaki eski üç aşama tarihsel geçiş açıklamasıdır. Güncel ek sözleşme: [MFA_DEVICE_CONTEXT.md](MFA_DEVICE_CONTEXT.md).

1. 20261009_password_mfa_activation.sql: HAZIRLIK. Yeni private tablolar/RPC ve users üzerinde toplam tek Superadmin indeksi ekler; eski fonksiyon, trigger, hesap verisi veya session değiştirmez. Birden fazla Superadmin kimliği varsa veri silmeden tüm hazırlık rollback olur. enabled=false, cutover=false.
2. 20261009_password_mfa_management.sql: HAZIRLIK. Yeni MFA yönetim RPC/audit ekler; eski yönetici session'larını korur.
3. 20261009_password_mfa_cutover.sql: yalnız onaylı bakım penceresinde. Aynı owner bağlantısında keeptimer.phase7_cutover ayarı confirmed-maintenance olmalıdır. 5 saniye lock timeout, transaction rollback. Eski privileged/password session'ları iptal eder, rollback'e karşı session/user trigger'larını ve sales wrapper'larını kurar. cutover=true olur; enabled ve sales false kalır.

Alfabetik otomatik uygulama YANLIŞTIR: management hazırlığı cutover'dan önce gelir. Bu teslim güncel ZIP kaynaklarının üzerine device-mfa patch’leridir. Güncel ZIP’ler önceki güvenlik revizyonlarını zaten içerir; eski patch zincirini yeniden uygulamayın. Patch’lerin yerelde uygulanması SQL’in çalıştırılması anlamına gelmez; üç SQL dosyası ayrıca bu sırayla incelenir.

Owner preflight katalogdan current_user OID'sini, public keeptimer_* function/relation owner'larını ve temel tablo owner'larını karşılaştırır. Sabit postgres owner varsayılmaz. Eksik bağımlılık, farklı owner, service/browser owner veya güvensiz owner üyeliği transaction'ı durdurur. Owner uyuşmazlığı PUBLIC/EXECUTE grant açılarak çözülmez. Gerçek deployment kataloğu ayrıca doğrulanmalıdır.

SECURITY DEFINER search_path boştur; owner assertion SECURITY INVOKER'dır. Yeni tablolar RLS açık, PUBLIC/anon/authenticated/service_role doğrudan erişime kapalıdır. Service yalnız auth_limit, auth_session, auth_command, link_queue_rpc, maintain, management RPC'lerini çalıştırır. Prepare/recover, inner helper'lar ve yeniden adlandırılan eski sales fonksiyonları owner-only. Üç migration sonunda PostgREST reload NOTIFY vardır. Service credential güvenilir backend sınırıdır; çalınmış service credential'a karşı bu RPC'ler bağımsız ikinci güven sınırı diye sunulmaz.

## Auth sözleşmesi

Şirket worker/manager PIN korunur. Individual yalnız aktive worker/password ve tutarlı private workspace/owner ile girer. Expired subscription login'i engellemez; premium hakkı açmaz. Superadmin/Agent yalnız web parola+OTP; eski PIN/native privileged giriş kapalıdır.

Access JWT 15 dakika, refresh JWT 30 gün; Individual DB session üst sınırı 30 gün, privileged DB/MFA üst sınırı 15 dakika; refresh bu süreyi uzatmaz. MFA yeni UUID yaratır. Ortak HTTP/Socket validator güncel user/session/version kontrol eder. Privileged timer/Telegram/Socket scope'u verilmez; şirket/Individual scope, entitlement ve outbox önceki kurallarla korunur.

Web POST JSON, exact Origin, X-KeepTimer-CSRF:1 ve no-store korunur. /api/auth proxy üzerinden Secure/HttpOnly/SameSite=Lax çerezler kullanılır. MFA öncesinde access/refresh/user/session verilmez. İmzalı 30 günlük cihaz cookie’si ve parola doğrulanınca türetilen pre-auth cookie vardır; ikincisi mevcut refresh-cookie bağlamına bağlıdır. PIN login/logout pre-auth cookie’sini temizler; cihaz cookie’si ve DB kilidi korunur. Cookie bağlamı yetki değildir. Native ayrımı ayrı endpoint/guard’dan gelir; privileged MFA web ile sınırlıdır.

| POST endpoint | Davranış |
|---|---|
| /auth/password-login | email,password,operationId (web UUID); Individual session veya privileged MFA pending |
| /auth/native/passwordLogin | email,password; mevcut native guard; yalnız Individual |
| /auth/mfa/status | boş nesne; bağlam oluşturma veya sunucu durumuyla devam |
| /auth/mfa/verify | challengeId,context,code,operationId; bağlı nonce ve tek kullanım |
| /auth/mfa/resend | challengeId,context,operationId; nonce/cooldown/send/attempt sınırı |
| /auth/activation/request, /auth/reset/request | email; aynı genel kabul zarfı, bounded private queue |
| /auth/activation/complete, /auth/reset/complete | challengeId,context,password; session yaratmaz |
| /auth/password/change | Bearer, email,currentPassword,password; eski session/challenge iptal |
| /auth/sessions/list, /auth/sessions/revoke-all | Bearer ve boş nesne; yalnız kendi session'ları |
| /auth/refresh, /auth/native/refresh | Mevcut transport + canlı auth/version/MFA kontrolü |
| /auth/logout, /auth/native/logout | Yalnız eşleşen session revoke; native kesin başarı/401'de store temizliği |

Parola bcrypt12, en az 16 kod noktası, en çok 72 UTF-8 byte, kontrol karakteri yok. Bilinmeyen/unready hesap dummy bcrypt12 compare kullanır. Hazır Individual login mail yapılandırmasından bağımsızdır; crypto/release/hash/session şartları korunur. Yeni mail isteği ve privileged MFA mail config yokken kapanır. Önceden kabul edilmiş geçerli aktivasyon/reset token tüketimi yeniden mail göndermediği için provider config gerektirmez; gate/expiry/version/token kontrolleri korunur.

## Enumeration, kuyruk, retention

Senkron link yolu validate/normalize → account/IP limit → enqueue'dur. Hesap lookup, readiness, challenge yazımı ve mail ancak HTTP kabulünden sonra worker'da yapılır. En çok 200 queue kaydı; try-advisory capacity lock; busy/full/DB sorunu tüm hesaplara genel 503. Sleep/jitter yoktur. Kabul, teslimat garantisi değildir.

Worker 5 saniyede ve kabul cevabı bitince tetiklenir; instance başına tek drain, tur başına en çok 5 iş, 60 saniye lease/SKIP LOCKED. İş TTL 15 dakika, provider timeout 10 saniye. Kuyruk yalnız private email/purpose saklar, ham token/parola/OTP saklamaz. Process ölümü lease retry sağlar; exactly-once mail veya eski token'ın kurtarılacağı garanti edilmez.

auth_maintain iç RPC'si her tablo için indeksli en çok 64 satır temizler: limits başlangıcı 24 saatten eski, challenges expiry üzerinden 7 gün geçmiş, queue süresi/lease'i bitmiş. Kullanılmış/başarısız challenge da 7 gün saklanır. SKIP LOCKED aktif transaction'ı beklemez. Temizlik ayrı transaction'da worker döngüsündedir; dış cron veya public HTTP cleanup yok. Worker durursa retention gecikir; 15 dakikalık bütçeler bypass olmaz.

Account/IP limitleri 15 dakikada login 10/50, send 5/25, verify 30/150; PIN ayrıca eski yerel limitlerle DB 10/50 kullanır. IP önce kilitlenir, reddedilen IP yeni email key'i yaratamaz. Eski MFA RPC yolu kapalıdır. Yeni MFA ilk kod 120 saniye, bağlam başına 6 yanlış deneme/10 dakika kilit, 15 dakikada ilk dahil 3 gönderim, en az 60 saniye resend uygular. Geçerli resend kalan süreye yalnız 30 saniye ekler; attempts sıfırlamaz. MFA limit anahtarındaki account boyutu artık doğrulanmış cihaz/hesap bağlamıdır; hesap geneli sert MFA gönderim kotası yoktur. Parola login 10/50 ve link send 5/25 değişmez. Dağıtık çok-IP yükte limits için mutlak toplam tablo boyutu garantisi yok; satır sayısı/cleanup throughput izlenmelidir. Yerel latency örnekleri sabit-zaman veya internet yan-kanal yokluğu kanıtı değildir.

## Yönetim

Eski users/admin-users/team-workspace URL'leri MFA korumalı management RPC'sine gider. Backend JWT/live session, exact Origin, mutasyonda CSRF/JSON uygular. RPC girişte ve bütün SQL/audit/lock beklemelerinden sonra Superadmin auth/session/MFA denetler. Genel şirket yönetimi sales gate'e bağlı değildir; Agent bu RPC'yi kullanamaz. Company manager/worker mevcut yolları korunur.

Liste/detail, şirket kullanıcısı create/update/disable/force-logout ve team create/join/leave/toggle/invite desteklenir. Fiziksel kullanıcı/timer/workspace silinmez. Private workspace okunmaz/atanmaz; credential türü veya privileged rol genel formdan değişmez. Agent create/revoke ve Agent customer create/renew/cancel/history satış yollarında auth+sales+MFA gerektirir. Wrapper kendi ek INSERT/readiness okumasından sonra yeniden actor/session/gates/MFA kontrol eder; geç hata audit/idempotency dahil tüm transaction'ı geri alır.

Eski yönetici parola-atama reset URL'leri kapalıdır. Individual kendi mailbox recovery'sini; privileged hesap owner kurtarmasını kullanır. PIN Superadmin yaratma genel formdan kaldırılmıştır. Ayrıntılı URL/rol/test matrisi teslim paketindedir.

## Owner enrollment ve recovery

Prepare(uuid,email,unknown_random_bcrypt12_placeholder) yalnız owner ve cutover sonrasında çalışır. Eski PIN otomatik taşınmaz; kişi aktivasyonla kendi parolasını belirler ve ayrıca MFA yapar.

Privileged kurtarma mailbox-only değildir. Bağımsız kimlik doğrulaması sonrasında owner private recovery_cases kaydına target, gerçek DB login adı, neden, kanıt referansı ve en çok 1 gün expiry yazar. recover_privileged(uuid,placeholder,case_uuid) session_user/case/target/unused/expiry eşleşmesini doğrular. HTTP aktör UUID'si alınmaz. Ayrı private audit operator_login=session_user, executing_owner=current_user, target/case/reason/evidence_ref/time saklar; hedef sahte actor yapılmaz. Case tek kullanımlıktır; service audit/case değiştiremez. Secret/kanıt içeriği audit'e yazılmaz.

DB login adı tek başına insan kimliği kanıtı değildir. Bireysel authenticated DB login ve kontrollü owner role tercih edilir. Paylaşılan owner hesabında ayrı denetlenebilir erişim/case kaydıyla insan atfı kurulamazsa recovery yapılmaz. Kurtarma aynı mailbox/role/owner'ı korur, version artırır, tüm session/challenge/proof iptal eder, pending yapar. Ardından aktivasyon+MFA gerekir. Provider kesintisi gizli bypass yaratmaz.

## Geçiş ve rollback

Hazırlık eski backend'le çalışabilir. Yeni backend eski SQL'de yeni RPC/limiter yokluğu nedeniyle auth/PIN'i kapatabilir; uyumlu production kombinasyonu değildir. Yeni backend cutover öncesi eski privileged session'ları kabul etmez: backend geçişi bakım penceresindedir. Yeni frontend eski backend'de yeni auth başarısız olur. Kesintisiz geçiş garantisi yoktur.

Gelecekte onaylı sıra: owner/ACL/yedek kontrolü → uygulanmış iki hazırlığı doğrulama → yeni cihaz MFA hazırlık SQL’i → staging mail/DNS/native/PG testleri → bakım ve eski instance trafiğini kesme → yeni backend/frontend → açıkça onaylı cutover → owner enrollment → ayrı auth release kararı/smoke. Sales ayrıca kapalı kalır. Bu teslim release açmaz.

Cutover sonrası Render rollback'ten ÖNCE trafik kesilerek owner transaction'ında auth=false ve sales=false doğrulanır. Auth true→false trigger'ı password/privileged session/challenge/queue/proof iptal eder. Sonra eski binary'ye dönülebilir; DB trigger eski privileged/password session INSERT'ini engeller, eski yönetici kullanılabilirliği geri gelmez. SQL drop/revert, PIN'e dönüş veya eski session restore rollback yöntemi değildir; yeni backend ileri düzeltilmelidir. Vercel-only rollback bypass açmaz, fakat auth/management UX'i kaybettirebilir.

## Yapılandırma / kanıt sınırı

Değişken ADLARI: JWT_SECRET, SUPABASE_URL, SUPABASE_SERVICE_KEY, AUTH_ALLOWED_ORIGINS, SUBSCRIPTION_IDEMPOTENCY_HMAC_KEY, AUTH_PUBLIC_ORIGIN, AUTH_EMAIL_PROVIDER, RESEND_API_KEY, AUTH_EMAIL_FROM, AUTH_TOKEN_HMAC_KEY, AUTH_RATE_HMAC_KEY. Hiçbiri SQL release açmaz; değerler rapor/log/repository'ye konmaz. HMAC anahtarları instance'lar arasında aynı, birbirinden/JWT'den bağımsızdır.

Resend sabit HTTPS/redirect kapalı/timeout/sanitize adapter kullanır. DI testleri gerçek domain/DNS/deliverability kanıtı değildir. Gerçek PG testleri mevcut loopback/disposable cluster/database/role/inventory guard'larından geçmeden bağlanmaz. Dış PostgreSQL'de schema-reset dosyaları tek tek, --test-concurrency=1 ile çalıştırılır. PGlite çok bağlantılı PG yarış kanıtı değildir.

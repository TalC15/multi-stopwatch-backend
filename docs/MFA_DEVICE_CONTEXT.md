# 16 Ekim 2026 — cihaz/giriş bağlamlı MFA

Bu ek, güncel kaynak ZIP’leri üzerine hazırlanmıştır; uygulanmış activation/management SQL dosyalarını değiştirmez. Yeni hazırlık `20261016_mfa_device_context.sql` tek transaction’dır. Mevcut katalog owner invariant’ını kullanır, auth/cutover/sales kapılarını kapalı doğrular ve satırlarını COMMIT’e kadar kilitler. Aynı migration ikinci kez çalıştırılırsa CREATE çakışmasında tamamen rollback olur; otomatik tekrar uygulama desteklenmez. Production’da çalıştırılmamıştır.

## Bağlam ve yetki

`POST /api/auth/mfa/status {}` parola formundan önce Secure, HttpOnly, SameSite=Lax, Path=/api/auth, 30 günlük `__Secure-keeptimer-mfa-device` cookie’sini oluşturur. Değer 32 rastgele byte ve ayrı amaçla türetilmiş HMAC imzasıdır. İstemci deviceId veremez. Parola doğrulanınca cihaz + kullanıcıdan pre-auth cookie türetilir. DB yalnız HMAC bağlamı/cihaz özeti ve mevcut refresh-cookie bağlam özetini saklar. Parola hash’i, hesap sürümü, aktif rol ve aktivasyon her transaction’da yeniden kontrol edilir. İlk faktör en çok 15 dakika geçerlidir.

Çerezler mevcut Vercel `/api` proxy’sinden aynı origin ile taşınır; frontend doğrudan Render origin’ine credential isteği yapmaz. Origin/CSRF/JSON/no-store guard’ları değişmez. CORS izinlerini genişletmeyin veya SameSite=None eklemeyin. Staging’de Secure cookie ve proxy Set-Cookie davranışı gerçek tarayıcıyla doğrulanmalıdır.

Cookie silme veya yeni tarayıcı fiziksel cihazı yeniden tanımayı imkânsız kılar. Çözüm fiziksel cihaz parmak izi değildir. Kilit cihaz+hesap+doğrulanmış giriş bağlamındadır. Aynı cookie ile reload, yeni login, backend restart veya başka instance kilidi sıfırlamaz. Logout/PIN login geçici cookie’yi temizlese de kalıcı cihaz cookie’si ve DB bağlamı korunur. Başka cihazdaki aynı hesap 10 dakikalık kilidi miras almaz.

## Süre, bütçe ve risk

SQL ilk OTP’yi 120 saniye, resend’i en az 60 saniye ve kayan 15 dakikada toplam 3 gönderim ile sınırlar. Resend geçerli challenge’ın eski son kullanma zamanına 30 saniye ekler; eski kanıt hemen değişir. Süresi geçmiş challenge canlandırılmaz. Aynı op UUID’si çift sayılmaz; farklı eşzamanlı resend cooldown’a takılır. Denemeler bağlamda kalır; resend veya yeni challenge sıfırlamaz. Altıncı yanlış kod challenge’ı tüketir ve 10 dakika kilitler. Kilit bitimi veya başarılı MFA denemeleri sıfırlar. OTP tüketimi ve session yaratma aynı transaction’dadır; kilit ve son yazı beklemelerinden sonra expiry yeniden denetlenir.

Mevcut parola brute-force 10 hesap/50 IP, link gönderim 5 hesap/25 IP, verify 30/150 bütçeleri 15 dakikadır. MFA send/verify için hesap anahtarı cihaz bağlamıyla ayrıştırılır; IP anahtarı paylaşılır. SQL mantıksal gönderim kotası accepted/pending/unknown kayıtları için 3’tür; kesin rejected kayıtları bu kotadan çıkar, cooldown ve abuse/risk bütçeleri devam eder; HTTP tekrarları ayrıca request bütçesini tüketebilir. Cookie değişimi IP bütçesini değiştirmez. Aynı NAT’taki kullanıcılar IP bütçesini paylaşabilir.

Hesapta 15 dakikada 6 MFA gönderiminden sonra yalnız yeni ve henüz güvenilmemiş bağlam bir kere 60 saniye bekler. Bilinen/başarılı bağlamlar etkilenmez, hesap geneli 10 dakika kilit veya 3 gönderim kotası yoktur. Bekleme ve kilit olayları private risk audit’ine yazılır. Bu, parola bilen dağıtık botnet’e karşı mutlak e-posta üst sınırı değildir; bilerek hesap çapında kolay DoS yaratılmaz. Trafik/audit izleme, sağlayıcı kapasitesi ve gerekirse ayrıca onaylanacak edge risk kontrolü gerekir.

## Teslimat ve idempotency

`operationId` istemcinin rastgele UUIDv4 işlem anahtarıdır, yetki veya cihaz kimliği değildir. İlk faktör/body tam alan kontrolünden geçer. Yeni send için server nonce yaratılır. OTP, gizli HMAC anahtarı ve bu nonce’tan ayrı domain ile türetilen sekiz haneli PRF çıktısıdır; plaintext OTP/token DB’ye veya loga yazılmaz. DB’deki private nonce, restart sonrası aynı kodu yeniden üretir. Bütün instance’lar aynı HMAC anahtarlarını kullanmalıdır. Anahtar rotasyonu bakım ve yeniden doğrulama gerektirir.

Gönderim DB lease’i 20 saniye; sağlayıcı timeout’u 10 saniye. `pending`, `accepted`, `rejected`, `unknown` ayrıdır. Network/5xx/408/409/429/belirsiz JSON unknown; kesin 4xx ret rejected. Unknown 5 saniye sonra status üzerinden aynı payload, OTP ve Resend Idempotency-Key ile yeniden denenebilir. Yeni kod/30 saniye/kota tekrar uygulanmaz. Kabul yalnız provider kabulüdür, inbox teslimatı değildir. Verify yalnız accepted challenge’ı kabul eder; rejected/unknown fail-closed. Sağlayıcı kesilince önceden accepted kod doğrulanabilir; yeni MFA mail olmadan başarılı gösterilmez. Normal Individual login provider’dan bağımsızdır.

Başarılı OTP’nin HTTP yanıtı kaybolursa JWT tekrar oynatılarak verilmez. Status consumed gösterir; kullanıcı yeni parola girişinden devam eder. Böyle bir yanıtsız işlem server’da bir session yaratmış olabilir; mevcut session TTL/revoke kuralları geçerlidir. Tek OTP iki session yaratmaz. Yanlış verify aynı op/proof ile yinelenirse tek deneme sayılır.

## Bakım, dağıtım ve rollback

Yeni tablolar RLS açık; PUBLIC/anon/authenticated/service_role doğrudan erişemez. `keeptimer_mfa_command` ve bounded `keeptimer_mfa_maintain` backend/owner yürütür; state ve eski MFA helper owner-only’dir. Eski auth_command non-MFA davranışını devreder; legacy MFA issue/inspect/consume/resend/delivery kapalıdır. Yeni backend zorunludur; eski backend’e dönüş yeni SQL üstünde legacy MFA’yı açmaz.

Mevcut 5 saniyelik worker bakım RPC’sini çağırır. Her tur en çok 64 challenge (expiry üzerinden 7 gün), 64 bağlam (30 gün hareketsiz, kilit/live challenge yok), 64 audit (30 gün) temizlenir. Alt send/verification kayıtları ayrı ayrı, her tablo için en çok 64 satırla temizlenir. FK’ler RESTRICT’tir; challenge/context yalnız bütün çocukları temizlendiyse silinir; dönen sayaçlar gerçek silinen satırları sayar. Parent→child lock sırası ve SKIP LOCKED kullanılır; aktif challenge ve kilit korunur. Yeni cron gerekmez; worker durursa retention gecikir, kota/kilit açılmaz. İşletim count/oldest-row/cleanup throughput izlemeli; private audit arşivi gerekiyorsa yetkili operatör 30 günden önce güvenli arşivlemelidir.

Önerilen sıra: staging/PG18 ve bağımsız inceleme → backup/owner kataloğu ve mevcut kapalı kapıların kontrolü → yeni hazırlık SQL’i → uyumlu backend/frontend bakım dağıtımı → tarayıcı/proxy/mail/native doğrulaması. Cutover/enrollment/auth release ayrı gelecekteki açık onaylardır; bu görev bunları çalıştırmaz veya onaylamaz. Sales false kalır. Hazırlık SQL’ini alfabetik toplu migration koşusuna eklemeyin: eski cutover dosyası kendiliğinden çalışmamalı.

Rollback’te trafiği durdurup auth/sales kapılarını kapalı tutun; veri/tablo veya yeni SQL’i DROP etmeyin. Auth true→false yeni MFA challenge’larını da tüketir ve ilk faktörü geçersizleştirir. Eski binary yeni RPC sözleşmesini desteklemez; güvenli seçenek kapalı kapılarla ileri düzeltmedir. Worker/Manager PIN, Individual workspace, abonelik/satış geçmişi, Phase 5 Telegram lock ve Phase 6 entitlement fonksiyonları değişmemiştir.


## İkinci inceleme düzeltmeleri (R2)

All-session revoke ve yetkili force_logout işlemleri, mevcut yetki kontrolleri başarılı olduktan sonra aynı transaction içinde hedefin context’lerini id sırasıyla kilitler, first-factor stamp’i epoch yapar ve bekleyen challenge’ları tüketir. Force logout hedefte hiç session yokken de çalışır; wrapper ek lock beklemelerinden sonra admin/MFA kontrolünü tekrar yapar. Kullanıcı security alanları ve auth-account version/email/activation değişimleri aynı invalidation helper’ını çağırır. Parola değiştirme, recovery ve disable işlemleri bu nedenle eski OTP’yi yaşatmaz. Kilit/attempt/send bütçesi resetlenmez.

Doğrudan session revoke/delete için ayrı private `keeptimer_mfa_revocations` tablosu kullanıcı başına monoton generation tutar. Session trigger’ı user/account/context parent kilidi almaz; bu tablo özellikle parent FK içermez. MFA başlangıcı generation’ı kaydeder, durum/doğrulama ve session yaratmanın son kontrolü bunu karşılaştırır. Bu küçük kalıcı fence silinmez; aksi hâlde eski generation yeniden geçerli olabilirdi. Normal tek-session logout başka tamamlanmış session’ları topluca iptal etmez; eşzamanlı all-session iptali user kilidiyle serialize edilir. Önceden bitmiş revoke sonrasında eski first factor kullanılamaz.

Release close zaten release satırının exclusive kilidine sahiptir. Retention kapılar kapalı olsa bile önce aynı satırı FOR SHARE ile alır. Sonra her ikisi context→challenge sırasını kullanır. Retention send/verification çocuklarını SKIP LOCKED ile siler; atlanan çocuk varsa parent kalır. ON DELETE CASCADE bulunmaz. Her tablo için en çok 64 silme, en çok 64 context ve context başına 64 challenge inceleme vardır. Release transaction rollback’i challenge/context invalidation’ını da geri alır. Gerçek PG18 yarışları ayrı test dosyasında; PGlite PASS, çok bağlantılı PG kanıtı değildir.

Delivery accepted/rejected terminal durumları değiştirilemez. Böylece gecikmiş veya yinelenmiş rejected sonucu kabul edilmiş gönderimi geriye dönük refund edemez. Unknown/pending slot tutar; yalnız kesin ret mantıksal 3-slot kotasından çıkar. Request limiter ve 60 saniye cooldown kesin rette de uygulanır.

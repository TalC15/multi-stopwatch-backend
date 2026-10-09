# Faz 6 — Abonelik yaşam döngüsü

Bu değişiklik inceleme içindir; production onayı değildir. Satış yayın kapısı
`keeptimer_sales_release.enabled=false` kalır. Gerçek parola/MFA akışı Faz 7,
son güvenlik ve production değerlendirmesi Faz 8 kapsamındadır.

## Sözleşme

- Entitlement'ın kesin kaynağı `keeptimer_resolve_entitlement` olarak kalır.
- Resolver, mevcut kilitler sonrasında kullandığı `clock_timestamp()` değerini
  ek `evaluatedAt` alanında döndürür. Seçim, başlangıç/bitiş ve iptal kuralları
  değişmez. PostgreSQL mikro-saniyeleri korunur.
- `GET /account/experience` bu alanı üst seviyede iletir. Tarih bir aktivasyon
  talimatı değildir. Yeni frontend eksik/geçersiz metadata ile Individual
  ücretli hak açmaz. Şirketin aynı oturumdaki doğrulanmış offline davranışı korunur.
- `keeptimer_phase3_subscription_json` dönem `status` alanını sunucu saatiyle
  ekler. Mevcut satış/geçmiş API'leri bunu iletir; yeni endpoint yoktur.
- İdempotent bir satışın tekrar yanıtı ilk kaydın görünümüdür. Yönetim ekranı
  işlem sonrası mevcut API'den geçmişi yeniden yüklemeye devam eder.
- Başlangıç için `starts_at <= clock_timestamp() < ends_at` kullanılır.
  Aktif yenileme mevcut bitişten, süresi dolmuş veya iptal edilmiş abonelik
  yenilemesi sunucunun güncel zamanından başlar. Bekleyen dönem varsa satış
  reddedilir. UTC takvim ayı fonksiyonu değiştirilmez.
- İptal seçilen döneme aittir. Bekleyen yenileme iptali aktif dönemi kapatmaz.
  Aktif dönem iptalinde başka geçerli aktif dönem yoksa ücretli hak kapanır;
  gelecekteki dönem varsa kendi başlangıcına kadar bekler.
- Timer, private workspace, satış ve outbox geçmişini temizleme/migration yoktur.
- SQL yetki/oturum kontrolleri ve mutasyon sonrası tekrar kontrolleri korunur.
  Telegram'ın kullanıcı satırındaki ilk `FOR UPDATE` kilidi değiştirilmez.

## Uygulama sırası (bu çalışmada uygulanmadı)

Bağımsız inceleme ve gerekli testler tamamlandıktan sonra: Faz 1–5 migration'ları
mevcut olmalı; ardından yalnız `20261009_subscription_lifecycle.sql`, backend,
sonra frontend. Eski migration'ları yeniden uygulamak yeni fonksiyon metadata'sını
geri alabilir. Frontend önce çıkarsa ücretli haklar güvenli biçimde kapalı kalır.
Bu sıra satış kapısını açma izni vermez. Canlı SQL veya deploy bu teslimin parçası değildir.

## Testler

Önce normal regresyonlar: `npm ci` ve `npm test`.
Gerçek PostgreSQL olmayan çalışmalarda yeni concurrency dosyası SKIP verir;
PGlite sonucu gerçek PostgreSQL concurrency sonucu değildir.

Kullanıcının ayrı, silinebilir PostgreSQL 18 kümesinde mevcut
`SUBSCRIPTION_TEST_DATABASE_URL` ve `SUBSCRIPTION_TEST_CLUSTER_NAME` değerleri
önceden ayarlanmış olmalı. URL loopback TCP, veritabanı adı `_keeptimer_test`
son eki ve küme adı `keeptimer_disposable_` + 32 küçük hex karakter koşullarını
karşılamalı. Mevcut sunucu kimliği, rol ve envanter guard'ları değiştirilmedi.
Bu testler yalnız guard'ların kabul ettiği test kümesinde `public` şemasını sıfırlar.
Başka veritabanı içeren küme veya canlı Supabase kullanılmaz.

Aynı test veritabanını kullanan dosyaları paralel koşturmayın:

```sh
node --test --test-concurrency=1 test/subscription-phase6.test.js test/subscription-phase6-concurrency.test.js
node --test --test-concurrency=1 test/subscription-phase2-concurrency.test.js test/subscription-phase3-concurrency.test.js test/subscription-phase5-concurrency.test.js
node --test test/subscription-database-safety.test.js
```

Yeni dokuz gerçek PostgreSQL testi: aynı/farklı anahtarla eşzamanlı yenileme,
yenileme/aktif iptal yarışının iki sırası, iptal/oturum iptali arkasında bekleyen
kişisel yazı, Vekil yetkisi kaldırılırken bekleyen satış ve başlangıç/bitiş
sınırında kilit bekleyen resolver. Kilit beklemesi `pg_blocking_pids` ile gözlenir.
Faz 5'in süre dolarken insert/update/delete rollback ve Telegram yarış testleri
ayrıca korunmuştur.

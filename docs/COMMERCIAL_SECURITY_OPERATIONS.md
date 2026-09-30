# Şirket teslimi ve güvenlik yapılandırması — 30 Eylül 2026

Bu değişiklik kod teslimidir. Canlı servis, Telegram ayarı veya SQL değiştirilmedi.

## Hesap ve şirket hazırlama

Süper yönetici yeni şirketi oluşturur; şirket oluşturma kendi çalışma alanını
 değiştirmez. Kullanıcı adı, 6–25 karakter PIN, worker/manager rolü ve şirketi
 seçerek hesapları oluşturur. İlk oluşturma sırasında bir şirkete birden fazla
 manager atanabilir. Worker/manager hesap/şirket oluşturamaz, davet koduyla
 şirket değiştiremez veya ayrılamaz. Manager kendi şirketindeki worker'ı mevcut
 onaylı kapatma akışıyla devre dışı bırakabilir; kayıtlar şirkette korunur.

Şirkete bağlı hesabın rol ve üyeliğini koruyan mevcut SQL kuralları değişmedi.
 Sonradan worker → manager yükseltme, şirket transferi veya manager kapatma
 yeni akış olarak eklenmedi. Başlangıç yetkileri doğru seçilmelidir. Kapatılmış
 worker giriş/refresh/sayaç işlemleri mevcut DB ve HTTP guard'larıyla reddedilir.
 Çevrimdışı cihazdaki yerel veri anında uzaktan geri alınamaz.

## İlk süper yönetici

Mevcut süper yönetici varsa başlangıç kodu yeni hesap oluşturmaz. Boş kurulumda
 `SUPERADMIN_PIN` en az 6, en fazla 25 karakter ve UTF-8 olarak en fazla 72 byte
 olmalıdır. Varsayılan `1234` ve PIN logu kaldırıldı. Eski kullanıcıların PIN'i
 veya oturumu topluca değiştirilmez. Önceden varsayılan PIN ile hazırlanmış bir
 kurulumun kimlik bilgilerini işletmeci ayrıca değerlendirmelidir.

## Telegram webhook — gerekli yeni ayar

1. `TELEGRAM_WEBHOOK_SECRET` için A–Z, a–z, 0–9, `_`, `-` karakterlerinden
    oluşan 32–256 karakterlik rastgele güçlü bir secret belirleyin.
2. Telegram'ın mevcut `setWebhook` yapılandırmasında `secret_token` alanına aynı
    değeri verin. Mevcut webhook URL'sini ve bot token'ını kendi güvenli kanalınızda
    kullanın; bunları kaynak kod veya test loguna yazmayın.
3. Secret yapılandırılmazsa `/webhook` 503; yanlış/eksik header için 403 verir.
    Doğru `X-Telegram-Bot-Api-Secret-Token` ile mevcut `/start` ve `/id` çalışır.

Resmi sözleşme: https://core.telegram.org/bots/api#setwebhook

Chat ID kaydı, botun adrese mesaj gönderebildiğini kontrol eder; sohbetin hesaba
 ait olduğunu kriptografik olarak kanıtlamaz. Mevcut yönlendirme politikası
 değişmedi. Şirket bildirimlerinin yalnız onaylı adreslere gitmesi isteniyorsa
 doğrulanmış eşleştirme veya yönetici kontrollü adres politikası ayrı kararla
 uygulanmalıdır. Rate limit bunun yerini tutmaz.

## Bağımlılık ve doğrulama

`npm ci` yeni lock ile engine.io 6.6.11 kurar. Socket.IO'nun 14 Eylül 2026
 bildirimi 6.6.0–6.6.9 upgrade DoS açığını tanımlar; 6.6.10 ve üstü düzeltilmiştir:
 https://github.com/socketio/socket.io/security/advisories/GHSA-2gc4-cqfq-p2gv

19 gerçek PostgreSQL testi burada ATLANDI. Canlı SQL/Supabase veya gerçek/restore
 veritabanı kullanılmadı. Yayından önce onaylı disposable ortamda gerçek PG,
 standart frontend build ve cihaz kabulü gereklidir. Mevcut RLS/grant, HTTPS,
 proxy/rate-limit ve üretim secret ayarları canlı ortamdan doğrulanmadı.

Atanmamış hesabın rol/şirket editinde kullanıcı güncellemesi ve oturum iptali
 ayrı işlemlerdir. İkinci adım doğrulanamazsa 503 ve açık belirsizlik mesajı
 döner; atomik teslim garantisi iddia edilmez. Şirkete bağlı kapsam değişikliği
 hâlâ reddedilir. Yeni migration veya auth altyapısı eklenmedi.

Telegram zamanlayıcısı bellek içidir. Süre aşımı parçalama düzeltmesi yeniden
 başlatmada kalıcı job teslim garantisi eklemez; mevcut snapshot/komut veya
 istemci uzlaştırmasıyla yeniden planlama sınırı korunur. Exactly-once Telegram
 veya ACK kaybından sonra gizli replay garantisi yoktur.

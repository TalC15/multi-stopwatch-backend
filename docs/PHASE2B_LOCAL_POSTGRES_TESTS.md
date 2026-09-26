# Phase 2B — ayrı bağlantı yarış testleri

Bu testler **yalnızca silinmesinde sakınca olmayan yerel** PostgreSQL
veritabanında çalıştırılmalıdır. `test/concurrency.test.js` her senaryodan
önce hedef veritabanının **`public` şemasını silip yeniden oluşturur**.
Supabase URL'si veya canlı veritabanı kullanmayın. Test kodu yalnız
`localhost`, `127.0.0.1` veya `::1` ve adı `_keeptimer_test` ile biten
veritabanlarını kabul eder.

Docker kurulu bir makinede, backend kökünde:

```sh
docker run --rm --name keeptimer-phase2b-db \
  -e POSTGRES_PASSWORD=keeptimer_local_only \
  -e POSTGRES_DB=keeptimer_keeptimer_test \
  -p 127.0.0.1:55432:5432 -d postgres:16
docker exec keeptimer-phase2b-db pg_isready -U postgres -d keeptimer_keeptimer_test
npm ci
TEST_DATABASE_URL=postgres://postgres:keeptimer_local_only@127.0.0.1:55432/keeptimer_keeptimer_test npm run test:concurrency
docker stop keeptimer-phase2b-db
```

`pg_isready` hazır değilse testleri başlatmadan önce tekrar kontrol edin.
Testler ayrı `pg.Client` bağlantılarıyla giriş/session, refresh, kişisel ve
shared timer yazmaları ile tekrarlanan kapatmanın kilit çakışmasını sınar.
Başarılı sonuç görülmeden Phase 2B canlıya hazır kabul edilmemelidir.

## Phase 2 ek yarış senaryoları

`test/concurrency.test.js` artık aynı silinebilir yerel veritabanında üç
kişisel senkronizasyon yarışını da çalıştırır: senkronizasyon kapatmadan önce,
kapatma senkronizasyondan önce ve farklı iki hesabın aynı UUID ile eşzamanlı
oluşturma girişimi. Yukarıdaki komut **yedi** ayrı bağlantı testini çalıştırır;
önce hem Phase 2B hem de yeni Phase 2 SQL migration'ını test veritabanına
uygular. Canlı Supabase URL'siyle çalıştırmayın.

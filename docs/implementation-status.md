# McpGuard — uygulama durumu

Bu dosya kullanıcı için değil, **işi devralan kişi** için yazılır. README ürünü
anlatır; burası her fazın ne yaptığını, hangi dikişi sonraki faza bıraktığını ve
o faz sırasında ortaya çıkan çelişkileri tutar.

---

## Nerede kaldık

**v0.1.1 yayına hazır, publish bekliyor.** Beş yayınlanan paket (`@tunedness/mcpguard`,
`@tunedness/mcpguard-core|detect|ruleset|proxy`) changesets akışıyla 0.1.1'e taşındı:
CHANGELOG'lar yazıldı, `*_VERSION` sabitleri, iç bağımlılık aralıkları ve lockfile
tutarlı, `packaging.test.ts` ve `pack:smoke` yeşil. Tag atılmadı, publish yapılmadı:
yayın düğmesi (`release.yml` → `publish`) kullanıcının. 0.1.0 hiç yayımlanmadı; onu
anlatan baseline changeset'i 0.1.0 girdisi olarak CHANGELOG'da duruyor, 0.1.1
girdisi Faz 14, 15, 25, 26 düzeltmelerini ve yeniden adlandırmayı anlatıyor.

Ürün durumu: Faz 0–10 ve 12 bitti; Faz 11 (HTTP gateway)
bilinçle P1'e bırakıldı ve çekirdeği Faz 18'de geldi. `mcpguard wrap -- <sunucu>` gerçek MCP protokolüyle
doğrulanmış tam korumalı proxy: deterministik injection taraması (700 öğelik
korpusta %100 recall / %0 FP, in-sample), PII maskeleme, erişim denetimi,
manifest sabitleme, hash zincirli audit, opsiyonel OTLP telemetri. Son kayıtlı
test sayısı 595 (Faz 9).

**P1 doğruluk düzeltmeleri (Faz 14) bitti.** v0.1.0'da anlatılıp çalışmayan
dört davranış artık çalışıyor ve testle kilitli: audit parmak izi ham metnin
HMAC'i, korelasyon anahtarı (`pii.correlation_key_env`) maskeye bağlı, kimlik
merdiveni (`--identity` / `MCPGUARD_IDENTITY` / `clientInfo.name`) erişim
kararında ve kayıtta, `checkpoint_to: syslog` açılışta hata. Test sayısı 627.

**Manifest kapısı (Faz 15) bağlandı.** `tools/list` artık `guardlock.json` ile
karşılaştırılıyor: ilk temasta pinleme (TOFU), sonra `on_mismatch: halt|flag`,
`on_first_use: require`, araç açıklamalarının taranıp bulguların kilide yazılması
ve `mcpguard lock --diff|--accept`. Rug-pull koruması artık anlatıldığı gibi
çalışıyor; ayrıntı aşağıdaki Faz 15 bölümünde.

**`wrap`'in P0 boşlukları (Faz 25) kapandı.** Üç boşluğun üçü de koşturularak
doğrulandı ve üçü de doğru çıktı: `wrap` yalnız legacy era'yı sunuyordu, upstream
sunucuya istemcinin capability'leri hiç gitmiyordu, kombinasyon kuralları
proxy'ye bağlı değildi. Üçü de düzeltildi ve testle kilitli; ayrıntı aşağıdaki
Faz 25 bölümünde.

**Ruleset digest'i lexicon'ları kapsıyor (Faz 26).** Digest yalnız kuralları
özetliyordu; lexicon'lar skoru değiştirdiği halde digest'e girmiyordu, yani aynı
digest'li iki ruleset farklı karar verebiliyordu (ADR-009 madde 2). Düzeltildi ve
testle kilitli; ayrıntı aşağıdaki Faz 26 bölümünde.

**Korumalı HTTP gateway çekirdeği (Faz 18) bitti, çoklu upstream (Faz 19) geldi.**
`mcpguard serve` her upstream için `wrap`'in üç kapısını (`tools/call`, `resources/read`, `tools/list`) aynı
`runtime.ts` koduyla HTTP üzerinden sunuyor; iki era'yı da (legacy session'lı,
modern session'sız) çeviri yapmadan ayrı bacaklar olarak taşıyor. Gelen oturum
ADR-006 merdiveniyle çözülüyor, kimlik bearer token'dan geliyor, loopback
varsayılan. Spike sonuçları ve sınırlar aşağıdaki Faz 18 bölümünde. Faz 19 ile tek
Guard birden çok sunucunun önünde duruyor: her sunucu kendi yolunda (`/mcp/<ad>`),
kendi kapılarıyla, kendi `guardlock.json` girdisi ve bağlantı havuzuyla; ayrıntı
aşağıdaki Faz 19 bölümünde.

Sıradaki iş:

1. **Yayın düğmesi** — kullanıcının. Adlar kararlı (`@tunedness/mcpguard` +
   `@tunedness/mcpguard-*`), sürüm 0.1.1'e taşındı (`changeset version` koşuldu) ve
   paketler tarball'dan kurulup koşturuluyor (`npm run pack:smoke`). Kalan:
   `release.yml`'in `publish` adımının elle tetiklenmesi.
2. ~~P1 manifest bağlama~~ — Faz 15'te bitti.
3. Diğer P1'ler: ~~`serve`'ün çoklu upstream ve havuzu~~ (Faz 19'da bitti), sağlık verisi tanıyıcıları, Kademe 2
   SLM hakem, checkpoint syslog sink'i, trace context yayımı.

Ayrıntı için bkz. [Faz 12 — Devralan kişiye](#faz-12--dokümanlar-ve-v010-bitti).

---

## Faz 0 — `.ssot` düzeltmeleri (bitti, `4349f3a` @ `McpGuard.ssot`)

Çatı ADR-002 kapsam değiştiren koddan önce doküman güncellemesi şart koşuyor.
Araştırma dört varsayımı geçersiz kıldı, üç karar eksikti.

- **ADR-002 güncellendi — SDK.** Metin `@modelcontextprotocol/sdk` diyordu; o ad
  v1 monolitine ait. Taban `@modelcontextprotocol/{server,client,core}@2.0.0` —
  AgentFuse'da kurulu ve çalışır durumda, yani varsayım değil ölçüm. Karar iki
  noktada daraltıldı: iki era var ve arası **çevrilmez**; düşük seviyeli
  `Server` + `fallbackRequestHandler` geçirgenlik dikişi kullanılır.
- **ADR-004 güncellendi — audit hash'i.** "Ham içeriğin hash'i" düz `sha256`
  olarak okunursa düşük entropili içerikte **PII kehanetine** dönüşüyor: tek bir
  TC kimlik numarasından ibaret bir sonucun aday uzayı ~10⁹. Zincir hash'i düz
  kalır (zaten maskeli kaydı hash'liyor); kayıt içindeki ham içerik parmak izi
  `HMAC-SHA256(auditKey, ham)` olur; bulgu alıntıları maskeli metinden kesilir.
  Aynı yerde bir kısıt daha yazıldı: `wrap` modunda stdout ajanın JSON-RPC
  akışıdır, checkpoint oraya **yazılamaz**.
- **ADR-006 eklendi — oturum kimliği ve zincirleme.** AgentFuse sözleşmenin
  okuma tarafını yapıyor, enjeksiyon tarafını McpGuard'a bırakıyor ve bu bizim
  kayıtlarımızda yazmıyordu. Artık yazıyor.
- **ADR-007 eklendi — telemetri.** El yazması OTLP, `@opentelemetry/*` ağaca
  girmez, varsayılan kapalı, `security_event` bu aracın olay tipi.
- **ADR-008 eklendi — tarama yüzeyi.** Üç kapı (`tools/call` sonucu,
  `resources/read` içeriği, `tools/list` manifesti) ve **neyin taranmadığı**:
  `prompts/get` ve `sampling/createMessage` v0.1.0'da bilinçli olarak dışarıda.
- **ADR-009 eklendi — tam sayı aritmetiği.** AgentFuse modeli olduğu için CI
  kapısına 0,02 recall toleransı koymak zorunda kaldı. Kademe 1'de model yok;
  o yüzden skor yolu tam sayıdır, verdict her platformda bayt-birebir aynıdır ve
  kapıda **tolerans yoktur**. Aynı kayıtta dördüncü madde: **motor içeriğe kendi
  cümlesini yazmaz** — araç sonucuna "⚠️ şüpheli içerik" eklemek, modelin
  okuyacağı bir talimatı araç sonucuna koymaktır, yani savunulan vektörün ta
  kendisi.
- **PRD §5'e iki ek.** Araç açıklamaları TOFU anında taranır (manifest
  sabitleme *değişimi* yakalar, ilk temastaki kötücüllüğü değil); transport
  sırası stdio önce, HTTP sonra ve kaçarsa açıkça yazılır.

**Yapılmadı, kullanıcı hesabı gerekiyor:** npm'de `mcpguard` ve `@mcpguard`
scope'unun talep edilmesi. İkisi de bugün itibarıyla boş (registry 404);
`mcp-guard` başkasında (0.1.0) ve kullanılmayacak. *(Güncelleme, Faz 16: yayın
adları `@tunedness/mcpguard` ve `@tunedness/mcpguard-*` olarak kararlaştırıldı; bu
paragraf Faz 0 anındaki durumu anlatır.)*

---

## Faz 1 — iskelet (bitti)

npm workspaces (pnpm yok), ESM-only, `engines: node >=20.19`, `tsc -b` project
references, bundler yok.

```
packages/core/      @tunedness/mcpguard-core     — SAF karar motoru
packages/detect/    @tunedness/mcpguard-detect   — SAF tarama motoru
packages/ruleset/   @tunedness/mcpguard-ruleset  — VERİ paketi, bağımsız sürümlü
packages/proxy/     @tunedness/mcpguard-proxy    — MCP adaptörü
packages/cli/       @tunedness/mcpguard (bin mcpguard) — bin, npx giriş noktası
bench/              @tunedness/mcpguard-bench (private)
```

Araçlar: TypeScript 5.9.3, Biome 2.5.14, Vitest 5.0.1, Changesets 3.
CI: Node 20/22/24 matrisi.

**Bilinmesi gerekenler:**

- Vitest config formu `vitest.config.ts` içinde **`test.projects`** dizisi;
  eski `vitest.workspace.ts` dosyası değil.
- Kökte ayrı bir `tsconfig.test.json` var: paket tsconfig'leri `**/*.test.ts`'i
  `exclude` ediyor ki `dist/` yayınlanabilir kalsın — ama o zaman testler hiç
  typecheck edilmezdi. `typecheck` scripti `tsc -b && tsc -p tsconfig.test.json`
  koşuyor.
- Coverage eşiği **iki pakette**: `core` ve `detect`, %90. Proxy ve CLI ince;
  onların rakamını şişirmek kimseye bir şey anlatmaz.
- `biome.json`'daki `$schema` sürümü kurulu Biome sürümüyle aynı olmalı, yoksa
  `biome check` bir info basıyor (kapıyı kırmıyor ama gürültü).
- Kabuk notu: bu makinede `ls` bir takma ad (eza) ve bazı bayrakları farklı
  yorumluyor. Betiklerde `find` ya da `/bin/ls` kullanın.

### Bağımlılık yönü — mimarinin değişmezi

Manifest'lerde zorlanır, konvansiyona bırakılmaz:

| Paket | dependencies |
| --- | --- |
| `@tunedness/mcpguard-core` | `zod` **yalnızca** |
| `@tunedness/mcpguard-detect` | `zod` **yalnızca** |
| `@tunedness/mcpguard-ruleset` | **hiçbiri** |
| `@tunedness/mcpguard-proxy` | `@tunedness/mcpguard-core`, `@tunedness/mcpguard-detect`, `@modelcontextprotocol/{server,client,core}` |
| `mcpguard` | yukarıdaki dördü + `yaml` |

`core` ve `detect` **saftır**: `@modelcontextprotocol/*` yok, I/O builtin yok,
timer yok, `node:crypto` kabul. Bunu zorlayan `purity.test.ts` Faz 2'de geliyor
ve **gevşetilmemeli** — denetlenebilirlik iddiasının tamamı ona dayanıyor.

### Sonraki faza bırakılan dikişler

- `packages/*/src/testing/` dizinleri yapılandırmada dışlandı ama henüz yok.
- `packages/core/scripts/generate-schema.mts` ve `schemas/` Faz 2'de gelir;
  `schema:check` scripti o zaman package.json'a geri konur.
- `packages/ruleset/scripts/lint.mts` (regex diyalekt linter'ı) Faz 4'te gelir.
- `examples/` boş. İlk içeriği Faz 8'de `wrap` ile birlikte gelir.

### Çelişki kaydı

Yok. Faz 1 yalnız iskelet kurdu ve `.ssot` ile çelişen bir şeye rastlamadı.

---

## Faz 2 — saf çekirdek: politika, erişim denetimi, portlar (bitti)

`@tunedness/mcpguard-core`. Tarama yok; sözleşme var. 110 yeni test, `core/src` üzerinde
%99 statement / %89 branch.

```
src/util/json.ts      stableStringify — manifest hash'i ve audit zinciri bunun üstünde
src/util/hash.ts      sha256 · hmacSha256 · digestsEqual
src/policy/glob.ts    compileGlob · toolKey (`<server>__<tool>`)
src/policy/duration.ts
src/policy/schema.ts  guardpolicy.v1 — tek doğruluk kaynağı
src/policy/parse.ts   parsePolicy · PolicyValidationError (dosya okumaz)
src/policy/compile.ts globlar bir kez derlenir; sıcak yol regex kurmaz
src/policy/evaluate.ts evaluateAccess · evaluateCombinations
src/ports/index.ts    Clock · IdGenerator · AuditKey · AuditSink · TelemetrySink
src/domain/events.ts  security_event · policy_decision
src/purity.test.ts    saflığı zorlayan test
scripts/generate-schema.mts + schemas/guardpolicy.v1.schema.json
```

**Kapı artık beş komut.** `schema:check` şemayla birlikte geldi ve CI'da ayrı
bir iş (`schema-drift`, Node 24 — generator `.mts` ve Node'un native type
stripping'iyle koşuyor).

### Bilinmesi gerekenler

- **`purity.test.ts` bir maddeyi AgentFuse'da olmayan şekilde genişletiyor:**
  `new RegExp(` yalnız `policy/glob.ts` ve `policy/schema.ts` içinde
  bulunabilir. Politika bir kez derlenir; sıcak yolda regex kurmak, 20 ms'lik
  bütçeyi sessizce yiyen şeydir.
- `digestsEqual` `Buffer` yerine `TextEncoder` kullanıyor — ikisi de global,
  ama biri web standardı ve öteki bu paketin uzanmak istemediği bir Node
  ad alanı.
- Şema `io: 'input'` ile üretiliyor. Çıkış şeklini üretmek, `10m` yazan her
  politikayı reddeden bir şema doğururdu.
- Erişim denetiminin varsayılanı **allow** ve bu bilinçli: eşleşmeyen araç
  geçer. Deny-by-default daha güvenli olurdu ve kurulmazdı; kurulmayan bir
  güvenlik denetimi kimseyi korumaz. Varsayılan açık olan **izin**dir —
  tarama, maskeleme ve audit ilk günden açık.

### Çelişki kaydı

**zod'un `.partial()`'ı iç varsayılanları silmiyor ve bu sessiz bir hataydı.**
`scan.tools` altındaki araç bazlı override `ScanSettingsSchema.partial()` ile
tanımlanmıştı. `.partial()` anahtarı opsiyonel yapıyor ama alanın kendi
`.default()`'unu yerinde bırakıyor; sonuç, yalnız `action` yazan bir override'ın
**tam** bir ayar nesnesine parse olması. Operatörün `scan.default.flag_at: 50`
değeri, override'ın taşıdığı şema varsayılanı 40 tarafından hiçbir şey
söylenmeden eziliyordu.

Testle yakalandı (`lays a per-tool scan override over the defaults without
erasing them`). Düzeltme: alanlar varsayılansız bir kez tanımlanıyor
(`scanField`), iki şema ondan kuruluyor — biri tam varsayılanlı, öteki tümüyle
opsiyonel. Birleştirme de spread değil, alan alan yazılmış: yokluğunda en çok
kaybedilecek alan `action` ve onun varsayılanı, proxy'nin kimsenin istemediği
trafiği bloklamasını engelleyen tek şey.

### Sonraki faza bırakılan dikişler

- `Ports` arayüzü donduruldu ama hiçbir uygulaması yok; `AuditSink` ve
  `TelemetrySink` Faz 6 ve Faz 9'da geliyor.
- `domain/events.ts` olay tiplerini tanımlıyor, yayan kimse yok.
- `src/audit/` ve `src/lock/` dizinleri açıldı ve boş — Faz 6'nın yeri.
- `evaluateCombinations` çağrı geçmişini parametre olarak alıyor; o geçmişi
  kimin tuttuğu (oturum durumu) Faz 7'nin işi.

---

## Faz 3 — korpus ve replay iskeleti (bitti)

Motordan **önce**, bilinçli. Gerekçe AgentFuse'un kendi kaydında: Faz 9'da
2337 aday çalışma noktasının hiçbiri PRD hedeflerini tutmadı, çünkü sorun eşik
değil eksendi. Tasarımı ölçmeden dondurmak o bedeli yeniden ödemek olurdu.

```
packages/detect/src/types.ts         ContentItem · Finding · ScanVerdict — donmuş sözleşme
packages/detect/src/score/combine.ts noisy-OR, TAM SAYI, aile tavanları
packages/detect/src/score/decide.ts  skor → allow|flag|strip|block
packages/detect/src/scan.ts          scanContent — Faz 3 stub'ı, EMPTY_RULESET
bench/src/rng.ts                      tohumlu mulberry32
bench/src/injection/types.ts          12 saldırı + 10 zararsız aile
bench/src/injection/carriers.ts       el yazması zararsız dokümanlar (tuzaklar)
bench/src/injection/payloads.ts       el yazması saldırı yükleri
bench/src/injection/obfuscate.ts      tag-block · zero-width · base64 · homoglyph
bench/src/injection/corpus.ts         üreteç + calibration/validation ayrımı
bench/src/injection/{replay,sweep,run}.ts
bench/injection/corpus.jsonl          commit'li, sha256 pinli (corpus.test.ts)
bench/injection/results.{md,json}     commit'li — recall %0 tabanı
```

### Bilinmesi gerekenler

- **Skorlama tam sayı ve ADR-009'u zorluyor.** `combine` noisy-OR'u 0-1000
  ölçeğinde tam sayı bölmesiyle yapıyor, tek yuvarlama en sonda. `purity.test.ts`
  score/ altında ondalık sayı ve `parseFloat` yasaklıyor.
- **`imperative` ailesinin tavanı en düşük (550) ve bloklamaya asla ulaşamaz.**
  Bilinçli: README, CLI help, hata mesajları ve Türkçe destek metni en çok
  oradan yanlış pozitif üretiyor. Kanıt: score.test.ts.
- **Korpus 300/400 pozitif/negatif.** Negatif sayısı keyfi değil: 100 negatifle
  bir yanlış pozitif %1 eder ve "< %2" iddiasının iki öğelik çözünürlüğü kalır;
  400 ile bir FP %0,25 ve hedefin sekiz öğelik payı olur.
- **En zor negatif `security-docs`:** injection'ı *anlatan* güvenlik dokümanı,
  saldırı cümlelerini birebir içerir. `corpus.test.ts` bunun varlığını pinliyor;
  yumuşatılırsa benchmark var oluş sebebini sınamayı bırakır.
- **calibration/validation ayrımı** id hash'iyle, aileye göre katmanlı. Çalışma
  noktası calibration'da seçilir, manşet validation'da ölçülür — korpus ve
  kural seti aynı elden çıktığı için aynı veride ayarlayıp raporlamak hiçbir
  şeyin iddiası olmazdı.

### Çelişki kaydı

**`combine` başta oluşum başına puanlıyordu, tekrarı ödüllendiriyordu.** noisy-OR
her bulguyu ayrı katlayınca, aynı kuralın 20 kez eşleşmesi 20 kat kanıt sayıldı
ve bir imza + bir beacon çiftini geçti — okuyucunun tam ters sıralayacağı çift.
Ölçümle yakalandı (score.test.ts: "twenty copies of one rule do not outscore a
diverse pair", beklenen 63 < 51 ile patladı). Düzeltme: katlama artık **ayrık
kural** üzerinden, her kural bir kez ve en yüksek ağırlığıyla. Oluşumların hepsi
hâlâ bulgu olarak raporlanıyor, yalnız puan almıyorlar.

### Sonraki faza bırakılan dikişler

- `scanContent` boş bulgu kümesi döndürüyor; dedektör hattı Faz 4.
- ADR-009'un "commit'li verdict anlık görüntüsü" (`determinism.test.ts`) Faz
  4'te gerçek kural setiyle anlamlı olacak — şimdi kural seti boş.
- Gecikme harness'i (`bench/src/latency/`) Faz 10.
- `bench.yml` yazıldı: korpus determinizmi + sonuç diff'i, her PR'da.

---

## Faz 4 — `@tunedness/mcpguard-ruleset` + injection tarama motoru (bitti)

Kademe 1 dedektör aileleri, tek normalizasyon geçişi, Aho–Corasick, kural seti
veri paketi. 220+ yeni test.

```
packages/detect/src/ac/aho-corasick.ts       tek geçişte tüm literal'ler
packages/detect/src/normalize/fold.ts        Türkçe-duyarlı + skeleton + homoglyph fold
packages/detect/src/normalize/{classes,regions,clauses}.ts
packages/detect/src/normalize/index.ts       tek geçiş, tüm artefaktlar
packages/detect/src/detectors/signature.ts   imza (literal/phrase/regex), kelime sınırı
packages/detect/src/detectors/imperative.ts  EN + TR morfoloji, model yok
packages/detect/src/detectors/unicode.ts     tag-block · bidi · zero-width yoğunluk
packages/detect/src/detectors/encoding.ts    base64 kapıları + çöz + yeniden tara
packages/detect/src/detectors/exfil.ts        beacon · tool-invocation · frame
packages/detect/src/detectors/anomaly.ts      css-hidden · comment · data-appendix
packages/detect/src/ruleset/{schema,lint,compile,load}.ts
packages/ruleset/rulesets/injection.v1.json   14 kural
packages/ruleset/lexicon/*.json               EN/TR fiiller + benign allowlist
packages/ruleset/src/index.ts                 JSON'ı okuyup ham nesne verir
bench/injection/results.{md,json}             %100/%0, in-sample uyarısıyla
```

### Bilinmesi gerekenler

- **Tek normalizasyon geçişi.** `normalize()` case fold + skeleton fold +
  karakter sınıfları + bölge işaretleri + clause bölme'yi tek `for...of` ile
  üretir. Dedektörler bunu sabit artefakt olarak okur; 100 KB'lık sonuç kural
  sayısı kadar değil sabit sayıda kez taranır.
- **Türkçe fold determinizmi.** `toLocaleLowerCase('tr')` ICU build'e bağlı,
  o yüzden **kullanılmıyor**. Altı Türkçe harf açık tabloyla, `İ`→tek `i`
  (yoksa offset kayardı). Skeleton fold ç/ğ/ı/ö/ş/ü'yü Latin'e indirir
  (deasciified yazımlar) ve Cyrillic/Greek homoglyph'leri de (gizleme).
- **Kelime sınırı** AC alt-dize eşleşmesinin yan etkisini kesiyor: `key`
  `keys` içinde bulunmaz. Baştaki sınır her zaman, sondaki yalnız exact
  token'da (prefix token `talimat`→`talimatları` için kasıtlı). Alt çizgi
  sınır sayılır: `API_KEY` içindeki `key` bulunur.
- **İmza tek yerde `new RegExp` kurar** (`ruleset/compile.ts`), bir kez, g/y
  bayrağı sıyrılmış — `exec` durumsuz. `purity.test.ts` bunu pinliyor.
- **Skorlama tam sayı, ADR-009.** noisy-OR ayrık kural üzerinden; aile tavanları;
  tek yuvarlama en sonda. `imperative` tavanı en düşük ve **tek başına flag'e
  ulaşamaz** — Türkçe destek metni saf emir kipidir.
- **Doküman-biçimi sönümlemesi** yalnız ≥3 başlık ya da >%25 kod oranında;
  güvenlik dokümanı (injection'ı *anlatan*) böyle damplanır, kısa markdown
  saldırı sayfası damplanmaz.
- **Coverage:** satır/fonksiyon/deyim %90, **branch %80** (config'te gerekçesi
  yazılı) — `noUncheckedIndexedAccess`'in dayattığı `?? default` fallback'leri
  branch'i şişiriyor; her gerçek davranışın davranışsal testi var.

### Çelişki kaydı

**Beş ayrı kalibrasyon bulgusu, hepsi ölçümle — hiçbiri tahminle:**

1. **noisy-OR oluşum başına puanlıyordu** (Faz 3'ten taşındı, burada da
   düzeltildi): aynı kuralın 20 tekrarı bir imza+beacon çiftini geçiyordu.
   Ayrık kurala geçildi.
2. **0.7 korroborasyon cezası meşru tek-sinyal saldırılarını eziyordu**
   (role-switch 38'e düşüyordu). Ceza kaldırıldı; korroborasyon artık yalnız
   *block* bandını kapılıyor (`decide`), flag'i değil.
3. **`imperative.tr` Türkçe destekte 55 ateşliyordu** — meşru "gönderiniz"
   saldırının "gönder"iyle aynı kök. Emir kipi tek aile olduğunda yarıya
   iniyor; artık yalnız korroborasyon.
4. **Emoji ZWJ surrogate-pair komşuluğu offset aritmetiğiyle kaçıyordu**
   (i18n 42 FP). Meşruluk kontrolü kod-noktası dizisi üzerinden yeniden yazıldı.
5. **replay `mimeType` geçirmiyordu** → markdown sönümlemesi atlanıp skor yapay
   yükseliyordu. Düzeltilince markdown içi enjeksiyonlar önce kayb/sonra
   `docLike` eşiği ≥3 başlığa sıkılaştırıldı.

Ve **testVector'lar iki gerçek zayıflık yakaladı:** bare `send_email` imzası
meşru araç açıklamalarında ateşliyordu (exfil dedektörüne bırakıldı) ve
"you are now" belirsizdi (negatif-lookahead regex'e çevrildi, "you are now
logged in" artık eşleşmiyor).

### Sonraki faza bırakılan dikişler

- `ScanVerdict.edits` boş; `strip` eylemi Faz 5.
- PII tanıyıcıları (`pii/recognizers`) ve maskeleme Faz 5.
- `@tunedness/mcpguard-ruleset` şu an yalnız injection kuralları; PII recognizer verisi
  Faz 5'te aynı pakete girer.
- Kural setinin kendi digest'ini `index.json`'a damgalayan lint scripti henüz
  yok; digest şimdilik yükleme anında hesaplanıyor (yeterli, ama tedarik
  zinciri doğrulaması için P1).
- Gecikme harness'i (`bench/latency/`) Faz 10.

---

## Faz 5 — PII tanıyıcıları, maskeleme ve `strip` (bitti)

488 test, kapı yeşil. Checksum'lu tanıyıcılar, maskeleme ve `strip` eylemi
`scanContent`'e bağlandı — PII injection'dan ayrı bir eksende koşar.

```
packages/detect/src/pii/checksums.ts   TCKN · VKN · Luhn+scheme · IBAN mod-97
packages/detect/src/pii/recognizers.ts aday → validator → bağlam üç kademe
packages/detect/src/pii/mask.ts        [KIND:***tail#tag] · HMAC korelasyon
packages/detect/src/strip.ts           applyEdits · buildStripEdits · defang
packages/detect/src/scan.ts            PII + strip tek geçişte entegre
```

### Bilinmesi gerekenler

- **Checksum kapıdır, varsayılan sıkı.** 11 haneli sayı her yerde; TC kontrol
  hanesi aday uzayını ~100 kat daraltır. `strict_checksum: false` regüle-kiracı
  ayarı: checksum düşse de yanında bağlam anahtar kelimesi varsa maskeler
  (KVKK: hatalı yazılmış TC de kişisel veridir). Bench iki noktayı da raporlar
  (Faz 10).
- **Kart:** Luhn **ve** IIN öneki **ve** şema uzunluğu; 13 haneli EAN (978/979)
  elenir. IBAN: ülke uzunluk tablosu + mod-97, büyük sayı oluşturmadan akış.
- **Maskeleme kendi ekseninde:** `flag` kararı da maskelenir, `block` zaten
  içeriği değiştirir. Tanıma **maskesiz** metinde yapılır — kart numarasına
  benzeyen bir yük, injection dedektörleri görmeden maskelenmemeli.
- **`strip` en azını yapar:** eşleşen aralık sabit, *talimat gibi okunmayan*
  `[…]` işaretçisiyle değişir (kural adı vermek saldırgana kehanet olurdu),
  görünmez unicode silinir, egress URL'i defang edilir (metin görünür kalır,
  `http`→`hxxp`), çevresi bayt-birebir korunur. Strip çıktısı bir kez yeniden
  taranır; hâlâ block bandındaysa `block`'a yükselir.
- **Degraded (büyük) öğe düzenlenmez:** örneklemeden sonra offset'ler
  hizalanmadığı için maskeleme yanlış yere düşerdi; degraded verdict
  düzenlenmeden iletilir ve öyle olduğunu söyler.
- **Korelasyon etiketi** `HMAC(deploymentKey, normalizedValue)`'nin ilk 4 hex'i;
  aynı kimliği iki yerde görmeye yeter, geri getirmeye yetmez (bilerek çakışır).
  Anahtar çağırandan gelir — çekirdek rastgelelik üretmez.

### Çelişki kaydı

**VKN checksum'u ilk yazımda yanlıştı.** `tmp===9?9:...` kısayolu Maliye
algoritmasını bozuyordu; kanonik forma (`t=0 atla; q=(t*2^(9-i))%9; q===0?9:q`)
düzeltildi ve ileri hesapla üretilen geçerli bir VKN ile doğrulandı. TCKN, IBAN,
Luhn bilinen geçerli değerlerle test edildi (10000000146, TR33..., 4111...).

### Sonraki faza bırakılan dikişler

- Maskeli içerik + **ham içeriğin HMAC parmak izi** audit kaydına Faz 6'da
  yazılır (`hmacSha256` çekirdekte hazır). ADR-004'ün 2026-09-16 düzeltmesi bu.
- Sağlık verisi tanıyıcıları (ICD-10, ATC, MEDULA, quasi-identifier
  co-occurrence) yazılmadı — PRD "kimlik maskeleme, PHI redaksiyonu değil" diyor;
  `profile: health` arkasında P1.
- PII için ayrı bench (`bench/pii/`) Faz 10; iki checksum noktası orada raporlanır.

---

## Faz 6 — audit log ve manifest sabitleme, çekirdek tarafı (bitti)

Saf hesaplama: kayıt üretimi, zincir doğrulaması, manifest normalizasyonu ve
diff. Dosyaya yazma Faz 8 CLI'ın işi. 522 test.

```
packages/core/src/audit/record.ts   AuditRecord · buildRecord (hash zinciri)
packages/core/src/audit/chain.ts     verifyChain · checkpoint
packages/core/src/lock/manifest.ts   hashTool · lockServer · diffServer (TOFU)
```

### Bilinmesi gerekenler

- **Kayıt ham içerik tutmaz:** maskeli içerik + `HMAC(auditKey, ham)` parmak
  izi (ADR-004 düzeltmesi). Düz `sha256(ham)` düşük entropili içerikte kehanet
  olurdu. Anahtar yoksa parmak izi yok — zayıf ama düz digest'ten iyi.
- **Zincir ortadaki düzenlemeyi yakalar:** her kayıt bir öncekinin hash'ini
  taşır; `verifyChain` üç şeyi kontrol eder — kaydın hash'i yeniden hesaplanır,
  `prevHash` öncekiyle eşleşir, seq bir artar. İlk bozulan yeri söyler.
- **Checkpoint toptan takası yakalar:** zincir kendi içinde tutarlı ama farklı
  bir dosyayla değiştirilmişse, orijinalden yayınlanan checkpoint tutmaz.
  `matchesCheckpoint` bunu sınar. Checkpoint stdout'a **asla** — Faz 8'de
  stderr/syslog'a yazılır.
- **Manifest hash'i davranış tanımlayan alanlar üzerinden** (name, description,
  inputSchema, annotations), anahtarlar sıralı: sunucu input-schema anahtar
  sırasını değiştirirse aracı değişmemiştir; parametre eklerse değişmiştir,
  sıralı serileştirme ikincisini gösterir birincisini değil. `diffServer`
  added/removed/**altered** ayrımı verir — altered rug-pull şeklidir.

### Çelişki kaydı

Yok. Çekirdek tarafı ADR-004 ve ADR-005'e birebir uydu; ADR-004'ün HMAC
düzeltmesi zaten Faz 0'da yazılmıştı, burada uygulandı.

### Sonraki faza bırakılan dikişler

- `AuditSink` portu (Faz 2) ve bu kayıt üreticileri Faz 8 CLI'da JSONL
  yazıcıyla birleşir; append-only dosya, checkpoint stderr/syslog.
- `guardlock.json` okuma/yazma ve TOFU akışı Faz 8 (`mcpguard lock`).
- Proxy `tools/list`'i görüp `diffServer` çağıracak — Faz 7.

---

## Faz 7 — `@tunedness/mcpguard-proxy` (bitti, tesisat kısmen doğrulandı)

MCP adaptörü. Motordan bağımsız dosyalar + üç kapı + `wrap` giriş noktası.
`@modelcontextprotocol/{server,client,core}@2.0.0` üzerinde. 557 test.

```
packages/proxy/src/era.ts          legacy/modern, çeviri YOK (assertSameEra)
packages/proxy/src/diagnostics.ts  stderr, prefixli, rate-limitli
packages/proxy/src/remap.ts        tunedness.session-id ENJEKSİYONU (ADR-006)
packages/proxy/src/content.ts      ContentBlock text çıkar/geri koy
packages/proxy/src/guard.ts        tek motoru-tanıyan dosya: scan+access+manifest
packages/proxy/src/bridge.ts       Server/Client çifti, üç kapı + fallback
packages/proxy/src/stdio-wrap.ts   child spawn + serveStdio tesisatı
packages/proxy/src/boundary.test.ts
```

### Bilinmesi gerekenler

- **`boundary.test.ts`** motoru-tanıyan dosyaları tam olarak `['guard.ts']`'e
  pinliyor; beşinci bir tanesi karar, kaza değil. Ayrıca hiçbir dosya
  `console.*`/`process.stdout`'a dokunamaz (wrap modunda stdout ajanın JSON-RPC
  akışı).
- **McpGuard'ın AgentFuse'dan farkı `remap.injectSession`:** en dıştaki proxy
  olduğu için baggage üyesini **yazar**. Var olan trace baggage'ına merge eder,
  zaten varsa dokunmaz (dıştakinin cevabı kazanır).
- **`resources/read` üçüncü kapı** — SDK'da içerik tipi var (`ReadResourceResult`)
  ama guard tarafı McpGuard'da yazıldı; AgentFuse'da bu kapı yok.
- **Gözlem modu (`enforce: false`) `block`'u `flag`'e düşürür** ama içeriği yine
  maskeler/strip eder — maskeleme enforcement değil, veri hijyeni.

### Çelişki kaydı — ve dürüst kapsam

**Bridge ve `stdio-wrap`'in SDK tesisatı derleniyor ve yapısal olarak
AgentFuse'un çalışan desenini taban alıyor, ama bu ortamda gerçek bir MCP
sunucusuyla uçtan uca koşturulup doğrulanmadı.** AgentFuse da gerçek-süreç
testlerini (`wrap-process.test.ts`) sonraki faza bırakmıştı; aynı dürüst
sıralama. Doğrulanan: `content`, `guard`, `era`, `remap`, `diagnostics`,
`boundary` (35 proxy testi). Doğrulanmayan: `Server`/`Client` köprüsünün gerçek
stdio boru üzerinden iki era'da da doğru çalışması — **Faz 8'in ilk işi**,
`examples/` altında zararsız bir fixture sunucu ile.

Ayrıca modern era `serveStdio` bir factory bekliyor; şu anki `stdio-wrap`
düşük seviyeli `Server` + `StdioServerTransport` kullanıyor (legacy için doğru).
Modern era serving'i Faz 8'de gerçek koşumla netleşecek.

### Sonraki faza bırakılan dikişler

- Gerçek-süreç `wrap` testi + `examples/noop-server.mjs` — Faz 8.
- Oturum çözümleme (ULID mint) `wrap`'te CLI tarafında — Faz 8.
- Manifest kapısı (`tools/list` → `diffServer` → `guardlock.json`) guard'a
  bağlanacak; şu an `guardList` sadece geçiriyor — Faz 8 lock akışıyla.

---

## Faz 8 — CLI ve `wrap` (bitti, proxy gerçek koşumla DOĞRULANDI)

`mcpguard` bin'i, altı komut, ve Faz 7'nin bekleyen uçtan uca doğrulaması.
583 test.

```
packages/cli/src/config.ts        yaml + LineCounter, dosya:satır hata
packages/cli/src/ruleset.ts       @tunedness/mcpguard-ruleset → loadRuleset
packages/cli/src/runtime.ts       policy+ruleset → guard gates (AuditRecorder)
packages/cli/src/audit-writer.ts  append-only JSONL, hash zinciri sahibi
packages/cli/src/ulid.ts          oturum kimliği (çekirdek değil, CLI mint eder)
packages/cli/src/commands/{wrap,scan,validate,init,audit,lock}.ts
packages/cli/src/commands/wrap-process.test.ts   GERÇEK stdio boru
packages/cli/src/testing/fixtures/echo-server.mjs
examples/echo-server.mjs
```

### DOĞRULANDI — proxy gerçek MCP protokolüyle çalışıyor

`wrap-process.test.ts` derlenmiş `dist/main.js`'i gerçek bir `StdioClientTransport`
ile sürüyor: client → `mcpguard wrap` → echo fixture sunucu. Kanıtlanan:

- `tools/list` proxy üzerinden geçiyor, `echo` görünüyor.
- Temiz sonuç bayt-birebir geçiyor.
- **PII maskeleniyor:** `kimlik 10000000146` → `kimlik [TCKN:***]`, ham değer
  hiçbir yerde yok.
- **Injection tespit ediliyor** (skor 64), audit'e yazılıyor ve
  **`verifyChain` gerçek dosyada geçiyor**; elle kurcalayınca kırılıyor.

Faz 7'nin "tesisat derleniyor ama gerçek sunucuyla koşturulmadı" çekincesi
**kapandı**.

### Bilinmesi gerekenler

- **`main.ts` süreç dokunan tek dosya** — `discipline.test.ts` bunu ve
  `@opentelemetry/*`'nin hiçbir manifest'te/kurulu olmadığını (`npm ls`)
  zorluyor.
- **Audit yazıcı hash zincirinin sahibi:** runtime yalnız `AuditFields` + ham
  içerik verir, `AuditWriter.record` prevHash/seq'i tutup zincirler. Dizini
  ilk yazımda `mkdirSync` ile açar (eksik `.mcpguard/` yüzünden proxy
  başlamamazlık etmez).
- **Oturum kimliği CLI'da ULID** ile üretilir (`node:crypto`); çekirdek
  rastgelelik üretmez. stdio wrap'te bir child = bir oturum (ADR-006).
- **`wrap` argümanları ilk `--`'de durur;** sonrası child'ın. `parseWrapArgs`.
- Politika arama: `--policy` → `MCPGUARD_POLICY` → `cwd`'den yukarı; göreli
  yollar politika dosyasına göre çözülür.

### Çelişki kaydı

**Testte `wrap` alt komutu argümanlardan düşmüştü** (`[MAIN, '--name'...]`,
`'wrap'` yok) → "unknown command: --name" → "Connection closed". Manuel e2e'de
vardı; testte eksikti. Eklendi. Gerçek bir hata değil, test kurulum hatası —
ama tam da bu yüzden gerçek-süreç testi değerli: birim test bunu yakalamazdı.

### Sonraki faza bırakılan dikişler

- **`serve` (HTTP gateway) bilinçle reddediyor** — Faz 11 (ya da P1). `wrap`
  bugün korumalı olan.
- Manifest kapısı (`guardList` → `diffServer` → `guardlock.json` yaz/kontrol)
  hâlâ sadece geçiriyor; TOFU akışı `wrap`'e bağlanacak — küçük kalan iş.
- Telemetri (OTLP `security_event`) Faz 9; şu an olaylar stderr'e
  `[mcpguard] {event...}` diye yazılıyor.
- Checkpoint stderr'e yazılıyor; syslog sink'i P1.

---

## Faz 10 — gecikme benchmark'ı (bitti, kalibrasyon Faz 4'te yapıldı)

Tespit kalibrasyonu Faz 4'te tamamlanmıştı (recall %100/FP %0, in-sample).
Bu faz gecikme bütçesini ölçtü. 586 test.

```
bench/src/latency/stats.ts   yüzdelik; eklenen gecikme = yüzdelik FARKI
bench/src/latency/run.ts     boyuta göre maliyet eğrisi
bench/latency/results.{md,json}
```

### Ölçülen — PRD §6 p95 < 20 ms

| boyut | p50 | p95 |
| --- | --- | --- |
| 1 KB | 0,19 | 0,24 ms |
| 16 KB | 2,9 | 3,1 ms |
| 64 KB | 15,1 | 16,0 ms |
| 128 KB | 31,4 | 33,3 ms |
| 256 KB | 47,1 | 49,2 ms |

**Referans yükünde MET.** Korpus median öğesi **188 bayt**, p95 **485 bayt** —
araç sonuçları çoğunlukla küçük. O boyutta p95 ~0,2 ms, muazzam pay. Bütçe
**~64 KB'ye kadar** tutuyor.

### Bilinmesi gerekenler ve dürüst çekince

- **Tek sayı değil eğri raporlandı:** "p95 < 20 ms" boyut belirtmeden yeterince
  küçük yük seçilerek doğrulanabilir; o yüzden nerede aşıldığı yazılıyor.
- **Maliyet boyutla büyür, kural sayısıyla değil** — tek geçiş + Aho-Corasick.
  İki kat büyük kural seti aynı sürede taranır.
- **128 KB+ öğe bütçeyi aşar** (~33 ms). Bunlar büyük sonuçlar (dosya/arama).
  256 KB üstü örneklenir ve degraded işaretlenir — sınırsız girdide bile
  maliyet sınırlı. Operatörün kolu `scan.max_bytes`.
- **Eklenen gecikme = yüzdelik farkı**, çağrı-çağrı değil: iki bağımsız koşumu
  eşleştirmek olmayan bir karşılıklık uydurur.
- CI (`bench.yml`) latency job'ı `referenceMet`'i kapı yapıyor; rakamlar
  makineyle oynadığı için diff'lenmiyor.

### Çelişki kaydı

Yok. Ölçüm PRD §6'yı referans yükünde tuttu; büyük-öğe aşımı tasarım gereği
(maxScanBytes cap + degraded) ve dürüstçe raporlandı.

### Sonraki faza bırakılan dikişler

- **Faz 11 (HTTP gateway) P1'e** — AgentFuse `serve`'ü de korumasız bırakıp
  dürüstçe yazmıştı; aynı sıralama. `.ssot` PRD zaten "kaçarsa P1" diyor.
- Faz 9 telemetri opsiyonel; olaylar şu an stderr'e yazılıyor.
- Faz 12: README güncellemesi, wiki, changeset baseline, release.yml.

---

## Faz 9 — telemetri (OTLP, `security_event`) (bitti)

El yazması OTLP/HTTP, `@opentelemetry/*` yok (ADR-007, `discipline.test.ts`
zorluyor), opt-in ve varsayılan kapalı. 595 test.

```
packages/cli/src/telemetry/otlp.ts   toLogRecord · toLogsPayload (el yazması)
packages/cli/src/telemetry/sink.ts   OtlpTelemetrySink (batch, best-effort)
```

### Bilinmesi gerekenler

- **`security_event` bu aracın olay tipi** (çatı ADR-003 ayırdı); `policy_decision`
  de yayılır. `loop_detection`/`budget_event` AgentFuse'un — çekirdek `EventType`
  tip sistemiyle yalnız ikisine izin veriyor.
- **Varsayılan kapalı:** `telemetry.enabled` + `endpoint` olmadan `NULL_TELEMETRY`.
  Güvenlik proxy'sinin varsayılan olarak eve telefon etmemesi, satın alma
  incelemesinde açıklanacak bir madde olmaktan çıkar.
- **Best-effort:** başarısız POST raporlanır, **asla** çağrıya fırlatılmaz —
  telemetri bir çağrıyı bloklayamaz. Batch dolunca flush; başarısızlık düşer.
- Namespace `tunedness.*`, timestamp nanosaniye, attribute kodlaması elle.

### Çelişki kaydı

Yok. ADR-007'ye birebir uydu.

### Sonraki faza bırakılan dikişler

- Checkpoint syslog sink'i hâlâ P1 (stderr çalışıyor).
- Trace context (`traceparent`) yayımı P1.

---

## Faz 12 — dokümanlar ve v0.1.0 (bitti)

README ürünü gerçek haliyle anlatıyor (ölçülmüş rakamlar, in-sample çekince,
"bilinçle olmayanlar"), paket README'leri, changeset baseline (düzyazı sürüm
notu), `release.yml` (manuel `workflow_dispatch`, `environment: npm`, tam kapıyı
yeniden koşturur — yayın bir karardır). `.ssot` PRD'ye v0.1.0 durumu ve P1
çizgisi yazıldı.

### v0.1.0 nedir, ne değildir

**Olan:** `mcpguard wrap -- <sunucu>` ile tam korumalı proxy — gerçek MCP
protokolüyle doğrulandı. Deterministik injection taraması (%100/%0 in-sample),
PII maskeleme, erişim denetimi, manifest sabitleme, hash zincirli audit,
opsiyonel OTLP telemetri. Komutlar: `wrap`, `scan`, `validate`, `init`,
`audit`, `lock`.

**Bilinçle olmayan (P1):**
- **Korumalı HTTP gateway (`serve`)** — koruma `wrap`'te; `serve` reddedip
  söylüyor. AgentFuse'un `serve` dürüstlüğü emsali.
- Sağlık verisi PHI redaksiyonu — MVP kimlik maskeleme.
- Kademe 2 SLM hakem — Kademe 1 tümüyle deterministik.
- Manifest kapısının `guardlock.json` yaz/kontrol akışının proxy'ye tam
  bağlanması (çekirdek `diffServer` hazır, `guardList` şu an geçiriyor).
- Checkpoint syslog sink'i; trace context yayımı.

### Devralan kişiye

1. ~~Yayın adı/scope kararı~~ — verildi ve Faz 16'da uygulandı:
   `@tunedness/mcpguard` (bin `mcpguard`) + `@tunedness/mcpguard-*`.
2. **`release.yml` iki adımlı:** `version` (changeset PR açar) ve `publish`
   (`environment: npm`, provenance). `*_VERSION` sabitleri manifest'lerle eşit
   olmalı; `packages/cli/src/packaging.test.ts` bunu zorlar (Faz 16).
3. **Gerçek-süreç testi (`wrap-process.test.ts`) her koşuda çalışır** ve
   proxy'yi gerçek sunucuyla sınar; kaldırılmamalı.
4. **Rakamlar yumuşatılmaz:** injection ve latency CI kapıları ulaşılanın
   kaydı. Düşürülmesi kötüleşme demektir; o zaman konuşulacak şey kapı değil
   algoritmadır.
5. P1 manifest bağlama küçük: `guardList` gate'i `diffServer`'a bağla,
   `on_first_use`/`on_mismatch` politikasını uygula, `guardlock.json`'ı
   CLI'da oku/yaz.

---

## Çalışma kuralları

- **`.ssot` koddan önce gelir** (çatı ADR-002). Kapsam değiştiren geliştirme
  öncesi `../.ssot/PRD.md` ve `../.ssot/ADR.md` güncellenir. Çatı kayıtları
  (`../../../Tunedness/.ssot/`) araç kayıtlarını **ezer**.
- Her fazın kapısı: `npm run lint && npm run typecheck && npm run build &&
  npm test`. **Yeşile ulaşmak için tsconfig katılığı gevşetilmez, lint kuralı
  kapatılmaz, coverage eşiği düşürülmez** — kod düzeltilir. Bir Biome kuralı
  gerçekten haklı bir desenle çatışıyorsa o satırda gerekçeli yorumla
  daraltılmış şekilde kapatılır; asla dosya geneli, asla config'te.
- **Commit mesajlarına hiçbir trailer eklenmez** — `Co-Authored-By`,
  `Generated with`, oturum bağlantısı, `Signed-off-by` yok. Mesaj anlatımın son
  cümlesiyle biter. Mesaj biçimi: emir kipi, tam cümle, niyeti anlatır;
  conventional commits öneki ve ticket numarası yok.
- `git add` yalnız kendi yollarını açıkça stage'ler, asla `git add -A`.
- Kod, yorumlar, commit mesajları ve README **İngilizce**; bu dosya ve `.ssot`
  **Türkçe**.

---

## Faz 14 — doğruluk düzeltmeleri (bitti)

v0.1.0'ın anlattığı ama yapmadığı dört şey. Her biri bir regresyon testiyle
kilitli; testler `packages/cli/src/runtime.test.ts`,
`packages/cli/src/commands/wrap-identity.test.ts` (gerçek pipe, derlenmiş
binary), `commands.test.ts`, `cli.test.ts` ve `audit.test.ts` içinde.

- **Audit HMAC'i.** `runtime.ts` parmak izini `totalBytes` listesinden alıyordu;
  şimdi upstream sonucunun maskelenmemiş metin blokları (`extractText`, `\n` ile
  birleşik) HMAC girdisi. `onCall` ve `onRead` aynı yolu kullanır. Ham metin
  kayda yazılmaz (ADR-004). `deny` kaydında upstream yok, girdi boş.
- **Korelasyon anahtarı.** Şemaya `pii.correlation_key_env` eklendi
  (`schema:generate` ile üretildi). `wrap` anahtarı env'den okur ve
  `scanOptionsFor`'a geçirir; `detect` tarafına dokunulmadı.
- **Kimlik merdiveni (ADR-010).** `wrap --identity`, `MCPGUARD_IDENTITY`,
  legacy era'da `clientInfo.name`. Modern era'da son basamak yok:
  `getNegotiatedProtocolVersion()` + `eraOf` ile elenir. `guardCall` artık
  oturum ULID'ini değil çözülmüş kimliği alır (ULID hiçbir rol eşlemesine
  uymaz). Çözüm `{ identity, source, exact }` olarak audit kaydında
  (`callerIdentity`) ve `security_event`/`policy_decision` olaylarında
  (`tunedness.identity*` attribute'ları). `source` değerleri ADR-010'daki gibi
  `flag | env | client_info | none` (faz dosyasındaki `clientInfo` yazımı
  ADR'ye uyduruldu). `--identity` değersiz verilirse hata: sezgisele düşmez.
- **Açılış kontrolleri.** `packages/cli/src/preflight.ts` (`validate` ve `wrap`
  ortak): `correlation_tags` açık ve anahtar yok/boş → `EXIT.policy`;
  `checkpoint_to: syslog` → "henüz desteklenmiyor (P1, Faz 23)", `EXIT.policy`.
  Gerçek syslog sink'i Faz 23'te.

**Geriye uyumluluk.** `callerIdentity` kayıtta isteğe bağlı bir alan; zincir
hash'i kaydın tuttuğu gövdeyi hash'lediği için alanı taşımayan v0.1.0 kayıtları
`audit verify`'dan geçmeye devam eder (testle kilitli).

**Devralan kişiye.** `wrap` kimliği gate'lere geç bağlanan bir referansla
okur (downstream `Server` bağlantıdan sonra var olur); bağlanmadan gelen bir
çağrı kimliksiz sayılır, yani politikanın varsayılanına düşer, bir role
yükselmez. `serve` (Faz 18) kimlik çözümünü ayrıca yapacak (ADR-011).


---

## Faz 15 — manifest kapısı (bitti)

Rug-pull koruması (ADR-005) proxy'ye bağlandı. Çekirdek `diffServer`/`hashTool`
olduğu gibi kullanıldı; yeni bir hash algoritması yok.

```
packages/cli/src/manifest-gate.ts     tools/list kapısı: karar mantığı
packages/cli/src/lock-file.ts         guardlock.json okuma, atomik yazma, yol çözümü
packages/cli/src/runtime.ts           onList kapıya bağlı; toolScanner; olay/kayıt çıkışı
packages/cli/src/commands/lock.ts     show | --diff | --accept
packages/core/src/lock/manifest.ts    parseLock · serializeLock · toToolDefinition · withServerLock
packages/proxy/src/list-tools.ts      listStdioTools (lock komutu için tek seferlik tools/list)
packages/cli/src/testing/fixtures/shifty-server.mjs   manifest'i değişen test sunucusu
```

**Davranış.**
- **İlk temas** (`on_first_use: write`): kilit ya da bu sunucunun girdisi yoksa
  manifest pinlenir (geçici dosya + `rename`, sıralı anahtarlar, 2 boşluk
  girinti, sonda `\n`), liste geçer. `require`: trafik durur, hiçbir şey
  yazılmaz. `on_mismatch: flag` `require`'ı yumuşatmaz.
- **Sonraki oturumlar:** `diffServer` farkı varsa `halt` (varsayılan) `tools/list`'i
  hata ile reddeder; `flag` geçirir, olayı yayar ve kayda düşer. Diff stderr'e
  JSON satırı olarak (`manifest_mismatch`: `altered`/`added`/`removed`),
  `security_event` olarak OTLP'ye ve `tool_list` türünde audit kaydına gider.
  İstemciye dönen hata mesajı araç adı/açıklaması taşımaz: onlar sunucunun
  sözleri.
- **Oturum içi değişiklik:** `notifications/tools/list_changed` olduğu gibi geçiyor; kapı her
  `tools/list` isteğinde çalıştığı için bir sonraki liste yeniden karşılaştırılır.
  Kilit her seferinde diskten okunur, yani `lock --accept` çalışan bir oturumda da
  görülür.
- **Hash kapsamı:** `name`, `description`, `inputSchema`, `annotations` ve —
  varsa — üst düzey `title` ile `outputSchema`. İkisi yalnız varsa hash'e girer;
  hiçbiri olmayan bir aracın hash'i değişmedi.
- **Açıklama taraması:** başlık, açıklama, annotation string'leri ve iki şemadaki
  `description`/`title` metinleri `tool_description` türüyle taranır. Eşik aşılırsa
  `injection_detected` olayı + `tool_list` kaydı çıkar ve kural kimlikleri kilitte
  `tools[].findings` olarak durur. **Bulgu işaretlenir, araç listeden çıkarılmaz**
  (PRD Faz 0 eki "bulgular kilide yazılır" diyor). `findings` hash'e girmez.
- **Sayfalı `tools/list`:** bir sayfa katalogun tamamı sayılmaz; `removed` yalnız
  son sayfada, ilk sayfa görüldüyse hesaplanır; TOFU yazımı son sayfada olur.
- **Kapının açık bırakmaması:** liste reddedilince `tools/call` de reddedilir.
  **Halt yapışkandır** (ADR-005 eki, Faz 18'de eklendi): pin'le eşleşen sonraki bir
  liste halt'ı kaldırmaz, liste de çağrı da reddedilmeye devam eder; halt'ı yalnız
  pin'i değiştiren `lock --accept` (ya da sürecin yeniden başlatılması) kaldırır.
  Kaldırıldığında upstream çağrıdan önce yeniden doğrulanır. Halt'ın birimi
  politikadaki sunucu kaydıdır (`servers.<ad>`): `wrap`'te tek sunucu; `serve`'de her
  iki era ve her oturum için tek durum. Bir oturumun upstream bağlantısında görülen
  uyumsuzluk o sunucunun bütün oturumlarını, sonradan açılanlar dahil, durdurur;
  modern bacakta paylaşılan `Client` yeniden bağlansa da korunur. Hiçbir oturum onu
  kendi listesiyle açamaz.
  "Doğrulandı" ise bağlantı başınadır: yeni bir oturum ya da yeniden kurulan
  paylaşılan bağlantı, çağrıdan önce kontrolü yeniden yapar. Okunamayan kilit
  `halt` politikasında kontrolsüz çağrıyı da geçirmez (bu, `wrap`'te davranış
  değişikliğidir). `require` + girdi yokken liste hiç istenmese
  bile çağrı reddedilir. Pin varken ve oturumda henüz doğrulanmış liste yokken
  ilk `tools/call`'dan önce kapı upstream'den kendisi `tools/list` çeker ve aynı
  karşılaştırmayı yapar (önbellekli kataloğa güvenen istemci kapıyı atlayamaz);
  upstream'e ulaşılamazsa o çağrı `unverified` ile reddedilir, kalıcı halt
  sayılmaz. Sınır: oturum ortasında gelen `list_changed` bildirimi bu "doğrulandı"
  durumunu sıfırlamaz; değişen manifest bir sonraki `tools/list`'te yakalanır.
- **Kilit okunamıyorsa** (bozuk JSON, yanlış şekil) `unreadable`: `halt`/`flag`
  politikasına tabidir ve ilk-temas yazımı asla üzerine yazmaz. Yazım başarısız
  olursa (`write_failed`) liste reddedilir; pinlenmemiş çalışmak sessiz bir
  koruma eksikliği olurdu. Adsız ya da tekrarlı araç adı `malformed` sayılır.

**`lock` komutu.** `mcpguard lock show`, `lock --diff -- <cmd>` (farkı gösterir,
fark ya da pin yoksa çıkış 5, hiçbir şey yazmaz), `lock --accept -- <cmd>`
(açık onay: mevcut manifest'i yazar, yalnız adı verilen sunucunun girdisini
değiştirir; zaten aynıysa dosyaya dokunmaz). Sunucu komutu `--`'den sonra gelir
çünkü taşıma politikada değil CLI argümanı; `--server` kilitteki adı verir
(`wrap --name` ile aynı, varsayılan `server`). `--diff` değişen/eklenen araçların
şu anki tanımını (tek satır, JSON-kotalı, 4000 karakterle sınırlı) ve manifest'in
`set:` hash'ini basar; `--accept --expect <set-hash>` yalnız incelenen manifest'i
pinler, arada değişmişse reddeder. `--full` 4000 karakter sınırını kaldırır (sınır
kesildiğini ve `--full`'u söyler). `show` ve `--diff` sunucudan gelen adları ve
tanımları `quote`/`escapeUnsafeJson` (core `util/display.ts`) ile basar: JSON-kotalı
ve ek olarak C1, bidi/format (RLO, izolatlar, sıfır genişlik) ve satır/paragraf
ayırıcıları görünür `\uXXXX` kaçışına çevrilir (`JSON.stringify` yalnız C0'ı
kaçırır). Aynı kaçış `wrap`'in stderr olay satırlarına ve `parseLock` hata
mesajlarına da uygulanır.

**Devralan kişiye.**
- **Gözlem modu (`mode: flag`) kilidi yumuşatmaz.** `on_mismatch` operatörün
  açık kararı; varsayılanı `halt`. Gözlemde kalıp farkı yalnız görmek isteyen
  `on_mismatch: flag` yazar. Bu, `scan` aksiyonlarının gözlemde `flag`'e
  düşmesinden bilinçle farklı.
- Birden çok `wrap` süreci aynı `guardlock.json`'a farklı sunucu adıyla ilk-temas
  yazarsa okuma-değiştirme-yazma yarışı olabilir (rename atomik, ama son yazan
  kazanır). Aynı dosyayı paylaşan eşzamanlı ilk temas için `lock --accept` önerilir.
- Faz dosyasının listesinde olmayan ama kapsam gereği dokunulanlar:
  `packages/proxy/src/{list-tools,index,boundary.test}.ts` (CLI'ya MCP istemci
  bağımlılığı eklememek için tek seferlik liste çağrısı proxy'de) ve yeni
  `manifest-gate.ts`/`lock-file.ts`.

---

## Faz 25 — `wrap`'in P0 boşlukları: era, capability aynalama, kombinasyon kuralları (bitti)

Faz 17'deki tasarım okumasının `wrap`'te gösterdiği üç boşluk. Her biri önce bir
testle yeniden üretildi (üçü de **kaldı**: bulgu doğruydu), sonra düzeltildi.

```
packages/proxy/src/stdio-wrap.ts      serveStdio fabrikası; era'ya göre upstream; OpeningObserver
packages/proxy/src/bridge.ts          forward: istek başına clientCapabilities'i upstream _meta'sına aktarır
packages/cli/src/runtime.ts           CombinationHistory; onCall'da evaluateCombinations
packages/cli/src/commands/wrap.ts     WrapHandle.current()/closed; DownstreamView artık geç bağlanıyor
packages/cli/src/testing/fixtures/    echo-server (read_file, send_http, show_capabilities),
                                      sampling-server, legacy-only-server, modern-only-server
```

**1. Era.** `wrap` downstream'i `bridge.server.connect(StdioServerTransport)` ile
sunuyordu; SDK'da era instance durumu ve yalnız serving entry'ler (`serveStdio`,
`createMcpHandler`) modern'i işaretliyor, bu yüzden modern bir istemci `server/discover`'a
cevap alamayıp bağlanamıyordu. Artık `serveStdio(factory)` kullanılıyor: istemcinin
açılış mesajı era'yı seçiyor, fabrika `{ era }` ile o era için upstream child'ı ve
bridge'i kuruyor. Modern'de upstream `versionNegotiation: { mode: 'auto' }` ile
bağlanıyor ve sonuç era `assertSameEra` ile downstream'inkiyle karşılaştırılıyor;
uyuşmazlık `EraMismatchError` (çeviri yok, ADR-002). Modern açılışta hata fırlatılır
(istemci bağlanamaz, sebep stderr'de); legacy açılışta `initialize`'a sebebiyle
birlikte hata dönen bir "reddeden" `Server` verilir, çünkü `serveStdio` modern'de
`server/discover`'ı kendisi cevaplıyor ve reddeden instance'ın cevabını ezer.
Bir `server/discover` probe instance'ı legacy'ye düşerken `serveStdio` tarafından
kapatılır; bridge `server.onclose`'ta upstream `Client`'ı kapatır, child sızmaz.

**Önemli — ADR-011 madde 2 (V1 spike) için ön bilgi.** Bridge `Server`'ı bir
fabrikadan modern olarak sunuluyor ve stdio'da çalışıyor: modern istemci
(`pin: '2026-07-28'`) `wrap` üzerinden `tools/call` yapıyor ve tarama uygulanıyor.
HTTP için henüz denenmedi (`createMcpHandler` istek başına fabrika çağırıyor; her
istekte upstream bağlamak orada ayrı bir iş). Modern'de MRTR (`input_required`)
upstream'den downstream'e taşınmıyor, test edilmedi.

**2. Capability aynalama.** Upstream `Client` capability'siz kuruluyordu; sunucu
"istemcide roots yok" görüyordu. Legacy'de çıkmaz: downstream `initialize`'ına upstream'in
capability'leriyle cevap vermek, upstream'i ise downstream'in capability'leriyle
bağlamak gerekiyor. SDK'nın `initialize` işleyicisi `Server` içinde ve capability'ler
yapıcıda sabit; çözüm `serveStdio`'nun belgeli `transport` seçeneği: `OpeningObserver`
downstream telin önüne geçip `initialize` (legacy) ve modern zarfındaki capability'leri
okuyor, hiçbir çerçeveyi değiştirmeden ya da yazmadan geçiriyor; fabrika upstream'i
bunlarla bağlıyor. Modern'de her istek kendi capability'sini taşıdığından `forward`
istek başına `io.modelcontextprotocol/clientCapabilities`'i upstream `_meta`'sına yazıyor
(handler'a gelen istekte zarf SDK tarafından sıyrılmış durumda; yazılmazsa upstream'in
ilk bağlantıdaki capability'leri geçerli kalırdı).

**3. Kombinasyon kuralları.** `evaluateCombinations` hiçbir yerden çağrılmıyordu.
`onCall`'da erişim kararından sonra, `forward`'dan önce çalışıyor. `CombinationHistory`
oturum kimliğiyle anahtarlı, en uzun pencerenin dışına düşeni atan, oturum başına 512
ve toplam 1024 oturumla, araç adı da 4096 karakterle sınırlı (aşan çağrı geçmişe
girmez; `deny` kuralı + `enforce` ise reddedilir, değilse bayraklanır) bir depo; `RuntimeDeps.history` ile dışarıdan
verilebiliyor (Faz 18 HTTP aynı depoyu istek başına çözülen oturumla kullanacak).
Kurallar `evaluateCombinations`'a olduğu gibi veriliyor; semantiği değişmedi. İki
ayrıntı bilinmeli: (a) o an yapılan çağrı listenin **başına** konuyor, çünkü fonksiyon
her glob için ilk eşleşen çağrıyı delil seçiyor ve yalnız delili o çağrıyı içeren
kurallar sayılıyor — yoksa daha önce tamamlanmış (ve `flag` ile geçirilmiş) bir kural
alakasız her çağrıda yeniden ateşlenirdi; (b) `all_of` sıralı değil: `read` önce de olsa
`send` önce de olsa ikinci çağrı tamamlayan olur. `deny` + `enforce`: çağrı reddedilir,
geçmişe girmez, audit'e `action: deny` ve kural kimliği yazılır (içerik yok; eşleşen
`server__tool` adları `maskedContent`'te JSON). `flag` ya da `mode: flag`: çağrı geçer,
olay (`combination_detected`, `policy_decision`) ve audit kaydı yazılır; çağrının kendi
sonuç kaydı ayrıca gelir.

**Devralan kişiye.**
- `wrap` artık upstream'i ilk istemci mesajına kadar başlatmıyor. Yanlış yazılmış bir
  komutun başlangıçta hata vermesi (`cli.test.ts`) için `assertRunnable` komutu
  PATH'te arıyor; sunucu başlayıp `initialize`'da ölürse hata istemciye gider.
- `WrapHandle.bridge` kalktı; `current()` ve `closed` geldi (bridge era'ya göre
  sonradan kuruluyor, probe instance'ı olabilir).
- `StdioServerTransport` stdin'in `end`'inde kapanmıyor; stdin kapanan bir `wrap`
  süreci kendiliğinden çıkmıyor. SDK davranışı, Faz 25'ten önce de böyleydi; bu fazda
  dokunulmadı.
- Pin'li modern istemci `StdioClientTransport` ile probe'u kardeş bir süreçte yapıyor
  ve onun stderr'ini atıyor; era uyuşmazlığının sebebi istemcinin değil `wrap`'in
  stderr'inde.

---

## Faz 26 — Ruleset digest'i lexicon'ları da kapsasın (bitti)

Bulgu önce testle yeniden üretildi, sonra düzeltildi.

```
packages/detect/src/ruleset/load.ts          digest = sha256(stable({ rules, lexicons }))
packages/detect/src/ruleset/ruleset.test.ts  4 yeni test
bench/injection/results.json                 yalnız rulesetDigest değişti
.changeset/lexicon-digest.md                 @tunedness/mcpguard-detect patch
```

**Yeniden üretme.** `ruleset.test.ts`'e iki test eklendi: aynı kurallar, farklı
`verbsEn` ile iki ruleset'in digest'i farklı olmalı; aynı iki ruleset aynı metni
farklı skorla taramalı (kurallarla eşleşmeyen `frobnicate` fiili imperative
dedektörünü tetikliyor). Düzeltmeden önce digest testi **kırmızı**, etki testi
**yeşil** çıktı: aynı digest, farklı skor.

**Düzeltme.** Digest, ayrıştırılmış ve varsayılanları doldurulmuş
`{ rules, lexicons }` nesnesinin kanonik biçiminden hesaplanıyor; lexicon'u
olmayan ruleset ile boş listeli olan aynı digest'i veriyor. Küçük harfe çevrilmiş
derlenmiş hâl kullanılmıyor, digest veriyi tanımlıyor. `rulesetVersion`,
`engineRange` ve `locales` digest'te değil (ilk ikisi paketi tanımlıyor, `locales`
hiçbir dedektörde okunmuyor); testle kilitli. Faz 21'in `pii` bölümü bu digest'e
girmeyecek, ayrı `piiDigest`'e girecek (ADR-012 madde 2); `load.ts`'teki yorum bunu
söylüyor.

**Etki.** Skor yoluna dokunulmadı: `determinism.test.ts` ve anlık görüntüleri
değişmedi, injection bench'inde recall/FP/tablolar aynı, yalnız `rulesetDigest`
satırı değişti (`0e30de7c…` → `ef2c6546…`). Bundan sonra her ruleset'in digest'i
değişir; eski motor sürümüyle yazılmış audit kayıtlarındaki digest eski formüldedir
ve o motor sürümüyle yeniden üretilir.

**Devralan kişiye.** `bench/src/injection/run.ts:69` `engineVersion` alanına
`ruleset.rulesetVersion` yazıyor (motor sürümü değil). Bu fazda dokunulmadı:
`results.json`'da ikinci bir satırı oynatırdı. Ayrı iş.

---

## Faz 16 — npm yayın hazırlığı (bitti)

Yayın yapılmadı; paketler yayınlanabilir ve kurulduğunda çalışır hâle getirildi.

```
packages/*/package.json              ad değişikliği, kırık export'lar kaldırıldı
packages/cli/src/packaging.test.ts   sürüm sabitleri == manifest, paket adları, bin adı
scripts/pack-smoke.mjs               pack -> temiz dizine kur -> mcpguard --version / init / validate / scan
package.json                         pack:smoke script'i
.github/workflows/ci.yml             "Package smoke test" adımı
.github/workflows/release.yml        gate'e pack:smoke
```

**Adlar.** CLI `@tunedness/mcpguard` (bin hâlâ `mcpguard`), kütüphaneler
`@tunedness/mcpguard-core|detect|ruleset|proxy`; `bench` özel kalır
(`@tunedness/mcpguard-bench`). Bağımlılıklar, import'lar, `tsconfig` referansları
(yol tabanlı olduklarından değişmedi), changeset'ler, README ve docs birlikte
güncellendi. `purity.test.ts`'lerdeki yasak listesi `@tunedness/mcpguard`
önekiyle CLI'yi de kapsıyor.

**Kırık export'lar.** `core` ve `detect` `./testing` export ediyordu, kaynak yoktu
ve repoda kullanan yoktu: kaldırıldı. `ruleset` `pii/` dizinini `files` ve
`exports`'ta listeliyordu, dizin yok: kaldırıldı; PHI verisi (Faz 21) gelince geri
eklenir. `biome.json`'daki `!packages/ruleset/pii` dışlaması bilerek kaldı.

**Sürüm sabitleri.** Türetmek yerine test seçildi: saf paketler `package.json`
okuyamaz (purity), `--version` ve audit kayıtları sabiti okur. `packaging.test.ts`
beş sabiti kaynaktan okuyup manifest'le karşılaştırır; `changeset version` bir
manifest'i sabit olmadan artırırsa release PR'ında CI kırmızı olur.
`RULESET_VERSION` (verinin sürümü) dokunulmadı.

**Paket bütünlüğü.** `scripts/pack-smoke.mjs` her paketi `npm pack` ile paketler,
yalnız tarball'ları boş bir dizine kurar, manifest'in vaat ettiği her `bin` ve
`exports` yolunun tarball'da olduğunu, `README.md`/`NOTICE` bulunduğunu, `src/`
gönderilmediğini doğrular; sonra kurulu `mcpguard`'ı koşturur: `--version`,
`init`, `validate`, zararsız dosyada `scan` (allow) ve bariz kötücül dosyada
`scan` (flag). Ağa hiç çıkmaz: yalnız `--offline`; cache eksikse neden
adlandırılarak durur. Cache'i CI ve release gate'indeki ayrı, adı açık bir adım
doldurur: `npm run pack:warm` (`pack-smoke.mjs --warm-cache`), aynı tarball'ları
ağdan kurup atar. `npm ci` bunu yapmaz (lockfile tarball'larını cache'ler, kurulumun
aralık çözümlediği registry metadata'sını değil). Ağ erişimi yalnız bu adımdadır.

**Devralan kişiye.** `release.yml` `version` adımı `*_VERSION` sabitlerini
kendisi güncellemiyor; release PR'ını `GITHUB_TOKEN` açtığı için `ci.yml` o PR'da
koşmaz, `packaging.test.ts` ilk `main` push'unda ve `publish` gate'inde kırmızı olur;
sabitler elle düzeltilir. Bunu otomatikleştirmek küçük bir betik işi.

**Yayın metadata'sı.** Her yayınlanan manifest `repository` (url + `directory`)
taşır: provenance'lı publish bunu ister. İç bağımlılıklar gerçek aralıktır
(`*` değil; changesets `*`'ı güncellemez): CLI core/detect/proxy'ye tam sürümle
sabitlenir, ruleset'e `^` ile bağlanır (veri paketi motor sürümü beklemeden
çıkabilsin, ADR-003); proxy kardeşlerine `^`. `packaging.test.ts` bunları kilitler.

**v0.1.1 hazırlığı.** `changeset version` iki turda koşuldu: önce 0.1.0 (baseline
changeset'i), sonra Faz 14, 15, 25, 26 ve yeniden adlandırmayı anlatan beş patch
changeset'iyle 0.1.1; böylece 0.1.0 bölümü CHANGELOG'da kalır. Sonrasında elle:
beş `*_VERSION` sabiti 0.1.1'e çekildi ve `packages/ruleset/index.json`
`engineRange`'i `^0.0.0` → `^0.1.0` yapıldı. İkincisi sürümleme tuzağı: motor
0.x'te minor'u uyumluluk çizgisi sayar (`engineSatisfies`), yani `^0.0.0` 0.1.1
motorunu reddeder ve **her paketin testi kırılır**. Her minor artışında
`engineRange` (ve `detect`/`proxy` testlerindeki sabit `'^0.1.0'` fixture'ları)
birlikte güncellenmeli. `engineRange` digest'te değil (Faz 26), kural verisi ve
sonuçlar değişmedi.

## Faz 18 — korumalı HTTP gateway çekirdeği (`mcpguard serve`) (bitti)

ADR-011'in seçilen seti. `serve` tek bir upstream'i, `wrap`'in kapılarının aynısıyla
HTTP üzerinden sunar. Çoklu upstream, `/mcp/<ad>` yönlendirmesinin birleştirilmesi
ve bağlantı havuzu Faz 19'a ait; burada yol `/mcp/<ad>` biçiminde yalnız tek ad için
çalışır.

```
packages/proxy/src/http-gateway.ts     createHttpGateway: iki era'yı ayırır, kapıları çalıştırır
packages/proxy/src/node-http.ts        Node HTTP ucu: 413, 503, soket adresi
packages/proxy/src/http-auth.ts        bearer token (sha256 + timingSafeEqual)
packages/proxy/src/session-ladder.ts   ADR-006 merdiveni
packages/proxy/src/upstream.ts         upstream bağlantısı, paylaşılan bağlantı, boyut sınırı
packages/proxy/src/bridge.ts           Gates<C>: çağrı bağlamı genelleştirildi
packages/cli/src/runtime.ts            CallContext; wrap ve serve aynı kapılar
packages/cli/src/commands/serve*.ts    serve komutu
packages/core/src/policy/schema.ts     servers.<ad>.upstream, http, auth.tokens, session.max_sessions
bench/src/latency/http.ts              HTTP gecikme benchmark'ı
```

### Spike — ADR-011 madde 2 (kod yazılmadan önce koşturuldu)

- **V1 — DOĞRU.** `createMcpHandler(factory, { legacy: 'reject' })` modern era'yı
  sunuyor; `isLegacyRequest` trafiği ayırıyor; legacy bacak istek başına değil
  session başına bir `WebStandardStreamableHTTPServerTransport` ile gidiyor. B planına
  (`PerRequestHTTPServerTransport` + `classifyInboundRequest`) gerek kalmadı. Gerçek
  soketlerle, SDK'nın kendi iki era istemcisiyle, `http-gateway.test.ts`'te kilitli.
- **V2 — YANLIŞ.** Upstream modern bir `input_required` (multi-round-trip) döndürdüğünde
  paylaşılan upstream `Client` onu kendisi karşılamak zorunda kalır; elinde bunun için
  handler yok ve downstream'in sorulabileceği bir kanal yok. Çağrı
  `Cannot fulfil input request '...'` ile hata verir. ADR'nin öngördüğü gibi
  "proxy'den geçmez" diye belgelenir ve `http-gateway.test.ts`'te testle sabitlenir
  (`does not carry a modern multi-round-trip result`). **Bu, ADR-008'deki sampling
  sınırıyla aynı listede:** sunucudan istemciye giden bir alışveriş taranmıyor, burada
  ayrıca taşınmıyor da.

### Davranış

- **Era.** Her istek kendi era'sında sunulur; era uyuşmazlığı çeviri değil, SDK
  biçiminde `-32022` 400 yanıtıdır (ADR-011). Legacy upstream session başına ayrı
  `Client`, modern upstream tek paylaşılan `Client`.
- **Oturum.** Merdiven: `traceparent` → baggage `tunedness.session-id` →
  `Mcp-Session-Id` (legacy) → `clientInfo` + adres özeti. Kaynak ve `exact`
  audit kaydına (`sessionSource`, `sessionExact`) yazılır; `tunedness.session-id`
  upstream `_meta`'ya enjekte edilir. Gateway kendi `Mcp-Session-Id`'sini üretir
  (UUID; upstream'inki istemciye hiç gitmez).
- **Kimlik.** `auth.tokens` (yalnız `token_sha256` saklanır) → ADR-010 çözüm biçimi,
  kaynak `token`. Tüm girişler sabit sürede karşılaştırılır.
- **Bind.** Varsayılan `127.0.0.1:8766`. Loopback dışı bind, `auth.tokens` ve
  `http.allowed_hosts` olmadan reddedilir. Host/Origin SDK yardımcılarıyla doğrulanır,
  CORS yok. Düz HTTP uyarısı `serve_started` satırında.
- **Sınırlar.** `max_body_bytes` (413), `max_inflight` (503 + `Retry-After`),
  `max_upstream_connections` (503), upstream yanıt boyutu sınırı, boşta kalan
  session'lar için zaman aşımı süpürmesi, upstream kopmasında geri çekilme.
- **Politika şeması.** `servers.<ad>.upstream` (`url` ya da `command`+`args`), `http`,
  `auth.tokens`, `session.max_sessions`, `max_upstream_connections` eklendi;
  `guardpolicy.v1.schema.json` yeniden üretildi.

### Ölçülen — gecikme (PRD §6)

`npm run bench:latency:http`, `bench/latency/results.md`'nin "HTTP gateway" bölümü.
Rakam gateway'in **kendi** eklediği süredir: isteğin gelişinden upstream çağrısının
çıkışına, upstream yanıtının gelişinden yanıtın yazılmasının bitişine; gateway içinde
ölçülür, süreçler arası loopback gürültüsü içinde değil. Referans iş yükünde
(1 KB, scan benchmark'ının referansı) iki era'da da p95 yaklaşık 1,2-2 ms; kapı
< 20 ms ve gevşetilmedi (aşılırsa komut sıfırdan farklı kodla çıkar). Maliyet
büyüklükle artar (64 KB'ta yaklaşık 16 ms, scan eğrisiyle aynı); gateway'in kendi payı
her boyutta ~0,1 ms. Uçtan uca fark ayrı bir sağlama olarak raporlanır ve kapı
değildir.

**Çekince.** Benchmark `runtime.ts`'in `tools/call` yolundaki motoru (erişim kararı,
PII maskeli tarama, senkron hash zincirli audit) koşturur; CLI bunu export etmediği
için kombinasyon ve manifest kayıtları onun dışındadır.

### Bilinmesi gerekenler

- `serve` upstream'i komut satırından alır (`--upstream <url>` ya da `-- komut`);
  politikadaki `servers.<ad>.upstream` Faz 19'da bağlandı. İkisi aynı adı tanımlarsa hata.
- `max_sessions` yalnız adres-bağlama tablosunu sınırlar.
- `wrap` davranışı değişmedi: `wrap-process.test.ts` dokunulmadan geçer. `runtime.ts`,
  `manifest-gate.ts` ve `stdio-wrap.ts` fazın dosya listesinin dışında, çağrı bağlamını
  genelleştirmek için dokunuldu (davranışsız).
- Modern MRTR taşınmaz (V2). `README`'deki "`serve` çalışmayı reddeder" satırı eski.

---

## Faz 19 — HTTP gateway: çoklu upstream ve oturum havuzu (bitti)

PRD P0 "tek Guard, N sunucu". Tasarım `.ssot/tasarim/2026-11-14-http-gateway.md`'deki
kabul edilmiş seçenek (S2-A yol bazlı, S3-A atıf ile bağlantı ayrık); ADR-011 madde 3.

```
packages/proxy/src/http-gateway.ts     createHttpGateway: servers[] alır, /mcp/<ad> ile yönlendirir
packages/proxy/src/session-pool.ts     SessionPool (atıf tablosu + süpürücü), ConnectionPool (sunucu başına)
packages/cli/src/commands/serve.ts     politika + komut satırından sunucu listesi, sunucu başına buildGates
packages/cli/src/runtime.ts            sunucu başına PII anahtarı (servers.<ad>.pii.enabled)
packages/core/src/policy/schema.ts     servers.<ad>.pii
```

### Davranış

- **Sunucu listesi.** `servers.<ad>.upstream` tanımlı her politika girdisi bir
  sunucudur; komut satırındaki (`--upstream` ya da `-- komut`, adı `--name`) bir
  tane daha ekler. Aynı ad iki yerde tanımlıysa açılışta hata (sessiz öncelik yok).
  Hiç sunucu yoksa hata. `--name` yalnız komut satırı upstream'inin adıdır.
  Sunucu adı URL yolunda kullanıldığı için `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` olmalı.
- **Yönlendirme.** `/mcp/<ad>`; tanımsız ad `404`, araç adı/URI/capability'ye dokunulmaz,
  birleştirme yok. Bir sunucunun legacy `Mcp-Session-Id`'si yalnız o yolda geçerlidir.
- **Kapılar sunucu başına.** `buildGates` her sunucu için kendi adıyla çağrılır: erişim
  kuralları (`tools: match: "<ad>__*"`), tarama kuralları (`scan.tools`) ve sunucu başına
  PII anahtarı (`servers.<ad>.pii.enabled`, yalnız açma/kapama; ne maskeleneceği politikanın
  tek kararıdır) o sunucuya uygulanır. Kombinasyon geçmişi ve audit zinciri **ortaktır**:
  `alpha__read_file` + `beta__send_http` aynı oturumda tek kuraldır.
- **Kilit.** Her sunucu `guardlock.json`'da kendi `servers.<ad>` girdisiyle pinlenir.
  Halt sunucu başınadır (ADR-005 eki): A'da görülen uyumsuzluk yalnız A'yı durdurur,
  `lock --accept --server A` yalnız A'nın halt'ını kaldırır, B'ninki durur.
- **Yalıtım.** Her sunucunun paylaşılan modern `Client`'ı, legacy havuzu ve geri
  çekilmesi kendisinindir. Çöken upstream'in yolu `upstream_unavailable` (sunucu adıyla)
  JSON-RPC hatası verir; diğer yollar etkilenmez. Gateway upstream'i ölü bir sunucuyla da
  açılır; `serve_started` satırı hangisinin `unavailable` olduğunu söyler.
- **Havuz (`session-pool.ts`).** İki ayrı şey, ayrı sınırlı:
  - *Atıf:* tek tablo, bütün sunucular için. Yalnız en alttaki basamak (`clientInfo` +
    adres tahmini) saklanır; `max_sessions` ile sınırlı, `idle_timeout` ile düşer, dolunca
    en uzun süredir boşta olan girdi gider. Kesin basamaklar (traceparent, baggage,
    `Mcp-Session-Id`) tabloda tutulmaz, hiçbir şey onları tahliye etmez. Aynı istemci
    iki sunucuyla konuşursa tahmin edilen oturum aynıdır.
  - *Bağlantı:* sunucu başına `ConnectionPool`. `max_upstream_connections` dolunca yeni
    `initialize` `503` + `Retry-After` alır, var olan oturum **tahliye edilmez**;
    `idle_timeout` dolan, çağrısı olmayan bağlantı `DELETE` gelmese de kapanır; çağrısı
    süren oturum boşta sayılmaz. Zamanlayıcı yok: süpürme enjekte saatle okunur,
    gateway başına tek düşük frekanslı `setInterval` (unref'li) ve legacy istekte tembel.
- **`serve_started` satırı değişti.** Üst düzey `url/server/upstream/upstreamEra` yerine
  `servers: [{ name, url, upstream, defined, upstreamEra, upstreamNote? }]`.
  `serve_stopped` `servers: [...]` taşır. Satırı okuyan betik varsa uyarlanmalı.

- **`lock --server <ad>` (kullanıcı kararı 2026-11-16).** `mcpguard lock --diff|--accept
  --server <ad>` komut verilmediğinde politikadaki sunucuyu (`servers.<ad>.upstream`: URL ya da
  komut) çözer, araçlarını okur, diff'ler ya da kabul eder. Okuma `serve`'ün kullandığı bağlantı
  yoluyla yapılır (`listUpstreamTools` -> `connectUpstream`): aynı transport, aynı yanıt boyutu
  sınırı (`http.max_upstream_response_bytes`), era'yı bulma sırası (önce modern, legacy-only ise
  legacy); böylece kilitte pinlenen manifest, kapının karşılaştıracağı manifesttir. Kimlik ve
  TLS: `serve` upstream'e bağlanırken ne kimlik başlığı gönderiyor ne de TLS'i özelleştiriyor
  (Node varsayılanı); `lock` de aynısını yapar, yani upstream kimlik doğrulaması gerektiriyorsa
  ikisi de aynı yerde başarısız olur. `-- komut` yolu aynen çalışır ve verilirse politikaya
  bakılmaz. Politikada olmayan ya da `upstream`'i olmayan ad açık hata verir ve upstream'i
  olan sunucuların adlarını sayar.
- `connectUpstream` bir era uyuşmazlığında açılmış legacy oturumunu upstream'de kapatıyor
  (öncesinde legacy-only bir upstream'e her modern deneme, probe dahil, bir oturum bırakıyordu).

### Doğrulama

`serve-process.test.ts` iki gerçek upstream, tek `serve`, iki era'da: A'da `deny` olan araç
B'de izinli ve tersi; A'da `block` olan tarama B'de yalnız işaretleniyor; A süreci
`SIGKILL` ile öldürülünce B sürüyor ve A hata veriyor; iki sunucu stdio `shifty-server` ile
tek `guardlock.json`'da: A mutasyona uğrayınca yalnız A duruyor, `lock --accept --server A`
yalnız A'yı açıyor (B'nin pin'i dosyada aynı, B hâlâ `tools/call refused`), sonra
`--server B` B'yi açıyor. Birim: `session-pool.test.ts`, `http-gateway.test.ts` (çoklu
sunucu), `manifest-gate.test.ts` (tek kilit iki sunucu), `runtime-context.test.ts`.

### Bilinmesi gerekenler

- Legacy `Mcp-Session-Id` yol başına üretilir; aynı istemcinin iki sunucuya açtığı legacy
  oturumların kimliği farklıdır, ortak oturum yalnız `traceparent`/baggage ile ya da
  tahmin basamağında (modern) olur. Kombinasyon kuralının sunucular arasında çalışması
  buna bağlıdır.
- Sunucu başına ayrı `max_upstream_connections` ve `max_sessions` yok: ilki sunucu
  başına aynı değerdir, ikincisi gateway'in tek tablosudur. `max_inflight` gateway geneli.
- **Ölen upstream ve legacy oturum.** Upstream bağlantısı kapanınca (stdio child'ın ölmesi)
  oturum havuzdan düşer, `Mcp-Session-Id` sonraki istekte `404` alır ve istemci yeniden
  `initialize` eder; yuva boşalır. HTTP upstream'de bağlantı kendiliğinden kapanmaz (her
  istek ayrı), dolayısıyla ölü bir HTTP upstream'in oturumu `idle_timeout` ile düşer; bilinen sınır.
- **Kimlik doğrulama yönlendirmeden önce.** `auth.tokens` tanımlıyken token'sız istek, sunucu
  adı var olsun olmasın aynı `401`'i alır; hangi sunucuların sunulduğu token'sız öğrenilemez.
  `/healthz` açık kalır.
- Bir sunucunun politika `servers.<ad>.roles` alanı Faz 19'da hâlâ okunmuyordu; Faz 27 erişim kararına bağladı.
- `bench/src/latency/http.ts` yalnız yeni `servers: [...]` imzası için güncellendi;
  `npm run bench:latency:http` p95 legacy 1,56 ms, modern 1,81 ms (bütçe 20 ms).

## Faz 27 — `servers.<ad>.roles` erişim kararına bağlandı (bitti)

Politika şemasında `servers.<ad>.roles` vardı ama kodda hiçbir yerde okunmuyordu (v0.1.0'dan
beri). Operatör bununla bir sunucuyu kısıtladığını sanabilirdi; alan sessizce yok sayılıyordu.
PRD P0 "araç ve sunucu bazında allow/deny; istemci kimliğine göre rol eşleme".

```
packages/core/src/policy/compile.ts    CompiledPolicy.serverRolesFor(sunucu)
packages/core/src/policy/evaluate.ts   evaluateServerAccess (tek soru); evaluateAccess onu kullanır
packages/core/src/policy/schema.ts     alanın açıklaması (JSON Schema'ya da yansır)
packages/proxy/src/bridge.ts           Gates.onRequest: üç özel kapısı olmayan her istek
packages/cli/src/runtime.ts            kapıların hepsinde sunucu kontrolü; ServerAccessError
packages/cli/src/server-name.ts        checkServerName: eşleşmeyen sunucu adı (enforce: dur, flag: uyar); wrap ve serve çağırır
packages/cli/src/testing/fixtures/catalog-server.mjs   araç + resource + template + prompt sunan fixture
```

### Davranış

- **Anlam.** `servers.<ad>.roles` bir ya da daha fazla rol içeriyorsa o sunucuya giden **her istek**
  yalnız bu rollerden birine sahip çağıranlardan kabul edilir. Çağıranın rolleri üst düzey `roles`
  haritasından, ADR-010 kimlik merdiveniyle çözülen kimlikle gelir. Kimliği olmayan çağıran hiçbir
  rol taşımaz, dolayısıyla reddedilir. Liste boş ya da tanımsızsa (şema varsayılanı `[]`) sunucu
  herkese açıktır; bu, araç kuralındaki boş `roles` okumasıyla aynıdır. Politikada olmayan sunucu
  adı kısıtsızdır.
- **Kapsam (kullanıcı kararı 2026-11-16).** Kapsanan yöntemler: `tools/list`, `tools/call`,
  `resources/list`, `resources/read`, `resources/templates/list`, `resources/subscribe`,
  `resources/unsubscribe`, `prompts/list`, `prompts/get`, `completion/complete`, `logging/setLevel`,
  `tasks/*`, `subscriptions/listen` ve proxy'nin adını bilmediği her istek: üç özel kapısı olmayan
  her şey `Gates.onRequest`'ten (köprünün fallback yolu) geçer.
  **Kapsam dışı (bağlantı düzeyi):** `initialize`, `ping` (SDK'nın kendisi yanıtlar, kapılara
  ulaşmaz) ve `server/discover` (modern era'nın `initialize`'ı; çağıran kendini adlandırmadan
  önce sunucunun ne olduğunu öğrenir, `runtime.ts` `CONNECTION_LEVEL_METHODS`). Bildirimler
  (`notifications/*`) istek değildir, kapsam dışıdır; upstream'in istemciye yönelik istekleri
  (sampling, elicitation, roots) sunucuya giden istek değildir, kapsam dışıdır.
- **Ret biçimi.** `tools/call` bugüne kadarki gibi `isError` sonucu (`content withheld`) döner.
  Öteki yöntemler açık bir JSON-RPC hatasıyla reddedilir (`[mcpguard] <yöntem> refused · the caller
  holds none of the roles this server admits ...`); boş liste ya da boş sonuç dönmez. Hata metni
  hangi rollerin yeteceğini söylemez. Upstream'e hiç gidilmez.
- **Tek yer.** Soru `evaluateServerAccess`'te (core) sorulur; `evaluateAccess` (`tools/call`) onu
  çağırır, `runtime.ts` öteki yöntemler için aynısını çağırır. `wrap` ve `serve` aynı `buildGates`'ten
  geçtiği için ikisi ayrışamaz. `tools/call`'da sunucu kontrolü manifest kapısından da önce yapılır:
  reddedilen çağıran proxy'nin upstream'i okumasına ya da kilide dokunmasına yol açamaz.
- **Birleşme.** Sunucu listesi önce sorulur; reddederse `deny` ve araç kuralı sorulmaz, yani bir
  `allow` kuralı kapalı sunucuyu yeniden açamaz. Listeden geçen çağrıyı araç kuralı yine
  reddedebilir. Daha kısıtlayıcı olan kazanır.
- **Kayıt.** Ret `access_denied` (stderr; `method`, `rule`, `action`, kimlik ve basamağı), `policy_decision`/
  `access_denied` security_event ve audit kaydı olarak yazılır. Audit `kind`: `tools/call` için
  `tool_call`, `tools/list` için `tool_list`, `resources/read` için `resource_read` (`toolName` uri),
  öteki yöntemler için `access_denied` (`toolName` yöntem adı). `findings` ve `evidence`
  `servers.<ad>.roles` alanını adlandırır, `callerIdentity` kimlik basamağını ve `exact` bilgisini
  taşır (ADR-010). Rol `clientInfo.name`'den çözüldüyse kayıt `source: client_info, exact: false` der;
  davranış değişmez. stderr `access_denied` olayı artık enforce'ta da `action: deny` taşır.
- **`mode: flag`.** İstek iletilir; aynı üç kayıt `action: flag` ile yazılır. (Araç kuralı `deny`'ı
  flag modunda bugüne kadar olduğu gibi kayıtsız geçer; bu fazda dokunulmadı.) Flag modunda istek
  ayrıca normal sonuç kaydını da üretir; bir çağrı için iki kayıt görülebilir (kombinasyon kuralının
  flag yolu da aynısını yapar).
- **Sunucu adı politikayla eşleşmeli (kullanıcı kararı 2026-11-16).** `servers.<ad>` çalışan sunucunun
  adıyla aranır: `wrap`'te `--name` (verilmezse `server`), `serve`'de komut satırı upstream'inin
  `--name`'i (verilmezse `server`); politikada `upstream` ile tanımlı sunucular zaten kendi anahtarıyla
  çalışır. Adı hiçbir kayıtla eşleşmeyen sunucu `servers.<ad>` kurallarının, roller dahil, hiçbirine
  tabi olmaz; bir yazım hatası güvenceyi sessizce düşürür. Bu yüzden, politikada bir `servers`
  bölümü varsa:
  - `mode: enforce`: `wrap` ve `serve` açılışta durur, `EXIT.policy` (3). Mesaj eşleşmeyen adı
    (`--name` verilmediyse bunu da), politikanın bildiği anahtarları ve kaçış yolunu söyler. `serve`
    dinlemeye başlamadan önce durur.
  - `mode: flag`: stderr'e `server_unmatched` olayı (eşleşmeyen ad, bilinen anahtarlar, ipucu) ve
    `security_event` (`kind: server_unmatched`, `action: flag`) yazılır, süreç devam eder.
  - **Kaçış yolu:** kısıtsız çalışması istenen sunucu için politikaya boş bir kayıt: `servers: { <ad>: {} }`.
  - `servers` bölümü yoksa ya da boşsa kontrol yoktur (bugünkü davranış). Eşleşme sahip anahtarla
    yapılır (`Object.hasOwn`), `constructor`/`toString` gibi adlar politikanın adlandırdığı sunucu sayılmaz.
  - Kontrol `packages/cli/src/server-name.ts`'te tek yerdedir (`checkServerName`); `wrap` ve `serve`
    aynısını çağırır. `mcpguard validate` çalışan sunucunun adını bilmediği için bunu yakalayamaz
    (`validate` yalnız politika dosyasına bakar); kontrol `wrap`/`serve` açılışındadır.
- Alan tanımsızsa hiçbir şey değişmez: mevcut testler değişmeden geçer.

### Doğrulama

Birim: `policy.test.ts` (`evaluateAccess` ve sunucu listesi), `runtime.test.ts` (`wrap` yolu: her yöntem
ailesi için ret/izin, kimliksiz, sezgisel kimlik, flag modu, bağlantı düzeyi yöntemler, manifest
kapısından önce ret, stricter-wins), `runtime-context.test.ts` (`serve` yolu, çağrı başına kimlik, her
aile), `server-name.test.ts` (ad kontrolü: `wrap`/`serve` × `enforce` süreç içinde, prototip anahtarları). Süreç düzeyi: `wrap-identity.test.ts` (gerçek stdio, `catalog-server`: araç, resource, template,
prompt; `wrap` × `flag`/`enforce` ad kontrolü) ve `serve-process.test.ts` (gerçek `serve`, token kimliği,
iki era, aynı fixture; `serve` komut satırı upstream'i × `flag`/`enforce`).

### Bilinmesi gerekenler

- Alan boş liste ile "tanımsız"ı ayırt etmez; "kimse giremez" yazmanın yolu yok (rolü olmayan bir
  ad listelenebilir). Şema bunu daha önce de ayırt etmiyordu.
- `Gates` arayüzüne `onRequest` eklendi (zorunlu); `Gates` kuran dış kod varsa tipi kırılır.
- `mode: flag` altında araç kuralı `deny`'ı kayıt üretmiyor; sunucu listesi üretiyor. Tutarsızlık
  Faz 27'den önce de vardı (araç kuralı tarafı), kapsam dışı bırakıldı.
- Araç düzeyi `tools` kuralları hâlâ yalnız `tools/call`'ı kapsar; `resources/read` ve `prompts/*`
  için kural yazılamaz, yalnız sunucu listesi bunları kapatır.

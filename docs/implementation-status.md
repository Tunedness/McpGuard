# McpGuard — uygulama durumu

Bu dosya kullanıcı için değil, **işi devralan kişi** için yazılır. README ürünü
anlatır; burası her fazın ne yaptığını, hangi dikişi sonraki faza bıraktığını ve
o faz sırasında ortaya çıkan çelişkileri tutar.

---

## Nerede kaldık

**Faz 3 bitti.** 700 öğelik etiketli korpus (300 pozitif / 400 negatif), gerçek
motoru koşturan replay + sweep hattı, `results.md` PRD §6 hedefini her koşuda
basıyor. Şu anki taban dürüst: kural seti boş, recall **%0**. 194 test, kapı
yeşil. Sıradaki iş **Faz 4**: `@mcpguard/ruleset` veri paketi + Kademe 1
dedektör aileleri, bu korpusa karşı kalibre edilerek.

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
`mcp-guard` başkasında (0.1.0) ve kullanılmayacak.

---

## Faz 1 — iskelet (bitti)

npm workspaces (pnpm yok), ESM-only, `engines: node >=20.19`, `tsc -b` project
references, bundler yok.

```
packages/core/      @mcpguard/core     — SAF karar motoru
packages/detect/    @mcpguard/detect   — SAF tarama motoru
packages/ruleset/   @mcpguard/ruleset  — VERİ paketi, bağımsız sürümlü
packages/proxy/     @mcpguard/proxy    — MCP adaptörü
packages/cli/       mcpguard           — bin, npx giriş noktası
bench/              @mcpguard/bench (private)
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
| `@mcpguard/core` | `zod` **yalnızca** |
| `@mcpguard/detect` | `zod` **yalnızca** |
| `@mcpguard/ruleset` | **hiçbiri** |
| `@mcpguard/proxy` | `@mcpguard/core`, `@mcpguard/detect`, `@modelcontextprotocol/{server,client,core}` |
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

`@mcpguard/core`. Tarama yok; sözleşme var. 110 yeni test, `core/src` üzerinde
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

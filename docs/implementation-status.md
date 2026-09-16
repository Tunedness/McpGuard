# McpGuard — uygulama durumu

Bu dosya kullanıcı için değil, **işi devralan kişi** için yazılır. README ürünü
anlatır; burası her fazın ne yaptığını, hangi dikişi sonraki faza bıraktığını ve
o faz sırasında ortaya çıkan çelişkileri tutar.

---

## Nerede kaldık

**Faz 1 bitti.** İskelet kuruldu, kapı yeşil, 15 test. Sıradaki iş **Faz 2**:
`@mcpguard/core` içinde `guardpolicy.v1` zod şeması, erişim denetimi, portlar ve
`purity.test.ts`.

Kapı şu an dört komut: `lint`, `typecheck`, `build`, `test`. Beşincisi
(`schema:check`) Faz 2'de şemayla birlikte gelir — var olmayan bir dosyayı
gösteren bir script, onu koşturan kişi için tuzaktır.

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

# Parry_DDoS — Decisões de Arquitetura

## Estrutura de diretórios

```
ParryWAF/
├── src/
│   ├── detectors/          Detectores de ameaça (SQL, XSS, NoSQL)
│   ├── middleware/         Ponto de entrada do Express middleware
│   └── core/               Utilitários reutilizáveis (RateLimiter, Logger)
├── config/                 Valores padrão configuráveis
├── constants/              Padrões regex centralizados
├── types/                  Tipagem pública TypeScript
├── tests/
│   ├── unit/               Um arquivo por módulo
│   ├── integration/        Middleware testado end-to-end com req/res mock
│   └── fixtures/           Payloads de ataque compartilhados
├── examples/               Demonstrações (fora de src/)
└── docs/                   Documentação de arquitetura e decisões
```

---

## Por que `core/` é separado de `middleware/`?

`RateLimiter` e `ThreatLogger` são utilitários independentes. Eles não dependem do
protocolo HTTP e poderiam ser usados em qualquer contexto (workers, CLIs, testes).
Misturá-los dentro de `middleware/` criaria acoplamento desnecessário e dificultaria
testes unitários isolados.

## Por que `constants/patterns.js` existe?

Centralizar todos os regex em um único arquivo resolve três problemas:

1. **Manutenção** — ajustar um padrão não requer abrir o detector correspondente.
2. **Revisão de segurança** — um revisor encontra todos os padrões num só lugar.
3. **Testes** — os fixtures de `tests/fixtures/payloads.js` são derivados dos mesmos
   padrões, garantindo que testes e detectores estejam sempre alinhados.

## Por que `config/defaults.js` e não constantes inline?

Permite que integradores inspecionem os defaults sem ler o código do middleware.
Facilita também testes que precisam sobrescrever apenas um subconjunto de opções.

## Por que `tests/` fica na raiz e não dentro de `src/`?

Testes não são código de produção. Incluí-los em `src/` os tornaria parte do bundle
publicado e obscureceria a separação entre código executável e código de verificação.

## Estratégia de detecção em camadas

Cada detector aplica decodificação antes de escanear:

```
input → URL decode (multi-pass) → HTML entity decode → Unicode strip → scan
```

Isso cobre os vetores de bypass mais comuns (double encoding, zero-width chars,
entity injection) sem depender de bibliotecas externas.

## Rate Limiting inteligente

O `RateLimiter` mantém dois contadores separados por IP:

- **`timestamps[]`** — janela deslizante de requisições normais.
- **`suspicious`** — incrementado a cada ameaça detectada, independente da janela.

O banimento é acionado pelo `suspicious`, não pelo volume. Isso permite que um IP
legítimo com alto volume não seja banido, enquanto um IP com poucas requisições
mas todas maliciosas seja bloqueado rapidamente.

## Considerações de produção

- O armazenamento do `RateLimiter` é in-memory. Para ambientes com múltiplas
  instâncias (clusters, Kubernetes), substitua o `Map` interno por Redis.
- O `x-forwarded-for` não é verificado contra uma lista de proxies confiáveis.
  Em produção, adicione verificação de CIDR antes de confiar nesse header.
- Os padrões regex cobrem os vetores mais comuns mas não são exaustivos.
  Considere complementar com uma WAF dedicada em camadas de alta criticidade.

# One-click Full Mainline GLM Oracle Campaign

本轮从已有 PoC / Pattern Bank 与 RAG/API Card 证据进入 GLM-assisted adapter recipe / slot binding，然后生成小规模 smoke cases，执行无二进制 `cc -fsyntax-only` compile check，并把 raw results 接入 oracle delta。

- GLM request/success/fallback: 1 / 1 / 0
- adapter recipe count: 5
- slot binding count: 5
- generated case count: 10
- compile/run jobs: 10
- compile_success / compile_failed / unsupported: 10 / 0 / 0
- candidate delta: 0

`candidate_queue` 仅表示后续 triage 队列，不表示已确认问题。

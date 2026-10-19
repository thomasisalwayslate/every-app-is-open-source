# Benchmarks

Every time I point Every App Is Open Source at something new, I run the same fight against [REA](https://github.com/morluto/rea) and [GhidraMCP](https://github.com/LaurieWired/GhidraMCP). This page gets one new row per target. Each one links to every run and every answer.

## At a glance

| Target | What it is | EAOS version | vs REA | vs GhidraMCP | Correct answers |
|---|---|---|---|---|---|
| [Modified Doom](#modified-doom) | Classic game, secretly altered and stripped | 0.1.0 | 36% cheaper, 27% faster, 52% fewer tokens | 16% cheaper, 17% faster, 26% fewer tokens | All three tools: 18/18 |

"Cheaper" means API-equivalent cost at published prices, with cached input discounted. It's not what my subscription charged. "Faster" means median agent time per run.

## The rules

These stay the same for every target:

- **Same model for every tool** (gpt-6.1-sol, high effort), fresh sessions, three runs per tool.
- **Questions and answer key frozen before the first run.** Where a model might know the answers by heart, I secretly change them and rebuild the program first.
- **Same head start.** Every tool begins with the program already analyzed, outside the timer.
- **REA runs the way people actually install it,** with its bundled skill and its full tool catalog.
- **Everything is kept,** including rounds I lost.

So far every tool has gotten every answer right, so these benchmarks show differences in cost and speed, not accuracy.

## Modified Doom

Six questions about gameplay logic, three runs per tool, measured on EAOS 0.1.0.

| Tool | Correct | Median time per run | Tokens, 3 runs | API-equivalent cost, 3 runs |
|---|---:|---:|---:|---:|
| **Every App Is Open Source** | **18/18** | **121.8s** | **1,728,000** | **$0.70** |
| Community GhidraMCP | 18/18 | 146.2s | 2,337,886 | $0.84 |
| REA 6.7.0 + its bundled skill | 18/18 | 166.7s | 3,603,877 | $1.09 |

**Why Doom, and why modified:** Doom's code is all over the internet, so an agent could answer from memory without looking at the program. I built Chocolate Doom with eight gameplay rules secretly altered and its function names stripped. An agent answering from memory gets the original values, and those are wrong. The answer key comes from running the modified game code, not from me reading it.

**The token saving (52%) is bigger than the cost saving (36%)** because cached input tokens are billed at a discount.

**The round I lost:** my first version actually lost to GhidraMCP on cost. I read the logs, cut the repeated metadata and the detail nobody had asked for yet, then retested on new questions and a new build.

The answers are public in the answer-by-answer check. The modified game, its source and the answer-key program stay private, so the test can't be spoiled.

[Full results](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/reports/round2/results.md) · [Every run](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/reports/round2/results.json) · [Answer-by-answer check](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/reports/round2/answer-review.json) · [Frozen protocol](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/benchmark/protocol-round2.json) · [The round I lost](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/reports/results.md) · [Write-up](https://thomasisalwayslate.github.io/research/same-answers-lower-cost/)

## Run your own

[BENCHMARK.md](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/BENCHMARK.md) explains how to build your own secretly modified target and get your own answer key.

## Credits

- **Chocolate Doom**, based on id Software's Doom, released under GPLv2.

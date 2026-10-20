# Benchmarks

Every time I point Every App Is Open Source at something new, I run the same fight against [REA](https://github.com/morluto/rea) and [GhidraMCP](https://github.com/LaurieWired/GhidraMCP). This page keeps one row per measured comparison, including retests. The summaries below retain wins, losses and protocol corrections; supporting material is linked or its availability stated.

## At a glance

| Target | What it is | EAOS version | vs REA | vs GhidraMCP | Correct answers |
|---|---|---|---|---|---|
| [Modified Doom](#modified-doom) | Classic game, secretly altered and stripped | 0.1.0 | 36% cheaper, 27% faster, 52% fewer tokens | 16% cheaper, 17% faster, 26% fewer tokens | All three tools: 18/18 |
| [Modified Ollama](#modified-ollama) | Native Go CLI/server, privately altered and stripped | 0.1.4 | 13.6% cheaper, 16.7% faster, 19.8% fewer tokens | 27.8% higher cost, 23.4% slower | EAOS/REA: 18/18; GhidraMCP: 17/18 |
| [Modified Ollama, round 2](#modified-ollama-round-2) | Fresh modified native Go CLI/server; matched new task inputs | 0.1.5 | 24.6% cheaper, 35.4% fewer tokens; similar median time | 5.6% cheaper, 7.9% fewer tokens; similar median time | Exact cases: EAOS 195/195; GhidraMCP 191/195; REA 189/195 (formatting differences detailed below) |

"Cheaper" means API-equivalent cost at published prices, with cached input discounted. It's not what my subscription charged. "Faster" means median agent time per run.

## The rules

These stay the same for every target:

- **Same model for every tool** (gpt-6.1-sol, high effort), fresh sessions, three runs per tool.
- **Questions and answer key frozen before the first run.** Where a model might know the answers by heart, I secretly change them and rebuild the program first.
- **Same head start.** Every tool begins with the program already analyzed, outside the timer.
- **REA runs the way people actually install it,** with its bundled skill and its full tool catalog.
- **Everything is kept,** including rounds I lost.

Doom tied on correctness. In the first Ollama round, one of three GhidraMCP sessions missed three cases in one question; EAOS and REA matched every case. EAOS was the only tool to match every scored case in both Ollama rounds: 195/195 in each round. Round 2's GhidraMCP/REA misses were formatting differences: header-list order and incomplete error text. Every HTTP status prediction in round 2 matched. Three repetitions per build do not establish a general accuracy advantage; EAOS's separate wrong IP-check explanation is disclosed below.

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

## Modified Ollama

Measured on **EAOS 0.1.4, 19 October 2026**. Six questions, 65 runtime-derived cases per session, three fresh sessions per tool. Model: **gpt-6.1-sol, high**.

| Tool | Complete questions | Correct cases | Median agent time | Tokens, 3 runs | API-equivalent cost, 3 runs |
|---|---:|---:|---:|---:|---:|
| Every App Is Open Source 0.1.4 | 18/18 | 195/195 | 312.9s | 12,354,650 | $3.1003 |
| Community GhidraMCP 2.0.0 | 17/18 | 192/195 | 253.6s | 8,594,050 | $2.4258 |
| REA 6.7.0 + bundled skill | 18/18 | 195/195 | 375.5s | 15,409,814 | $3.5901 |

**Result:** EAOS matched REA on every case, using 19.8% fewer tokens, 13.6% lower API-equivalent cost and 16.7% lower median agent time. Against GhidraMCP, EAOS cost 27.8% more and took 23.4% longer. GhidraMCP was fastest and cheapest, but its final session missed three validation-error cases. Its first two sessions got all 65 cases right.

**What was tested:** a 25,402,946-byte, privately modified Ollama v0.40.6 darwin/arm64 CLI/server, built with Go 1.27.1 and `-s -w`. Ordinary Go symbols and DWARF were removed; embedded Go runtime function metadata and some CGO/dynamic symbols remain. This tests request validation, runner selection, Host/CORS handling and environment configuration. It does not test model inference, model weights or the complete Ollama application stack. Two executions of the modified build agreed on the runtime key; 41 of 65 case outcomes differed from an unmodified control.

**Fair setup:** released PyPI EAOS 0.1.4 (seven tools); normally installed REA 6.7.0 with its bundled skill and full 207-tool catalog, including byte search, references and Go metadata; stock community GhidraMCP 2.0.0 (28 tools, documented headless setup). Nobody received code addresses, source, separate symbol maps, runtime access or the hidden key. Selected-target restrictions were enforced at the MCP interface, not by an OS sandbox. Ghidra stayed at 12.1.4. EAOS/community loaded clean copies of one default-analyzed project; REA completed its own default analysis before timing. No question-specific decompilation warmup. Tool order rotated across repetitions. REA skill-reading time counted. Unlike the historical Doom study, no shared calculator was added to competitors.

**Timer and cache:** agent time includes model startup, reasoning, tool calls and final answer; it excludes preparation and backend shutdown. Agent time ranges were EAOS 257.1–337.4s, GhidraMCP 213.5–281.1s and REA 369.9–408.7s. Per-session readiness took 2.82–4.58s for EAOS and 2.82–3.15s for GhidraMCP from copied analyzed projects; REA independent analysis took 180.25–406.61s. These are different preparation paths, not a cold-start comparison. Cached input fractions were 94.0%, 92.8% and 95.2% respectively; caches were measured rather than forced equal.

**Cost basis:** normalized short-context API-equivalent rates per million tokens: $2 fresh input, $0.10 cached input, $2.50 cache-write input and $10 output. No cache-write tokens were reported. Cached input is included within input; reasoning is included within output. The usage receipts do not reconstruct per-request pricing tiers or subscription bills. Applying long-context rates to every request instead gives EAOS $5.9724, GhidraMCP $4.6519 and REA $6.8559, with the same cost ordering. [Model pricing](https://developers.openai.com/api/docs/models/gpt-6.1-sol).

### Every clarified run

| Run | Tool | Complete questions | Correct cases | Agent seconds | Total tokens | API-equivalent USD |
|---|---|---:|---:|---:|---:|---:|
| c11o | ours | 6/6 | 65/65 | 337.39 | 4,495,332 | $1.095749 |
| c12g | community | 6/6 | 65/65 | 281.12 | 3,377,532 | $0.877552 |
| c13r | rea | 6/6 | 65/65 | 375.53 | 5,508,773 | $1.222733 |
| c21g | community | 6/6 | 65/65 | 253.60 | 2,294,430 | $0.723854 |
| c22r | rea | 6/6 | 65/65 | 408.70 | 5,594,160 | $1.285144 |
| c23o | ours | 6/6 | 65/65 | 257.12 | 3,338,472 | $0.904141 |
| c31r | rea | 6/6 | 65/65 | 369.87 | 4,306,881 | $1.082208 |
| c32o | ours | 6/6 | 65/65 | 312.86 | 4,520,846 | $1.100406 |
| c33g | community | 5/6 | 62/65 | 213.50 | 2,922,088 | $0.824370 |

The final GhidraMCP session misread the generate endpoint’s empty-model fallback and omitted the quoted model reference in two source-conflict error bodies. Exact status and full error bodies were required before any run. It retrieved relevant code; these were agent interpretation errors, not demonstrated GhidraMCP decompiler bugs. All other clarified cases matched the key. Evidence review separately checked retrieved code, literals and branches, beyond merely finding cited addresses.

### Stopped attempt and retained failures

The first full attempt was stopped because the questions omitted the hostname and local-interface conditions. The same clarification sentence was added for all three tools, then nine fresh sessions were run. **The binary and answer key did not change.** The earlier EAOS run matched 65/65 cases under stated assumptions; the earlier community run matched 57/65, with eight unknown responses correctly identifying the omitted conditions. Those raw scores are not a fair accuracy ranking and are excluded from the clarified medians. REA preparation stopped before that attempt’s model session.

One earlier community response also predicted an exposed-header field absent from both runtime recordings. That separate header discrepancy is retained alongside the missing-condition issue; clarification alone did not resolve that prediction. The clarified community runs got the header case right.

All three pilot sessions, both stopped-attempt full sessions, nine clarified sessions and tool failures remain saved. The pilot used Q1 only and is excluded from these aggregates; this prior task exposure is a limitation despite fresh sessions. New-round spending was **$9.116156**, below the approved $23.20. The stopped full attempt cost $1.7978784; all full attempts together cost $10.9140344. Pilot spending was a separate $1.5163684.

EAOS retained three unmapped-memory read failures and one out-of-range evidence-page request; REA retained six stock response/view errors across two runs. Agents recovered without silent retries or changes to tool contracts. No participant used forbidden external tools or accessed the oracle in the recorded sessions.

Detailed transcripts, target, modified source, oracle and answer key remain private. This section provides all nine run summaries and the failures; it does not claim the full sealed comparison is publicly reproducible. [Public preparation guidance](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/BENCHMARK.md) explains the general method, and [Go discovery implementation and checks](https://github.com/thomasisalwayslate/every-app-is-open-source/pull/12) describes the 0.1.4 fix.

## Modified Ollama, round 2

Measured on **released EAOS 0.1.5, 20 October 2026**. A newly modified build and new frozen inputs, matched to round 1's six task families and case counts. Three fresh sessions per tool, 65 cases each. Same **gpt-6.1-sol/high/default tier**. The earlier 0.1.4 results above remain unchanged.

| Tool | Exact cases | Median agent time | Tokens, 3 runs | API-equivalent cost, 3 runs |
|---|---:|---:|---:|---:|
| Every App Is Open Source 0.1.5 | 195/195 | 376.8s | 7,475,587 | $2.2770 |
| Community GhidraMCP 2.0.0 | 191/195 | 372.0s | 8,112,595 | $2.4120 |
| REA 6.7.0 + bundled skill | 189/195 | 385.9s | 11,564,471 | $3.0191 |

**Result:** round 1 lost to GhidraMCP on cost and speed. After the 0.1.5 inspection changes, this fresh comparison used **7.9% fewer tokens** and cost **5.6% less** than GhidraMCP. EAOS's median was **1.3% longer**, a 4.73-second gap. The median times were similar; three repetitions do not establish a clear speed advantage or a statistical tie. Against REA, EAOS used **35.4% fewer tokens**, cost **24.6% less** and had a **2.4% shorter median agent time**. That small timing difference also does not establish a clear speed advantage. These are descriptive results from three repetitions per tool, not a statistical equivalence test or evidence of general superiority. EAOS was the only tool with every scored case exactly right in both Ollama rounds; that does not mean every explanation was right.

**Read the exact-match scores carefully.** EAOS matched 195/195 cases. Community's last session differed in four preflight header lists: the same allowed names appeared in a different order. REA's first session made that kind of ordering difference in four cases and omitted the quoted input suffix in two conflict-error bodies. Header-list order and complete error text were required by the frozen primary scorer. Every tested HTTP status in this round matched its runtime reference. The primary scores are unchanged, and these differences do not establish that EAOS understands behavior better. Complete-question counts were EAOS 18/18, community 17/18 and REA 16/18.

**What changed:** 0.1.5 keeps seven tools and extends inspect with large-function outlines, focused slices, in-function text/integer search, assembly focus and bounded pages. The changes were generic, tested locally against saved requests, and released before this round. The new questions were not built around these operations. There were no tool, binary, key or prompt changes between the new pilot and full sessions. Different hidden values and inputs prevent direct before/after attribution to the inspection changes alone.

**Target and fairness:** the fresh privately modified Ollama v0.40.6 Go 1.27.1 darwin/arm64 build is 25,402,946 bytes (SHA-256 `69d1997397713a913bf300c7c0446f5f684a546eca434c04b2dcc84ce1d80a36`). `-s -w` removes ordinary Go symbols and DWARF; embedded runtime metadata and dynamic symbols remain. Two independent runtime executions derive the same key; 41/65 outcomes differ from unmodified control and 44/65 differ from round 1 by matched case position. Same task families/counts approximate difficulty, not a statistically established equivalence. Hostname/interface conditions were included before any new session. Tests cover request/configuration logic, not model inference or the full Ollama stack.

REA retained its normally installed bundled skill and all 207 stock tools, including byte search, xrefs and Go metadata; its installed-document reader counted toward usage. Community retained 28 stock tools. EAOS used the verified live PyPI install. All used pinned Ghidra 12.1.4, completed initial analysis before agent timing and received no code addresses, source, runtime access or key. EAOS/community copied the same clean default Ghidra database; REA performed its own stock analysis. No question-specific decompiler warmup. Fresh sessions/evidence and Latin rotation; initial preparation and backend cleanup excluded from agent time. This is an audited MCP boundary, not an OS sandbox.

### Every round-2 full run

| Run | Tool | Complete questions | Exact cases | Agent seconds | Tokens | API-equivalent USD |
|---|---|---:|---:|---:|---:|---:|
| f11o | ours | 6/6 | 65/65 | 376.76 | 2,725,778 | $0.820738 |
| f12g | community | 6/6 | 65/65 | 366.67 | 2,877,530 | $0.758079 |
| f13r | rea | 4/6 | 59/65 | 384.87 | 3,463,800 | $0.969440 |
| f21g | community | 6/6 | 65/65 | 372.03 | 2,708,642 | $0.813993 |
| f22r | rea | 6/6 | 65/65 | 385.89 | 4,296,776 | $1.086190 |
| f23o | ours | 6/6 | 65/65 | 319.93 | 2,697,766 | $0.767542 |
| f31r | rea | 6/6 | 65/65 | 398.71 | 3,803,895 | $0.963513 |
| f32o | ours | 6/6 | 65/65 | 462.65 | 2,052,043 | $0.688753 |
| f33g | community | 5/6 | 61/65 | 379.89 | 2,526,423 | $0.839947 |

**Retained failures and evidence:** EAOS made three returned tool errors (two unsupported calculator expressions and one zero-fill memory read) and five rejected inspect argument attempts. They were counted in time/cost; the agents recovered. REA's first final answer mistyped one evidence ID by one hexadecimal character; its actual corresponding tool evidence was present. That is a participant citation error, not a demonstrated provider ID bug. Other final cited IDs resolve, content/target hashes validate where provided, and semantic review covers retrieved branches/literals rather than addresses alone. EAOS f32o also misstated an unscored IP branch in its explanation, calling IsUnspecified a link-local-unicast check. No frozen case distinguishes them, so its 65 exact predictions remain correct while that explanation is flagged as wrong. No recorded participant accessed forbidden tools, source or the key. One postprocessing checkpoint incorrectly reflagged an already-reviewed argument typo and blocked a launch before a model started; its bookkeeping was corrected, with no extra model session or frozen-runner/tool change.

Agent-time ranges were EAOS 319.9–462.7s, community 366.7–379.9s and REA 384.9–398.7s. All three tools sometimes batch requests; call counts are not model-turn counts. Raw MCP envelope bytes can duplicate text/structured results and are not provider tokens. Cached-token fractions are not cost fractions.

**Accounting and preservation:** the nine full sessions cost **$7.7081956** normalized short-context API-equivalent, within the $15 planned allowance. The separate three-session pilot cost $1.4146912; it used Q1 only and is excluded from full medians. Rates and subset accounting match round 1. All-long sensitivity totals are EAOS $4.2850, community $4.6077, REA $5.7824. Aggregate usage arrives after completion; the allowance is not a live hard cap. Both builds, both rounds, stopped attempts, pilots and the private diagnostic rehearsal are kept. The old-question rehearsal is not comparison evidence. Detailed transcripts, modified source, binary, runtime observations and key remain private, so this sealed comparison is not claimed as fully publicly reproducible.

## Run your own

[BENCHMARK.md](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/BENCHMARK.md) explains how to build your own secretly modified target and get your own answer key.

## Credits

- **Chocolate Doom**, based on id Software's Doom, released under GPLv2.
- **Ollama**, MIT-licensed; its original license and notices are retained with the private source/build.

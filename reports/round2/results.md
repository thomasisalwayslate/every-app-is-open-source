# New Doom control-flow comparison

Model **gpt-6.1-sol**, effort **high**. Three fresh sessions per arm; six new tasks and 24 scored fields per session. Separate privately modified build. Earlier results remain unchanged.

| Tool | Correct questions | Correct fields | Median agent time | Median tokens | Total tokens (3 runs) | API-equivalent USD (3 runs) |
|---|---:|---:|---:|---:|---:|---:|
| ours | 18/18 | 72/72 | 121.8s | 564,026 | 1,728,000 | $0.7042 |
| rea | 18/18 | 72/72 | 166.7s | 1,089,492 | 3,603,877 | $1.0929 |
| community | 18/18 | 72/72 | 146.2s | 776,520 | 2,337,886 | $0.8368 |

API-equivalent estimates include discounted cached input. Actual Codex subscription billing is unavailable. Standard short-context rates are pinned in benchmark/pricing.json; all-long sensitivity is recorded in results.json.

Timing includes agent startup, reasoning, tool use and final answer. Initial analysis and identical first-function decompiler warmup occur before timing; setup is reported separately. Model prompt cache is uncontrolled and measured, with counterbalanced serial order.

Changes: compact evidence envelope; full content-checked records retained; memory defaults to hex with explicit UTF-8/both; call graphs requested explicitly; compact search references/full metadata option; deterministic content IDs and sorted call lists; shorter descriptions.

No claim of better decompilation or general superiority. Missing/null/duplicate fields fail. Evidence validity and answer correctness are separate checks. See answer-review.json for each answer, expected value and evidence.

## Individual trials

| ID | Tool | Questions | Fields | Seconds | Input | Cached | Output | API USD |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| n11 | community | 6/6 | 24/24 | 166.7 | 728,304 | 660,736 | 5,109 | $0.2523 |
| n12 | ours | 6/6 | 24/24 | 126.0 | 647,091 | 570,752 | 4,884 | $0.2586 |
| n13 | rea | 6/6 | 24/24 | 163.2 | 1,023,833 | 942,720 | 6,645 | $0.3229 |
| n21 | rea | 6/6 | 24/24 | 209.3 | 1,476,509 | 1,368,064 | 7,398 | $0.4277 |
| n22 | community | 6/6 | 24/24 | 146.2 | 822,499 | 737,664 | 5,454 | $0.2980 |
| n23 | ours | 6/6 | 24/24 | 110.1 | 507,736 | 443,136 | 4,263 | $0.2161 |
| n31 | ours | 6/6 | 24/24 | 121.8 | 559,859 | 490,496 | 4,167 | $0.2294 |
| n32 | rea | 6/6 | 24/24 | 166.7 | 1,082,809 | 994,816 | 6,683 | $0.3423 |
| n33 | community | 6/6 | 24/24 | 136.2 | 771,832 | 686,336 | 4,688 | $0.2865 |

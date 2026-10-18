# Doom comparison

Model: gpt-6.1-sol; effort: high. all corrected trials recorded.

**Primary comparison: real-clean.** The original real round is diagnostic because the shared calculator failed its macOS memory-limit setup. All original results remain below. Tiny timings include REA lazy analysis; real-round timings prewarm all engines.

| Round | Tool | Runs | Correct fields | Complete questions | Median agent time | Tokens incl. cached | API equivalent* |
|---|---|---:|---:|---:|---:|---:|---:|
| real-clean | ours | 3 | 42/42 | 18/18 | 131.1s | 1,929,792 | $0.889 |
| real-clean | rea | 3 | 42/42 | 18/18 | 164.9s | 2,680,570 | $1.019 |
| real-clean | community | 3 | 42/42 | 18/18 | 131.7s | 2,088,112 | $0.788 |
| tiny | ours | 1 | 3/3 | 1/1 | 39.9s | 222,542 | $0.156 |
| tiny | rea | 1 | 3/3 | 1/1 | 93.6s | 499,120 | $0.197 |
| tiny | community | 1 | 3/3 | 1/1 | 57.0s | 339,677 | $0.139 |
| real | ours | 3 | 42/42 | 18/18 | 124.6s | 1,755,904 | $0.826 |
| real | rea | 3 | 42/42 | 18/18 | 186.2s | 2,756,749 | $1.012 |
| real | community | 3 | 42/42 | 18/18 | 130.0s | 1,909,097 | $0.817 |

*Standard short-context API-equivalent estimate, not a subscription charge. Cached input is discounted. Missing usage is not zero. See pricing.json for long-context sensitivity and tier assumptions.

Backend setup is measured separately. Ours and community use copies of the same analyzed Ghidra project; stock REA opens the same stripped executable. All processes and model sessions are fresh.

One binary, six related questions, three repetitions per tool. No general superiority claim. The tiny question is repeated in the real round.

Proof: [results.json](results.json), [runs.csv](runs.csv), [per-answer review](answer-review.json), [tiny protocol](../benchmark/protocol.json), [diagnostic protocol](../benchmark/protocol-real.json), [primary protocol](../benchmark/protocol-real-clean.json).

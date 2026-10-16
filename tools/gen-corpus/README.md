# tools/gen-corpus

The corpus generator lives in the `WinGuard.Eval` console project
(`src/WinGuard.Eval/Corpus/`) and is invoked as a command of that project:

```bash
dotnet run --project src/WinGuard.Eval -- gen-corpus
```

It writes the committed, reproducible corpus to `data/corpus/`:

| File           | Contents                                                                 |
| -------------- | ------------------------------------------------------------------------ |
| `benign.jsonl` | Snapshots with no tamper indicators (`labels: []`). Used to measure the false-positive rate. |
| `labeled.jsonl`| Mixed corpus, ~15% tampered, each line carrying a ground-truth `labels` array of expected rule ids. |

## Properties

- **Deterministic.** Everything derives from `CorpusOptions.Seed` (default
  `20260115`), so re-running the generator reproduces byte-identical files.
- **Realistic.** ~42 simulated endpoints run believable Windows process archetypes
  (game clients, services, browsers, developer tools) with genuine module sets
  (`ntdll`, `kernel32`, D3D, Valve/NVIDIA/Google/Mozilla modules) and both
  System32/Program Files and game-directory paths.
- **Labeled.** Six tamper categories are injected: injected DLL from a
  non-system path, manually mapped module with no backing file, patched in-memory
  `.text`, unsigned/self-signed module or driver, RWX private region in a
  protected process, and process hollowing.
- **Hard negatives.** Legitimate self-signed/unsigned modules in *non-protected*
  processes and private (non-executable) regions are included so the rules are
  measured against realistic noise rather than only obvious tamper.

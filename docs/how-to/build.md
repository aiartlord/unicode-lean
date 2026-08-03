# Project Runbook

This is the operational entry point for building, testing, packaging, and
auditing this repository.

The runtime security layer is the default product path. Lean assurance and full
conformance are evidence paths and must stay opt-in.

## Hard Rules

- Do not run a broad Lean build on a cold cache as a casual check.
- Do not run Lean assurance or full conformance while unrelated heavy builds are
  active on the same WSL host.
- Keep `LEAN_NUM_THREADS=1` and `JOBS=1` for local staged Lean work.
- Build Lean cache stages in dependency order and stop at the first failure.
- Treat optional product domains, assurance proofs, and conformance fixtures as
  separate roots, not default `Unicode` imports.
- Runtime packaging and port tests must not invoke Lean.

## Fast Product Path

Use this path for normal runtime work, CLI work, port work, packaging, and
deployment smoke checks:

```bash
nix develop .#runtime -c scripts/build-runtime.sh
nix develop .#runtime -c scripts/test-runtime-ports.sh --smoke
nix develop .#runtime -c scripts/package-runtime.sh
nix develop .#runtime -c scripts/check-runtime-package.sh dist/runtime
```

Small CLI install:

```bash
nix develop .#runtime -c scripts/install-unicode-security.sh dist/runtime/rust
```

Release preflight for runtime packages:

```bash
nix develop .#runtime -c env JOBS=1 scripts/check-release-runtime-preflight.sh
```

## Deployment Path

Deployable artifacts and consumer smoke checks are documented in
[`DEPLOYMENT.md`](DEPLOYMENT.md).

The deployment package must state that Lean was not built. Deployment evidence
comes from runtime package checks and downstream consumer smokes, not from
proof-root builds.

## Lean Root Boundaries

The default Lean root is `Unicode`. It should contain executable algorithms and
runtime API modules only.

Optional roots:

- `UnicodeSecurity`
- `UnicodeIdna`
- `UnicodeUca`
- `UnicodeUnihan`
- `UnicodeSegmentationSpecs`

Evidence roots:

- `UnicodeAssurance`
- `UnicodeFullConformance`

Audit the import graph without invoking Lean:

```bash
scripts/audit-lean-root-boundaries.py --fail-consumer-boundary \
  --plan-out /tmp/unicode-root-cache-plan.tsv
```

This command is read-only. It derives closures and cache order from the current
Lean import graph and does not touch `.lake`.

## Lean Cache Pipeline

The staged Lean cache pipeline is a resource-control mechanism. It is not a
single "make everything green" command.

The target shape is:

1. Stage 0: clean/snapshot
2. Stage 1: generated base
3. Stage 2: normalization runtime
4. Stage 3: runtime property tables
5. Stage 4: product default root
6. Stage 5: optional product roots, one at a time
7. Stage 6: assurance proof chunks, one at a time
8. Stage 7: assurance aggregate
9. Stage 8: full conformance modules, one at a time
10. Stage 9: full conformance aggregate
11. Stage 10: cleanup/report

Quick-check soundness evidence belongs in Stage 6. It is an opt-in assurance
layer, not a runtime normalization prerequisite and not part of the default
`Unicode` root. Do not run Lean, Lake, or the staged cache runner while local
free disk is below the project safety floor; finish source-only cleanup first,
recover disk, then validate one module at a time.

The root-boundary audit treats `QuickCheckFacts`, `QuickCheckHangulFacts`, and
`QuickCheckSingletonRankData` as assurance facts, and treats
`QuickCheckSoundness*` modules as assurance proofs. None of these modules should
enter the default runtime root.

`Unicode.Normalization.QuickCheckSingletonRankData` is generated assurance fact
data. Cache it before the structural rank support module
`Unicode.Normalization.QuickCheckSoundnessSingletonRank`:

```bash
scripts/lean-cache-stages.py \
  --preset evidence \
  --only-module Unicode.Normalization.QuickCheckSingletonRankData \
  --run \
  --resume \
  --max-rss-gb 40 \
  --timeout-sec 0

scripts/lean-cache-stages.py \
  --preset evidence \
  --only-module Unicode.Normalization.QuickCheckSoundnessSingletonRank \
  --run \
  --resume \
  --max-rss-gb 40 \
  --timeout-sec 0
```

Measured local reference: these targets built one module at a time with
`LEAN_NUM_THREADS=1` and `JOBS=1`; `QuickCheckSingletonRankData` built in 417
seconds after adding lookup-shaped coverage, `QuickCheckSoundnessSingletonRank`
built in 1.3 s with its dependencies already cached, and
`QuickCheckSoundnessSingletonTable` built in 345 ms.

After disk recovery, validate the kept QuickCheck assurance layer in this order,
one module target per Lean process:

1. `Unicode.Normalization.QuickCheckSoundnessPrefix`
2. `Unicode.Normalization.QuickCheckSoundnessSingletonAtomic`
3. `Unicode.Normalization.QuickCheckSoundnessSingletonPair`
4. `Unicode.Normalization.QuickCheckSoundnessHangul`
5. `Unicode.Normalization.QuickCheckSoundnessSingletonRank`
6. `Unicode.Normalization.QuickCheckSoundnessSingletonTable`
7. `Unicode.Normalization.QuickCheckSoundnessMaster`
8. `Unicode.Normalization.QuickCheckSoundnessSnocClosure`
9. `Unicode.Normalization.QuickCheckSoundnessTheorem`

`Unicode.Precis.ZsPreservationFacts` holds the heavy `decide +kernel` table
facts for the "no non-ASCII Zs" preservation proofs — the all-rows
canonical-decomposition fact (over the `List` mirror `UnicodeData.rowsList`, not
the quadratic Array `.all`), the 11172-syllable Hangul decomposition fact, and
the per-codepoint `fullCanonicalDecompose` fact. Cache it before
`Unicode.Precis.ZsPreservation`, whose structural proof lemmas consume the cached
facts without re-running the kernel reductions:

```bash
scripts/lean-cache-stages.py \
  --preset evidence \
  --only-module Unicode.Precis.ZsPreservationFacts \
  --run \
  --resume \
  --max-rss-gb 40 \
  --timeout-sec 0

scripts/lean-cache-stages.py \
  --preset evidence \
  --only-module Unicode.Precis.ZsPreservation \
  --run \
  --resume \
  --max-rss-gb 40 \
  --timeout-sec 0
```

The `UnicodeUca` product root (Stage 5) closes its collation spot-checks through
a kernel-reducible DUCET mirror, not the runtime lookup. `Unicode.Uca.Lookup`
carries both paths: the runtime `matchAt`/`resolveAt` read the `Std.HashMap`
`ducetIndex` and use `Id.run`/`for`, which the kernel cannot reduce, and the
mirror `matchAtList`/`resolveAtList` do the same lookup structurally over
`ducetEntriesList` so `decide +kernel` can evaluate them. `Unicode.Uca.SortKey`
drives its `sortKey` pipeline through `matchAtList`, so the `ucaCompare` and
`resolveAtList` spot-checks are kernel-checked. These are heavy: built one module
at a time with `LEAN_NUM_THREADS=1` and `JOBS=1`, `Unicode.Uca.Lookup` built in
349 s and `Unicode.Uca.SortKey` in 795 s. `Lookup` caches before `SortKey`
automatically through the import graph; build it first when replaying a single
module:

```bash
scripts/lean-cache-stages.py \
  --preset product \
  --only-module Unicode.Uca.Lookup \
  --run \
  --resume \
  --max-vmem-gb 0 \
  --max-rss-gb 40 \
  --timeout-sec 0

scripts/lean-cache-stages.py \
  --preset product \
  --only-module Unicode.Uca.SortKey \
  --run \
  --resume \
  --max-vmem-gb 0 \
  --max-rss-gb 40 \
  --timeout-sec 0
```

Current implemented support:

- `scripts/audit-lean-root-boundaries.py` derives root closures and a
  dependency-order cache plan.
- `scripts/lean-cache-stages.py` consumes the graph-derived plan, assigns
  dependency-valid resource stages, and defaults to dry-run mode.
- Stage 0 snapshots record active Lean/Lake processes, git tree state, planned
  untracked Lean modules, cache state, root plan, and available memory.
- `--preset product`, `--preset evidence`, and `--preset full` avoid hand-typed
  root lists.
- `--report` summarizes `status.json` and GNU time peak-RSS evidence from module
  logs.
- `--max-rss-gb` monitors the whole module-build process tree and terminates the
  process group if it crosses the configured cap.
- `--cleanup-report` inventories logs and moved-aside caches without deleting
  anything.
- `--archive-existing-out-dir` moves an existing stage output directory under
  `--archive-dir` before writing a fresh plan.
- `--explain-plan` writes why each module landed in its stage, including
  dependency promotions.
- `scripts/check-lean-cache-plan-fixtures.py` checks graph-derived plan
  summaries for default/product/evidence presets.
- `scripts/check-lean-cache-runner-selftest.py` exercises runner bookkeeping
  paths with a controlled child process. It does not invoke Lean and is not
  build evidence.
- every run writes a plan signature and `--resume` refuses stale `status.json`
  unless `--allow-status-plan-drift` is explicitly set.
- `--only-module` and `--from-module` provide precise replay/range selection
  through the same safety wrapper.
- `--fail-if-plan-drift` compares selected preset summaries against tracked
  fixtures before any execution.
- `--list-roots`, `--list-stages`, and `--list-memory-backends` expose operator
  inventory without planning or building.
- `--dry-run-command-lines` prints exact per-module command lines without
  execution.
- `--bundle-evidence` packages plan, snapshot, status, report, triage, and logs
  under a tarball.
- `scripts/check-lean-cache-runbook.py` validates documented Lean-cache commands
  without invoking Lean.
- `Unicode.lean` is separated from optional product roots in `lakefile.lean`.

Current missing support before a safe cold-cache Lean run:

- external/cgroup-level RSS enforcement if WSL process accounting proves
  insufficient

Plan the default root without invoking Lean:

```bash
scripts/lean-cache-stages.py --root default
```

Plan all product roots without invoking Lean:

```bash
scripts/lean-cache-stages.py --preset product --out-dir dist/lean-cache-stages-product
```

List roots, stages, and memory backend availability:

```bash
scripts/lean-cache-stages.py --list-roots
scripts/lean-cache-stages.py --list-stages
scripts/lean-cache-stages.py --list-memory-backends
```

Explain why modules landed in their stages:

```bash
scripts/lean-cache-stages.py \
  --preset product \
  --explain-plan \
  --out-dir dist/lean-cache-stages-product
```

Fail if a preset plan drifts from the tracked summary fixtures:

```bash
scripts/lean-cache-stages.py \
  --preset product \
  --fail-if-plan-drift \
  --out-dir dist/lean-cache-stages-product
```

Print exact command lines without executing them:

```bash
scripts/lean-cache-stages.py \
  --preset product \
  --stage stage-1-generated-base \
  --dry-run-command-lines \
  --out-dir dist/lean-cache-stages-product
```

Plan assurance/full-conformance evidence roots without invoking Lean:

```bash
scripts/lean-cache-stages.py --preset evidence --out-dir dist/lean-cache-stages-evidence
```

Record Stage 0 state before executing any cache stage:

```bash
scripts/lean-cache-stages.py \
  --preset product \
  --stage0 \
  --out-dir dist/lean-cache-stages-product
```

If a previous cache must be moved out of the way, use move-aside, not deletion:

```bash
scripts/lean-cache-stages.py \
  --preset product \
  --stage0 \
  --move-cache-aside \
  --out-dir dist/lean-cache-stages-product
```

Move old stage output aside before starting a fresh plan:

```bash
scripts/lean-cache-stages.py \
  --preset product \
  --archive-existing-out-dir \
  --out-dir dist/lean-cache-stages-product \
  --archive-dir dist/lean-cache-archive
```

Inventory stage logs/caches without deleting anything:

```bash
scripts/lean-cache-stages.py \
  --preset product \
  --cleanup-report \
  --out-dir dist/lean-cache-stages-product
```

Execute only an explicit stage. This is the shape to use when the machine is
reserved for Lean work:

```bash
scripts/lean-cache-stages.py \
  --preset product \
  --stage stage-1-generated-base \
  --run \
  --resume \
  --max-vmem-gb 40 \
  --max-rss-gb 40 \
  --rss-poll-sec 5 \
  --min-available-gb 8 \
  --timeout-sec 0
```

`--timeout-sec 0` means no per-module timeout. Each executed module runs as its
own `lake build <Module>` process group with `LEAN_NUM_THREADS=1` and `JOBS=1`.
The runner polls process-tree RSS, writes peak usage to status/logs, and stops at
the first timeout, RSS cap, or build failure.

Replay one module through the same wrapper:

```bash
scripts/lean-cache-stages.py \
  --preset product \
  --only-module Unicode.Generated.UnicodeData \
  --run \
  --resume \
  --max-rss-gb 40 \
  --timeout-sec 0
```

Resume a long selected stage from a specific module:

```bash
scripts/lean-cache-stages.py \
  --preset evidence \
  --stage stage-8-conformance-module \
  --from-module Unicode.Conformance.NormalizationTest \
  --run \
  --resume \
  --max-rss-gb 40 \
  --timeout-sec 0
```

Summarize progress without invoking Lean:

```bash
scripts/lean-cache-stages.py --preset product --report --out-dir dist/lean-cache-stages-product
```

Bundle staged-cache evidence after a run/report:

```bash
scripts/lean-cache-stages.py \
  --preset product \
  --report \
  --bundle-evidence dist/lean-cache-stages-product/evidence.tar.gz \
  --out-dir dist/lean-cache-stages-product
```

Check staged-cache plumbing without invoking Lean:

```bash
scripts/check-runtime-import-boundary.sh
scripts/check-lean-cache-plan-fixtures.py
scripts/check-lean-cache-runner-selftest.py
scripts/check-lean-cache-runbook.py
```

## Runtime Port Contract

Runtime ports are self-contained product targets. They must carry their own
data files and must not import from another port or from local repository paths
at package-consumer time.

Port documentation lives in [`PORTS.md`](PORTS.md). Self-contained package
checks are part of the runtime preflight.

## Evidence And Specs

- Build tiers and budgets: [`BUILD_TIERS.md`](BUILD_TIERS.md)
- Security calculus and family specs: [`specs/security/`](specs/security/)
- Trust boundary notes: [`TCB.md`](TCB.md)
- Internal roadmap: [`ROADMAP.md`](ROADMAP.md)

## When Something Fails

1. Stop at the first failure.
2. Record the exact command, root/module, cache state, elapsed time, and peak
   memory if available.
3. Do not broaden the build to "see what else fails".
4. Fix the smallest root or module that explains the failure.
5. Rerun the same bounded step before moving forward.

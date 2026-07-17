/-
  Unicode.Assurance

  Opt-in proof-heavy assurance root. This imports theorem modules that may load
  generated-row proofs or official evidence suites and are intentionally kept
  out of the default runtime `Unicode` root.
-/

import Unicode

-- Reusable state-machine proof machinery: lets a scanning detector or
-- normalization pass be proven correct for every input (a state-machine
-- invariant via `feedThrough_append`) instead of witness-tested on a corpus.
import Unicode.Machine

-- Generated/support modules that are not part of the default runtime surface.
import Unicode.Generated.NormalizationTypes
import Unicode.NatIntervalUnion
import Unicode.Segmentation.GraphemeBreakParallel

-- Normalization theorem surface.
import Unicode.Normalization.ToNFDAppend
import Unicode.Normalization.ReorderAppend
import Unicode.Normalization.ComposeInversion
import Unicode.Normalization.ComposeBufferStructure
import Unicode.Normalization.ComposeBlockAdditive
import Unicode.Normalization.ComposeKernelSupport
import Unicode.Normalization.QuickCheckSoundness
import Unicode.Normalization.QuickCheckSoundnessSnocClosure
import Unicode.Normalization.QuickCheckSoundnessMaster
import Unicode.Normalization.QuickCheckSoundnessTheorem

-- Case-fold and PRECIS theorem surface.
import Unicode.CaseFoldCommutation
import Unicode.CaseFoldRoundtrip
import Unicode.Precis.Preparation
import Unicode.Precis.ZsPreservation
import Unicode.Precis.OpaqueString

-- Runtime-domain example/theorem vectors kept out of the default root.
import Unicode.WidthExamples

-- Confusable-skeleton table soundness. Extracted from the runtime `Confusables`
-- module so the default root does not reduce the full UCD 17.0 confusables
-- table; the aggregate gathers the per-chunk `decide +kernel` facts here so the
-- evidence root actually verifies them.
import Unicode.ConfusablesTableFacts

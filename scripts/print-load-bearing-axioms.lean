/-
  Axiom evidence for the load-bearing theorems.

  `scripts/check-axiom-footprint.lean` is the gate: it fails the build if any
  declaration in the audited closure reaches an axiom outside the Lean core.
  This probe is the evidence: it prints, for each theorem a reader is most
  likely to ask about by name, the exact set of axioms the proof term depends
  on. A reviewer checking the bidi and normalization claims wants to read that
  set rather than trust a pass.

  The admitted set is `propext`, `Quot.sound`, and `Classical.choice`. Anything
  reaching `sorryAx` or `Lean.ofReduceBool` would mean the theorem is not
  proven, and that is precisely what a reader is checking for.

  Run through `lake env lean scripts/print-load-bearing-axioms.lean` after a
  completed build; the probe reads the built `.olean` artifacts.
-/

import Lean.Util.CollectAxioms
import Lean.Elab.Command
import Unicode.SecurityRoot
import Unicode.FullConformance

open Lean (Name collectAxioms)

/-- The theorems named here are the ones the security claims rest on.

    The bidi walk invariants hold for EVERY input: they are what makes a
    non-zero final embedding or isolate stack a genuine imbalance rather than
    an artefact of the walk's bookkeeping, so the detector's verdict means
    something. The normalization identities are the UAX #15 stability
    properties, also over every input, discharged from the algorithm-
    correctness proofs rather than sampled. The zero-width sanction theorems
    are the negative-control evidence: legitimate Devanagari and Persian
    orthography stays clear while a spliced joiner still reports. -/
def loadBearing : List Name :=
  [ `Unicode.Security.Covert.BidiControlBalance.runWalk_depthAccounted,
    `Unicode.Security.Covert.BidiControlBalance.runWalk_stackConsistent,
    `Unicode.Security.Display.RtlInjection.countBidiControl_le_size,
    `Unicode.Conformance.NormalizationTest.nfc_stable,
    `Unicode.Conformance.NormalizationTest.nfd_stable,
    `Unicode.Conformance.NormalizationTest.nfd_of_nfc,
    `Unicode.Security.Covert.ZeroWidthPayload.detect_devanagari_zwnj_clear,
    `Unicode.Security.Covert.ZeroWidthPayload.detect_persian_zwnj_clear,
    `Unicode.Security.Covert.ZeroWidthPayload.detect_zwnj_in_latin_hazard ]

#eval show Lean.Elab.Command.CommandElabM Unit from do
  let env ← Lean.getEnv
  let admitted (ax : Name) : Bool :=
    ax == ``propext || ax == ``Quot.sound || ax == ``Classical.choice
  let mut missing : Array Name := #[]
  let mut offenders : Array (Name × Name) := #[]
  for declName in loadBearing do
    if !env.contains declName then
      missing := missing.push declName
    else
      let axs ← collectAxioms declName
      let rendered :=
        if axs.isEmpty then "no axioms"
        else String.intercalate ", " (axs.toList.map toString)
      IO.println s!"{declName}\n    {rendered}"
      for ax in axs do
        if !(admitted ax) then
          offenders := offenders.push (declName, ax)
  if !missing.isEmpty then
    let names := String.intercalate "\n" (missing.toList.map fun n => s!"  {n}")
    throwError "FATAL: named theorem absent from the built closure:\n{names}"
  if offenders.isEmpty then
    IO.println s!"clean: {loadBearing.length} load-bearing theorems depend only on propext, Quot.sound, Classical.choice"
  else
    let lines := offenders.map fun p => s!"  {p.1} depends on {p.2}"
    throwError "FATAL: axiom outside the Lean core:\n{String.intercalate "\n" lines.toList}"

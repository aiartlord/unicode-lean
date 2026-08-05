/-
  Axiom-footprint gate for the audited root.

  `scripts/check-no-axiom.sh` guards the source text: no `axiom`
  declaration, no `unsafe`, no runtime escape hatch may appear under
  `Unicode/`. This probe guards the elaborated artifacts. It imports the
  audited root `Unicode` and computes, for every declaration defined in a
  `Unicode` module, the exact set of axioms its term transitively depends
  on. The admitted set is the three Lean-core axioms — `propext`,
  `Quot.sound`, and `Classical.choice` — and nothing else. A declaration
  whose footprint reaches `sorryAx`, `Lean.ofReduceBool`,
  `Lean.trustCompiler`, or a project-local axiom fails the gate, and the
  error names both the declaration and the axiom.

  Run through `scripts/check-axiom-footprint.sh` after a completed
  `lake build`; the probe reads the built `.olean` artifacts.
-/
import Lean.Util.CollectAxioms
import Lean.Elab.Command
import Unicode

open Lean (Name collectAxioms)

#eval show Lean.Elab.Command.CommandElabM Unit from do
  let env ← Lean.getEnv
  let moduleNames := env.allImportedModuleNames
  let inUnicodeModule (declName : Name) : Bool :=
    match env.getModuleIdxFor? declName with
    | some modIdx =>
      match moduleNames[modIdx.toNat]? with
      | some modName => modName.getRoot == `Unicode
      | none => false
    | none => false
  let allowed (ax : Name) : Bool :=
    ax == ``propext || ax == ``Quot.sound || ax == ``Classical.choice
  let mut checked : Nat := 0
  let mut offenders : Array (Name × Name) := #[]
  for entry in env.constants.toList do
    let declName := entry.1
    if inUnicodeModule declName then
      checked := checked + 1
      let axs ← collectAxioms declName
      for ax in axs do
        if !(allowed ax) then
          offenders := offenders.push (declName, ax)
  if offenders.isEmpty then
    IO.println s!"clean: axiom footprint of {checked} declarations is contained in the Lean-core axioms propext, Quot.sound, Classical.choice"
  else
    let lines := offenders.map fun p => s!"  {p.1} depends on {p.2}"
    let report := String.intercalate "\n" lines.toList
    throwError "FATAL: axiom footprint outside the Lean-core axioms:\n{report}"

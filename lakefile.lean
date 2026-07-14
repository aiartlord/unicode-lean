import Lake
open Lake DSL

package unicode where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib Unicode where
  srcDir := "."
  roots := #[`Unicode]

lean_lib UnicodeAssurance where
  srcDir := "."
  roots := #[`Unicode.Assurance]

lean_lib UnicodeFullConformance where
  srcDir := "."
  roots := #[`Unicode.FullConformance]

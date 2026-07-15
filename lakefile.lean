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

lean_lib UnicodeSecurity where
  srcDir := "."
  roots := #[`Unicode.SecurityRoot]

lean_lib UnicodeIdna where
  srcDir := "."
  roots := #[`Unicode.Idna]

lean_lib UnicodeUca where
  srcDir := "."
  roots := #[`Unicode.Uca]

lean_lib UnicodeUnihan where
  srcDir := "."
  roots := #[`Unicode.UnihanRoot]

lean_lib UnicodeSegmentationSpecs where
  srcDir := "."
  roots := #[`Unicode.SegmentationSpecs]

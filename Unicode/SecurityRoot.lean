/-
  Unicode.SecurityRoot

  Optional product root for the Unicode security engine. This is intentionally
  outside the default `Unicode` root so normal consumers can build the core
  Unicode runtime without also compiling every detector and policy surface.
-/

import Unicode.Security
import Unicode.Security.RunAll
import Unicode.Security.Level
import Unicode.Security.Policy

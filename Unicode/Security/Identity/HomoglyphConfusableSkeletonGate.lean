/-
  Unicode.Security.Identity.HomoglyphConfusableSkeletonGate

  Integrity gate for the materialized canonical-target letter skeletons.

  `HomoglyphConfusable.canonicalTargetSkeletons` pins the letter skeleton of
  every curated attack target as a literal so that detection never re-descends
  the confusable decision tree once per target. This module certifies that the
  pinned literal is exactly what the skeleton pipeline computes from
  `canonicalTargets`, and is the only place that reduction is performed. A
  drifted target list or a changed skeleton definition fails here rather than
  silently weakening every downstream detection.

  The certification is held in its own module because reducing all sixty-seven
  target skeletons is the single most expensive proof in the detector; keeping it
  apart bounds the elaboration of the spot-check modules.
-/

import Unicode.Security.Identity.HomoglyphConfusable

namespace Unicode.Security.Identity.HomoglyphConfusableSkeletonGate

open Unicode.Security.Identity.HomoglyphConfusable
  (canonicalTargets canonicalTargetSkeletons)

set_option maxRecDepth 100000
set_option maxHeartbeats 4000000

/-- The pinned skeleton table is exactly the skeleton pipeline applied to the
    curated target list, position by position. -/
theorem canonicalTargetSkeletons_correct :
    canonicalTargetSkeletons.toList
      = canonicalTargets.toList.map
          (fun t => (Unicode.Confusables.letterSkeleton t.cps.toList).toArray) := by
  decide +kernel

/-- The pinned table and the target list agree in length, so zipping them in
    `findTargetMatch` drops no target. -/
theorem canonicalTargetSkeletons_size :
    canonicalTargetSkeletons.size = canonicalTargets.size := by
  simpa using congrArg List.length canonicalTargetSkeletons_correct

end Unicode.Security.Identity.HomoglyphConfusableSkeletonGate

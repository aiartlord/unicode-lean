/-
  Unicode.SegmentationSpecs

  Optional root for declarative segmentation spec bridges. Runtime segmentation
  algorithms stay in the default root; these spec bridges can be cached as a
  separate stage.
-/

import Unicode.Segmentation.GraphemeBreakSpec
import Unicode.Segmentation.WordBreakSpec
import Unicode.Segmentation.LineBreakSpec

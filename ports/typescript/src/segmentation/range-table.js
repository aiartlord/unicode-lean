// Lookup over a generated property range table.
//
// Every segmentation property in this directory is emitted as the same shape —
// parallel typed arrays of range starts, range ends and class indices — so both
// the UAX #14 line breaker and the UAX #29 cluster breaker read their tables
// through the one search here.

/**
 * The index of the one range covering `cp`, or -1 when no range does.
 *
 * Each table is sorted by range start and its ranges are disjoint, so the
 * covering range is unique and a binary search finds it. That is what makes the
 * search agree with the linear first-match of the Lean reference: with one
 * covering range, whichever the search finds is the one a scan in file order
 * would have found first.
 *
 * @param {{start: Uint32Array, end: Uint32Array}} table
 * @param {number} cp
 * @returns {number}
 */
export function rangeIndex(table, cp) {
  let lo = 0;
  let hi = table.start.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (cp < table.start[mid]) {
      hi = mid;
    } else if (cp > table.end[mid]) {
      lo = mid + 1;
    } else {
      return mid;
    }
  }
  return -1;
}

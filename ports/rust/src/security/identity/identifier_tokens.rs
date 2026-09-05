//! The identifier-shaped tokens of running text.
//!
//! Direct port of `Unicode/Security/Identity/IdentifierTokens.lean`. A source
//! file or a message is not one identifier, and the identifier detectors judge
//! a whole document wrongly when handed one; switching them off for running
//! text is wrong the other way, because `scоpe` with a Cyrillic о inside a
//! source file is exactly the homograph they exist to catch. The reading that
//! is right for both is per token: a maximal run of codepoints with the UAX #31
//! `XID_Continue` property, judged as the identifier it is. No language is
//! assumed and no region is exempt.

use crate::security::identity::ucd;

/// One token: where it starts in the input, and its codepoints. Mirrors
/// `Token`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub start: usize,
    pub cps: Vec<u32>,
}

/// True iff `cp` may continue an identifier: UAX #31 `XID_Continue`. Mirrors
/// `isTokenChar`.
pub fn is_token_char(cp: u32) -> bool {
    ucd::is_xid_continue(cp)
}

/// The identifier-shaped tokens of `input`, in input order: maximal runs of
/// `XID_Continue` codepoints, each with the position it starts at. Mirrors
/// `tokens`.
pub fn tokens(input: &[u32]) -> Vec<Token> {
    let mut out = Vec::new();
    let mut current: Option<(usize, Vec<u32>)> = None;
    for (idx, &cp) in input.iter().enumerate() {
        if is_token_char(cp) {
            match current.as_mut() {
                Some((_, cps)) => cps.push(cp),
                None => current = Some((idx, vec![cp])),
            }
        } else if let Some((start, cps)) = current.take() {
            out.push(Token { start, cps });
        }
    }
    if let Some((start, cps)) = current {
        out.push(Token { start, cps });
    }
    out
}

/// Shift a position list from token-relative to input-relative. Mirrors
/// `shiftPositions`.
pub fn shift_positions(start: usize, positions: &[usize]) -> Vec<usize> {
    positions.iter().map(|&p| p + start).collect()
}

#[cfg(test)]
mod tests {
    use super::{tokens, Token};

    // Ground truth: the spot-check theorems in
    // `Unicode/Security/Identity/IdentifierTokens.lean`.

    #[test]
    fn empty_and_two_words() {
        assert_eq!(tokens(&[]), Vec::<Token>::new());
        assert_eq!(
            tokens(&[0x61, 0x62, 0x20, 0x63, 0x64]),
            vec![
                Token { start: 0, cps: vec![0x61, 0x62] },
                Token { start: 3, cps: vec![0x63, 0x64] },
            ]
        );
    }

    #[test]
    fn source_line_and_greek_math() {
        assert_eq!(
            tokens(&[0x78, 0x20, 0x3D, 0x20, 0x73, 0x63, 0x043E, 0x70, 0x65, 0x3B]),
            vec![
                Token { start: 0, cps: vec![0x78] },
                Token { start: 4, cps: vec![0x73, 0x63, 0x043E, 0x70, 0x65] },
            ]
        );
        assert_eq!(
            tokens(&[0x03B4, 0x20, 0x3D, 0x20, 0x03B1, 0x20, 0x2212, 0x20, 0x03B2]),
            vec![
                Token { start: 0, cps: vec![0x03B4] },
                Token { start: 4, cps: vec![0x03B1] },
                Token { start: 8, cps: vec![0x03B2] },
            ]
        );
    }

    #[test]
    fn trailing_token_closes_at_end() {
        assert_eq!(tokens(&[0x20, 0x61]), vec![Token { start: 1, cps: vec![0x61] }]);
    }
}

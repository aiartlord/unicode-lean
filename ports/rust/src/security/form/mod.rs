//! Form-layer detectors — inputs whose normalization / case / width form
//! diverges from a safe canonical form. Direct ports of
//! `Unicode/Security/Form/*.lean`.

pub mod locale_case_inversion;
pub mod normalization_bomb;

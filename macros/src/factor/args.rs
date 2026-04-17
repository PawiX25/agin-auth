use std::str::FromStr;

use darling::FromMeta;
use strum::EnumString;
use syn::Path;

#[derive(Debug, FromMeta)]
pub struct FactorArgs {
    pub slug: String,
}

#[derive(Clone, Copy, PartialEq, Eq, EnumString)]
pub enum ImplKind {
    /// The primary `Factor` trait
    Factor,

    /// `FactrorConfigurable` trait
    FactorConfirmable,

    /// `FactorChallenge` trait
    FactorChallenge,
}

impl ImplKind {
    pub fn detect(trait_ty: &Path) -> Result<Self, darling::Error> {
        trait_ty
            .segments
            .last()
            .map(|s| Self::from_str(&s.ident.to_string()))
            .ok_or_else(|| darling::Error::custom("Missing trait in the implmentation"))
            .and_then(|s| s.map_err(|_| darling::Error::custom("Unknwon trait being implemented")))
    }
}

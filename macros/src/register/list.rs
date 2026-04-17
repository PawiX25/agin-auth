use syn::{
    Token,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
};

use crate::register::entry::FactorEntry;

pub struct FactorList {
    pub entries: Punctuated<FactorEntry, Token![,]>,
}

impl Parse for FactorList {
    fn parse(input: ParseStream) -> Result<Self, syn::Error> {
        Ok(Self {
            entries: Punctuated::parse_terminated(input)?,
        })
    }
}

use syn::{
    LitStr, Path, PathSegment, Token,
    parse::{Parse, ParseStream},
};

pub struct FactorEntry {
    pub slug: LitStr,
    pub path: Path,
    pub last_segment: PathSegment,
    pub module_segment: PathSegment,
}

impl Parse for FactorEntry {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let slug = input.parse::<LitStr>()?;
        input.parse::<Token![=>]>()?;
        let path = input.parse::<Path>()?;

        let last_segment = path
            .segments
            .last()
            .ok_or_else(|| syn::Error::new_spanned(&path, "expected a non-empty path"))?
            .clone();

        let module_segment = path
            .segments
            .iter()
            .nth_back(1)
            .ok_or_else(|| syn::Error::new_spanned(&path, "expected a module path"))?
            .clone();

        Ok(Self {
            slug,
            path,
            last_segment,
            module_segment,
        })
    }
}

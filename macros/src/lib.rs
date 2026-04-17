mod factor;
mod register;
mod util;

use proc_macro::TokenStream;

use crate::register::list::FactorList;

/// Generate Axum handlers annotated with `utoipa` for the factor.
#[proc_macro_attribute]
pub fn factor(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = match darling::ast::NestedMeta::parse_meta_list(args.into()) {
        Ok(x) => x,
        Err(e) => return e.into_compile_error().into(),
    };

    let args = match <factor::args::FactorArgs as darling::FromMeta>::from_list(&args) {
        Ok(x) => x,
        Err(e) => return e.write_errors().into(),
    };

    let input = syn::parse_macro_input!(input as syn::ItemImpl);

    match factor::factor(&args, input) {
        Ok(x) => x,
        Err(e) => e.write_errors().into(),
    }
}

/// Collect all factors and generate Axum router with them.
/// Also generate `FactorConfig` and `FactorName` enums.
#[proc_macro]
pub fn register_factors(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as FactorList);

    match register::register(&input) {
        Ok(x) => x,
        Err(e) => e.to_compile_error().into(),
    }
}

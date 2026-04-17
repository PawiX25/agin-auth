use std::collections::HashMap;

use quote::format_ident;

pub fn associated_type(
    base: &syn::TypePath,
    trait_path: &syn::Path,
    member: &str,
) -> Result<syn::TypePath, darling::Error> {
    let member_ident = format_ident!("{member}");

    let tokens = quote::quote! {
        <#base as #trait_path>::#member_ident
    };

    let type_path = syn::parse2(tokens)?;
    Ok(type_path)
}

pub fn capitalize_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
    }
}

pub fn wrap_with_generic(
    inner_path: &syn::TypePath,
    generic_path: &str,
) -> Result<syn::TypePath, darling::Error> {
    let generic_path = syn::parse_str::<syn::Path>(generic_path)?;

    let tokens = quote::quote! {
        #generic_path<#inner_path>
    };

    let type_path = syn::parse2(tokens)?;
    Ok(type_path)
}

pub fn extract_methods(input: syn::ItemImpl) -> HashMap<String, syn::ImplItemFn> {
    input
        .items
        .into_iter()
        .filter_map(|item| {
            if let syn::ImplItem::Fn(method) = item {
                Some((method.sig.ident.to_string(), method))
            } else {
                None
            }
        })
        .collect::<HashMap<_, _>>()
}

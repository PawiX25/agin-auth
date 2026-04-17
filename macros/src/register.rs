use std::collections::HashSet;

use proc_macro2::TokenStream;
use quote::quote;
use syn::LitStr;

use crate::register::{entry::FactorEntry, list::FactorList};

pub mod entry;
pub mod list;

pub fn register(factor_list: &FactorList) -> Result<proc_macro::TokenStream, syn::Error> {
    let mut output = TokenStream::new();

    let mut seen_factors = HashSet::new();
    let mut router = quote! { ::utoipa_axum::router::OpenApiRouter::new() };
    let mut config_variants = TokenStream::new();
    let mut name_variants = TokenStream::new();
    let mut flow_type_arms = TokenStream::new();
    let mut security_level_arms = TokenStream::new();
    let mut role_arms = TokenStream::new();

    for FactorEntry {
        path,
        slug,
        last_segment,
        module_segment,
    } in &factor_list.entries
    {
        if seen_factors.contains(slug) {
            return Err(syn::Error::new_spanned(
                slug,
                "Each factor has to be unique",
            ));
        }
        seen_factors.insert(slug);

        let last_segment_str =
            LitStr::new(&last_segment.ident.to_string(), last_segment.ident.span());

        let slug_assertion = quote! {
            #[doc(hidden)]
            const _: () = assert!(
                ::auth_core::str_eq(<#path as ::auth_core::FactorSlug>::SLUG, #slug),
                concat!("slug mismatch for factor `", #last_segment_str, "`: slug `", #slug, "` doesn't match trait definition")
            );
        };
        output.extend(slug_assertion);

        router.extend(quote! {
            .merge(#module_segment::routes())
        });

        let variant_name = &last_segment.ident;

        config_variants.extend(quote! {
            #[serde(rename = #slug)]
            #variant_name(<#path as ::auth_core::Factor>::Config),
        });

        name_variants.extend(quote! {
            #[serde(rename = #slug)]
            #variant_name,
        });

        flow_type_arms.extend(quote! {
            Self::#variant_name => <#path as ::auth_core::FactorMetadata>::FLOW_TYPE,
        });
        security_level_arms.extend(quote! {
            Self::#variant_name => <#path as ::auth_core::FactorMetadata>::SECURITY_LEVEL,
        });
        role_arms.extend(quote! {
            Self::#variant_name => <#path as ::auth_core::FactorMetadata>::ROLE,
        });
    }

    let handler = quote! {
        pub fn routes() -> ::utoipa_axum::router::OpenApiRouter<crate::state::AppState> {
            #router
        }
    };
    output.extend(handler);

    output.extend(quote! {
        #[derive(Clone, Debug, ::serde::Serialize, ::serde::Deserialize)]
        pub enum FactorConfig {
            #config_variants
        }
    });

    output.extend(quote! {
        #[derive(Clone, Copy, PartialEq, Eq, Debug, ::serde::Serialize, ::serde::Deserialize)]
        pub enum FactorName {
            #name_variants
        }

        impl ::auth_core::FactorMetadataDynamic for FactorName {
            fn flow_type(&self) -> ::auth_core::FlowType {
                match self {
                    #flow_type_arms
                }
            }

            fn security_level(&self) -> ::auth_core::SecurityLevel {
                match self {
                    #security_level_arms
                }
            }

            fn role(&self) -> ::auth_core::FactorRole {
                match self {
                    #role_arms
                }
            }
        }
    });

    Ok(output.into())
}

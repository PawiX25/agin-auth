use proc_macro2::{Ident, Span};

use crate::factor::args::ImplKind;

pub fn generate_router(routes: &[syn::Ident], impl_kind: ImplKind) -> proc_macro2::TokenStream {
    let router_ident = Ident::new(
        match impl_kind {
            ImplKind::Factor => "factor",
            ImplKind::FactorConfirmable => "confirmable",
            ImplKind::FactorChallenge => "challenge",
        },
        Span::call_site(),
    );

    let route_calls = routes.iter().map(|route| {
        quote::quote! {
            .routes(::utoipa_axum::routes!(#route))
        }
    });

    quote::quote! {
        pub fn #router_ident() -> ::utoipa_axum::router::OpenApiRouter<crate::state::AppState> {
            ::utoipa_axum::router::OpenApiRouter::new()
                #(#route_calls)*
        }
    }
}

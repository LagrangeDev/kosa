use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Error};

pub(crate) fn expand_service_state(item: TokenStream) -> syn::Result<TokenStream2> {
    let input: DeriveInput = syn::parse(item)?;

    if !matches!(&input.data, Data::Struct(_)) {
        return Err(Error::new_spanned(
            &input.ident,
            "`ServiceState` can only be derived for structs",
        ));
    }

    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics crate::service::ServiceState for #struct_name #ty_generics #where_clause {
            fn as_any(&self) -> &dyn ::core::any::Any {
                self
            }
        }
    })
}

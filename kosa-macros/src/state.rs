use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Error};

pub(crate) fn expand_service_state(item: TokenStream) -> syn::Result<TokenStream2> {
    let input: DeriveInput = syn::parse(item)?;
    expand_service_state_impl(&input)
}

fn expand_service_state_impl(input: &DeriveInput) -> syn::Result<TokenStream2> {

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

#[cfg(test)]
mod tests {
    use quote::quote;
    use syn::{DeriveInput, parse_quote};

    use super::expand_service_state_impl;

    #[test]
    fn derives_service_state_for_generic_struct() {
        let input: DeriveInput = parse_quote! {
            pub struct ServiceStateHolder<T>
            where
                T: Send + Sync + 'static,
            {
                state: T,
            }
        };

        let expanded = expand_service_state_impl(&input).unwrap().to_string();
        let expected = quote! {
            impl <T> crate::service::ServiceState for ServiceStateHolder<T>
            where
                T: Send + Sync + 'static,
            {
                fn as_any(&self) -> &dyn ::core::any::Any {
                    self
                }
            }
        }
        .to_string();

        assert_eq!(expanded, expected);
    }

    #[test]
    fn rejects_non_struct_targets() {
        let input: DeriveInput = parse_quote! {
            enum ServiceStateHolder {
                A,
            }
        };

        let err = match expand_service_state_impl(&input) {
            Ok(_) => panic!("expected enum derive to be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("can only be derived for structs"));
    }
}

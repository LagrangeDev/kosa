use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Error, GenericArgument, ItemImpl, PathArguments, Type};

pub fn register_service(_attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream2> {
    let impl_block: ItemImpl = syn::parse(item)?;
    expand_register_service(&impl_block)
}

fn expand_register_service(impl_block: &ItemImpl) -> syn::Result<TokenStream2> {
    let self_ty = &impl_block.self_ty;

    if impl_block.trait_.is_none() {
        return Err(Error::new_spanned(
            &impl_block.self_ty,
            "must be a trait implementation",
        ));
    }

    let submit_code = expand_service_submit(self_ty);

    Ok(quote! {
        #impl_block
        #submit_code
    })
}

pub fn register_oidb_service(_attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream2> {
    let impl_block: ItemImpl = syn::parse(item)?;
    expand_register_oidb_service(&impl_block)
}

fn expand_register_oidb_service(impl_block: &ItemImpl) -> syn::Result<TokenStream2> {
    let self_ty = &impl_block.self_ty;

    let trait_path = match &impl_block.trait_ {
        Some((_, path, _)) => path,
        None => {
            return Err(Error::new_spanned(
                &impl_block.self_ty,
                "must implement a trait like OidbService<Req, Resp>",
            ));
        }
    };

    let (req_ty, resp_ty) = extract_trait_type_args(trait_path)?;

    let service_impl = quote! {
        impl crate::service::Service<#req_ty, #resp_ty> for #self_ty {
            const METADATA: crate::service::Metadata = crate::service::Metadata {
                encrypt_type: crate::service::EncryptType::D2,
                request_type: crate::service::RequestType::D2Auth,
                support_protocols: <#self_ty as crate::service::OidbService<#req_ty, #resp_ty>>::SUPPORT_PROTOCOLS,
            };

            fn build(
                state: &Self,
                req: #req_ty,
                app_info: &AppInfo,
                session: &Session,
            ) -> anyhow::Result<Bytes> {
                let oidb_data = <#self_ty as crate::service::OidbService<#req_ty, #resp_ty>>::build(
                    state, req, app_info, session,
                )?;
                let data = crate::service::oidb::encode(
                    <#self_ty as crate::service::OidbCommandMarker>::COMMAND,
                    <#self_ty as crate::service::OidbCommandMarker>::SERVICE,
                    <#self_ty as crate::service::OidbCommandMarker>::RESERVED,
                    oidb_data,
                );
                Ok(data)
            }

            fn parse(
                state: &Self,
                data: Bytes,
                app_info: &AppInfo,
                session: &Session,
            ) -> anyhow::Result<#resp_ty> {
                let oidb_data = crate::service::oidb::decode(data)?;
                <#self_ty as crate::service::OidbService<#req_ty, #resp_ty>>::parse(
                    state, oidb_data, app_info, session,
                )
            }
        }
    };

    let submit_code = expand_service_submit(self_ty);

    Ok(quote! {
        #impl_block
        #service_impl
        #submit_code
    })
}

fn extract_trait_type_args(trait_path: &syn::Path) -> syn::Result<(&Type, &Type)> {
    let last_segment = trait_path
        .segments
        .last()
        .ok_or_else(|| Error::new_spanned(trait_path, "trait path has no segments"))?;

    let args = match &last_segment.arguments {
        PathArguments::AngleBracketed(args) => args,
        _ => {
            return Err(Error::new_spanned(
                trait_path,
                "trait must have generic arguments like OidbService<Req, Resp>",
            ));
        }
    };

    let types: Vec<&Type> = args
        .args
        .iter()
        .filter_map(|arg| {
            if let GenericArgument::Type(ty) = arg {
                Some(ty)
            } else {
                None
            }
        })
        .collect();

    match types.as_slice() {
        [req, resp] => Ok((req, resp)),
        _ => Err(Error::new_spanned(
            args,
            "expected exactly 2 type arguments: OidbService<Req, Resp>",
        )),
    }
}

fn expand_service_submit(self_ty: &Type) -> TokenStream2 {
    quote! {
        inventory::submit! {
            crate::service::ServiceEntry {
                creator: || {
                    let cmd = <#self_ty as crate::utils::marker::CommandMarker>::COMMAND;
                    let instance = <#self_ty as std::default::Default>::default();
                    (cmd, Box::new(instance))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use quote::quote;
    use syn::{ItemImpl, Path, parse_quote};

    use super::{
        expand_register_oidb_service, expand_register_service, expand_service_submit,
        extract_trait_type_args,
    };

    #[test]
    fn register_service_wraps_trait_impl_with_inventory_submit() {
        let impl_block: ItemImpl = parse_quote! {
            impl crate::service::SomeService for FetchService {}
        };

        let expanded = expand_register_service(&impl_block).unwrap().to_string();
        assert!(expanded.contains("impl crate :: service :: SomeService for FetchService"));
        assert!(expanded.contains("inventory :: submit !"));
        assert!(expanded.contains("crate :: service :: ServiceEntry"));
    }

    #[test]
    fn register_service_rejects_inherent_impl() {
        let impl_block: ItemImpl = parse_quote! {
            impl FetchService {}
        };

        let err = match expand_register_service(&impl_block) {
            Ok(_) => panic!("expected inherent impl to be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("must be a trait implementation"));
    }

    #[test]
    fn extract_trait_type_args_accepts_req_and_resp() {
        let path: Path = parse_quote!(crate::service::OidbService<Request, Response>);

        let (req_ty, resp_ty) = extract_trait_type_args(&path).unwrap();
        assert_eq!(quote!(#req_ty).to_string(), "Request");
        assert_eq!(quote!(#resp_ty).to_string(), "Response");
    }

    #[test]
    fn extract_trait_type_args_requires_exactly_two_types() {
        let path: Path = parse_quote!(crate::service::OidbService<Request>);

        let err = match extract_trait_type_args(&path) {
            Ok(_) => panic!("expected generic arity validation to fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("expected exactly 2 type arguments"));
    }

    #[test]
    fn register_oidb_service_generates_service_impl_and_submit() {
        let impl_block: ItemImpl = parse_quote! {
            impl crate::service::OidbService<Request, Response> for FetchService {}
        };

        let expanded = expand_register_oidb_service(&impl_block).unwrap().to_string();
        assert!(expanded.contains("impl crate :: service :: Service < Request , Response > for FetchService"));
        assert!(expanded.contains("crate :: service :: OidbService < Request , Response >"));
        assert!(expanded.contains("crate :: service :: oidb :: encode"));
        assert!(expanded.contains("inventory :: submit !"));
    }

    #[test]
    fn register_oidb_service_rejects_missing_trait_impl() {
        let impl_block: ItemImpl = parse_quote! {
            impl FetchService {}
        };

        let err = match expand_register_oidb_service(&impl_block) {
            Ok(_) => panic!("expected missing trait impl to be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("must implement a trait like OidbService<Req, Resp>"));
    }

    #[test]
    fn service_submit_uses_default_instance_and_command_marker() {
        let expanded = expand_service_submit(&parse_quote!(FetchService)).to_string();
        assert!(expanded.contains("crate :: utils :: marker :: CommandMarker"));
        assert!(expanded.contains("< FetchService as std :: default :: Default > :: default ()"));
    }
}

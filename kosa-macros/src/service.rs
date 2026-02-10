use proc_macro::TokenStream;
use quote::quote;
use syn::{Error, GenericArgument, ItemImpl, PathArguments, Type, parse_macro_input};

pub fn register_service(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let impl_block = parse_macro_input!(item as ItemImpl);
    let self_ty = &impl_block.self_ty;

    if impl_block.trait_.is_none() {
        return Error::new_spanned(impl_block, "must be a trait implementation")
            .to_compile_error()
            .into();
    }

    let submit_code = expand_service_submit(self_ty);

    let expanded = quote! {
        #impl_block
        #submit_code
    };

    TokenStream::from(expanded)
}

pub fn register_oidb_service(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let impl_block = parse_macro_input!(item as ItemImpl);
    let self_ty = &impl_block.self_ty;

    let trait_path = match &impl_block.trait_ {
        Some((_, path, _)) => path,
        None => {
            return Error::new_spanned(
                impl_block,
                "must implement a trait like OidbService<Req, Resp>",
            )
            .to_compile_error()
            .into();
        }
    };

    let (req_ty, resp_ty) = match extract_trait_type_args(trait_path) {
        Ok(types) => types,
        Err(e) => return e.to_compile_error().into(),
    };

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

    let expanded = quote! {
        #impl_block
        #service_impl
        #submit_code
    };

    TokenStream::from(expanded)
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

fn expand_service_submit(self_ty: &syn::Type) -> proc_macro2::TokenStream {
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

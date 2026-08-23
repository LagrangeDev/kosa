use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{
    Item, ItemStruct, LitInt, LitStr, Token,
    parse::{Parse, ParseStream},
};

pub(crate) fn expand_command(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream2> {
    let cmd_lit: LitStr = syn::parse(attr)?;
    let input_struct: Item = syn::parse(item)?;
    expand_command_tokens(&input_struct, &cmd_lit)
}

fn expand_command_tokens(input_item: &Item, cmd_lit: &LitStr) -> syn::Result<TokenStream2> {
    let command_impl = expand_command_impl(input_item, cmd_lit)?;

    let expand = quote! {
        #input_item

        #command_impl
    };
    Ok(expand)
}

struct OidbCommandArgs {
    command: u32,
    sub_command: u32,
}

impl Parse for OidbCommandArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let command_lit: LitInt = input.parse()?;
        let _ = input.parse::<Token![,]>()?;
        let sub_command_lit: LitInt = input.parse()?;
        Ok(Self {
            command: command_lit.base10_parse()?,
            sub_command: sub_command_lit.base10_parse()?,
        })
    }
}

pub(crate) fn expand_oidb_command(
    attr: TokenStream,
    item: TokenStream,
) -> syn::Result<TokenStream2> {
    let oidb_command_args: OidbCommandArgs = syn::parse(attr)?;
    let input_struct: ItemStruct = syn::parse(item)?;
    expand_oidb_command_tokens(&input_struct, &oidb_command_args)
}

fn expand_oidb_command_tokens(
    input_struct: &ItemStruct,
    oidb_command_args: &OidbCommandArgs,
) -> syn::Result<TokenStream2> {
    let command = format!(
        "OidbSvcTrpcTcp.{:#x}_{}",
        oidb_command_args.command, oidb_command_args.sub_command
    );
    let cmd_lit = LitStr::new(command.as_str(), Span::call_site());
    let struct_name = &input_struct.ident;
    let (impl_generics, ty_generics, where_clause) = input_struct.generics.split_for_impl();

    let command_val = oidb_command_args.command;
    let sub_command_val = oidb_command_args.sub_command;

    let command_impl = expand_command_impl(&Item::Struct(input_struct.clone()), &cmd_lit)?;

    let expand = quote! {
        #input_struct

        #command_impl

        impl #impl_generics crate::service::OidbCommandMarker for #struct_name #ty_generics #where_clause {
            const COMMAND: u32 = #command_val;
            const SERVICE: u32 = #sub_command_val;
        }
    };
    Ok(expand)
}

pub(crate) fn expand_push_event_impl(
    attr: TokenStream,
    item: TokenStream,
) -> syn::Result<TokenStream2> {
    let cmd_lit: LitStr = syn::parse(attr)?;
    let input_struct: ItemStruct = syn::parse(item)?;
    expand_push_event_tokens(&input_struct, &cmd_lit)
}

fn expand_push_event_tokens(
    input_struct: &ItemStruct,
    cmd_lit: &LitStr,
) -> syn::Result<TokenStream2> {
    let struct_name = &input_struct.ident;
    let (_, ty_generics, _) = input_struct.generics.split_for_impl();
    let command_impl = expand_command_impl(&Item::Struct(input_struct.clone()), cmd_lit)?;

    let expand = quote! {
        #input_struct

        #command_impl

        inventory::submit! {
            crate::event::EventEntry {
                creator: || {
                    (#cmd_lit, <#struct_name #ty_generics as crate::event::PushEvent>::handle)
                }
            }
        }
    };
    Ok(expand)
}

fn expand_command_impl(input_item: &Item, cmd_lit: &LitStr) -> syn::Result<TokenStream2> {
    let (name, generics) = match input_item {
        Item::Struct(item) => (&item.ident, &item.generics),
        Item::Enum(item) => (&item.ident, &item.generics),
        _ => {
            return Err(syn::Error::new_spanned(
                input_item,
                "command can only be applied to struct or enum",
            ));
        }
    };
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expand = quote! {
        impl #impl_generics crate::utils::marker::CommandMarker
            for #name #ty_generics #where_clause {
            const COMMAND: &'static str = #cmd_lit;
        }
    };
    Ok(expand)
}

#[cfg(test)]
mod tests {
    use quote::quote;
    use syn::{Item, ItemStruct, LitStr, parse_quote, parse2};

    use super::{
        OidbCommandArgs, expand_command_impl, expand_command_tokens, expand_oidb_command_tokens,
        expand_push_event_tokens,
    };

    #[test]
    fn command_impl_preserves_generics_and_where_clause() {
        let input_struct: Item = parse_quote! {
            pub struct FetchEvent<T>
            where
                T: Clone,
            {
                value: T,
            }
        };
        let cmd_lit: LitStr = parse_quote!("MessageSvc.PbGetMsg");

        let expanded = expand_command_impl(&input_struct, &cmd_lit)
            .unwrap()
            .to_string();
        assert!(
            expanded.contains(
                "impl < T > crate :: utils :: marker :: CommandMarker for FetchEvent < T >"
            )
        );
        assert!(expanded.contains("where T : Clone"));
        assert!(expanded.contains("MessageSvc.PbGetMsg"));
    }

    #[test]
    fn command_tokens_include_original_struct_and_marker_impl() {
        let input_struct: Item = parse_quote! {
            pub struct GetMsg;
        };
        let cmd_lit: LitStr = parse_quote!("MessageSvc.GetMsg");

        let expanded = expand_command_tokens(&input_struct, &cmd_lit)
            .unwrap()
            .to_string();
        assert!(expanded.contains("pub struct GetMsg ;"));
        assert!(expanded.contains("crate :: utils :: marker :: CommandMarker"));
        assert!(expanded.contains("MessageSvc.GetMsg"));
    }

    #[test]
    fn oidb_command_args_parse_two_integers() {
        let args: OidbCommandArgs = parse2(quote!(4660, 1)).unwrap();
        assert_eq!(args.command, 4660);
        assert_eq!(args.sub_command, 1);
    }

    #[test]
    fn oidb_command_tokens_generate_marker_impls() {
        let input_struct: ItemStruct = parse_quote! {
            pub struct OidbFetch;
        };
        let args: OidbCommandArgs = parse2(quote!(4660, 7)).unwrap();

        let expanded = expand_oidb_command_tokens(&input_struct, &args)
            .unwrap()
            .to_string();
        assert!(expanded.contains("OidbSvcTrpcTcp.0x1234_7"));
        assert!(expanded.contains("crate :: service :: OidbCommandMarker"));
        assert!(expanded.contains("const COMMAND : u32 = 4660"));
        assert!(expanded.contains("const SERVICE : u32 = 7"));
    }

    #[test]
    fn push_event_tokens_register_inventory_creator() {
        let input_struct: ItemStruct = parse_quote! {
            pub struct PushMessage<T>(T);
        };
        let cmd_lit: LitStr = parse_quote!("PushMessage");

        let expanded = expand_push_event_tokens(&input_struct, &cmd_lit)
            .unwrap()
            .to_string();
        assert!(expanded.contains("inventory :: submit !"));
        assert!(expanded.contains("crate :: event :: EventEntry"));
        assert!(
            expanded.contains("< PushMessage < T > as crate :: event :: PushEvent > :: handle")
        );
    }
}

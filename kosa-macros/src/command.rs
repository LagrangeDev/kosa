use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{
    ItemStruct, LitInt, LitStr, Token,
    parse::{Parse, ParseStream},
};

pub(crate) fn expand_command(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream2> {
    let cmd_lit: LitStr = syn::parse(attr)?;
    let input_struct: ItemStruct = syn::parse(item)?;
    let command_impl = expand_command_impl(&input_struct, &cmd_lit);

    Ok(quote! {
        #input_struct

        #command_impl
    })
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
    let command = format!(
        "OidbSvcTrpcTcp.{:#x}_{}",
        oidb_command_args.command, oidb_command_args.sub_command
    );
    let cmd_lit = LitStr::new(command.as_str(), Span::call_site());
    let input_struct: ItemStruct = syn::parse(item)?;
    let struct_name = &input_struct.ident;
    let (impl_generics, ty_generics, where_clause) = input_struct.generics.split_for_impl();

    let command_val = oidb_command_args.command;
    let sub_command_val = oidb_command_args.sub_command;

    let command_impl = expand_command_impl(&input_struct, &cmd_lit);

    Ok(quote! {
        #input_struct

        #command_impl

        impl #impl_generics crate::service::OidbCommandMarker for #struct_name #ty_generics #where_clause {
            const COMMAND: u32 = #command_val;
            const SERVICE: u32 = #sub_command_val;
        }
    })
}

pub(crate) fn expand_push_event_impl(
    attr: TokenStream,
    item: TokenStream,
) -> syn::Result<TokenStream2> {
    let cmd_lit: LitStr = syn::parse(attr)?;
    let input_struct: ItemStruct = syn::parse(item)?;
    let struct_name = &input_struct.ident;
    let (_, ty_generics, _) = input_struct.generics.split_for_impl();
    let command_impl = expand_command_impl(&input_struct, &cmd_lit);

    Ok(quote! {
        #input_struct

        #command_impl

        inventory::submit! {
            crate::event::EventEntry {
                creator: || {
                    (#cmd_lit, <#struct_name #ty_generics as crate::event::PushEvent>::handle)
                }
            }
        }
    })
}

fn expand_command_impl(input_struct: &ItemStruct, cmd_lit: &LitStr) -> TokenStream2 {
    let struct_name = &input_struct.ident;
    let (impl_generics, ty_generics, where_clause) = input_struct.generics.split_for_impl();

    quote! {
        impl #impl_generics crate::utils::marker::CommandMarker for #struct_name #ty_generics #where_clause {
            const COMMAND: &'static str = #cmd_lit;
        }
    }
}

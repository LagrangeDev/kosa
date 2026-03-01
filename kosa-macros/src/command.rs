use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use quote::quote;
use syn::{
    ItemStruct, LitInt, LitStr, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

pub(crate) fn expand_command(attr: TokenStream, item: TokenStream) -> TokenStream {
    let cmd_lit = parse_macro_input!(attr as LitStr);
    let input_struct = parse_macro_input!(item as ItemStruct);

    let command_impl =
        proc_macro2::TokenStream::from(expand_command_impl(&cmd_lit, &input_struct.ident));
    let expand = quote! {
        #input_struct

        #command_impl
    };
    TokenStream::from(expand)
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

pub(crate) fn expand_oidb_command(attr: TokenStream, item: TokenStream) -> TokenStream {
    let oidb_command_args = parse_macro_input!(attr as OidbCommandArgs);
    let command = format!(
        "OidbSvcTrpcTcp.{:#x}_{}",
        oidb_command_args.command, oidb_command_args.sub_command
    );
    let cmd_lit = LitStr::new(command.as_str(), Span::call_site());
    let input_struct = parse_macro_input!(item as ItemStruct);
    let struct_name = &input_struct.ident;

    let command_val = oidb_command_args.command;
    let sub_command_val = oidb_command_args.sub_command;

    let command_impl = proc_macro2::TokenStream::from(expand_command_impl(&cmd_lit, struct_name));
    let expand = quote! {
        #input_struct

        #command_impl

        impl crate::service::OidbCommandMarker for #struct_name {
            const COMMAND: u32 = #command_val;
            const SERVICE: u32 = #sub_command_val;
        }
    };

    TokenStream::from(expand)
}

pub(crate) fn expand_push_event_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let cmd_lit = parse_macro_input!(attr as LitStr);
    let input_struct = parse_macro_input!(item as ItemStruct);
    let struct_name = &input_struct.ident;
    let command_impl = proc_macro2::TokenStream::from(expand_command_impl(&cmd_lit, struct_name));
    let expand = quote! {
        #input_struct

        #command_impl

        inventory::submit! {
            crate::event::EventEntry {
                creator: || {
                    (#cmd_lit, <#struct_name as crate::event::PushEvent>::handle)
                }
            }
        }
    };
    TokenStream::from(expand)
}

fn expand_command_impl(cmd_lit: &LitStr, struct_name: &Ident) -> TokenStream {
    let expand = quote! {
        impl crate::utils::marker::CommandMarker for #struct_name {
            const COMMAND: &'static str = #cmd_lit;
        }
    };

    TokenStream::from(expand)
}

mod command;
mod service;

use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, ItemFn, LitInt, parse_macro_input};

/// 自动写入tlv tag，使用writer可以写入其他数据
#[proc_macro_attribute]
pub fn tlv(attr: TokenStream, item: TokenStream) -> TokenStream {
    let tlv_tag = parse_macro_input!(attr as LitInt)
        .base10_parse::<u16>()
        .expect("Error parsing tag into i16");
    let ast = parse_macro_input!(item as ItemFn);
    let vis = &ast.vis;
    let sig = &ast.sig;
    let block = &ast.block;

    let expanded = quote! {
        #vis #sig {
            self.writer.write_u16(#tlv_tag);
            self.count += 1;
            self.writer.write_with_prefix(crate::utils::binary::Prefix::U16, false, |writer| #block);
            self
        }
    };
    expanded.into()
}

#[proc_macro_attribute]
pub fn push_event(attr: TokenStream, item: TokenStream) -> TokenStream {
    command::expand_push_event_impl(attr, item)
}

#[proc_macro_attribute]
pub fn command(attr: TokenStream, item: TokenStream) -> TokenStream {
    command::expand_command(attr, item)
}

#[proc_macro_attribute]
pub fn oidb_command(attr: TokenStream, item: TokenStream) -> TokenStream {
    command::expand_oidb_command(attr, item)
}

#[proc_macro_derive(ServiceState)]
pub fn service_state_derive(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let struct_name = &input.ident;
    let expanded = quote! {
        impl crate::service::ServiceState for #struct_name {
            fn as_any(&self) -> &dyn ::core::any::Any {
                self
            }
        }
    };
    expanded.into()
}

/// 注册service到对应的command
#[proc_macro_attribute]
pub fn register_service(attr: TokenStream, item: TokenStream) -> TokenStream {
    service::register_service(attr, item)
}

/// 注册service到对应的oidb command
#[proc_macro_attribute]
pub fn register_oidb_service(attr: TokenStream, item: TokenStream) -> TokenStream {
    service::register_oidb_service(attr, item)
}

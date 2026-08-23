mod command;
mod tlv;

use proc_macro::TokenStream;
use syn::Error;

/// 自动写入tlv tag，使用writer可以写入其他数据
#[proc_macro_attribute]
pub fn tlv(attr: TokenStream, item: TokenStream) -> TokenStream {
    tlv::expand_tlv(attr, item)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

#[proc_macro_attribute]
pub fn push_event(attr: TokenStream, item: TokenStream) -> TokenStream {
    command::expand_push_event_impl(attr, item)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

#[proc_macro_attribute]
pub fn command(attr: TokenStream, item: TokenStream) -> TokenStream {
    command::expand_command(attr, item)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

#[proc_macro_attribute]
pub fn oidb_command(attr: TokenStream, item: TokenStream) -> TokenStream {
    command::expand_oidb_command(attr, item)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

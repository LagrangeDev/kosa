use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Error, ItemFn, LitInt};

pub(crate) fn expand_tlv(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream2> {
    let tlv_tag_lit: LitInt = syn::parse(attr)?;
    let tlv_tag = tlv_tag_lit.base10_parse::<u16>().map_err(|_| {
        Error::new_spanned(
            &tlv_tag_lit,
            "`tlv` attribute expects a `u16` integer literal",
        )
    })?;
    let ast: ItemFn = syn::parse(item)?;
    let vis = &ast.vis;
    let sig = &ast.sig;
    let block = &ast.block;

    Ok(quote! {
        #vis #sig {
            self.writer.write_u16(#tlv_tag);
            self.count += 1;
            self.writer.write_with_prefix(crate::utils::binary::Prefix::U16, false, |writer| #block);
            self
        }
    })
}

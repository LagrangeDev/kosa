use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Error, ItemFn, LitInt};

pub(crate) fn expand_tlv(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream2> {
    let tlv_tag = parse_tlv_tag(attr.into())?;
    let ast: ItemFn = syn::parse(item)?;
    Ok(expand_tlv_fn(&ast, tlv_tag))
}

fn parse_tlv_tag(attr: TokenStream2) -> syn::Result<u16> {
    let tlv_tag_lit: LitInt = syn::parse2(attr)?;
    tlv_tag_lit.base10_parse::<u16>().map_err(|_| {
        Error::new_spanned(
            &tlv_tag_lit,
            "`tlv` attribute expects a `u16` integer literal",
        )
    })
}

fn expand_tlv_fn(ast: &ItemFn, tlv_tag: u16) -> TokenStream2 {
    let vis = &ast.vis;
    let sig = &ast.sig;
    let block = &ast.block;

    quote! {
        #vis #sig {
            self.writer.write_u16(#tlv_tag);
            self.count += 1;
            self.writer.write_with_prefix(crate::utils::binary::Prefix::U16, false, |writer| #block);
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use syn::{ItemFn, parse_quote};

    use super::{expand_tlv_fn, parse_tlv_tag};

    #[test]
    fn parses_u16_tag() {
        assert_eq!(parse_tlv_tag(quote::quote!(4660)).unwrap(), 4660);
    }

    #[test]
    fn rejects_non_u16_tag() {
        let err = match parse_tlv_tag(quote::quote!(70000)) {
            Ok(_) => panic!("expected u16 parsing to fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("expects a `u16` integer literal"));
    }

    #[test]
    fn tlv_expansion_wraps_original_body() {
        let input_fn: ItemFn = parse_quote! {
            pub fn build(self, value: u32) -> Self {
                writer.write_u32(value);
            }
        };

        let expanded = expand_tlv_fn(&input_fn, 12).to_string();
        assert!(expanded.contains("pub fn build"));
        assert!(expanded.contains("value : u32"));
        assert!(expanded.contains("-> Self"));
        assert!(expanded.contains("write_u16"));
        assert!(expanded.contains("12"));
        assert!(expanded.contains("count += 1"));
        assert!(expanded.contains("write_with_prefix"));
        assert!(expanded.contains("write_u32"));
        assert!(expanded.contains("value"));
        assert!(expanded.contains("self"));
    }
}

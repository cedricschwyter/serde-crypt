use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(GenSealed, attributes(serde_crypt))]
pub fn serde_crypt(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let vis = ast.vis;
    let name = ast.ident;
    let fields = match &ast.data {
        syn::Data::Struct(ref data_struct) => &data_struct.fields,
        _ => panic!("#[derive(GenSealed)] may only be used on structs"),
    };

    let sealed_type = quote! {
        #vis struct #name {
            #fields
        }
    };
    sealed_type.into()
}

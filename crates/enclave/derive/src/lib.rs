use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemTrait, ReturnType, TraitItem};

/// Derive a sync client from an async rpc trait.
#[proc_macro_attribute]
pub fn derive_sync_client_trait(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemTrait);
    let trait_name = &input.ident;
    let sync_trait_name = syn::Ident::new(&format!("Sync{}Client", trait_name), trait_name.span());

    let methods = input.items.iter().filter_map(|item| {
        if let TraitItem::Fn(m) = item {
            let sig = &m.sig;
            let method_name = &sig.ident;
            let inputs = &sig.inputs;
            match &sig.output {

                    ReturnType::Type(_, ty) =>{
                        if let syn::Type::Path(type_path) = &**ty {
                            if let Some(segment) = type_path.path.segments.last() {
                                if segment.ident == "RpcResult" {
                                    if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                                        if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                                            return Some(quote! {
                                                fn #method_name(#inputs) -> Result<#inner_ty, jsonrpsee::core::client::Error>;
                                            })
                                        }
                                    }
                                }
                            }
                    }
                    panic!("Method {} has an invalid return type. Return type must be RpcResult<T>", method_name);
                }
                _ => {
                    panic!("Method {} has an invalid return type. Return type must be RpcResult<T>", method_name);
                }
            }
        } else {
            None
        }
    });

    let expanded = quote! {
        pub trait #sync_trait_name {
            #(#methods)*
        }

        #input  // Keep the original async trait unchanged
    };

    TokenStream::from(expanded)
}

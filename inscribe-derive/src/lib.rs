use proc_macro2::TokenStream;
use syn::{AttrStyle, Data, DataStruct, DeriveInput, Field, Fields, Meta, MetaNameValue,
    Token};
use syn::punctuated::Punctuated;
use quote::quote;

const INSCRIBE_LENGTH: usize = 64;
const INSCRIBE_IDENT: &'static str = "inscribe";
const INSCRIBE_ADDL_IDENT: &'static str = "inscribe_addl";
const SKIP_IDENT: &'static str = "skip";
const SERIALIZE_IDENT: &'static str = "serialize";
const RECURSE_IDENT: &'static str = "recurse";
const ADDL_IDENT: &'static str = "additional";

// The three derive options for each struct member: inscribe it, serialize it, or skip it.
enum Handling {
    Recurse,
    Serialize,
    Skip
}

// Determines the handling of the current struct member, based on the associated attributes. The
// three possible outcomes are defined in the `Handling` enum:
//  - `Recurse`: Recursively inscribe the member by calling `get_inscription` on it (default)
//  - `Serialize`: Use `bcs` to serialize the member (given by `inscribe(serialize)`)
//  - `Skip`: Don't include the member in the inscription at all (given by `inscribe(skip)`)
fn get_field_handling(field: &Field) -> Handling {
    for attr in &field.clone().attrs {
        // Skip inner attributes
        if let AttrStyle::Inner(_) = attr.style { continue; }

        // Skip any attributes that aren't "inscribe" attributes
        if !attr.path().is_ident(INSCRIBE_IDENT) { continue; }

        // Get the nested attribute data
        let nested = match attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) {
            Ok(parse_result) => {
                parse_result
            },
            Err(_) => { panic!("Failed to parse inscribe field attribute"); }
        };

        // This was originally a for loop, but clippy noted that it never actually loops, so it
        // has been replaced with an if-let construction. This may be something to watch if the
        // metadata API changes.
        if let Some(meta) = nested.iter().next() {
            match meta {
                Meta::Path(path) => {
                    if path.is_ident(SKIP_IDENT) {
                        return Handling::Skip;
                    }
                    else if path.is_ident(SERIALIZE_IDENT) {
                        return Handling::Serialize;
                    }
                    else if path.is_ident(RECURSE_IDENT) {
                        return Handling::Recurse;
                    }
                    panic!("Invalid field attribute");
                },
                _ => { panic!("Invalid metadata for field attribute"); },
            }
        }
    }

    // By default, assume that we will recurse on the `Inscribe` trait.
    Handling::Recurse
}

fn implement_get_inscription(dstruct: &DataStruct) -> TokenStream {
    let members = match dstruct.fields.clone() {
        Fields::Named(a) => a,
        _ => { panic!("Invalid struct type"); }
    };

    // Each field in the struct will be either skipped or included in a `TupleHash` computation
    // that higher-level code will integrate into the Merlin transcript as representative of the
    // value.
    // For each element that gets included, there are two possibilities:
    //      (1) The field's own `get_inscription` method is called, and the result is included in
    //          the `TupleHash` computation (this is the default assumption)
    //      (2) The `bcs` serialization gets included in the `TupleHash`
    let mut center = quote!{};
    for field in members.named.iter() {
        let handling = get_field_handling(field);
        let member_ident = match field.ident.clone() {
            Some(k) => k,
            None => { panic!("Couldn't get field name"); }
        };

        // Based on each handling flag, generate a token string to compute the appropriate
        // update for the `TupleHash` struct
        let elt = match handling {
            Handling::Recurse => quote!{
                let sub_inscription = self.#member_ident.get_inscription()?;
                hasher.update(sub_inscription.as_slice());
            },
            Handling::Serialize => quote!{
                serial_out = match bcs::to_bytes(&self.#member_ident) {
                    Ok(bvec) => bvec,
                    _ => { panic!("Couldn't serialize value"); },
                };
                hasher.update(serial_out.as_slice());
            },
            Handling::Skip => quote!{}, // Add nothing to the process
        };

        // Integrate the hash update string into the overall routine
        center = quote!{
            #center
            #elt
        }
    }

    // Now that we have all the relevant hash update lines in #center, we slap in in the middle
    // of a routine that sets up the various temporary values and performs the final hash
    // computation.
    quote! {
            fn get_inscription(&self) -> Result<Vec<u8>, decree::error::Error> {
                use tiny_keccak::TupleHash;
                use tiny_keccak::Hasher;
                use bcs;
                use serde::Serialize;
                use decree::inscribe::InscribeBuffer;
                use decree::decree::FSInput;

                let mut serial_out: Vec<u8> = Vec::new();
                let mut hasher = TupleHash::v256(self.get_mark().as_bytes());

                // Add the struct members into the TupleHash
                #center

                // Add the final additional data
                let additional = self.get_additional()?;
                hasher.update(additional.as_slice());

                let mut hash_buf: InscribeBuffer = [0u8; #INSCRIBE_LENGTH];
                hasher.finalize(&mut hash_buf);
                Ok(hash_buf.to_vec())
            }
    }
}


fn implement_get_mark(ast: DeriveInput) -> TokenStream {
    // By default, the mark/identifier for a struct will be its name
    let ident = ast.ident;
    let ident_str = ident.to_string();

    let get_mark = quote!{
            fn get_mark(&self) -> &'static str {
                return #ident_str;
            }
        };
    get_mark
}


fn implement_inscribe_trait(ast: DeriveInput, dstruct: &DataStruct) -> TokenStream {
    let get_mark: TokenStream = implement_get_mark(ast.clone());
    let get_inscr: TokenStream = implement_get_inscription(dstruct);
    let get_addl: TokenStream = implement_get_addl(ast.clone());

    let ident = ast.ident;
    let generics = ast.generics;

    quote! {
        impl #generics Inscribe for #ident #generics {

            #get_mark

            #get_inscr

            #get_addl
        }
    }
}

fn implement_get_addl(ast: DeriveInput) -> TokenStream {
    // In the absence of an outer attribute, we use the default implementation
    let mut addl_implementation: TokenStream = quote!{};

    // Check the outer attributes for something like `#[inscribe(additional = addl_function)]`
    for attr in ast.attrs {
        // We only look for "inscribe" attributes
        if !attr.path().is_ident(INSCRIBE_ADDL_IDENT) { continue; }

        let nested = match attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) {
            Ok(parse_result) => {
                parse_result
            },
            Err(_) => { panic!("Failed to parse inscribe_addl field attribute"); }
        };

        if let Some(meta) = nested.iter().next() {
            match meta {
                Meta::Path(path) => { addl_implementation = quote!{
                    fn get_additional(&self) -> Result<Vec<u8>, decree::error::Error> {
                        self.#path()
                    }
                 }},
                _ => { panic!("Invalid metadata for field attribute"); },
            }
        }
    }
    addl_implementation
}

#[proc_macro_derive(Inscribe, attributes(inscribe, inscribe_addl))]
pub fn inscribe_derive(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast: DeriveInput = syn::parse(item.clone()).unwrap();

    // We don't support for derive for anything but structs
    let dstruct = match ast.clone().data {
        Data::Struct(d) => d,
        _ => { panic!("Invalid type for derive(Inscribe)")},
    };

    // We don't support unnamed structs
    if !matches!(dstruct.fields, Fields::Named(_)) {
        panic!("Unnamed structs not supported for derive(Inscribe)");
    }

    implement_inscribe_trait(ast, &dstruct).into()
}
use proc_macro2::TokenStream;
use syn::{AttrStyle, Data, DataStruct, DeriveInput, Field, Fields, Meta, Token};
use syn::punctuated::Punctuated;
use quote::quote;

const INSCRIBE_LENGTH: usize = 64;

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
fn get_handling(field: &Field) -> Handling {
    for attr in &field.clone().attrs {
        /* Skip inner attributes */
        if let AttrStyle::Inner(_) = attr.style { continue; }

        /* Skip any attributes that aren't "inscribe" attributes */
        if !attr.path().is_ident("inscribe") { continue; }
        let nested = match attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) {
            Ok(parse_result) => {
                parse_result
            },
            Err(_) => { panic!("Failed to parse inscribe() attributes"); }
        };

        // This was originally a for loop, but clippy noted that it never actually loops, so it
        // has been replaced with an if-let construction. This may be something to watch if the
        // metadata API changes.
        if let Some(meta) = nested.iter().next() {
            match meta {
                Meta::Path(path) => {
                    if path.is_ident("skip") {
                        return Handling::Skip;
                    }
                    else if path.is_ident("serialize") {
                        return Handling::Serialize;
                    }
                    else if path.is_ident("recurse") {
                        return Handling::Recurse;
                    }
                    panic!("Invalid inscribe() attribute");
                },
                _ => { panic!("Invalid metadata for inscribe attribute"); },
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
        let handling = get_handling(field);
        let member_ident = match field.ident.clone() {
            Some(k) => k,
            None => { panic!("Couldn't get field name"); }
        };

        // Based on each handling flag, generate a token string to compute the appropriate
        // update for the `TupleHash` struct
        let elt = match handling {
            Handling::Recurse => quote!{
                self.#member_ident.get_inscription(&mut hash_buf);
                hasher.update(&hash_buf);
            },
            Handling::Serialize => quote!{
                serial_out = match bcs::to_bytes(&self.#member_ident) {
                    Ok(bvec) => bvec,
                    _ => { panic!("Couldn't serialize value"); },
                };
                hasher.update(serial_out.as_slice());
            },
            Handling::Skip => quote!{}, // Nothing to do here!
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
            fn get_inscription(&self, buf: &mut InscribeBuffer) {
                use tiny_keccak::TupleHash;
                use tiny_keccak::Hasher;
                use bcs;
                use serde::Serialize;
                use decree::inscribe::InscribeBuffer;

                let mut hash_buf: InscribeBuffer = [0u8; #INSCRIBE_LENGTH];
                let mut serial_out: Vec<u8> = Vec::new();
                let mut hasher = TupleHash::v256(self.get_mark().as_bytes());

                #center

                hasher.finalize(buf);
            }
    }
}

fn implement_get_mark(ast: DeriveInput) -> TokenStream {
    /* By default, the mark/identifier for a struct will be its name */
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

    let ident = ast.ident;
    let generics = ast.generics;

    quote! {
        impl #generics Inscribe for #ident #generics {

            #get_mark

            #get_inscr
        }
    }
}

#[proc_macro_derive(Inscribe, attributes(inscribe))]
pub fn inscribe_derive(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast: DeriveInput = syn::parse(item.clone()).unwrap();

    /* We don't support for derive for anything but structs */
    let dstruct = match ast.clone().data {
        Data::Struct(d) => d,
        _ => { panic!("Invalid type for derive(Inscribe)")},
    };

    /* We don't support unnamed structs */
    if !matches!(dstruct.fields, Fields::Named(_)) {
        panic!("Unsupported data type for derive(Inscribe)");
    }

    implement_inscribe_trait(ast, &dstruct).into()
}

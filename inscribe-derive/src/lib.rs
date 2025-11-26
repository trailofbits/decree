#![deny(warnings)]
#![deny(clippy::pedantic)]

use proc_macro2::TokenStream;
use syn::{Attribute, AttrStyle, Data, DataStruct, DeriveInput, Field, Fields, Ident, Meta, Token};
use syn::punctuated::Punctuated;
use quote::quote;
use std::collections::HashMap;

const INSCRIBE_LENGTH: usize = 64;
const INSCRIBE_HANDLING_IDENT: &str = "inscribe";
const INSCRIBE_ADDL_IDENT: &str = "inscribe_addl";
const INSCRIBE_MARK_IDENT: &str = "inscribe_mark";
const INSCRIBE_NAME_IDENT: &str = "inscribe_name";
const SKIP_IDENT: &str = "skip";
const SERIALIZE_IDENT: &str = "serialize";
const RECURSE_IDENT: &str = "recurse";

// The three derive options for each struct member: inscribe it, serialize it, or skip it.
enum Handling {
    Recurse,
    Serialize,
    Skip
}

struct MemberInfo {
    handling:   Handling,
    name_ident: Ident,
    sort_ident: Ident,
}

fn parse_contained_ident(attr: &Attribute) -> Option<Ident> {
    // Get the nested attribute data
    let Ok(nested) = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) else { return None; };

    // This was originally a for loop, but clippy noted that it never actually loops, so it
    // has been replaced with an if-let construction. This may be something to watch if the
    // metadata API changes.
    if let Some(Meta::Path(path)) = nested.iter().next() {
        return Some(path.get_ident().unwrap().clone());
    }

    None
}

fn get_member_info(field: &Field) -> MemberInfo {
    // By default: handling is recursive, and the name is the field name
    let mut member_handling = Handling::Recurse;
    let mut found_handling: bool = false;
    let mut found_name: bool = false;
    let Some(mut sort_name) = field.ident.clone() else { panic!("Couldn't get field name"); };

    // Run over all the attributes
    for attr in field.clone().attrs {
        // Skip inner attributes
        if let AttrStyle::Inner(_) = attr.style { continue; }

        // Don't process attributes we don't care about
        if  !attr.path().is_ident(INSCRIBE_HANDLING_IDENT) &&
            !attr.path().is_ident(INSCRIBE_NAME_IDENT) {
                continue;
        }

        // Parse out whatever is inside the attribute
        let Some(inside) = parse_contained_ident(&attr) else { panic!("Failed to parse member attribute for Inscribe trait"); };

        // Get handling specifications
        if attr.path().is_ident(INSCRIBE_HANDLING_IDENT) {
            // Don't process the same handling twice
            assert!(!found_handling, "Inscribe handling attribute defined more than once");

            if inside == SKIP_IDENT {
                member_handling = Handling::Skip;
            } else if inside == SERIALIZE_IDENT {
                member_handling = Handling::Serialize;
            } else if inside == RECURSE_IDENT {
                member_handling = Handling::Recurse;
            } else {
                panic!("Invalid handling specification");
            }
            found_handling = true;
        }

        // Get sorting name
        if attr.path().is_ident(INSCRIBE_NAME_IDENT) {
            // Don't process the name twice
            assert!(!found_name, "Inscribe name attribute defined more than once");
            sort_name = inside.clone();
            found_name = true;
        }
    }

    MemberInfo {
        name_ident: field.ident.clone().unwrap(),
        sort_ident: sort_name,
        handling: member_handling
    }
}

fn implement_get_inscription(dstruct: &DataStruct) -> TokenStream {
    let Fields::Named(members) = dstruct.fields.clone() else { panic!("Invalid struct type"); };

    // Build hash table to match each of the struct member names to an associated MemberInfo
    // struct
    let mut member_table: HashMap<String, MemberInfo> = HashMap::new();
    let mut member_vec: Vec<String> = Vec::new();


    for field in &members.named {
        let member_info = get_member_info(field);
        let sort_name_str = member_info.sort_ident.to_string();

        member_table.insert(sort_name_str.clone(), member_info);
        member_vec.push(sort_name_str);
    }

    // Now run through the elements in sorted order
    let mut center = quote!{};
    member_vec.sort();

    for sort_name in &member_vec {
        let current_member = member_table.get(sort_name).unwrap(); // Guaranteed to work
        let member_ident = current_member.name_ident.clone();

        let elt = match current_member.handling {
            Handling::Recurse => quote!{
                let sub_inscription = self.#member_ident.get_inscription()?;
                hasher.update(sub_inscription.as_slice());
            },
            Handling::Serialize => quote!{
                serial_out = match bcs::to_bytes(&self.#member_ident) {
                    Ok(bvec) => bvec,
                    _ => { return Err(decree::error::Error::new_general("Could not serialize Value")); },
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

fn implement_default_mark(ast: &DeriveInput) -> TokenStream {
    // By default, the mark/identifier for a struct will be its name
    let ident = &ast.ident;
    let ident_str = ident.to_string();

    let get_mark = quote!{
            fn get_mark(&self) -> &'static str {
                return #ident_str;
            }
        };
    get_mark
}

fn implement_get_addl(ast: &DeriveInput) -> TokenStream {
    // In the absence of an outer attribute, we use the default implementation
    let mut addl_implementation: TokenStream = quote!{};

    // Check the outer attributes for something like `#[inscribe_addl(addl_function)]`
    for attr in &ast.attrs {
        // We only look for "inscribe" attributes
        if !attr.path().is_ident(INSCRIBE_ADDL_IDENT) { continue; }

        let Ok(nested) = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) else { panic!("Failed to parse inscribe_addl field attribute"); };

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

        break;
    }
    addl_implementation
}

fn implement_get_mark(ast: &DeriveInput) -> TokenStream {
    let mut found_mark: bool = false;
    let mut mark_implementation: TokenStream = quote!{};

    // Check the outer attributes for something like `#[inscribe_mark(mark_function)]`
    for attr in &ast.attrs {
        // We only look for "inscribe" attributes
        if !attr.path().is_ident(INSCRIBE_MARK_IDENT) { continue; }

        let Ok(nested) = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) else { panic!("Failed to parse inscribe_mark field attribute"); };

        if let Some(meta) = nested.iter().next() {
            match meta {
                Meta::Path(path) => { mark_implementation = quote!{
                    fn get_mark(&self) -> &'static str {
                        self.#path()
                    }
                 }},
                _ => { panic!("Invalid metadata for field attribute"); },
            }
        }
        found_mark = true;
        break;
    }
    if found_mark {
        mark_implementation
    } else {
        implement_default_mark(ast)
    }
}

fn implement_inscribe_trait(ast: DeriveInput, dstruct: &DataStruct) -> TokenStream {
    let get_mark: TokenStream = implement_get_mark(&ast);
    let get_inscr: TokenStream = implement_get_inscription(dstruct);
    let get_addl: TokenStream = implement_get_addl(&ast);

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


#[proc_macro_derive(Inscribe, attributes(inscribe, inscribe_addl, inscribe_mark, inscribe_name))]
#[allow(clippy::missing_panics_doc)]
pub fn inscribe_derive(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast: DeriveInput = syn::parse(item.clone()).unwrap();

    // We don't support for derive for anything but structs
    let Data::Struct(dstruct) = ast.clone().data else { panic!("Invalid type for derive(Inscribe)")};

    // We don't support unnamed structs
    assert!(matches!(dstruct.fields, Fields::Named(_)), "Unnamed structs not supported for derive(Inscribe)");

    implement_inscribe_trait(ast, &dstruct).into()
}
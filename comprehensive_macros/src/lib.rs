extern crate proc_macro;
use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, quote_spanned};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, Data, DeriveInput, Fields, GenericArgument, Generics, Ident, PathArguments,
    Type,
};

fn find_type_inside_arc(ty: &Type) -> Result<&Type, Span> {
    let Type::Path(ref path) = ty else {
        return Err(ty.span());
    };
    let a = &path
        .path
        .segments
        .last()
        .ok_or_else(|| path.span())?
        .arguments;
    let PathArguments::AngleBracketed(ref generics) = a else {
        return Err(a.span());
    };
    if generics.args.len() != 1 {
        return Err(generics.span());
    };
    let generic = generics.args.first().unwrap();
    let GenericArgument::Type(ref ty) = generic else {
        return Err(generic.span());
    };
    Ok(ty)
}

fn derive_r_d_struct(name: &Ident, generics: &Generics, fields: &Fields) -> TokenStream {
    const NO_FIELDS: &Punctuated<syn::Field, syn::token::Comma> = &Punctuated::new();
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let dep_types = match fields {
        Fields::Named(ref f) => &f.named,
        Fields::Unnamed(ref f) => &f.unnamed,
        Fields::Unit => NO_FIELDS,
    }
    .iter()
    .map(|f| match find_type_inside_arc(&f.ty) {
        Ok(ty) => Ok(ty),
        Err(span) => Err(quote_spanned! {
            span => compile_error!("ResourceDependencies type must be Arc<T>");
        }),
    })
    .collect::<Vec<_>>();

    let registrations = dep_types.iter().map(|r| match r {
        Ok(ty) => quote! {
            ::comprehensive::assembly::Registrar::< #ty >::register(cx);
        },
        Err(ts) => ts.clone(),
    });
    let productions = dep_types.iter().enumerate().map(|(i, r)| match r {
        Ok(ty) => {
            let temp = format_ident!("dep_{}", i);
            quote! {
                let #temp = ::comprehensive::assembly::Registrar::< #ty >::produce(cx)?;
            }
        }
        Err(ts) => ts.clone(),
    });
    let definition = match fields {
        Fields::Named(ref f) => {
            let elements = f.named.iter().enumerate().map(|(i, field)| {
                let name = field.ident.as_ref().unwrap();
                let temp = format_ident!("dep_{}", i);
                quote! { #name: #temp, }
            });
            quote! {
                ::std::result::Result::Ok(Self { #( #elements )* })
            }
        }
        Fields::Unnamed(ref f) => {
            let elements = f.unnamed.iter().enumerate().map(|(i, _)| {
                let temp = format_ident!("dep_{}", i);
                quote! { #temp, }
            });
            quote! {
                ::std::result::Result::Ok(Self ( #( #elements )* ))
            }
        }
        Fields::Unit => quote! { ::std::result::Result::Ok(Self) },
    };

    quote! {
        #[automatically_derived]
        impl #impl_generics ::comprehensive::ResourceDependencies for #name #ty_generics #where_clause {
            fn register(cx: &mut ::comprehensive::assembly::RegisterContext) {
                #( #registrations )*
            }

            fn produce(cx: &mut ::comprehensive::assembly::ProduceContext) -> ::std::result::Result<Self, ::std::boxed::Box<dyn ::std::error::Error>> {
                #( #productions )*
                #definition
            }
        }
    }
}

#[proc_macro_derive(ResourceDependencies)]
pub fn derive_resource_dependencies(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input: DeriveInput = parse_macro_input!(item);
    match input.data {
        Data::Struct(ref s) => derive_r_d_struct(&input.ident, &input.generics, &s.fields),
        _ => quote_spanned! {
            input.span() => compile_error!("`#[derive(ResourceDependencies)]` requires a struct");
        },
    }
    .into()
}
//! Macros in support of [`comprehensive`]. It is not necessary to depend on this crate directly.
//!
//! [`comprehensive`]: https://docs.rs/comprehensive/latest/comprehensive/

extern crate proc_macro;
use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, quote_spanned};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, Attribute, Data, DeriveInput, Fields, GenericArgument, Generics, Ident,
    LitStr, PathArguments, Type,
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

fn derive_grpc_service_internal(
    name: &Ident,
    generics: &Generics,
    attrs: &[Attribute],
) -> Result<TokenStream, syn::Error> {
    let mut implementation: Option<syn::Type> = None;
    let mut service: Option<syn::Type> = None;
    let mut descriptor: Option<syn::Expr> = None;
    for attr in attrs {
        if attr.path().is_ident("implementation") {
            implementation = Some(attr.parse_args()?);
        } else if attr.path().is_ident("service") {
            service = Some(attr.parse_args()?);
        } else if attr.path().is_ident("descriptor") {
            descriptor = Some(attr.parse_args()?);
        }
    }
    let Some(implementation) = implementation else {
        return Ok(quote! {
            compile_error!("`[#implementation(T)]` is required");
        });
    };
    let Some(service) = service else {
        return Ok(quote! {
            compile_error!("`[#service(T)]` is required");
        });
    };
    let descriptor_registration = match descriptor {
        Some(d) => quote! {
            d.server.register_encoded_file_descriptor_set( #d );
        },
        None => quote! {},
    };

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::comprehensive::Resource for #name #ty_generics #where_clause {
            type Args = ::comprehensive::NoArgs;
            type Dependencies = ::comprehensive_grpc::GrpcServiceDependencies< #implementation >;
            const NAME: &str = ::comprehensive_grpc::const_format::concatcp!(
                < #service ::< #implementation > as ::tonic::server::NamedService>::NAME,
                " gRPC service"
            );

            fn new(
                d: ::comprehensive_grpc::GrpcServiceDependencies< #implementation >,
                _: ::comprehensive::NoArgs,
            ) -> ::std::result::Result<Self, std::boxed::Box<dyn ::std::error::Error>> {
                #descriptor_registration
                d.server.add_service( #service ::from_arc(d.implementation))?;
                Ok(Self)
            }
        }

        #[automatically_derived]
        impl #impl_generics ::comprehensive_grpc::GrpcService for #name #ty_generics #where_clause {}
    })
}

#[proc_macro_derive(GrpcService, attributes(implementation, service, descriptor))]
pub fn derive_grpc_service(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input: DeriveInput = parse_macro_input!(item);
    derive_grpc_service_internal(&input.ident, &input.generics, &input.attrs)
        .unwrap_or_else(|e| {
            let e = e.to_compile_error();
            quote! { #e }
        })
        .into()
}

fn get_str_lit_val(v: &syn::Expr) -> Result<LitStr, Span> {
    let syn::Expr::Lit(exprlit) = v else {
        return Err(v.span());
    };
    let syn::Lit::Str(ref litstr) = exprlit.lit else {
        return Err(exprlit.lit.span());
    };
    Ok(litstr.clone())
}

fn is_router(f: &syn::Field) -> bool {
    f.attrs.iter().any(|a| a.path().is_ident("router"))
}

fn derive_h_s_i(
    name: &Ident,
    data: &Data,
    generics: &Generics,
    attrs: &[Attribute],
) -> Result<TokenStream, syn::Error> {
    let mut flag_prefix: Option<LitStr> = None;
    for attr in attrs {
        if attr.path().is_ident("flag_prefix") {
            flag_prefix = match get_str_lit_val(&attr.meta.require_name_value()?.value) {
                Ok(prefix) => Some(prefix),
                Err(span) => {
                    return Ok(quote_spanned! {
                        span => compile_error!("flag_prefix argument must be str literal");
                    });
                }
            };
        }
    }
    let Some(flag_prefix) = flag_prefix else {
        return Ok(quote! {
            compile_error!("`[#flag_prefix = \"foo_\"]` is required");
        });
    };
    let Data::Struct(ref st) = data else {
        return Ok(quote! {
            compile_error!("`#[derive(HttpServingInstance)]` requires a struct");
        });
    };
    let router_members: Vec<syn::Member> = match st.fields {
        Fields::Named(ref f) => f
            .named
            .iter()
            .filter_map(|field| {
                if is_router(field) {
                    Some(syn::Member::Named(field.ident.clone().unwrap()))
                } else {
                    None
                }
            })
            .take(2)
            .collect(),
        Fields::Unnamed(ref f) => f
            .unnamed
            .iter()
            .enumerate()
            .filter_map(|(i, field)| {
                if is_router(field) {
                    Some(syn::Member::Unnamed(syn::Index {
                        index: i as u32,
                        span: field.span(),
                    }))
                } else {
                    None
                }
            })
            .take(2)
            .collect(),
        Fields::Unit => Vec::new(),
    };
    if router_members.len() != 1 {
        return Ok(quote! {
            compile_error!("exactly 1 struct field must be annotated with #[router]");
        });
    }
    let router_member = router_members.get(0).unwrap();

    let http_port_flag_name = format!("{}http-port", flag_prefix.value());
    let http_port_flag_name_lit = LitStr::new(&http_port_flag_name, flag_prefix.span());
    let http_bind_addr_flag_name = format!("{}http-bind-addr", flag_prefix.value());
    let http_bind_addr_flag_name_lit = LitStr::new(&http_bind_addr_flag_name, flag_prefix.span());
    let https_port_flag_name = format!("{}https-port", flag_prefix.value());
    let https_port_flag_name_lit = LitStr::new(&https_port_flag_name, flag_prefix.span());
    let https_bind_addr_flag_name = format!("{}https-bind-addr", flag_prefix.value());
    let https_bind_addr_flag_name_lit = LitStr::new(&https_bind_addr_flag_name, flag_prefix.span());

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::comprehensive::http::HttpServingInstance for #name #ty_generics #where_clause {
            const HTTP_PORT_FLAG_NAME: &str = #http_port_flag_name_lit ;
            const HTTP_BIND_ADDR_FLAG_NAME: &str = #http_bind_addr_flag_name_lit ;
            const HTTPS_PORT_FLAG_NAME: &str = #https_port_flag_name_lit ;
            const HTTPS_BIND_ADDR_FLAG_NAME: &str = #https_bind_addr_flag_name_lit ;

            fn get_router(&self) -> ::axum::Router {
                self. #router_member .clone()
            }
        }
    })
}

#[proc_macro_derive(HttpServingInstance, attributes(flag_prefix, router))]
pub fn derive_http_serving_instance(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input: DeriveInput = parse_macro_input!(item);
    derive_h_s_i(&input.ident, &input.data, &input.generics, &input.attrs)
        .unwrap_or_else(|e| {
            let e = e.to_compile_error();
            quote! { #e }
        })
        .into()
}

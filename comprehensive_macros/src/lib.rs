//! Macros in support of [`comprehensive`]. It is not necessary to depend on this crate directly.
//!
//! [`comprehensive`]: https://docs.rs/comprehensive/latest/comprehensive/

extern crate proc_macro;
use convert_case::{Case, Casing};
use proc_macro2::{Span, TokenStream};
use quote::{ToTokens, format_ident, quote, quote_spanned};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{
    Attribute, Data, DeriveInput, Fields, GenericArgument, Generics, Ident, Lit, LitBool, LitStr,
    Path, PathArguments, Type, Visibility, parse_macro_input,
};

fn find_type_inside_arc(ty: &Type) -> Result<&Type, Span> {
    let Type::Path(path) = ty else {
        return Err(ty.span());
    };
    let a = &path
        .path
        .segments
        .last()
        .ok_or_else(|| path.span())?
        .arguments;
    let PathArguments::AngleBracketed(generics) = a else {
        return Err(a.span());
    };
    if generics.args.len() != 1 {
        return Err(generics.span());
    };
    let generic = generics.args.first().unwrap();
    let GenericArgument::Type(ty) = generic else {
        return Err(generic.span());
    };
    Ok(ty)
}

fn derive_r_d_struct(name: &Ident, generics: &Generics, fields: &Fields) -> TokenStream {
    const NO_FIELDS: &Punctuated<syn::Field, syn::token::Comma> = &Punctuated::new();
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let dep_types = match fields {
        Fields::Named(f) => &f.named,
        Fields::Unnamed(f) => &f.unnamed,
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
        Fields::Named(f) => {
            let elements = f.named.iter().enumerate().map(|(i, field)| {
                let name = field.ident.as_ref().unwrap();
                let temp = format_ident!("dep_{}", i);
                quote! { #name: #temp, }
            });
            quote! {
                ::std::result::Result::Ok(Self { #( #elements )* })
            }
        }
        Fields::Unnamed(f) => {
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
    let Data::Struct(st) = data else {
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

fn path_and_single_generic_type(ty: &Type) -> Result<(&Path, &Type), Span> {
    let Type::Path(path) = ty else {
        return Err(ty.span());
    };
    let Some(last) = path.path.segments.last() else {
        return Err(path.path.segments.span());
    };
    let PathArguments::AngleBracketed(ref generics) = last.arguments else {
        return Err(last.arguments.span());
    };
    if generics.args.len() != 1 {
        return Err(generics.span());
    }
    let GenericArgument::Type(gty) = generics.args.first().unwrap() else {
        return Err(generics.span());
    };
    Ok((&path.path, gty))
}

fn client_type(ty: &Type) -> Result<(bool, &Path), Span> {
    let (path1, inner) = path_and_single_generic_type(ty)?;
    let seg = &path1.segments;
    if seg.len() == 1 {
        let seg1 = &seg.first().unwrap().ident;
        if *seg1 == Ident::new("Option", seg1.span()) {
            let (path2, _) = path_and_single_generic_type(inner)?;
            return Ok((true, path2));
        }
    }
    Ok((false, path1))
}

fn derive_struct(
    vis: &Visibility,
    name: &Ident,
    generics: &Generics,
    fields: &Fields,
    attrs: &[Attribute],
) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let mut fields_it = fields.iter();
    let client_field = fields_it.next().unwrap();
    let cts = client_field.ty.span();

    let mut propagate_health = true;
    for attr in attrs {
        if attr.path().is_ident("no_propagate_health") {
            propagate_health = false;
        }
    }

    let (is_option, client_type) = match client_type(&client_field.ty) {
        Ok(v) => v,
        Err(span) => {
            return quote_spanned! {
                span => compile_error!("First field of struct must be pb::client::Type<_> or Option<pb::client::Type<_>>");
            };
        }
    };

    let mut builder = client_type.clone();
    if let Some(last) = builder.segments.last_mut() {
        last.arguments = PathArguments::None;
    }
    builder
        .segments
        .push(Ident::new("with_origin", builder.segments.last().span()).into());

    let name_str = name.to_string();
    let name_lit = Lit::Str(LitStr::new(&name_str, name.span()));
    let label = Lit::Str(LitStr::new(&name_str.to_case(Case::Snake), name.span()));
    let required = Lit::Bool(LitBool::new(!is_option, client_type.span()));
    let flag_prefix = format!("{}-", name_str.to_case(Case::Kebab));
    let flag_prefix_span = name.span();
    let flag_prefix = Lit::Str(LitStr::new(&flag_prefix, flag_prefix_span));

    let (producer, cloner, client_return_type) = if is_option {
        (
            quote_spanned! { cts => param.map(|(stack, uri)| #builder (stack, uri)) },
            quote! { as_ref().map(|c| c.clone()) },
            quote_spanned! { cts => Option < #client_type > },
        )
    } else {
        (
            // unwrap okay because we made it a required arg in Clap
            quote_spanned! { cts => { let (stack, uri) = param.unwrap(); #builder (stack, uri) } },
            quote! { clone() },
            client_type.to_token_stream(),
        )
    };
    let (builder, get0, get1) = match client_field.ident {
        None => (
            quote_spanned! { fields.span() => Self( #producer , worker ) },
            quote! { self.0 },
            quote! { self.1 },
        ),
        Some(ref client_field_name) => {
            let worker_field_name = fields_it.next().unwrap().ident.as_ref().unwrap();
            (
                quote_spanned! {
                    fields.span() => Self {
                        #client_field_name : #producer ,
                        #worker_field_name : worker,
                    }
                },
                quote! { self. #client_field_name },
                quote! { self. #worker_field_name },
            )
        }
    };

    quote! {
        #[automatically_derived]
        impl #impl_generics ::comprehensive_grpc::client::InstanceDescriptor for #name #ty_generics #where_clause {
            const REQUIRED: bool = #required ;
            ::comprehensive_grpc::declare_client_flag_name_constants!( #flag_prefix );
        }

        #[automatically_derived]
        impl #impl_generics ::comprehensive::Resource for #name #ty_generics #where_clause {
            type Args = ::comprehensive_grpc::client::GrpcClientArgs<Self>;
            type Dependencies = ::comprehensive_grpc::client::GRPCClientDependencies;
            const NAME: &'static str = #name_lit ;

            fn new(d: ::comprehensive_grpc::client::GRPCClientDependencies, a: ::comprehensive_grpc::client::GrpcClientArgs<Self>) -> ::std::result::Result<Self, ::std::boxed::Box<dyn ::std::error::Error>> {
                let (param, worker) = ::comprehensive_grpc::client::new(a, #label , #propagate_health , d)?;
                Ok( #builder )
            }

            async fn run(&self) -> ::std::result::Result<(), ::std::boxed::Box<dyn ::std::error::Error>> {
                #get1 .go().await;
                Ok(())
            }
        }

        #[automatically_derived]
        impl #impl_generics #name #ty_generics #where_clause {
            #vis fn client(&self) -> #client_return_type {
                #get0 . #cloner
            }
        }
    }
}

#[proc_macro_derive(GrpcClient, attributes(no_propagate_health))]
pub fn derive_grpc_client(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input: DeriveInput = parse_macro_input!(item);
    match input.data {
        Data::Struct(ref s) if s.fields.len() == 2 => derive_struct(&input.vis, &input.ident, &input.generics, &s.fields, &input.attrs),
        _ => quote_spanned! {
            input.span() => compile_error!("`#[derive(GrpcClient)]` requires a struct with exactly 2 fields");
        },
    }
    .into()
}

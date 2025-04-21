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

enum DependencyType<'a> {
    Concrete(&'a Type),
    Trait(&'a Type),
}

fn find_dependency_type(ty: &Type) -> Result<DependencyType<'_>, Span> {
    // We are looking for either Arc<T> or Vec<Arc<dyn Tr>>.
    let Type::Path(path) = ty else {
        return Err(ty.span());
    };
    // a = <T> or <Arc<dyn Tr>>
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
    // ty = T or Arc<dyn Tr>
    let Type::Path(path) = ty else {
        return Ok(DependencyType::Concrete(ty));
    };
    Ok(path
        .path
        .segments
        .last()
        .and_then(|last| match last.arguments {
            PathArguments::AngleBracketed(ref generics) => {
                if generics.args.len() == 1 {
                    match generics.args.first().unwrap() {
                        GenericArgument::Type(ty) => match ty {
                            Type::TraitObject(_) => Some(ty),
                            _ => None,
                        },
                        _ => None,
                    }
                } else {
                    None
                }
            }
            _ => None,
        })
        .map_or(DependencyType::Concrete(ty), DependencyType::Trait))
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
    .map(|f| match find_dependency_type(&f.ty) {
        Ok(dty) => Ok(dty),
        Err(span) => Err(quote_spanned! {
            span => compile_error!("ResourceDependencies type must be Arc<T>");
        }),
    })
    .collect::<Vec<_>>();

    let registrations = dep_types.iter().map(|r| match r {
        Ok(DependencyType::Concrete(ty)) => quote! {
            ::comprehensive::assembly::Registrar::< #ty >::register(cx);
        },
        Ok(DependencyType::Trait(ty)) => quote! {
            cx.require_trait::< #ty >();
        },
        Err(ts) => ts.clone(),
    });
    let productions = dep_types.iter().enumerate().map(|(i, r)| match r {
        Ok(DependencyType::Concrete(ty)) => {
            let temp = format_ident!("dep_{}", i);
            quote! {
                let #temp = ::comprehensive::assembly::Registrar::< #ty >::produce(cx)?;
            }
        }
        Ok(DependencyType::Trait(ty)) => {
            let temp = format_ident!("dep_{}", i);
            quote! {
                let #temp = cx.produce_trait::< #ty >();
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

fn type_unless_self_colon_colon(ty: &Type) -> Option<Type> {
    let Type::Path(typ) = ty else {
        return Some(ty.clone());
    };
    if typ
        .path
        .segments
        .first()
        .map(|s| s.ident == "Self")
        .unwrap_or(false)
    {
        // The function signature is referencing the associated
        // type so we cannot infer the associated type from the
        // function signature.
        None
    } else {
        Some(Type::Path(typ.clone()))
    }
}

fn get_fnarg_type(arg: &syn::FnArg) -> Result<Option<Type>, TokenStream> {
    match arg {
        syn::FnArg::Typed(pat) => Ok(type_unless_self_colon_colon(&pat.ty)),
        _ => Err(quote_spanned! {
            arg.span() => compile_error!("expected a typed argument");
        }),
    }
}

fn bad_return_type(ty: &Type) -> TokenStream {
    quote_spanned! {
        ty.span() => compile_error!("expected return type Result<_, _>");
    }
}

fn parse_v1resource_error_return_type(ty: &Type) -> Result<Option<Type>, TokenStream> {
    let Type::Path(typ) = ty else {
        return Err(bad_return_type(ty));
    };
    let Some(result) = typ.path.segments.last() else {
        return Err(bad_return_type(ty));
    };
    let syn::PathArguments::AngleBracketed(ref args) = result.arguments else {
        return Err(bad_return_type(ty));
    };
    if args.args.len() != 2 {
        return Err(bad_return_type(ty));
    }
    let syn::GenericArgument::Type(ref err_ty) = args.args[1] else {
        return Err(bad_return_type(ty));
    };
    Ok(type_unless_self_colon_colon(err_ty))
}

enum OursNotOurs<A, B> {
    Ours(A),
    NotOurs(B),
}

impl<A, B> OursNotOurs<A, B> {
    fn ours(&self) -> bool {
        matches!(self, Self::Ours(_))
    }
}

#[proc_macro_attribute]
pub fn v1resource(
    _attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let mut block: syn::ItemImpl = parse_macro_input!(item);
    let mut errors = Vec::new();

    let mut dependencies = None;
    let mut args = None;
    let mut creation_error = None;

    let mut name_already_specified = false;
    let mut dependencies_already_specified = false;
    let mut args_already_specified = false;
    let mut creation_error_already_specified = false;

    for item in &block.items {
        match item {
            syn::ImplItem::Fn(f) => {
                if f.sig.ident == "new" {
                    if f.sig.inputs.len() == 3 {
                        match get_fnarg_type(&f.sig.inputs[0]) {
                            Ok(Some(ty)) => {
                                dependencies = Some(ty);
                            }
                            Ok(None) => (),
                            Err(e) => {
                                errors.push(e);
                            }
                        }
                        match get_fnarg_type(&f.sig.inputs[1]) {
                            Ok(Some(ty)) => {
                                args = Some(ty);
                            }
                            Ok(None) => (),
                            Err(e) => {
                                errors.push(e);
                            }
                        }
                    } else {
                        errors.push(quote_spanned! {
                            f.sig.inputs.span() => compile_error!("expected Resource::new to take exactly 3 arguments");
                        });
                    }
                    match f.sig.output {
                        syn::ReturnType::Type(_, ref ty) => {
                            // Result<Arc<Self>, Self::CreationError>
                            match parse_v1resource_error_return_type(ty) {
                                Ok(maybe_error) => {
                                    creation_error = maybe_error;
                                }
                                Err(e) => {
                                    errors.push(e);
                                }
                            }
                        }
                        _ => {
                            errors.push(quote_spanned! {
                                f.sig.output.span() => compile_error!("expected a return type");
                            });
                        }
                    }
                }
            }
            syn::ImplItem::Const(ico) => {
                if ico.ident == "NAME" {
                    name_already_specified = true;
                }
            }
            syn::ImplItem::Type(ity) => {
                if ity.ident == "Dependencies" {
                    dependencies_already_specified = true;
                }
                if ity.ident == "Args" {
                    args_already_specified = true;
                }
                if ity.ident == "CreationError" {
                    creation_error_already_specified = true;
                }
            }
            _ => (),
        }
    }
    if !name_already_specified {
        let name = LitStr::new(
            &block.self_ty.to_token_stream().to_string(),
            block.self_ty.span(),
        );
        block.items.push(syn::ImplItem::Verbatim(quote! {
            const NAME: &str = #name ;
        }));
    }
    if !dependencies_already_specified {
        if let Some(d) = dependencies {
            block.items.push(syn::ImplItem::Verbatim(quote_spanned! {
                d.span() => type Dependencies = #d ;
            }));
        }
    }
    if !args_already_specified {
        if let Some(a) = args {
            block.items.push(syn::ImplItem::Verbatim(quote_spanned! {
                a.span() => type Args = #a ;
            }));
        }
    }
    if !creation_error_already_specified {
        if let Some(e) = creation_error {
            block.items.push(syn::ImplItem::Verbatim(quote_spanned! {
                e.span() => type CreationError = #e ;
            }));
        }
    }
    let (ours, not_ours): (Vec<_>, Vec<_>) = block
        .attrs
        .into_iter()
        .map(|a| {
            if matches!(a.style, syn::AttrStyle::Outer) {
                match a.meta {
                    syn::Meta::List(l) if l.path.is_ident("export") => OursNotOurs::Ours(l),
                    _ => OursNotOurs::NotOurs(a),
                }
            } else {
                OursNotOurs::NotOurs(a)
            }
        })
        .partition(|ono| ono.ours());
    block.attrs = not_ours
        .into_iter()
        .filter_map(|ono| match ono {
            OursNotOurs::Ours(_) => None,
            OursNotOurs::NotOurs(v) => Some(v),
        })
        .collect();
    let mut exports = ours.into_iter().filter_map(|ono| match ono {
        OursNotOurs::Ours(l) => Some(match l.parse_args::<syn::Type>() {
            Ok(ty) => quote_spanned! {
                ty.span() => installer.offer(|s| ::std::sync::Arc::clone(s) as ::std::sync::Arc< #ty >);
            },
            Err(e) => e.to_compile_error(),
        }),
        OursNotOurs::NotOurs(_) => None,
    }).peekable();
    if exports.peek().is_some() {
        block.items.push(syn::ImplItem::Verbatim(quote! {
            fn provide_as_trait<'provide_as_trait>(installer: &'provide_as_trait mut ::comprehensive::v1::TraitInstaller<'_, 'provide_as_trait, '_, Self>) {
                #( #exports )*
            }
        }));
    }
    for e in errors {
        block.items.push(syn::ImplItem::Verbatim(e));
    }
    block.into_token_stream().into()
}

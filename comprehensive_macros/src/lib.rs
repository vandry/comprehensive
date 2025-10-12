//! Macros in support of [`comprehensive`]. It is not necessary to depend on this crate directly.
//!
//! [`comprehensive`]: https://docs.rs/comprehensive/latest/comprehensive/

// Would impose a requirement for rustc 1.88
// https://github.com/rust-lang/rust/pull/132833
#![allow(clippy::collapsible_if)]

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
    Concrete(&'a Type, bool),
    Trait(&'a Type, bool),
    Weak(&'a Type),
    NewStyle(&'a Type),
}

enum DependencyLabel {
    Arc,
    Option,
    Vec,
    PhantomData,
}

impl DependencyLabel {
    fn expect_arc_inside(&self) -> bool {
        match *self {
            Self::Arc => false,
            Self::Option => true,
            Self::PhantomData => false,
            Self::Vec => true,
        }
    }

    fn into_dependency_type<'a>(
        self,
        ty: &'a Type,
        may_fail: bool,
    ) -> Result<DependencyType<'a>, Span> {
        let (expect_trait, result) = match self {
            Self::Arc => (false, DependencyType::Concrete(ty, false)),
            Self::Option => (false, DependencyType::Concrete(ty, true)),
            Self::Vec => (true, DependencyType::Trait(ty, may_fail)),
            Self::PhantomData => (false, DependencyType::Weak(ty)),
        };
        if expect_trait == matches!(ty, Type::TraitObject(_)) {
            Ok(result)
        } else {
            Err(ty.span())
        }
    }
}

fn find_path_with_1_generic_type(ty: &Type) -> Result<(DependencyLabel, &Type), Span> {
    let Type::Path(path) = ty else {
        return Err(ty.span());
    };
    let last_segment = path.path.segments.last().ok_or_else(|| path.span())?;
    let dep_type = if last_segment.ident == "Arc" {
        DependencyLabel::Arc
    } else if last_segment.ident == "Vec" {
        DependencyLabel::Vec
    } else if last_segment.ident == "Option" {
        DependencyLabel::Option
    } else if last_segment.ident == "PhantomData" {
        DependencyLabel::PhantomData
    } else {
        return Err(path.span());
    };
    // a = <T> or <Arc<dyn Tr>> or <Arc<T>>
    let PathArguments::AngleBracketed(ref generics) = last_segment.arguments else {
        return Err(last_segment.arguments.span());
    };
    if generics.args.len() != 1 {
        return Err(generics.span());
    };
    let generic = generics.args.first().unwrap();
    let GenericArgument::Type(ty) = generic else {
        return Err(generic.span());
    };
    Ok((dep_type, ty))
}

fn find_dependency_type<'a>(
    orig_ty: &'a Type,
    attrs: &[Attribute],
) -> Result<DependencyType<'a>, Span> {
    let may_fail = attrs.iter().any(|a| a.path().is_ident("may_fail"));
    let old_style = attrs.iter().any(|a| a.path().is_ident("old_style"));
    if !old_style && !may_fail {
        return Ok(DependencyType::NewStyle(orig_ty));
    }
    // We accept:
    // Arc<T>
    // Option<Arc<T>>
    // Vec<Arc<dyn Tr>>
    // PhantomData<T>
    let (dep_type, mut ty) = find_path_with_1_generic_type(orig_ty)?;
    if dep_type.expect_arc_inside() {
        let (inner_dep_type, inner_ty) = find_path_with_1_generic_type(ty)?;
        if !matches!(inner_dep_type, DependencyLabel::Arc) {
            return Err(orig_ty.span());
        }
        ty = inner_ty;
    }
    dep_type.into_dependency_type(ty, may_fail)
}

fn produce_concrete(
    dep_types: &Vec<Result<DependencyType<'_>, TokenStream>>,
    for_optional: bool,
) -> impl Iterator<Item = TokenStream> {
    dep_types
        .iter()
        .enumerate()
        .filter_map(move |(i, r)| match r {
            Ok(DependencyType::Concrete(ty, optional)) if *optional == for_optional => {
                let temp = format_ident!("dep_{}", i);
                Some(quote! {
                    let #temp = ::comprehensive::assembly::Registrar::< #ty >::produce(cx);
                })
            }
            Ok(DependencyType::Trait(ty, optional)) if *optional == for_optional => {
                let temp = format_ident!("dep_{}", i);
                Some(if for_optional {
                    quote! { let #temp = cx.produce_trait::< #ty >(); }
                } else {
                    quote! { let #temp = cx.produce_trait_fallible::< #ty >(); }
                })
            }
            Ok(DependencyType::NewStyle(ty)) => {
                let temp = format_ident!("dep_{}", i);
                Some(if for_optional {
                    quote! { let #temp = < #ty as ::comprehensive::dependencies::ResourceDependency >::produce_late(cx, #temp ); }
                } else {
                    quote! { let #temp = < #ty as ::comprehensive::dependencies::ResourceDependency >::produce_early(cx); }
                })
            }
            _ => None,
        })
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
    .map(|f| match find_dependency_type(&f.ty, &f.attrs) {
        Ok(dty) => Ok(dty),
        Err(span) => Err(quote_spanned! {
            span => compile_error!("each field of a ResourceDependencies struct must have a type matching one of: Arc<T>, Option<Arc<T>>, Vec<Arc<dyn Tr>>, PhantomData<T>");
        }),
    })
    .collect::<Vec<_>>();

    let registrations = dep_types.iter().map(|r| match r {
        Ok(DependencyType::Concrete(ty, _)) => quote! {
            ::comprehensive::assembly::Registrar::< #ty >::register(cx);
        },
        Ok(DependencyType::Trait(ty, _)) => quote! {
            cx.require_trait::< #ty >();
        },
        Ok(DependencyType::Weak(ty)) => quote! {
            ::comprehensive::assembly::Registrar::< #ty >::register_without_dependency(cx);
        },
        Ok(DependencyType::NewStyle(ty)) => quote! {
            < #ty as ::comprehensive::dependencies::ResourceDependency >::register(cx);
        },
        Err(ts) => ts.clone(),
    });
    // Produce all of the required dependencies, collecting the errors.
    let productions1 = produce_concrete(&dep_types, false);
    // Return if any failed.
    let productions2 = dep_types.iter().enumerate().filter_map(|(i, r)| match r {
        Ok(DependencyType::Concrete(_, false)) => {
            let temp = format_ident!("dep_{}", i);
            Some(quote! { let #temp = #temp ?; })
        }
        Ok(DependencyType::Trait(_, false)) => {
            let temp = format_ident!("dep_{}", i);
            Some(quote! { let #temp = #temp ?; })
        }
        Ok(DependencyType::NewStyle(_)) => {
            let temp = format_ident!("dep_{}", i);
            Some(quote! { let #temp = #temp ?; })
        }
        _ => None,
    });
    // Produce all of the optional dependencies.
    let productions3 = produce_concrete(&dep_types, true);
    let definition = match fields {
        Fields::Named(f) => {
            let elements =
                f.named
                    .iter()
                    .zip(dep_types.iter())
                    .enumerate()
                    .map(|(i, (field, dt))| {
                        let name = field.ident.as_ref().unwrap();
                        match dt {
                            Ok(DependencyType::Concrete(_, false)) => {
                                let temp = format_ident!("dep_{}", i);
                                quote! { #name: #temp , }
                            }
                            Ok(DependencyType::Concrete(_, true)) => {
                                let temp = format_ident!("dep_{}", i);
                                quote! { #name: #temp .ok(), }
                            }
                            Ok(DependencyType::Trait(_, _)) => {
                                let temp = format_ident!("dep_{}", i);
                                quote! { #name: #temp , }
                            }
                            Ok(DependencyType::Weak(_)) => {
                                quote! { #name: ::std::marker::PhantomData, }
                            }
                            Ok(DependencyType::NewStyle(_)) => {
                                let temp = format_ident!("dep_{}", i);
                                quote! { #name: #temp ?, }
                            }
                            Err(ts) => ts.clone(),
                        }
                    });
            quote! {
                ::std::result::Result::Ok(Self { #( #elements )* })
            }
        }
        Fields::Unnamed(_) => {
            let elements = dep_types.iter().enumerate().map(|(i, dt)| match dt {
                Ok(DependencyType::Concrete(_, false)) => {
                    let temp = format_ident!("dep_{}", i);
                    quote! { #temp , }
                }
                Ok(DependencyType::Concrete(_, true)) => {
                    let temp = format_ident!("dep_{}", i);
                    quote! { #temp .ok(), }
                }
                Ok(DependencyType::Trait(_, _)) => {
                    let temp = format_ident!("dep_{}", i);
                    quote! { #temp , }
                }
                Ok(DependencyType::Weak(_)) => {
                    quote! { ::std::marker::PhantomData, }
                }
                Ok(DependencyType::NewStyle(_)) => {
                    let temp = format_ident!("dep_{}", i);
                    quote! { #temp ?, }
                }
                Err(ts) => ts.clone(),
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
                #( #productions1 )*
                #( #productions2 )*
                #( #productions3 )*
                #definition
            }
        }
    }
}

/// This macro should be used to derive the
/// [`ResourceDependencies`](https://docs.rs/comprehensive/latest/comprehensive/assembly/trait.ResourceDependencies.html)
/// trait for expressing dependencies between resources.
///
/// It takes a struct as input. The types of the fields of the struct should all
/// match one of:
///
/// - [`Arc<T>`](std::sync::Arc) where T is a Resource. That resource will be a
///   required dependency.
/// - [`Option<Arc<T>>`](std::option::Option) where T is a Resource. That resource
///   will be an optional dependency with the value being set no [`None`] if
///   the dependency fails initialisation.
/// - [`Vec<Arc<dyn T>>`](Vec) where T is a trait that might be implemented by
///   some resources. All of the resources that exist in the graph and
///   implement that trait and declare that they do so in their
///   [`Resource`](https://docs.rs/comprehensive/latest/comprehensive/v1/trait.Resource.html)
///   definition (using
///   [`v1::resource`](https://docs.rs/comprehensive/latest/comprehensive/v1/attr.resource.html))
///   will be collected here.
///
///   By default, if some resources matching the requested trait exist but
///   fail initialisation, this will be considered an error: this set of
///   dependencies will fail to construct and the error will be bubbled up.
///   This mode is suitable for resources that wish to collect all available
///   dependencies of a given type and not silently ignore a failing subset.
///
///   If a struct field of type [`Vec`] is annotated with `#[may_fail]`,
///   then resources matching the requested trait exist but which fail
///   initialisation will instead be dropped and a vector containing only
///   the successful ones will be produced. This mode is suitable for
///   resources that degrade well if some dependencies are not available
///   (especially ones seeking just one working dependency resource from
///   a set of possible ones.
///
///   Note that in order to be selected for this, a Resource has to exist
///   somewhere in the graph already, which means that somewhere it must
///   be declared as a dependency under its concrete name. For this, a
///   common expected pattern is that the Assembly's top-level dependencies
///   request it under its concrete type but otherwise do not make any use
///   of it, enabling one or more resources elsewhere in the graph to
///   discover it under its trait interface.
/// - [`PhantomData<T>`](std::marker::PhantomData) where T is a Resource.
///   The resource
///   will be made available to the assembly, but no dependency on it is
///   introduced in the graph. The resource will be actually included in
///   the assembly only if something depends on it in some other way.
///
///   This is only useful if another resource depends upon `T` via a trait
///   that it exposes. In that case, the
///   [`PhantomData`](std::marker::PhantomData) dependency serves to import
///   `T` so that it can be discovered.
///
/// See
/// [`ResourceDependencies`](https://docs.rs/comprehensive/latest/comprehensive/assembly/trait.ResourceDependencies.html)
/// for usage information.
#[proc_macro_derive(ResourceDependencies, attributes(may_fail, old_style))]
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

/// This macro is obsolete after GrpcService was converted to expect
/// [`Resource`](https://docs.rs/comprehensive/latest/comprehensive/v1/trait.Resource.html).
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
    let router_member = router_members.first().unwrap();

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
        impl #impl_generics ::comprehensive_http::HttpServingInstance for #name #ty_generics #where_clause {
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

fn derive_grpc_client_struct(
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
    let mut deps = quote! { GRPCClientDependencies };
    let mut defaults = quote! {};
    for attr in attrs {
        if attr.path().is_ident("no_propagate_health") {
            propagate_health = false;
        }
        if attr.path().is_ident("no_tls") {
            deps = quote! { GRPCClientDependenciesNoTls };
        }
        if let syn::Meta::List(l) = &attr.meta {
            if l.path.is_ident("defaults") {
                let tokens = &l.tokens;
                defaults = quote! {
                    fn instance_defaults() -> ::comprehensive_grpc::client::GrpcClientResourceDefaults {
                        #tokens
                    }
                };
            }
        }
        if attr.path().is_ident("defaults") {
            deps = quote! { GRPCClientDependenciesNoTls };
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
    let worker_field = fields_it.next();
    let (builder, get0, maybe_get1) = match client_field.ident {
        None => (
            if worker_field.is_some() {
                quote_spanned! { fields.span() => Self( #producer , worker ) }
            } else {
                quote_spanned! { fields.span() => Self( #producer ) }
            },
            quote! { self.0 },
            worker_field.map(|_| quote! { self.1 }),
        ),
        Some(ref client_field_name) => {
            if let Some(f) = worker_field {
                let worker_field_name = f.ident.as_ref().unwrap();
                (
                    quote_spanned! {
                        fields.span() => Self {
                            #client_field_name : #producer ,
                            #worker_field_name : worker,
                        }
                    },
                    quote! { self. #client_field_name },
                    Some(quote! { self. #worker_field_name }),
                )
            } else {
                (
                    quote_spanned! {
                        fields.span() => Self {
                            #client_field_name : #producer ,
                        }
                    },
                    quote! { self. #client_field_name },
                    None,
                )
            }
        }
    };

    let resource = if let Some(get1) = maybe_get1 {
        quote! {
            impl #impl_generics ::comprehensive::v0::Resource for #name #ty_generics #where_clause {
                type Args = ::comprehensive_grpc::client::GrpcClientArgs<Self>;
                type Dependencies = ::comprehensive_grpc::client:: #deps ;
                const NAME: &'static str = #name_lit ;

                fn new(d: ::comprehensive_grpc::client:: #deps , a: ::comprehensive_grpc::client::GrpcClientArgs<Self>) -> ::std::result::Result<Self, ::std::boxed::Box<dyn ::std::error::Error>> {
                    let (param, worker) = ::comprehensive_grpc::client::new(a, #label , #propagate_health , d)?;
                    Ok( #builder )
                }

                async fn run(&self) -> ::std::result::Result<(), ::std::boxed::Box<dyn ::std::error::Error>> {
                    #get1 .go().await;
                    Ok(())
                }
            }

            impl #impl_generics ::comprehensive::AnyResource for #name #ty_generics #where_clause {
                type Target = ::comprehensive::v0::ResourceProvider< #name #ty_generics >;
            }
        }
    } else {
        quote! {
            impl #impl_generics ::comprehensive::v1::Resource for #name #ty_generics #where_clause {
                type Args = ::comprehensive_grpc::client::GrpcClientArgs<Self>;
                type Dependencies = ::comprehensive_grpc::client:: #deps ;
                type CreationError = ::std::boxed::Box<dyn ::std::error::Error>;
                const NAME: &'static str = #name_lit ;

                fn new(
                    d: ::comprehensive_grpc::client:: #deps ,
                    a: ::comprehensive_grpc::client::GrpcClientArgs<Self>,
                    api: &mut ::comprehensive::v1::AssemblyRuntime<'_>,
                ) -> ::std::result::Result<::std::sync::Arc<Self>, ::std::boxed::Box<dyn ::std::error::Error>> {
                    let (param, worker) = ::comprehensive_grpc::client::new(a, #label , #propagate_health , d)?;
                    api.set_task(async move { worker.go().await; Ok(()) });
                    Ok(::std::sync::Arc::new( #builder ))
                }
            }

            impl #impl_generics ::comprehensive::AnyResource for #name #ty_generics #where_clause {
                type Target = ::comprehensive::v1::ResourceProvider< #name #ty_generics >;
            }
        }
    };

    quote! {
        #[automatically_derived]
        impl #impl_generics ::comprehensive_grpc::client::InstanceDescriptor for #name #ty_generics #where_clause {
            const REQUIRED: bool = #required ;
            ::comprehensive_grpc::declare_client_flag_name_constants!( #flag_prefix );
            #defaults
        }

        #[automatically_derived]
        #resource

        #[automatically_derived]
        impl #impl_generics #name #ty_generics #where_clause {
            #vis fn client(&self) -> #client_return_type {
                #get0 . #cloner
            }
        }
    }
}

/// Declare a resource for a gRPC client using a particular gRPC service to
/// a particular backend.
///
/// Use this derive macro on a struct with a single field:
/// a [`tonic`] gRPC client type, parameterised with [`Channel`].
///
/// The single field may be wrapped in an [`Option`].
///   - If it is, then the client is considered optional and will
///     be [`Some`] only if a URI for it is given on the command line.
///   - If it is not, then the client is considered required and
///     the program will fail at startup unless a URI for it is given.
///
/// ```
/// # mod pb {
/// #     pub mod test_client {
/// #         #[derive(Clone)]
/// #         pub struct TestClient<T>(std::marker::PhantomData<T>);
/// #         impl<T> TestClient<T> {
/// #             pub fn with_origin<U>(_: T, _: U) -> Self {
/// #                 Self(std::marker::PhantomData)
/// #             }
/// #         }
/// #     }
/// # }
/// use comprehensive_grpc::GrpcClient;
/// use comprehensive_grpc::client::Channel;
///
/// #[derive(GrpcClient)]
/// struct MyClientResource(
///     pb::test_client::TestClient<Channel>,
/// );
/// ```
///
/// Normally, the health of the gRPC client will count toward the health of
/// the [`Assembly`] as a whole. To prevent that, add `#[no_propagate_health]`.
///
/// The attribute `#[no_tls]` may be used to prevent the channel from
/// supporting TLS even when the `tls` feature is enabled. That attribute
/// is not expected to be widely useful and exists only to prevent a
/// circular dependency. In this case, the struct field should referncen
/// `ChannelNoTls` instead of `Channel`.
///
/// To customise the default values of the command line flags used to set the gRPC
/// client channels' default parameters, add `#[defaults(foo)]` where `foo` is a
/// block of code that evaluates to [`GrpcClientResourceDefaults`].
///
/// [`tonic`]: https://docs.rs/tonic/latest/tonic/
/// [`Channel`]: https://docs.rs/comprehensive_grpc/latest/comprehensive_grpc/client/type.Channel.html
/// [`GrpcClientResourceDefaults`]: https://docs.rs/comprehensive_grpc/latest/comprehensive_grpc/client/type.GrpcClientResourceDefaults.html
/// [`Assembly`]: https://docs.rs/comprehensive/latest/comprehensive/assembly/struct.Assembly.html
#[proc_macro_derive(GrpcClient, attributes(defaults, no_propagate_health, no_tls))]
pub fn derive_grpc_client(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input: DeriveInput = parse_macro_input!(item);
    match input.data {
        Data::Struct(ref s) if s.fields.len() <= 2 => derive_grpc_client_struct(&input.vis, &input.ident, &input.generics, &s.fields, &input.attrs),
        _ => quote_spanned! {
            input.span() => compile_error!("`#[derive(GrpcClient)]` requires a struct with exactly 1 field (or 2, for backward compatibility");
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

enum ExportType<A, B, C, D> {
    General(A),
    Grpc(B),
    ProtoDescriptor(C),
    NotOurs(D),
}

impl<A, B, C, D> ExportType<A, B, C, D> {
    fn ours(&self) -> bool {
        !matches!(self, Self::NotOurs(_))
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
                    syn::Meta::List(ref l) => {
                        if l.path.is_ident("export") {
                            ExportType::General(l.parse_args::<Type>())
                        } else if l.path.is_ident("export_grpc") {
                            ExportType::Grpc(l.parse_args::<Path>())
                        } else if l.path.is_ident("proto_descriptor") {
                            ExportType::ProtoDescriptor(l.parse_args::<syn::Expr>())
                        } else {
                            ExportType::NotOurs(a)
                        }
                    }
                    _ => ExportType::NotOurs(a),
                }
            } else {
                ExportType::NotOurs(a)
            }
        })
        .partition(|ono| ono.ours());
    block.attrs = not_ours
        .into_iter()
        .filter_map(|ono| match ono {
            ExportType::NotOurs(v) => Some(v),
            _ => None,
        })
        .collect();
    let mut grpc_exports = ours
        .iter()
        .filter_map(|ono| match ono {
            ExportType::Grpc(Ok(pa)) => Some(quote_spanned! {
                pa.span() => server.add_service( #pa ::from_arc(self))?;
            }),
            _ => None,
        })
        .peekable();
    let mut grpc_descriptors = ours
        .iter()
        .filter_map(|ono| match ono {
            ExportType::ProtoDescriptor(Ok(ex)) => Some(quote_spanned! {
                ex.span() => server.register_encoded_file_descriptor_set( #ex );
            }),
            _ => None,
        })
        .peekable();
    let (impl_generics, _, where_clause) = block.generics.split_for_impl();
    let self_ty = &block.self_ty;
    let grpc_derive = if grpc_exports.peek().is_some() || grpc_descriptors.peek().is_some() {
        quote! {
            #[automatically_derived]
            impl #impl_generics ::comprehensive_grpc::GrpcService for #self_ty #where_clause {
                fn add_to_server(
                    self: Arc<Self>,
                    server: &mut ::comprehensive_grpc::server::GrpcServiceAdder,
                ) -> Result<(), ::comprehensive_grpc::ComprehensiveGrpcError> {
                    #( #grpc_descriptors )*
                    #( #grpc_exports )*
                    Ok(())
                }
            }
        }
    } else {
        quote! {}
    };
    let mut exports = ours.into_iter().filter_map(|ono| match ono {
        ExportType::General(Ok(ty)) => Some(quote_spanned! {
            ty.span() => installer.offer(|s| ::std::sync::Arc::clone(s) as ::std::sync::Arc< #ty >);
        }),
        ExportType::General(Err(e)) => Some(e.to_compile_error()),
        ExportType::Grpc(Ok(pa)) => Some(quote_spanned! {
            pa.span() => installer.offer(|s| ::std::sync::Arc::clone(s) as ::std::sync::Arc<dyn ::comprehensive_grpc::GrpcService>);
        }),
        ExportType::Grpc(Err(e)) => Some(e.to_compile_error()),
        ExportType::ProtoDescriptor(Ok(_)) => None,
        ExportType::ProtoDescriptor(Err(e)) => Some(e.to_compile_error()),
        ExportType::NotOurs(_) => None,
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
    quote! {
        #block

        #[automatically_derived]
        impl #impl_generics ::comprehensive::AnyResource for #self_ty #where_clause {
            type Target = ::comprehensive::v1::ResourceProvider< #self_ty >;
        }

        #grpc_derive
    }
    .into()
}

//! Expresssion of dependencies among Resources in a Comprehensive
//! [`Assembly`]. The salient traits are:
//!
//! - [`ResourceDependency`]: Expresses a dependency of one [`Resource`]
//!   on another one (or set of other ones) in an [`Assembly`]
//! - [`ResourceDependencies`]: A list of [`ResourceDependency`].
//!
//! [`Assembly`]: crate::Assembly
//! [`Resource`]: crate::v1::Resource

use paste::paste;
use std::any::Any;
use std::sync::Arc;

use crate::AnyResource;
use crate::assembly::{ProduceContext, RegisterContext};

type ProduceError = Box<dyn std::error::Error>;

/// This trait expresses the collection of types of other resources that a
/// Resource depends on. It is also used to list the top-level resource
/// types at the roots of the [`Assembly`] graph. There are two main ways
/// to use it:
///
/// - The trait is automatically implemented on tuples of length up to
///   16, if each member of the tuple implements [`ResourceDependency`]
/// - By [deriving](macro@ResourceDependencies) [`ResourceDependencies`]
///   on a struct containing zero or more fields.
///
/// Either way, each member of the tuple or struct represents a requested
/// dependency, and the exact type of the field determines whether it's
/// of a concrete type or a trait, whether it is allowed to fail, etc...
/// See [`ResourceDependency`] for options.
///
/// ```
/// use comprehensive::{NoArgs, NoDependencies, ResourceDependencies};
/// use std::sync::Arc;
///
/// # struct OtherResource;
/// # #[comprehensive::v1::resource]
/// # impl comprehensive::v1::Resource for OtherResource {
/// #     fn new(
/// #         _: NoDependencies, _: NoArgs,
/// #         _: &mut comprehensive::v1::AssemblyRuntime<'_>,
/// #     ) -> Result<Arc<Self>, std::convert::Infallible> {
/// #         Ok(Arc::new(Self))
/// #     }
/// # }
/// # type ImportantResource = OtherResource;
/// # trait ProviderOfSomething {}
/// #
/// #[derive(ResourceDependencies)]
/// struct DependenciesOfSomeResource {
///     other_resource: Arc<OtherResource>,
///     i_need_this: Arc<ImportantResource>,
///     i_can_use_things: Vec<Arc<dyn ProviderOfSomething>>,
/// }
///
/// type AnotherWayToSayIt = (
///     Arc<OtherResource>,
///     Arc<ImportantResource>,
///     Vec<Arc<dyn ProviderOfSomething>>,
/// );
/// ```
///
/// **On the use of [`Arc`]**: During initialisation, a Resource might
/// reasonably desire mutable references to its dependencies, but this is
/// not available since the dependencies are supplied as [`Arc<T>`].
/// Resources can get around this by offering interior mutability APIs
/// (such as [`std::sync::Mutex`]) to their consumers. This was a design
/// tradeoff. An alternative design was considered where the dependencies
/// were supplied as `&'a mut T` (where `'a` is the lifetime of the
/// [`Assembly`]) but that arguably had worse issues since resources could
/// not retain those references outside of [`crate::v0::Resource::new`]
/// (since the reference needs to be available to another consumer).
/// Solutions are possible in case more longer-lived access is required,
/// but these are arguably not better than the [`Arc`] solution.
///
/// [`Assembly`]: crate::Assembly
/// [`Resource`]: crate::v1::Resource
pub trait ResourceDependencies: Sized {
    /// Opaque method used in the implementation of the
    /// [`ResourceDependencies`] trait, which should be derived.
    #[doc(hidden)]
    fn register(cx: &mut RegisterContext);

    /// Opaque method used in the implementation of the
    /// [`ResourceDependencies`] trait, which should be derived.
    #[doc(hidden)]
    fn produce(cx: &mut ProduceContext) -> Result<Self, ProduceError>;
}

pub use comprehensive_macros::ResourceDependencies;

/// Convenience type that can be used as the `Dependencies` associated
/// type on any leaf [`Resource`].
///
/// [`Resource`]: [`crate::v1::Resource`]
pub type NoDependencies = ();

pub(crate) mod sealed {
    use super::*;

    pub trait AvailableResource {
        type ResourceType;

        fn register(cx: &mut RegisterContext);
        fn register_without_dependency(cx: &mut RegisterContext);
        fn produce(cx: &mut ProduceContext) -> Result<Arc<Self::ResourceType>, ProduceError>;
    }

    pub struct SealedMarker;
}

/// A wrapper for `Vec<Arc<dyn Trait>>` intended to be used as a
/// [`ResourceDependency`] which says that some of the resource types
/// implementing the trait are allowed to fail to initialise, and the
/// rest should be retained.
pub struct MayFail<T>(T);

impl<T> std::ops::Deref for MayFail<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> std::ops::DerefMut for MayFail<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> From<T> for MayFail<T> {
    fn from(v: T) -> Self {
        Self(v)
    }
}

impl<T> MayFail<T> {
    /// Extract the contents of this [`MayFail`].
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// Expresses a single type of dependency of one resource (or of the
/// [`Assembly`]'s top level) on another.
///
/// [`Assembly`]: crate::Assembly
pub trait ResourceDependency: Sized {
    #[doc(hidden)]
    type Intermediate;

    #[doc(hidden)]
    fn register(cx: &mut RegisterContext);

    #[doc(hidden)]
    fn produce_early(cx: &mut ProduceContext) -> Result<Self::Intermediate, ProduceError>;

    #[doc(hidden)]
    fn produce_late(cx: &mut ProduceContext, i: Self::Intermediate) -> Result<Self, ProduceError>;

    #[doc(hidden)]
    fn sealed_impl() -> sealed::SealedMarker;
}

/// A null dependency. May be useful as a stand-in for dependencies selected
/// out by conditional compilation.
impl ResourceDependency for () {
    type Intermediate = ();

    fn register(_: &mut RegisterContext<'_>) {}

    fn produce_early(_: &mut ProduceContext) -> Result<(), ProduceError> {
        Ok(())
    }

    fn produce_late(_: &mut ProduceContext, _: ()) -> Result<Self, ProduceError> {
        Ok(())
    }

    fn sealed_impl() -> sealed::SealedMarker {
        sealed::SealedMarker
    }
}

/// A direct dependency on one other concrete resource of type `T`.
impl<T: AnyResource> ResourceDependency for Arc<T> {
    type Intermediate = Self;

    fn register(cx: &mut RegisterContext<'_>) {
        <T::Target as sealed::AvailableResource>::register(cx);
    }

    fn produce_early(cx: &mut ProduceContext) -> Result<Self, ProduceError> {
        <T::Target as sealed::AvailableResource>::produce(cx)
    }

    fn produce_late(_: &mut ProduceContext, i: Self) -> Result<Self, ProduceError> {
        Ok(i)
    }

    fn sealed_impl() -> sealed::SealedMarker {
        sealed::SealedMarker
    }
}

/// A direct dependency on one other concrete resource of type `T` which is
/// allowed to fail to initialise at startup.
impl<T: AnyResource> ResourceDependency for Option<Arc<T>> {
    type Intermediate = ();

    fn register(cx: &mut RegisterContext<'_>) {
        <T::Target as sealed::AvailableResource>::register(cx);
    }

    fn produce_early(_: &mut ProduceContext) -> Result<(), ProduceError> {
        Ok(())
    }

    fn produce_late(cx: &mut ProduceContext, _: ()) -> Result<Self, ProduceError> {
        Ok(<T::Target as sealed::AvailableResource>::produce(cx).ok())
    }

    fn sealed_impl() -> sealed::SealedMarker {
        sealed::SealedMarker
    }
}

/// `T` should be a trait object, like `dyn R`. This expresses a dependency
/// on each of the resources in the assembly that offer that trait. Other
/// resources can offer themselves into this set using the `#[export(dyn R)]`
/// attribute of the [`#[resource]`](macro@comprehensive::v1::resource) macro.
/// This dependency will fail if any of the resources depended upon fail
/// to initialise.
impl<T: Any + ?Sized> ResourceDependency for Vec<Arc<T>> {
    type Intermediate = Self;

    fn register(cx: &mut RegisterContext<'_>) {
        cx.require_trait::<T>();
    }

    fn produce_early(cx: &mut ProduceContext) -> Result<Self, ProduceError> {
        Ok(cx.produce_trait_fallible::<T>()?)
    }

    fn produce_late(_: &mut ProduceContext, i: Self) -> Result<Self, ProduceError> {
        Ok(i)
    }

    fn sealed_impl() -> sealed::SealedMarker {
        sealed::SealedMarker
    }
}

/// `T` should be a trait object, like `dyn R`. This expresses a dependency
/// on each of the resources in the assembly that offer that trait. Other
/// resources can offer themselves into this set using the `#[export(dyn R)]`
/// attribute of the [`#[resource]`](macro@comprehensive::v1::resource) macro.
/// If any of the resources depended upon fail to initialise then they will
/// be omited and a [`Vec`] containing only the successful ones will be
/// returned.
impl<T: Any + ?Sized> ResourceDependency for MayFail<Vec<Arc<T>>> {
    type Intermediate = ();

    fn register(cx: &mut RegisterContext<'_>) {
        cx.require_trait::<T>();
    }

    fn produce_early(_: &mut ProduceContext) -> Result<(), ProduceError> {
        Ok(())
    }

    fn produce_late(cx: &mut ProduceContext, _: ()) -> Result<Self, ProduceError> {
        Ok(cx.produce_trait::<T>().into())
    }

    fn sealed_impl() -> sealed::SealedMarker {
        sealed::SealedMarker
    }
}

/// There is no dependency expressed on `T` however the concrete resource
/// `T` will be made available to the assembly so that it can be selected
/// as a dependency under any traits it exports using the `#[export(dyn R)]`
/// attribute of the [`#[resource]`](macro@comprehensive::v1::resource) macro.
impl<T: AnyResource> ResourceDependency for std::marker::PhantomData<T> {
    type Intermediate = ();

    fn register(cx: &mut RegisterContext<'_>) {
        <T::Target as sealed::AvailableResource>::register_without_dependency(cx);
    }

    fn produce_early(_: &mut ProduceContext) -> Result<(), ProduceError> {
        Ok(())
    }

    fn produce_late(_: &mut ProduceContext, _: ()) -> Result<Self, ProduceError> {
        Ok(Self)
    }

    fn sealed_impl() -> sealed::SealedMarker {
        sealed::SealedMarker
    }
}

macro_rules! impl_r_d_tuple {
    ( $($g:literal),* ) => {
        paste! {
            impl<$( [< D $g >] , )*> ResourceDependencies for ($( [< D $g >] , )*)
            where
                $( [< D $g >] : ResourceDependency, )*
            {
                #[allow(unused_variables)]
                fn register(cx: &mut RegisterContext) {
                    $( [< D $g >] ::register(cx); )*
                }

                #[allow(unused_variables)]
                fn produce(cx: &mut ProduceContext) -> Result<Self, ProduceError> {
                    // Produce all of the required dependencies.
                    // Do not short-circuit on error.
                    $( let [< dep_ $g >] = [< D $g >] ::produce_early(cx); )*
                    // Now return all the accumulated errors.
                    $( let [< dep_ $g >] = [< dep_ $g >] ?; )*
                    // Then produce optional dependencies with short-circuit.
                    Ok((
                        $( [< D $g >] ::produce_late(cx, [< dep_ $g >] )?, )*
                    ))
                }
            }
        }
    }
}

impl_r_d_tuple!();
impl_r_d_tuple!(0);
impl_r_d_tuple!(0, 1);
impl_r_d_tuple!(0, 1, 2);
impl_r_d_tuple!(0, 1, 2, 3);
impl_r_d_tuple!(0, 1, 2, 3, 4);
impl_r_d_tuple!(0, 1, 2, 3, 4, 5);
impl_r_d_tuple!(0, 1, 2, 3, 4, 5, 6);
impl_r_d_tuple!(0, 1, 2, 3, 4, 5, 6, 7);
impl_r_d_tuple!(0, 1, 2, 3, 4, 5, 6, 7, 8);
impl_r_d_tuple!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
impl_r_d_tuple!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
impl_r_d_tuple!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
impl_r_d_tuple!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);
impl_r_d_tuple!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13);
impl_r_d_tuple!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14);
impl_r_d_tuple!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

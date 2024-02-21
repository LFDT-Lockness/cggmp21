use std::fmt;

/// Validated value
///
/// `Valid<T>` wraps a value `T` that has been validated using [`Validate`] trait.
///
/// `Valid<T>` provides only immutable access to `T`. For instance, if you want to change content of `T`, you
/// need to [deconstruct](Valid::into_inner) it, do necessary modifications, and then validate it again.
///
/// ## Transitive "validness" through `AsRef`
/// `Valid<T>` assumes that if `T` implements `AsRef<K>` and `K` can be validated (i.e. `K` implements [`Validate`]),
/// then `K` has been validated when `T` was validated. Thus, if you have value of type `Valid<T>`, you can obtain
/// `&Valid<K>` via `AsRef` trait.
///
/// Example of transitive validness is demostrated below:
/// ```rust
/// use key_share::{Validate, Valid};
///
/// pub type CoreKeyShare = Valid<DirtyCoreKeyShare>;
/// pub type KeyInfo = Valid<DirtyKeyInfo>;
/// # use key_share::InvalidCoreShare as InvalidKeyShare;
///
/// # type SecretScalar = u128;
/// pub struct DirtyCoreKeyShare {
///     i: u16,
///     key_info: DirtyKeyInfo,
///     x: SecretScalar,
/// }
/// pub struct DirtyKeyInfo { /* ... */ }
///
/// // Key info can be validated separately
/// impl Validate for DirtyKeyInfo {
///     type Error = InvalidKeyShare;
///     fn is_valid(&self) -> Result<(), Self::Error> {
///         // ...
///         # Ok(())
///     }
/// }
///
/// // CoreKeyShare can be validated as well
/// impl Validate for DirtyCoreKeyShare {
///     type Error = InvalidKeyShare;
///     fn is_valid(&self) -> Result<(), Self::Error> {
///         // Since `key_info` is part of key share, it **must be** validated when
///         // the key share is validated
///         self.key_info.is_valid();
///         // ...
///         # Ok(())
///     }
/// }
/// impl AsRef<DirtyKeyInfo> for DirtyCoreKeyShare {
///     fn as_ref(&self) -> &DirtyKeyInfo {
///         &self.key_info
///     }
/// }
///
/// # let (i, key_info, x) = (0, DirtyKeyInfo {}, 42);
/// let key_share: CoreKeyShare = DirtyCoreKeyShare { i, key_info, x }.validate()?;
///
/// // Since `key_share` is validated, and it contains `key_info`, we can obtain a `&KeyInfo`.
/// // `Valid<T>` trusts that `<DirtyCoreKeyShare as Validate>::is_valid` has validated `key_info`.
/// let key_info: &KeyInfo = key_share.as_ref();
/// #
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
///
/// This mechanism allow to improve performance by not validating what's already been validated. However, incorrect
/// implementation of `Validate` trait may lead to obtaining `Valid<K>` that's actually invalid. It may, in return,
/// lead to runtime panic and/or compromised security of the application. Make sure that all implementations of
/// [`Validate`] trait are correct and aligned with `AsRef` implementations.
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct Valid<T>(T);

impl<T> Valid<T>
where
    T: Validate,
{
    /// Validates the value
    ///
    /// If value is valid, returns `Ok(validated_value)` wrapped into type guard [`Valid<T>`](Valid), otherwise returns
    /// `Err(err)` containing the error and the invalid value.
    pub fn validate(value: T) -> Result<Self, ValidateError<T, <T as Validate>::Error>> {
        if let Err(err) = value.is_valid() {
            Err(ValidateError {
                invalid_value: value,
                error: err,
            })
        } else {
            Ok(Self(value))
        }
    }

    /// Validates a reference to value `&T` returning `&Valid<T>` if it's valid
    pub fn validate_ref(value: &T) -> Result<&Self, ValidateError<&T, <T as Validate>::Error>> {
        if let Err(err) = value.is_valid() {
            Err(ValidateError {
                invalid_value: value,
                error: err,
            })
        } else {
            Ok(Self::from_ref_unchecked(value))
        }
    }

    /// Constructs and validates value from parts
    ///
    /// Refer to [`ValidateFromParts`] trait documentation
    pub fn from_parts<Parts>(
        parts: Parts,
    ) -> Result<Self, ValidateError<Parts, <T as Validate>::Error>>
    where
        T: ValidateFromParts<Parts>,
    {
        if let Err(err) = T::validate_parts(&parts) {
            Err(ValidateError {
                invalid_value: parts,
                error: err,
            })
        } else {
            Ok(Self(T::from_parts(parts)))
        }
    }

    /// Constructs `&Valid<T>` from `&T`, assumes that `T` has been validated
    ///
    /// Performs a debug assertion that `T` is validated
    fn from_ref_unchecked(value: &T) -> &Self {
        #[cfg(debug_assertions)]
        value
            .is_valid()
            .expect("debug assertions: value is invalid, but was assumed to be valid");

        // SAFETY: &T and &Valid<T> have exactly the same in-memory representation
        // thanks to `repr(transparent)`, so it's sound to transmute the references.
        // Note also that input and output references have exactly the same lifetime.
        unsafe { core::mem::transmute(value) }
    }
}

impl<T> Valid<T> {
    /// Returns wraped validated value
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> AsRef<T> for Valid<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> core::ops::Deref for Valid<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, K> AsRef<Valid<K>> for Valid<T>
where
    T: Validate + AsRef<K>,
    K: Validate,
{
    fn as_ref(&self) -> &Valid<K> {
        let sub_value = self.0.as_ref();
        Valid::from_ref_unchecked(sub_value)
    }
}

/// Represents a type that can be validated
pub trait Validate {
    /// Validation error
    type Error: fmt::Debug;

    /// Checks whether value is valid
    ///
    /// Returns `Ok(())` if it's valid, otherwise returns `Err(err)`
    fn is_valid(&self) -> Result<(), Self::Error>;

    /// Validates the value
    ///
    /// If value is valid, returns `Ok(validated_value)` wrapped into type guard [`Valid<T>`](Valid), otherwise returns
    /// `Err(err)` containing the error and the invalid value.
    fn validate(self) -> Result<Valid<Self>, ValidateError<Self, Self::Error>>
    where
        Self: Sized,
    {
        Valid::validate(self)
    }

    /// Validates the value by reference
    ///
    /// If value is valid, returns [`&Valid<Self>`](Valid), otherwise returns validation error
    fn validate_ref(&self) -> Result<&Valid<Self>, Self::Error>
    where
        Self: Sized,
    {
        Valid::validate_ref(self).map_err(|err| err.into_error())
    }
}

impl<T: Validate> Validate for &T {
    type Error = <T as Validate>::Error;
    fn is_valid(&self) -> Result<(), Self::Error> {
        (*self).is_valid()
    }
}

/// Represents a type that can be constructed and validated from `Parts`
///
/// That can be particularly useful when vaidating `Parts` is cheaper than validating `Self`.
///
/// ## Example
/// Suppose you have a struct `KeyShare` that consists of [`DirtyCoreKeyShare`](crate::DirtyCoreKeyShare) and some `AuxData`. In
/// order to validate `KeyShare`, both core key share and aux data need to be validated separately and then they need to be
/// checked for consistency. Now, if you already have `Valid<DirtyKeyShare>` and `Valid<AuxData>`, then you can skip their validation
/// and only check that they're consistent.
///
/// ```rust
/// use key_share::{Valid, Validate, ValidateFromParts};
/// use generic_ec::Curve;
///
/// pub struct KeyShare<E: Curve> {
///     core: key_share::DirtyCoreKeyShare<E>,
///     aux: AuxData,
/// }
/// # pub struct AuxData { /* ... */ }
/// # impl Validate for AuxData {
/// #     type Error = std::convert::Infallible;
/// #     fn is_valid(&self) -> Result<(), Self::Error> { Ok(()) }
/// # }
///
/// # type InvalidKeyShare = Box<dyn std::error::Error>;
/// // Validation for the whole key share can be expensive
/// impl<E: Curve> Validate for KeyShare<E> {
///     type Error = InvalidKeyShare;
///     fn is_valid(&self) -> Result<(), Self::Error> {
///         self.core.is_valid()?;
///         self.aux.is_valid()?;
///         check_consistency(&self.core, &self.aux)
///     }
/// }
/// fn check_consistency<E: Curve>(
///     core: &key_share::DirtyCoreKeyShare<E>,
///     aux: &AuxData,
/// ) -> Result<(), InvalidKeyShare> {
///     // check that `core` and `aux` seem to match each other
/// # Ok(())
/// }
///
/// // Sometimes, we already validated that `core` and `aux` are valid, so we can perform cheaper validation:
/// impl<E: Curve> ValidateFromParts<(Valid<key_share::DirtyCoreKeyShare<E>>, Valid<AuxData>)>
///     for KeyShare<E>
/// {
///     fn validate_parts(parts: &(Valid<key_share::DirtyCoreKeyShare<E>>, Valid<AuxData>)) -> Result<(), Self::Error> {
///         check_consistency(&parts.0, &parts.1)
///     }
///     fn from_parts(parts: (Valid<key_share::DirtyCoreKeyShare<E>>, Valid<AuxData>)) -> Self {
///         Self { core: parts.0.into_inner(), aux: parts.1.into_inner() }
///     }
/// }
/// ```
pub trait ValidateFromParts<Parts>: Validate {
    /// Validates parts
    ///
    /// Note: implementation **must** guarantee that if `T::validate_parts(parts).is_ok()` then `T::from_parts(parts).is_valid().is_ok()`
    fn validate_parts(parts: &Parts) -> Result<(), Self::Error>;
    /// Constructs `Self` from parts
    fn from_parts(parts: Parts) -> Self;
}

/// Validation error
///
/// Contains an error that explains why value was considered invalid, and the value itself. It can be used
/// to reclaim ownership over invalid value.
pub struct ValidateError<T, E> {
    invalid_value: T,
    error: E,
}

impl<T, E> ValidateError<T, E> {
    /// Returns reference to value that did not pass validation
    pub fn invalid_value(&self) -> &T {
        &self.invalid_value
    }

    /// Returns error explaining why value was considered invalid
    pub fn error(&self) -> &E {
        &self.error
    }

    /// Reclaim ownership over invalidated value
    pub fn into_invalid_value(self) -> T {
        self.invalid_value
    }

    /// Returns ownership over error
    pub fn into_error(self) -> E {
        self.error
    }
}

impl<T, E: fmt::Debug> fmt::Debug for ValidateError<T, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidateError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<T, E: fmt::Display> fmt::Display for ValidateError<T, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("validation error")
    }
}

impl<T, E> std::error::Error for ValidateError<T, E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[cfg(feature = "serde")]
impl<T> serde::Serialize for Valid<T>
where
    T: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (**self).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, T> serde::Deserialize<'de> for Valid<T>
where
    T: Validate + serde::Deserialize<'de>,
    <T as Validate>::Error: fmt::Display,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let value = T::deserialize(deserializer)?;
        value.validate().map_err(|err| {
            D::Error::custom(format_args!(
                "deserialized value is invalid: {}",
                err.error()
            ))
        })
    }
}

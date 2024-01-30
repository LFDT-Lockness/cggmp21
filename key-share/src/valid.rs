use std::fmt;

/// Validated value
///
/// `Valid<T>` wraps a value `T` that has been validated using [`Validate`] trait.
///
/// `Valid<T>` provides only immutable access to `T`. For instance, if you want to change content of `T`, you
/// need to [deconstruct](Valid::into_inner) it, do necessary modifications, and then validate it again using `TryFrom`.
#[derive(Debug, Clone)]
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

/// Represents a type that can be validated
pub trait Validate {
    /// Validation error
    type Error;

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

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
    pub fn validate(value: T) -> Result<Self, ValidateError<T>> {
        if let Err(err) = value.is_valid() {
            Err(ValidateError {
                invalid_value: value,
                error: err,
            })
        } else {
            Ok(Self(value))
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
    type Error: std::error::Error + 'static;

    /// Checks whether value is valid
    ///
    /// Returns `Ok(())` if it's valid, otherwise returns `Err(err)`
    fn is_valid(&self) -> Result<(), Self::Error>;

    /// Validates the value
    ///
    /// If value is valid, returns `Ok(validated_value)` wrapped into type guard [`Valid<T>`](Valid), otherwise returns
    /// `Err(err)` containing the error and the invalid value.
    fn validate(self) -> Result<Valid<Self>, ValidateError<Self>>
    where
        Self: Sized,
    {
        Valid::validate(self)
    }
}

/// Validation error
///
/// Contains an error that explains why value was considered invalid, and the value itself. It can be used
/// to reclaim ownership over invalid value.
pub struct ValidateError<T: Validate> {
    invalid_value: T,
    error: <T as Validate>::Error,
}

impl<T: Validate> ValidateError<T> {
    /// Returns reference to value that did not pass validation
    pub fn invalid_value(&self) -> &T {
        &self.invalid_value
    }

    /// Returns error explaining why value was considered invalid
    pub fn error(&self) -> &<T as Validate>::Error {
        &self.error
    }

    /// Reclaim ownership over invalidated value
    pub fn into_invalid_value(self) -> T {
        self.invalid_value
    }

    /// Returns ownership over error
    pub fn into_error(self) -> <T as Validate>::Error {
        self.error
    }
}

impl<T> fmt::Debug for ValidateError<T>
where
    T: Validate,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidateError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<T: Validate> fmt::Display for ValidateError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("validation error")
    }
}

impl<T> std::error::Error for ValidateError<T>
where
    T: Validate,
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
        (&**self).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, T> serde::Deserialize<'de> for Valid<T>
where
    T: Validate + serde::Deserialize<'de>,
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

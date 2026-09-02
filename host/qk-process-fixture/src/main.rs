//! Shared, non-fixture state for the QK-DEC-156 subprocess harness.
//!
//! This file deliberately contains no registered fixture bytes. The fixture
//! driver alone includes `scenario.rs`; the harness owns only process and pipe
//! lifecycle.

#![allow(dead_code)]

use core::fmt;
use std::ffi::OsString;

pub const CYCLE_TIMEOUT_MILLIS: u64 = 15_000;
pub const EXPECTED_SUCCESS_CYCLES: usize = 12;
pub const EXPECTED_NEGATIVE_CYCLES: usize = 7;
pub const EXPECTED_TOTAL_CYCLES: usize = EXPECTED_SUCCESS_CYCLES + EXPECTED_NEGATIVE_CYCLES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    SimpleRecovery,
    Inheritance,
    QuantumShelter,
}

impl Profile {
    pub const ALL: [Self; 3] = [
        Self::SimpleRecovery,
        Self::Inheritance,
        Self::QuantumShelter,
    ];

    pub const fn argument(self) -> &'static str {
        match self {
            Self::SimpleRecovery => "01",
            Self::Inheritance => "02",
            Self::QuantumShelter => "03",
        }
    }

    pub const fn wire(self) -> u8 {
        match self {
            Self::SimpleRecovery => 1,
            Self::Inheritance => 2,
            Self::QuantumShelter => 3,
        }
    }

    pub fn parse(value: &str) -> Result<Self, FixtureError> {
        match value {
            "01" => Ok(Self::SimpleRecovery),
            "02" => Ok(Self::Inheritance),
            "03" => Ok(Self::QuantumShelter),
            _ => Err(FixtureError::Invocation),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ingress {
    Camera,
    Media,
}

impl Ingress {
    pub const ALL: [Self; 2] = [Self::Camera, Self::Media];

    pub const fn argument(self) -> &'static str {
        match self {
            Self::Camera => "camera",
            Self::Media => "media",
        }
    }

    pub fn parse(value: &str) -> Result<Self, FixtureError> {
        match value {
            "camera" => Ok(Self::Camera),
            "media" => Ok(Self::Media),
            _ => Err(FixtureError::Invocation),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Sd,
    Bbqr,
}

impl Route {
    pub const ALL: [Self; 2] = [Self::Sd, Self::Bbqr];

    pub const fn argument(self) -> &'static str {
        match self {
            Self::Sd => "sd",
            Self::Bbqr => "bbqr",
        }
    }

    pub fn parse(value: &str) -> Result<Self, FixtureError> {
        match value {
            "sd" => Ok(Self::Sd),
            "bbqr" => Ok(Self::Bbqr),
            _ => Err(FixtureError::Invocation),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Negative {
    HostileQkdv,
    IngressCap,
    ProfileMismatch,
    EarlyHold,
    WrongWallet,
    WrongKey,
    HighS,
}

impl Negative {
    pub const ALL: [Self; 7] = [
        Self::HostileQkdv,
        Self::IngressCap,
        Self::ProfileMismatch,
        Self::EarlyHold,
        Self::WrongWallet,
        Self::WrongKey,
        Self::HighS,
    ];

    pub const fn argument(self) -> &'static str {
        match self {
            Self::HostileQkdv => "hostile-qkdv",
            Self::IngressCap => "ingress-cap",
            Self::ProfileMismatch => "profile-mismatch",
            Self::EarlyHold => "early-hold",
            Self::WrongWallet => "wrong-wallet",
            Self::WrongKey => "wrong-key",
            Self::HighS => "high-s",
        }
    }

    pub fn parse(value: &str) -> Result<Self, FixtureError> {
        match value {
            "hostile-qkdv" => Ok(Self::HostileQkdv),
            "ingress-cap" => Ok(Self::IngressCap),
            "profile-mismatch" => Ok(Self::ProfileMismatch),
            "early-hold" => Ok(Self::EarlyHold),
            "wrong-wallet" => Ok(Self::WrongWallet),
            "wrong-key" => Ok(Self::WrongKey),
            "high-s" => Ok(Self::HighS),
            _ => Err(FixtureError::Invocation),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CycleSpec {
    pub profile: Profile,
    pub ingress: Ingress,
    pub route: Route,
    pub negative: Option<Negative>,
}

impl CycleSpec {
    pub const fn success(profile: Profile, ingress: Ingress, route: Route) -> Self {
        Self {
            profile,
            ingress,
            route,
            negative: None,
        }
    }

    pub const fn negative(negative: Negative) -> Self {
        Self {
            profile: Profile::SimpleRecovery,
            ingress: Ingress::Camera,
            route: Route::Sd,
            negative: Some(negative),
        }
    }

    pub fn driver_arguments(self) -> Vec<OsString> {
        let mut arguments = Vec::with_capacity(5);
        arguments.push(OsString::from(if self.negative.is_some() {
            "negative"
        } else {
            "success"
        }));
        arguments.push(OsString::from(self.profile.argument()));
        arguments.push(OsString::from(self.ingress.argument()));
        arguments.push(OsString::from(self.route.argument()));
        if let Some(negative) = self.negative {
            arguments.push(OsString::from(negative.argument()));
        }
        arguments
    }
}

pub fn cycle_matrix() -> Vec<CycleSpec> {
    let mut cycles = Vec::with_capacity(EXPECTED_TOTAL_CYCLES);
    for profile in Profile::ALL {
        for ingress in Ingress::ALL {
            for route in Route::ALL {
                cycles.push(CycleSpec::success(profile, ingress, route));
            }
        }
    }
    for negative in Negative::ALL {
        cycles.push(CycleSpec::negative(negative));
    }
    debug_assert_eq!(cycles.len(), EXPECTED_TOTAL_CYCLES);
    cycles
}

pub fn parse_driver_arguments<I>(arguments: I) -> Result<CycleSpec, FixtureError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let mode = text(arguments.next())?;
    let profile = Profile::parse(&text(arguments.next())?)?;
    let ingress = Ingress::parse(&text(arguments.next())?)?;
    let route = Route::parse(&text(arguments.next())?)?;
    let negative = match mode.as_str() {
        "success" => None,
        "negative" => Some(Negative::parse(&text(arguments.next())?)?),
        _ => return Err(FixtureError::Invocation),
    };
    if arguments.next().is_some() {
        return Err(FixtureError::Invocation);
    }
    Ok(CycleSpec {
        profile,
        ingress,
        route,
        negative,
    })
}

fn text(value: Option<OsString>) -> Result<String, FixtureError> {
    value
        .ok_or(FixtureError::Invocation)?
        .into_string()
        .map_err(|_| FixtureError::Invocation)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixtureError {
    Invocation,
    Pipe,
    Spawn,
    Wait,
    Timeout,
    ChildStatus,
    Io,
    Wire,
    Fixture,
    FactMismatch,
    UnexpectedEof,
}

impl FixtureError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Invocation => "Invocation",
            Self::Pipe => "Pipe",
            Self::Spawn => "Spawn",
            Self::Wait => "Wait",
            Self::Timeout => "Timeout",
            Self::ChildStatus => "ChildStatus",
            Self::Io => "Io",
            Self::Wire => "Wire",
            Self::Fixture => "Fixture",
            Self::FactMismatch => "FactMismatch",
            Self::UnexpectedEof => "UnexpectedEof",
        }
    }
}

impl fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for FixtureError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_is_exact_twelve_plus_seven() {
        let cycles = cycle_matrix();
        assert_eq!(cycles.len(), EXPECTED_TOTAL_CYCLES);
        assert_eq!(
            cycles
                .iter()
                .filter(|cycle| cycle.negative.is_none())
                .count(),
            12
        );
        assert_eq!(
            cycles
                .iter()
                .filter(|cycle| cycle.negative.is_some())
                .count(),
            7
        );
        for profile in Profile::ALL {
            for ingress in Ingress::ALL {
                for route in Route::ALL {
                    assert!(cycles.contains(&CycleSpec::success(profile, ingress, route)));
                }
            }
        }
        for negative in Negative::ALL {
            assert!(cycles.contains(&CycleSpec::negative(negative)));
        }
    }

    #[test]
    fn driver_arguments_round_trip_without_defaults() {
        for cycle in cycle_matrix() {
            assert_eq!(parse_driver_arguments(cycle.driver_arguments()), Ok(cycle));
        }
        assert_eq!(parse_driver_arguments([]), Err(FixtureError::Invocation));
    }
}

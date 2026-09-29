use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    VerifiedPureRustPrimitive,
    CurrentOnlineBridgeOnly,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityError {
    pub component: &'static str,
    pub reason: &'static str,
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} unavailable: {}", self.component, self.reason)
    }
}

impl std::error::Error for CapabilityError {}

pub fn current_medusa() -> Result<(), CapabilityError> {
    Err(CapabilityError {
        component: "current Tomato Medusa VM9",
        reason: "independent parameterization is not complete; use the documented Java/Unidbg bridge for research trials",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_medusa_is_explicitly_unavailable() {
        let error = current_medusa().expect_err("current VM must not be guessed");
        assert_eq!(error.component, "current Tomato Medusa VM9");
    }
}

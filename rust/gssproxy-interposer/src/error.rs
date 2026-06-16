//! Minor-status error code mapping between the remote (daemon) mech and the
//! local mechglue.
//!
//! Port of `gpp_map_error`/`gpp_unmap_error` from `src/mechglue/gss_plugin.c`.
//! As in the C code this is a placeholder scheme: a fixed base is added to any
//! non-zero minor code so that remote minor codes do not collide with local
//! mechglue codes. It must stay byte-for-byte identical to the C behaviour so
//! that an application seeing a mapped minor code from the Rust interposer gets
//! the same value the C interposer would have produced.

const MAP_ERROR_BASE: u32 = 0x0420_0000;

/// `gpp_map_error`: shift a remote minor code into the mapped range.
pub fn map_error(err: u32) -> u32 {
    if err != 0 {
        err.wrapping_add(MAP_ERROR_BASE)
    } else {
        err
    }
}

/// `gpp_unmap_error`: reverse [`map_error`].
pub fn unmap_error(err: u32) -> u32 {
    if err != 0 {
        err.wrapping_sub(MAP_ERROR_BASE)
    } else {
        err
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_unmap_round_trip() {
        assert_eq!(map_error(0), 0);
        assert_eq!(unmap_error(0), 0);
        assert_eq!(unmap_error(map_error(42)), 42);
        assert_eq!(map_error(1), 0x0420_0001);
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    /// The single non-zero minor code whose mapping wraps back to 0. This is an
    /// inherent property of the C scheme (unsigned add of a fixed base) and is
    /// preserved here deliberately for byte-for-byte parity with `gpp_map_error`.
    const WRAP_TO_ZERO: u32 = 0u32.wrapping_sub(MAP_ERROR_BASE);

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 1024,
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// `unmap_error` inverts `map_error` for every input except the lone
        /// wrap-collision value, exactly as the C placeholder scheme does.
        #[test]
        fn map_then_unmap_is_identity(x in any::<u32>()) {
            let mapped = map_error(x);
            if mapped == 0 {
                // Either x == 0, or the wrap-collision value; both unmap to 0,
                // matching the C behaviour (which is likewise non-invertible
                // for this one code).
                prop_assert!(x == 0 || x == WRAP_TO_ZERO);
                prop_assert_eq!(unmap_error(mapped), 0);
            } else {
                prop_assert_eq!(unmap_error(mapped), x);
            }
        }

        /// Non-zero codes are shifted by exactly `MAP_ERROR_BASE`; zero is the
        /// identity in both directions.
        #[test]
        fn shift_amount_matches_c(x in any::<u32>()) {
            if x == 0 {
                prop_assert_eq!(map_error(x), 0);
                prop_assert_eq!(unmap_error(x), 0);
            } else {
                prop_assert_eq!(map_error(x), x.wrapping_add(MAP_ERROR_BASE));
                prop_assert_eq!(unmap_error(x), x.wrapping_sub(MAP_ERROR_BASE));
            }
        }
    }
}

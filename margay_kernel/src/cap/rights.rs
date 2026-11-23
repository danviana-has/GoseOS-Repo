//! Capability Access Rights (`CapRights`)
//!
//! Capabilities encode unforgeable authority over kernel objects. Rights may
//! only be attenuated (narrowed) during `cap_copy` / `cap_mint`, never amplified.

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapRights(pub u32);

impl CapRights {
    pub const NONE: Self = Self(0);
    /// Read data / receive IPC / map read-only.
    pub const READ: Self = Self(1 << 0);
    /// Write data / send IPC / signal notification / map writable.
    pub const WRITE: Self = Self(1 << 1);
    /// Transfer capabilities inside IPC messages.
    pub const GRANT: Self = Self(1 << 2);
    /// Automatically generate a single-use Reply capability on `ipc_call`.
    pub const GRANT_REPLY: Self = Self(1 << 3);
    /// Revoke all derived child capabilities via the CDT.
    pub const REVOKE: Self = Self(1 << 4);
    /// Map physical frames as executable (mutually exclusive with WRITE under W^X).
    pub const EXECUTE: Self = Self(1 << 5);
    /// Copy / mint / derive new capabilities from this slot.
    pub const DERIVE: Self = Self(1 << 6);

    pub const READ_WRITE: Self = Self(Self::READ.0 | Self::WRITE.0);
    pub const ALL: Self = Self(
        Self::READ.0
            | Self::WRITE.0
            | Self::GRANT.0
            | Self::GRANT_REPLY.0
            | Self::REVOKE.0
            | Self::EXECUTE.0
            | Self::DERIVE.0,
    );

    #[inline]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits & Self::ALL.0)
    }

    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[inline]
    pub const fn contains(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Attenuate rights by intersecting with `mask` (can never amplify).
    #[inline]
    pub const fn attenuate(self, mask: Self) -> Self {
        Self(self.0 & mask.0)
    }
}

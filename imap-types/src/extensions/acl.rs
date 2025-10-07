//! The IMAP ACL Extension
//!
//! This extends ...
//!
//! * [`Capability`](crate::response::Capability) with a new variant:
//!
//!     - [`Capability::Acl`](crate::response::Capability::Acl)
//!
//! * [`CommandBody`](crate::command::CommandBody) with new variants:
//!
//!     - [`CommandBody::SetAcl`](crate::command::CommandBody::SetAcl)
//!     - [`CommandBody::DeleteAcl`](crate::command::CommandBody::DeleteAcl)
//!     - [`CommandBody::GetAcl`](crate::command::CommandBody::GetAcl)
//!     - [`CommandBody::ListRights`](crate::command::CommandBody::ListRights)
//!     - [`CommandBody::MyRights`](crate::command::CommandBody::MyRights)
//!
//! * [`Data`] with new variants:
//!
//!     - [`Data::Acl`]
//!     - [`Data::ListRights`]
//!     - [`Data::MyRights`]

use crate::core::AString;
use crate::{command::CommandBody, mailbox::Mailbox, response::Data};
#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use bounded_static_derive::ToStatic;

impl<'a> CommandBody<'a> {
    /// <div class="warning">
    /// This extension must only be used when the server advertised support for it by sending the ACL capability.
    /// </div>

    pub fn setacl(
        mailbox: Mailbox<'a>,
        identifier: AString<'a>,
        mod_rights: ModRights<'a>,
    ) -> Self {
        CommandBody::SetAcl {
            mailbox,
            identifier,
            mod_rights,
        }
    }

    pub fn deleteacl(mailbox: Mailbox<'a>, identifier: AString<'a>) -> Self {
        CommandBody::DeleteAcl {
            mailbox,
            identifier,
        }
    }

    pub fn getacl(mailbox: Mailbox<'a>) -> Self {
        CommandBody::GetAcl { mailbox }
    }

    pub fn listrights(mailbox: Mailbox<'a>, identifier: AString<'a>) -> Self {
        CommandBody::ListRights {
            mailbox,
            identifier,
        }
    }

    pub fn myrights(mailbox: Mailbox<'a>) -> Self {
        CommandBody::MyRights { mailbox }
    }
}

impl<'a> Data<'a> {
    pub fn acl(mailbox: Mailbox<'a>, entries: Vec<AclEntry<'a>>) -> Self {
        Self::Acl { mailbox, entries }
    }

    pub fn listrights(
        mailbox: Mailbox<'a>,
        identifier: AString<'a>,
        required: Rights<'a>,
        optional: Vec<Rights<'a>>,
    ) -> Self {
        Self::ListRights {
            mailbox,
            identifier,
            required,
            optional,
        }
    }

    pub fn myrights(mailbox: Mailbox<'a>, rights: Rights<'a>) -> Self {
        Self::MyRights { mailbox, rights }
    }
}

/// A single entry in an Access Control List, associating an identifier
/// with a set of rights.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct AclEntry<'a> {
    pub identifier: AString<'a>,
    pub rights: Rights<'a>,
}

/// Represents how rights should be modified for a `SETACL` command.
///
/// This corresponds to the `mod-rights` ABNF rule in RFC 4314.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum ModRights<'a> {
    /// Adds the given rights to any existing rights for the identifier.
    /// Corresponds to `+<rights>`.
    Add(Rights<'a>),
    /// Removes the given rights from any existing rights for the identifier.
    /// Corresponds to `-<rights>`.
    Remove(Rights<'a>),
    /// Replaces any existing rights for the identifier with the given rights.
    /// Corresponds to `<rights>`.
    Replace(Rights<'a>),
}

/// Represents a set of ACL rights as a string.
///
/// Each character in the string represents a specific right.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct Rights<'a>(pub AString<'a>);

/// Error-related types.
pub mod error {
    use thiserror::Error;

    #[derive(Clone, Debug, Eq, Error, Hash, Ord, PartialEq, PartialOrd)]
    pub enum AclError {
        #[error("Invalid identifier: {0}")]
        Identifier(String),
        #[error("Invalid rights: {0}")]
        Rights(String),
    }
}

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

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use bounded_static_derive::ToStatic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{command::CommandBody, core::AString, mailbox::Mailbox, response::Data};

impl<'a> CommandBody<'a> {
    /// <div class="warning">
    /// This extension must only be used when the server advertised support for it by sending the ACL capability.
    /// </div>

    pub fn setacl(mailbox: Mailbox<'a>, identifier: AString<'a>, mod_rights: AString<'a>) -> Self {
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
        required: AString<'a>,
        optional: Vec<AString<'a>>,
    ) -> Self {
        Self::ListRights {
            mailbox,
            identifier,
            required,
            optional,
        }
    }

    pub fn myrights(mailbox: Mailbox<'a>, rights: AString<'a>) -> Self {
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
    pub rights: AString<'a>,
}

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

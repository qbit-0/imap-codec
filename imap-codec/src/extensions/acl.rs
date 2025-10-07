//! The IMAP ACL Extension (RFC 4314)

use imap_types::{extensions::acl::AclEntry, response::Data};
use nom::{
    bytes::complete::tag_no_case,
    character::complete::space1,
    combinator::map,
    multi::{many0, many1},
    sequence::{preceded, tuple},
};

use crate::{core::astring, decode::IMAPResult, mailbox::mailbox};

// -------------------------------------------------------------------------------------------------
// Decoders

/// Parses an untagged `ACL` response.
///
/// ```abnf
/// acl-data = "ACL" SP mailbox 1*(SP identifier SP rights)
/// ```
pub(crate) fn acl_response(input: &[u8]) -> IMAPResult<&[u8], Data> {
    let mut parser = tuple((
        tag_no_case("ACL "),
        mailbox,
        many1(preceded(space1, acl_entry)),
    ));

    let (remaining, (_, mailbox, entries)) = parser(input)?;

    Ok((remaining, Data::acl(mailbox, entries)))
}

/// Parses an `identifier SP rights` pair used in the ACL response.
fn acl_entry(input: &[u8]) -> IMAPResult<&[u8], AclEntry> {
    map(
        tuple((astring, preceded(space1, astring))),
        |(identifier, rights)| AclEntry { identifier, rights },
    )(input)
}

/// Parses an untagged `LISTRIGHTS` response.
///
/// ```abnf
/// listrights-data = "LISTRIGHTS" SP mailbox SP identifier SP rights *(SP rights)
/// ```
pub(crate) fn listrights_response(input: &[u8]) -> IMAPResult<&[u8], Data> {
    let mut parser = tuple((
        tag_no_case("LISTRIGHTS "),
        mailbox,
        preceded(space1, astring),
        preceded(space1, astring),
        many0(preceded(space1, astring)),
    ));

    let (remaining, (_, mailbox, identifier, required, optional)) = parser(input)?;

    Ok((
        remaining,
        Data::listrights(mailbox, identifier, required, optional),
    ))
}

/// Parses an untagged `MYRIGHTS` response.
///
/// ```abnf
/// myrights-data = "MYRIGHTS" SP mailbox SP rights
/// ```
pub(crate) fn myrights_response(input: &[u8]) -> IMAPResult<&[u8], Data> {
    let mut parser = tuple((tag_no_case("MYRIGHTS "), mailbox, preceded(space1, astring)));

    let (remaining, (_, mailbox, rights)) = parser(input)?;

    Ok((remaining, Data::myrights(mailbox, rights)))
}

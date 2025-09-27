use crate::{command::CommandBody, core::AString, mailbox::Mailbox};

impl<'a> CommandBody<'a> {
    pub fn listrights(mailbox: Mailbox<'a>, identifier: AString<'a>) -> Self {
        CommandBody::ListRights {
            mailbox,
            identifier,
        }
    }

    pub fn myrights(mailbox: Mailbox<'a>) -> Self {
        CommandBody::MyRights { mailbox }
    }

    pub fn setacl(mailbox: Mailbox<'a>, identifier: AString<'a>, mod_rights: AString<'a>) -> Self {
        CommandBody::SetAcl {
            mailbox,
            identifier,
            mod_rights,
        }
    }
}

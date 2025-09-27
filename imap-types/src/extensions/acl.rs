use crate::command::CommandBody;

impl<'a> CommandBody<'a> {
    pub fn listrights() -> Self {
        CommandBody::ListRights
    }

    pub fn myrights() -> Self {
        CommandBody::MyRights
    }

    pub fn setacl() -> Self {
        CommandBody::SetAcl
    }
}

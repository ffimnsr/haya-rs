
/// Error in retrieving user info.
#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum UserInfoError<RE>
where
    RE: std::error::Error + 'static,
{
    ClaimsVerification,
    Parse,
    Request(RE),
    Response,
    Other,
}

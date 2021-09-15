fn revoke_authentication_session() {
    let sid = revoke_authentication_cookie();
}

fn revoke_authentication_cookie() -> String {
    // let cookie_auth_sid_name = "";
    // let mut cookie = Cookie::new();
    // let sid = cookie.get(cookie_auth_sid_name);
    String::from("hello")
}

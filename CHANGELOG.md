# Changelog

## 0.3.1 - 2026-10-23

### Features

- update endpoints and functionality for oauth2 (`b7db8d1`)
- add initial structure for auth endpoint (`b18b83f`)
- overhaul to Supabase Auth (GoTrue) compatible drop-in replacement (`14891f9`)
- overhaul to Supabase Auth compatible server with all auth endpoints (`3f40d26`)
- add linux systemd files for it to be easily installed as daemon in linux (`aaca3a4`)
- cleanup of unused files (`750239a`)
- add a proper demo app to showcase the integration (`ebc52a4`)
- make the endpoints more secure (`2c38ff2`)
- add mailer using lettre (`21b2c6c`)
- add mfa and sso oidc (`22ec1fc`)
- add cli tool to manage haya server (`94ba222`)
- fix cli issues (`3610d5c`)
- harden flow of the auth (`e2c7e2b`)
- update issues on the server (`5f7dcde`)
- patch the security holes (`0d2a1ec`)
- add hardening of all endpoints (`778759e`)
- do some security fixes on the oicd and tokens (`914e472`)
- update the guarantees and admin paths (`b710c58`)
- add passkey relying party (`d48f45a`)
- add release workflow (`946f800`)
- update CI workflow (`6c0aa4a`)
- update cargo metadata deps (`fb1f14c`)


### Fixes

- address code review feedback (`0889d09`)
- improve code quality after review (`563244b`)
- add fixes to token generation (`f67ba0c`)
- unblock version bumps and clear build warnings (`608ce3f`)
- roll back generated files on failed release (`40272da`)


### Documentation

- add CHANGELOG to repo (`d5bcdd1`)


### CI

- add github workflow (`92f5355`)


### Maintenance

- initial commit (`4bbffab`)
- add initial well known structure (`ce90887`)


### Other Changes

- re-structure the code and added initial migrations (`f104aaf`)
- update authorize and token endpoints (`eea625e`)
- refactor code for authorize and token endpoint (`f6953af`)
- add all migrations from db (`fb964c4`)
- update calculation of pkce code_verifier (`e1e84d5`)
- update cargo and migrations (`9d20ff8`)
- update authorize endpoint to accept body params (`1ca47c1`)
- format with cargo fmt (`6112141`)
- 🍕 Continue on transitioning to MongoDB (`873b896`)
- 🍕 Update models for haya (`5becb73`)
- 🍕 Modify router and still WIP (`17a14c2`)
- 🍕 Update haya for new use (`216490c`)
- 🍕 Add handler function for axum and fallback (`b86283e`)


## 0.4.0 - 2026-10-23

### Features

- update endpoints and functionality for oauth2 (`b7db8d1`)
- add initial structure for auth endpoint (`b18b83f`)
- overhaul to Supabase Auth (GoTrue) compatible drop-in replacement (`14891f9`)
- overhaul to Supabase Auth compatible server with all auth endpoints (`3f40d26`)
- add linux systemd files for it to be easily installed as daemon in linux (`aaca3a4`)
- cleanup of unused files (`750239a`)
- add a proper demo app to showcase the integration (`ebc52a4`)
- make the endpoints more secure (`2c38ff2`)
- add mailer using lettre (`21b2c6c`)
- add mfa and sso oidc (`22ec1fc`)
- add cli tool to manage haya server (`94ba222`)
- fix cli issues (`3610d5c`)
- harden flow of the auth (`e2c7e2b`)
- update issues on the server (`5f7dcde`)
- patch the security holes (`0d2a1ec`)
- add hardening of all endpoints (`778759e`)
- do some security fixes on the oicd and tokens (`914e472`)
- update the guarantees and admin paths (`b710c58`)
- add passkey relying party (`d48f45a`)
- add release workflow (`946f800`)
- update CI workflow (`6c0aa4a`)
- update cargo metadata deps (`fb1f14c`)


### Fixes

- address code review feedback (`0889d09`)
- improve code quality after review (`563244b`)
- add fixes to token generation (`f67ba0c`)


### CI

- add github workflow (`92f5355`)


### Maintenance

- initial commit (`4bbffab`)
- add initial well known structure (`ce90887`)


### Other Changes

- re-structure the code and added initial migrations (`f104aaf`)
- update authorize and token endpoints (`eea625e`)
- refactor code for authorize and token endpoint (`f6953af`)
- add all migrations from db (`fb964c4`)
- update calculation of pkce code_verifier (`e1e84d5`)
- update cargo and migrations (`9d20ff8`)
- update authorize endpoint to accept body params (`1ca47c1`)
- format with cargo fmt (`6112141`)
- 🍕 Continue on transitioning to MongoDB (`873b896`)
- 🍕 Update models for haya (`5becb73`)
- 🍕 Modify router and still WIP (`17a14c2`)
- 🍕 Update haya for new use (`216490c`)
- 🍕 Add handler function for axum and fallback (`b86283e`)


## 0.3.0 - 2026-10-23

### Features

- update endpoints and functionality for oauth2 (`b7db8d1`)
- add initial structure for auth endpoint (`b18b83f`)
- overhaul to Supabase Auth (GoTrue) compatible drop-in replacement (`14891f9`)
- overhaul to Supabase Auth compatible server with all auth endpoints (`3f40d26`)
- add linux systemd files for it to be easily installed as daemon in linux (`aaca3a4`)
- cleanup of unused files (`750239a`)
- add a proper demo app to showcase the integration (`ebc52a4`)
- make the endpoints more secure (`2c38ff2`)
- add mailer using lettre (`21b2c6c`)
- add mfa and sso oidc (`22ec1fc`)
- add cli tool to manage haya server (`94ba222`)
- fix cli issues (`3610d5c`)
- harden flow of the auth (`e2c7e2b`)
- update issues on the server (`5f7dcde`)
- patch the security holes (`0d2a1ec`)
- add hardening of all endpoints (`778759e`)
- do some security fixes on the oicd and tokens (`914e472`)
- update the guarantees and admin paths (`b710c58`)
- add passkey relying party (`d48f45a`)
- add release workflow (`946f800`)
- update CI workflow (`6c0aa4a`)


### Fixes

- address code review feedback (`0889d09`)
- improve code quality after review (`563244b`)
- add fixes to token generation (`f67ba0c`)


### CI

- add github workflow (`92f5355`)


### Maintenance

- initial commit (`4bbffab`)
- add initial well known structure (`ce90887`)


### Other Changes

- re-structure the code and added initial migrations (`f104aaf`)
- update authorize and token endpoints (`eea625e`)
- refactor code for authorize and token endpoint (`f6953af`)
- add all migrations from db (`fb964c4`)
- update calculation of pkce code_verifier (`e1e84d5`)
- update cargo and migrations (`9d20ff8`)
- update authorize endpoint to accept body params (`1ca47c1`)
- format with cargo fmt (`6112141`)
- 🍕 Continue on transitioning to MongoDB (`873b896`)
- 🍕 Update models for haya (`5becb73`)
- 🍕 Modify router and still WIP (`17a14c2`)
- 🍕 Update haya for new use (`216490c`)
- 🍕 Add handler function for axum and fallback (`b86283e`)

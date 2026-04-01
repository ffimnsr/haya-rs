//! SMTP mailer with file-based email template overrides.
//!
//! ## Configuration (environment variables)
//! | Variable             | Default                  | Description                              |
//! |----------------------|--------------------------|------------------------------------------|
//! | `SMTP_HOST`          | *(required to enable)*   | SMTP server hostname                     |
//! | `SMTP_PORT`          | `587`                    | SMTP port                                |
//! | `SMTP_TLS`           | `true`                   | Use STARTTLS; set `false` for MailHog    |
//! | `SMTP_USERNAME`      |                          | SMTP auth username (optional)            |
//! | `SMTP_PASSWORD`      |                          | SMTP auth password (optional)            |
//! | `SMTP_FROM_EMAIL`    | `noreply@example.com`    | Sender address                           |
//! | `SMTP_FROM_NAME`     | *(site name)*            | Sender display name                      |
//! | `EMAIL_TEMPLATES_DIR`| `./templates/email`      | Directory with HTML/text template files  |
//!
//! ## Customising templates
//! Drop any of the following files into `EMAIL_TEMPLATES_DIR`.  Missing files
//! fall back to the built-in defaults automatically.
//!
//! | File               | Available variables                                       |
//! |--------------------|-----------------------------------------------------------|
//! | `confirm.html/txt` | `{{site_name}}`, `{{confirmation_url}}`, `{{email}}`      |
//! | `recovery.html/txt`| `{{site_name}}`, `{{recovery_url}}`, `{{email}}`          |
//! | `magic_link.html/txt` | `{{site_name}}`, `{{magic_link_url}}`, `{{email}}`     |

use std::path::Path;

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, MultiPart, SinglePart, header},
    transport::smtp::authentication::Credentials,
};

// ── Built-in default templates ───────────────────────────────────────────────

const DEFAULT_CONFIRM_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Confirm your email</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f9fafb; margin: 0; padding: 40px 20px; }
    .card { background: white; border-radius: 8px; max-width: 480px; margin: 0 auto; padding: 40px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
    h2 { margin: 0 0 16px; font-size: 22px; color: #111; }
    p { margin: 0 0 16px; color: #555; line-height: 1.6; }
    .btn { display: inline-block; padding: 12px 24px; background: #0070f3; color: white; text-decoration: none; border-radius: 6px; font-weight: 600; }
    .url { color: #999; word-break: break-all; font-size: 13px; }
    .footer { margin-top: 32px; font-size: 12px; color: #999; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Confirm your email address</h2>
    <p>Welcome to <strong>{{site_name}}</strong>! Click below to confirm your email and complete your registration.</p>
    <p><a href="{{confirmation_url}}" class="btn">Confirm Email</a></p>
    <p class="url">Or copy this link:<br>{{confirmation_url}}</p>
    <div class="footer">
      <p>If you didn't create an account with {{site_name}}, you can safely ignore this email.</p>
    </div>
  </div>
</body>
</html>"#;

const DEFAULT_CONFIRM_TXT: &str = "Welcome to {{site_name}}!\n\nPlease confirm your email address by visiting the link below:\n\n{{confirmation_url}}\n\nIf you didn't create an account with {{site_name}}, you can safely ignore this email.\n";

const DEFAULT_RECOVERY_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset your password</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f9fafb; margin: 0; padding: 40px 20px; }
    .card { background: white; border-radius: 8px; max-width: 480px; margin: 0 auto; padding: 40px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
    h2 { margin: 0 0 16px; font-size: 22px; color: #111; }
    p { margin: 0 0 16px; color: #555; line-height: 1.6; }
    .btn { display: inline-block; padding: 12px 24px; background: #0070f3; color: white; text-decoration: none; border-radius: 6px; font-weight: 600; }
    .url { color: #999; word-break: break-all; font-size: 13px; }
    .footer { margin-top: 32px; font-size: 12px; color: #999; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Reset your password</h2>
    <p>We received a request to reset the password for <strong>{{email}}</strong> on <strong>{{site_name}}</strong>.</p>
    <p><a href="{{recovery_url}}" class="btn">Reset Password</a></p>
    <p class="url">Or copy this link:<br>{{recovery_url}}</p>
    <div class="footer">
      <p>This link expires in 1 hour. If you didn't request a password reset, you can safely ignore this email.</p>
    </div>
  </div>
</body>
</html>"#;

const DEFAULT_RECOVERY_TXT: &str = "Reset your password for {{site_name}}\n\nWe received a request to reset the password for {{email}}.\n\nClick the link below to reset your password (expires in 1 hour):\n\n{{recovery_url}}\n\nIf you didn't request a password reset, you can safely ignore this email.\n";

const DEFAULT_MAGIC_LINK_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Your magic link</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f9fafb; margin: 0; padding: 40px 20px; }
    .card { background: white; border-radius: 8px; max-width: 480px; margin: 0 auto; padding: 40px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
    h2 { margin: 0 0 16px; font-size: 22px; color: #111; }
    p { margin: 0 0 16px; color: #555; line-height: 1.6; }
    .btn { display: inline-block; padding: 12px 24px; background: #0070f3; color: white; text-decoration: none; border-radius: 6px; font-weight: 600; }
    .url { color: #999; word-break: break-all; font-size: 13px; }
    .footer { margin-top: 32px; font-size: 12px; color: #999; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Sign in to {{site_name}}</h2>
    <p>Click the link below to sign in to your account. This link can only be used once.</p>
    <p><a href="{{magic_link_url}}" class="btn">Sign In</a></p>
    <p class="url">Or copy this link:<br>{{magic_link_url}}</p>
    <div class="footer">
      <p>This link expires in 24 hours. If you didn't request this, you can safely ignore this email.</p>
    </div>
  </div>
</body>
</html>"#;

const DEFAULT_MAGIC_LINK_TXT: &str = "Sign in to {{site_name}}\n\nClick the link below to sign in to your account (this link can only be used once):\n\n{{magic_link_url}}\n\nThis link expires in 24 hours. If you didn't request this, you can safely ignore this email.\n";

// ── Email kind ───────────────────────────────────────────────────────────────

/// Identifies which email to send.  Each variant maps to a pair of template
/// files (`{name}.html` / `{name}.txt`) under `EMAIL_TEMPLATES_DIR`.
pub enum EmailKind {
    /// Email-address confirmation sent after signup.
    Confirmation,
    /// Password-recovery link.
    Recovery,
    /// Passwordless magic-link for sign-in / OTP flows.
    MagicLink,
}

impl EmailKind {
    /// Base file name (without extension) used when looking up template files.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Confirmation => "confirm",
            Self::Recovery => "recovery",
            Self::MagicLink => "magic_link",
        }
    }

    /// Default `Subject:` header for this email type.
    pub fn subject(&self) -> &'static str {
        match self {
            Self::Confirmation => "Confirm your email address",
            Self::Recovery => "Reset your password",
            Self::MagicLink => "Your magic link",
        }
    }

    fn default_html(&self) -> &'static str {
        match self {
            Self::Confirmation => DEFAULT_CONFIRM_HTML,
            Self::Recovery => DEFAULT_RECOVERY_HTML,
            Self::MagicLink => DEFAULT_MAGIC_LINK_HTML,
        }
    }

    fn default_text(&self) -> &'static str {
        match self {
            Self::Confirmation => DEFAULT_CONFIRM_TXT,
            Self::Recovery => DEFAULT_RECOVERY_TXT,
            Self::MagicLink => DEFAULT_MAGIC_LINK_TXT,
        }
    }
}

// ── Mailer config ────────────────────────────────────────────────────────────

pub struct MailerConfig {
    pub from_email: String,
    pub from_name: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    /// `true` → STARTTLS (port 587); `false` → plain/no-TLS (e.g. MailHog on port 1025).
    pub smtp_tls: bool,
    /// Directory path checked for HTML/text template overrides at send time.
    pub templates_dir: String,
}

// ── Mailer ───────────────────────────────────────────────────────────────────

pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    config: MailerConfig,
}

impl std::fmt::Debug for Mailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mailer")
            .field("smtp_host", &self.config.smtp_host)
            .field("smtp_port", &self.config.smtp_port)
            .finish_non_exhaustive()
    }
}

impl Mailer {
    pub fn new(config: MailerConfig) -> anyhow::Result<Self> {
        let transport = build_transport(&config)?;
        Ok(Self { transport, config })
    }

    /// Load `{kind}.html` and `{kind}.txt` from `templates_dir`, falling back
    /// to the built-in defaults when the files are absent.
    fn load_template(&self, kind: &EmailKind) -> (String, String) {
        let dir = Path::new(&self.config.templates_dir);
        let name = kind.name();
        let html = std::fs::read_to_string(dir.join(format!("{name}.html")))
            .unwrap_or_else(|_| kind.default_html().to_string());
        let text = std::fs::read_to_string(dir.join(format!("{name}.txt")))
            .unwrap_or_else(|_| kind.default_text().to_string());
        (html, text)
    }

    /// Render and send an email.
    ///
    /// `vars` is a slice of `(key, value)` pairs substituted into every
    /// `{{key}}` placeholder in both the HTML and plain-text templates.
    pub async fn send(
        &self,
        kind: EmailKind,
        to_email: &str,
        vars: &[(&str, &str)],
    ) -> anyhow::Result<()> {
        let (html_tpl, txt_tpl) = self.load_template(&kind);
        let html = render(&html_tpl, vars);
        let text = render(&txt_tpl, vars);

        let from: Mailbox = format!("{} <{}>", self.config.from_name, self.config.from_email)
            .parse()?;
        let to: Mailbox = to_email.parse()?;

        let message = Message::builder()
            .from(from)
            .to(to)
            .subject(kind.subject())
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(text),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body(html),
                    ),
            )?;

        self.transport.send(message).await?;
        Ok(())
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

fn build_transport(config: &MailerConfig) -> anyhow::Result<AsyncSmtpTransport<Tokio1Executor>> {
    let transport = if config.smtp_tls {
        let builder = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)?
            .port(config.smtp_port);
        if config.smtp_username.is_empty() {
            builder.build()
        } else {
            builder
                .credentials(Credentials::new(
                    config.smtp_username.clone(),
                    config.smtp_password.clone(),
                ))
                .build()
        }
    } else {
        let builder =
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.smtp_host)
                .port(config.smtp_port);
        if config.smtp_username.is_empty() {
            builder.build()
        } else {
            builder
                .credentials(Credentials::new(
                    config.smtp_username.clone(),
                    config.smtp_password.clone(),
                ))
                .build()
        }
    };
    Ok(transport)
}

/// Replaces every `{{key}}` placeholder in `template` with its matching value.
fn render(template: &str, vars: &[(&str, &str)]) -> String {
    let mut result = template.to_string();
    for (key, value) in vars {
        result = result.replace(&format!("{{{{{key}}}}}"), value);
    }
    result
}

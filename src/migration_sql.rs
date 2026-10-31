//! Extract the forward half of a Haya SQL migration.
//!
//! A migration is either a single up script or an up script followed by
//! `-- !DOWN` and a rollback script. `-- !UP` is optional for older files, so
//! a missing marker must not turn the whole up script into a no-op.

/// Return the SQL that should run for `migration up`.
///
/// - `-- !UP` present: everything between it and `-- !DOWN`.
/// - No `-- !UP`, with `-- !DOWN`: everything before `-- !DOWN`.
/// - No markers: the whole file.
pub(crate) fn migration_up_sql(sql: &str) -> String {
  let mut in_up = false;
  let mut saw_up = false;
  let mut lines = Vec::new();

  for line in sql.lines() {
    match line.trim() {
      "-- !UP" => {
        in_up = true;
        saw_up = true;
      },
      "-- !DOWN" => {
        in_up = false;
      },
      _ if in_up => lines.push(line),
      _ => {},
    }
  }

  if saw_up {
    let mut up_sql = lines.join("\n");
    up_sql.push('\n');
    return up_sql;
  }

  match sql.split_once("-- !DOWN") {
    Some((up, _)) => {
      let mut up_sql = up.to_string();
      if !up_sql.ends_with('\n') {
        up_sql.push('\n');
      }
      up_sql
    },
    None => sql.to_string(),
  }
}

#[cfg(test)]
mod tests {
  use super::migration_up_sql;

  #[test]
  fn returns_a_file_without_markers_unchanged() {
    let sql = "alter table auth.users add column x integer;\n";
    assert_eq!(migration_up_sql(sql), sql);
  }

  #[test]
  fn extracts_the_up_section_between_markers() {
    let sql = "-- !UP\nalter table auth.users add column x integer;\n-- !DOWN\nalter table auth.users drop column x;\n";
    assert_eq!(
      migration_up_sql(sql),
      "alter table auth.users add column x integer;\n"
    );
  }

  #[test]
  fn treats_a_down_only_file_as_the_up_script() {
    // Regression: the passkey migration shipped with `-- !DOWN` but no
    // `-- !UP`, was applied as empty SQL, and still recorded its version.
    let sql = "alter table auth.mfa_factors add column web_authn_credential_id bytea;\n\n-- !DOWN\nalter table auth.mfa_factors drop column web_authn_credential_id;\n";
    assert_eq!(
      migration_up_sql(sql),
      "alter table auth.mfa_factors add column web_authn_credential_id bytea;\n\n"
    );
  }

  #[test]
  fn ignores_statements_after_the_down_marker() {
    let sql = "-- !UP\nselect 1;\n-- !DOWN\nselect 2;\nselect 3;\n";
    assert_eq!(migration_up_sql(sql), "select 1;\n");
  }
}

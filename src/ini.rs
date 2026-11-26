//! Parser for `.repo` files and `rpf.conf` (the INI dialect dnf uses).
//!
//! Deliberately permissive: real-world repo files contain quoted values,
//! inline comments after values, CRLF line endings and duplicate keys
//! (last one wins), and a package manager that chokes on them is a bad
//! package manager.

use crate::{Error, Result};

#[derive(Debug, Clone, Default)]
pub struct Section {
    pub name: String,
    entries: Vec<(String, String)>,
}

impl Section {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Interpret a value as a boolean the way dnf does (`1/0`, `yes/no`,
    /// `true/false`, case-insensitive).
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).map(parse_bool).or(None).and_then(|b| b)
    }

    pub fn get_bool_or(&self, key: &str, default: bool) -> bool {
        self.get_bool(key).unwrap_or(default)
    }

    pub fn get_i64_or(&self, key: &str, default: i64) -> i64 {
        self.get(key)
            .and_then(|v| v.trim().parse::<i64>().ok())
            .unwrap_or(default)
    }

    pub fn get_u32_or(&self, key: &str, default: u32) -> u32 {
        self.get(key)
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(default)
    }

    /// Split a whitespace/comma separated list value.
    pub fn get_list(&self, key: &str) -> Vec<String> {
        self.get(key)
            .map(|v| {
                v.split(|c: char| c.is_whitespace() || c == ',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn entries(&self) -> &[(String, String)] {
        &self.entries
    }

    pub fn set(&mut self, key: &str, value: &str) {
        if let Some(existing) = self.entries.iter_mut().find(|(k, _)| k == key) {
            existing.1 = value.to_string();
        } else {
            self.entries.push((key.to_string(), value.to_string()));
        }
    }
}

fn parse_bool(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" | "enabled" => Some(true),
        "0" | "no" | "false" | "off" | "disabled" => Some(false),
        _ => None,
    }
}

#[derive(Debug, Clone, Default)]
pub struct Ini {
    pub sections: Vec<Section>,
    /// Text before the first section header, useful for diagnostics.
    pub preamble: Vec<String>,
}

impl Ini {
    pub fn parse(text: &str) -> Result<Ini> {
        let mut ini = Ini::default();
        let mut current: Option<Section> = None;

        for raw in text.lines() {
            // Normalise CRLF and strip a UTF-8 BOM on the first line.
            let line = raw.trim_start_matches('\u{feff}').trim();

            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            if line.starts_with('[') {
                let end = line.find(']').ok_or_else(|| {
                    Error::new(format!("malformed section header: {:?}", line))
                })?;
                let name = line[1..end].trim().to_string();
                if name.is_empty() {
                    return Err(Error::new("empty section name"));
                }
                if let Some(sec) = current.take() {
                    ini.sections.push(sec);
                }
                current = Some(Section {
                    name,
                    entries: Vec::new(),
                });
                continue;
            }

            let Some(sec) = current.as_mut() else {
                ini.preamble.push(line.to_string());
                continue;
            };

            let Some(eq) = line.find('=') else {
                // A bare key is legal-ish; record it as an empty value.
                sec.entries.push((line.to_string(), String::new()));
                continue;
            };

            let key = line[..eq].trim().to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            let mut value = line[eq + 1..].trim().to_string();

            // Strip matching quotes.
            if value.len() >= 2 {
                let b = value.as_bytes();
                if (b[0] == b'"' && b[b.len() - 1] == b'"')
                    || (b[0] == b'\'' && b[b.len() - 1] == b'\'')
                {
                    value = value[1..value.len() - 1].to_string();
                }
            }
            sec.entries.push((key, value));
        }

        if let Some(sec) = current.take() {
            ini.sections.push(sec);
        }
        Ok(ini)
    }

    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn section_mut(&mut self, name: &str) -> Option<&mut Section> {
        self.sections.iter_mut().find(|s| s.name == name)
    }

    pub fn section_names(&self) -> Vec<String> {
        self.sections.iter().map(|s| s.name.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_fedora_repo_file() {
        let text = r#"
# comment
[fedora]
name=Fedora $releasever - $basearch
metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-$releasever&arch=$basearch
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-$releasever-$basearch

[fedora-debuginfo]
name=Fedora $releasever - $basearch - Debug
enabled=0
"#;
        let ini = Ini::parse(text).unwrap();
        assert_eq!(ini.section_names(), vec!["fedora", "fedora-debuginfo"]);

        let fedora = ini.section("fedora").unwrap();
        assert_eq!(fedora.get("name"), Some("Fedora $releasever - $basearch"));
        assert!(fedora.get_bool("enabled").unwrap());
        assert!(!ini.section("fedora-debuginfo").unwrap().get_bool("enabled").unwrap());
        assert_eq!(fedora.get_list("gpgkey").len(), 1);
    }

    #[test]
    fn tolerates_quotes_comments_and_crlf() {
        let text = "[a]\r\nname = \"Quoted Value\"\r\nenabled=yes\r\n; note\r\n";
        let ini = Ini::parse(text).unwrap();
        let a = ini.section("a").unwrap();
        assert_eq!(a.get("name"), Some("Quoted Value"));
        assert_eq!(a.get_bool("enabled"), Some(true));
    }

    #[test]
    fn multiple_values_in_one_key() {
        let text = "[a]\nbaseurl=https://one/ https://two/\ngpgkey=file:///k1 file:///k2\n";
        let ini = Ini::parse(text).unwrap();
        let a = ini.section("a").unwrap();
        assert_eq!(a.get_list("baseurl"), vec!["https://one/", "https://two/"]);
        assert_eq!(a.get_list("gpgkey"), vec!["file:///k1", "file:///k2"]);
    }

    #[test]
    fn last_duplicate_key_wins() {
        let text = "[a]\nenabled=0\nenabled=1\n";
        let ini = Ini::parse(text).unwrap();
        assert_eq!(ini.section("a").unwrap().get_bool("enabled"), Some(true));
    }

    #[test]
    fn malformed_section_is_an_error() {
        assert!(Ini::parse("[unclosed\nkey=1\n").is_err());
    }
}

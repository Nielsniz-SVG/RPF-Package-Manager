//! A small, allocation-light XML pull parser.
//!
//! RPF has to read repository metadata (`repomd.xml`, `primary.xml`,
//! `metalink`) without pulling in a crate, and `primary.xml` for a full Fedora
//! release is hundreds of megabytes once decompressed. A DOM would be wasteful,
//! so the core is a pull parser that borrows element names straight out of the
//! source buffer; a tiny DOM (`parse`) is layered on top for small documents.
//!
//! Supported: elements, attributes, self-closing tags, text, CDATA, comments,
//! processing instructions, DOCTYPE (skipped), and the standard entities.

use crate::{Error, Result};

/// Events are emitted in document order. A self-closing tag such as `<empty/>`
/// produces a single `Start` with `self_closing: true` and **no** matching
/// `End`, so `Start`/`End` stay balanced for every non-self-closing element.
#[derive(Debug)]
pub enum Event<'a> {
    Start {
        name: &'a str,
        attrs: Vec<(&'a str, &'a str)>,
        self_closing: bool,
    },
    End {
        name: &'a str,
    },
    Text(&'a str),
}

pub struct XmlParser<'a> {
    src: &'a str,
    pos: usize,
    done: bool,
}

impl<'a> XmlParser<'a> {
    pub fn new(src: &'a str) -> Self {
        // Skip a UTF-8 BOM if present.
        let pos = if src.starts_with('\u{feff}') { 3 } else { 0 };
        XmlParser {
            src,
            pos,
            done: false,
        }
    }

    pub fn next_event(&mut self) -> Result<Option<Event<'a>>> {
        if self.done || self.pos >= self.src.len() {
            return Ok(None);
        }

        let bytes = self.src.as_bytes();

        // Text before the next '<'.
        if bytes[self.pos] != b'<' {
            let end = self.src[self.pos..]
                .find('<')
                .map(|i| self.pos + i)
                .unwrap_or(self.src.len());
            let text = &self.src[self.pos..end];
            self.pos = end;
            if text.is_empty() {
                return self.next_event();
            }
            return Ok(Some(Event::Text(text)));
        }

        // Comments.
        if self.src[self.pos..].starts_with("<!--") {
            let end = self.src[self.pos + 4..]
                .find("-->")
                .ok_or_else(|| Error::new("unterminated XML comment"))?;
            self.pos = self.pos + 4 + end + 3;
            return self.next_event();
        }

        // CDATA.
        if self.src[self.pos..].starts_with("<![CDATA[") {
            let start = self.pos + 9;
            let end = self.src[start..]
                .find("]]>")
                .ok_or_else(|| Error::new("unterminated CDATA section"))?;
            let text = &self.src[start..start + end];
            self.pos = start + end + 3;
            return Ok(Some(Event::Text(text)));
        }

        // DOCTYPE or other declarations; skip to the matching '>' accounting
        // for an optional internal subset in brackets.
        if self.src[self.pos..].starts_with("<!") {
            let mut i = self.pos + 2;
            let mut depth = 0i32;
            let b = self.src.as_bytes();
            while i < b.len() {
                match b[i] {
                    b'[' => depth += 1,
                    b']' => depth -= 1,
                    b'>' if depth <= 0 => break,
                    _ => {}
                }
                i += 1;
            }
            self.pos = (i + 1).min(self.src.len());
            return self.next_event();
        }

        // Processing instruction.
        if self.src[self.pos..].starts_with("<?") {
            let end = self.src[self.pos + 2..]
                .find("?>")
                .ok_or_else(|| Error::new("unterminated XML processing instruction"))?;
            self.pos = self.pos + 2 + end + 2;
            return self.next_event();
        }

        // Closing tag.
        if self.src[self.pos..].starts_with("</") {
            let end = self.src[self.pos + 2..]
                .find('>')
                .ok_or_else(|| Error::new("unterminated XML closing tag"))?;
            let name = self.src[self.pos + 2..self.pos + 2 + end].trim();
            self.pos = self.pos + 2 + end + 1;
            return Ok(Some(Event::End { name }));
        }

        // Opening tag.
        self.pos += 1;
        let name_start = self.pos;
        while self.pos < bytes.len() && !is_name_end(bytes[self.pos]) {
            self.pos += 1;
        }
        let name = &self.src[name_start..self.pos];
        if name.is_empty() {
            return Err(Error::new("empty XML element name"));
        }

        let mut attrs = Vec::new();
        let mut self_closing = false;
        loop {
            self.skip_ws();
            if self.pos >= bytes.len() {
                return Err(Error::new(format!("unterminated XML tag <{}>", name)));
            }
            match bytes[self.pos] {
                b'>' => {
                    self.pos += 1;
                    break;
                }
                b'/' if self.pos + 1 < bytes.len() && bytes[self.pos + 1] == b'>' => {
                    self.pos += 2;
                    self_closing = true;
                    break;
                }
                _ => {
                    let attr_start = self.pos;
                    while self.pos < bytes.len()
                        && !is_name_end(bytes[self.pos])
                        && bytes[self.pos] != b'='
                    {
                        self.pos += 1;
                    }
                    let attr_name = &self.src[attr_start..self.pos];
                    self.skip_ws();
                    if self.pos >= bytes.len() || bytes[self.pos] != b'=' {
                        // Valueless attribute: treat as empty.
                        if !attr_name.is_empty() {
                            attrs.push((attr_name, ""));
                        }
                        continue;
                    }
                    self.pos += 1; // '='
                    self.skip_ws();
                    if self.pos >= bytes.len() {
                        return Err(Error::new("unterminated XML attribute"));
                    }
                    let quote = bytes[self.pos];
                    if quote != b'"' && quote != b'\'' {
                        // Unquoted value: read to whitespace or '>'.
                        let start = self.pos;
                        while self.pos < bytes.len()
                            && !bytes[self.pos].is_ascii_whitespace()
                            && bytes[self.pos] != b'>'
                        {
                            self.pos += 1;
                        }
                        attrs.push((attr_name, &self.src[start..self.pos]));
                    } else {
                        self.pos += 1;
                        let start = self.pos;
                        while self.pos < bytes.len() && bytes[self.pos] != quote {
                            self.pos += 1;
                        }
                        if self.pos >= bytes.len() {
                            return Err(Error::new(format!(
                                "unterminated attribute value in <{}>",
                                name
                            )));
                        }
                        attrs.push((attr_name, &self.src[start..self.pos]));
                        self.pos += 1;
                    }
                }
            }
        }

        Ok(Some(Event::Start {
            name,
            attrs,
            self_closing,
        }))
    }

    fn skip_ws(&mut self) {
        let b = self.src.as_bytes();
        while self.pos < b.len() && b[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }
}

#[inline]
fn is_name_end(b: u8) -> bool {
    b.is_ascii_whitespace() || b == b'>' || b == b'/' || b == b'='
}

/// Decode the standard XML entities and numeric character references.
pub fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some(semi) = s[i..].find(';') {
                let ent = &s[i + 1..i + semi];
                let decoded = match ent {
                    "amp" => Some('&'),
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    _ => {
                        if let Some(hex) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X"))
                        {
                            u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
                        } else if let Some(dec) = ent.strip_prefix('#') {
                            dec.parse::<u32>().ok().and_then(char::from_u32)
                        } else {
                            None
                        }
                    }
                };
                if let Some(c) = decoded {
                    out.push(c);
                    i += semi + 1;
                    continue;
                }
            }
        }
        // Not an entity we understand: copy the byte as part of a char.
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// A cursor with convenience helpers for consuming structured documents.
pub struct Reader<'a> {
    parser: XmlParser<'a>,
}

impl<'a> Reader<'a> {
    pub fn new(src: &'a str) -> Self {
        Reader {
            parser: XmlParser::new(src),
        }
    }

    pub fn next(&mut self) -> Result<Option<Event<'a>>> {
        self.parser.next_event()
    }

    /// Skip forward until the next `Start` event with the given name.
    pub fn until_start(&mut self, name: &str) -> Result<bool> {
        while let Some(ev) = self.next()? {
            if let Event::Start { name: n, .. } = ev {
                if n == name {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Read the text content of the element whose `Start` was just consumed,
    /// up to and including its matching `End`.
    pub fn text(&mut self) -> Result<String> {
        let mut out = String::new();
        let mut depth = 1usize;
        while let Some(ev) = self.next()? {
            match ev {
                Event::Text(t) => out.push_str(&unescape(t)),
                Event::Start { self_closing, .. } => {
                    if !self_closing {
                        depth += 1;
                    }
                }
                Event::End { .. } => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
            }
        }
        Ok(out)
    }

    /// Discard the remainder of the current element (after its `Start`).
    pub fn skip_element(&mut self) -> Result<()> {
        let mut depth = 1usize;
        while let Some(ev) = self.next()? {
            match ev {
                Event::Start { self_closing, .. } => {
                    if !self_closing {
                        depth += 1;
                    }
                }
                Event::End { .. } => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                Event::Text(_) => {}
            }
        }
        Ok(())
    }

    /// Look up an attribute value from a `Start` event's attribute list.
    pub fn attr<'b>(attrs: &'b [(&'a str, &'a str)], name: &str) -> Option<&'a str> {
        attrs.iter().find(|(k, _)| *k == name).map(|(_, v)| *v)
    }
}

/// A minimal DOM node, used for small documents like `repomd.xml`.
#[derive(Debug, Default, Clone)]
pub struct Node {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Node>,
    pub text: String,
}

impl Node {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name == name)
    }

    pub fn children_named<'s, 'n>(&'s self, name: &'n str) -> impl Iterator<Item = &'s Node> + 'n
    where
        's: 'n,
    {
        let name = name.to_string();
        self.children.iter().filter(move |c| c.name == name)
    }

    /// Text of the first descendant path, e.g. `path(&["data", "location"])`.
    pub fn find(&self, path: &[&str]) -> Option<&Node> {
        let mut cur = self;
        for step in path {
            cur = cur.child(step)?;
        }
        Some(cur)
    }
}

/// Parse a complete document into a DOM. Intended for small files.
pub fn parse(src: &str) -> Result<Node> {
    let mut reader = Reader::new(src);
    let mut stack: Vec<Node> = vec![Node {
        name: "#document".to_string(),
        ..Default::default()
    }];

    while let Some(ev) = reader.next()? {
        match ev {
            Event::Start {
                name,
                attrs,
                self_closing,
            } => {
                let node = Node {
                    name: name.to_string(),
                    attrs: attrs
                        .iter()
                        .map(|(k, v)| (k.to_string(), unescape(v)))
                        .collect(),
                    children: Vec::new(),
                    text: String::new(),
                };
                if self_closing {
                    stack.last_mut().unwrap().children.push(node);
                } else {
                    stack.push(node);
                }
            }
            Event::End { .. } => {
                if stack.len() > 1 {
                    let node = stack.pop().unwrap();
                    stack.last_mut().unwrap().children.push(node);
                }
            }
            Event::Text(t) => {
                let parent = stack.last_mut().unwrap();
                parent.text.push_str(&unescape(t));
            }
        }
    }

    // Unwind any unbalanced elements rather than failing; repositories in the
    // wild occasionally serve sloppy XML.
    while stack.len() > 1 {
        let node = stack.pop().unwrap();
        stack.last_mut().unwrap().children.push(node);
    }
    Ok(stack.pop().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_elements_attributes_and_text() {
        let doc = r#"<?xml version="1.0"?>
        <!-- a comment -->
        <root a="1" b='two &amp; three'>
          <child>hello</child>
          <empty/>
          <self attr="x"/>
        </root>"#;
        let root = parse(doc).unwrap();
        let r = root.child("root").unwrap();
        assert_eq!(r.attr("a"), Some("1"));
        assert_eq!(r.attr("b"), Some("two & three"));
        assert_eq!(r.child("child").unwrap().text.trim(), "hello");
        assert!(r.child("empty").is_some());
        assert_eq!(r.child("self").unwrap().attr("attr"), Some("x"));
    }

    #[test]
    fn handles_cdata_and_numeric_entities() {
        let doc = "<r><v><![CDATA[a < b]]></v><n>&#65;&#x42;</n></r>";
        let root = parse(doc).unwrap();
        let r = root.child("r").unwrap();
        assert_eq!(r.child("v").unwrap().text, "a < b");
        assert_eq!(r.child("n").unwrap().text, "AB");
    }

    #[test]
    fn handles_doctype_and_comments_before_root() {
        let doc = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE repomd>
<!-- comment -->
<repomd><revision>123</revision></repomd>"#;
        let root = parse(doc).unwrap();
        let repomd = root.child("repomd").unwrap();
        assert_eq!(repomd.find(&["revision"]).unwrap().text, "123");
    }

    #[test]
    fn handles_utf8_text() {
        let doc = "<r><n>Fédora — ünïcode</n></r>";
        let root = parse(doc).unwrap();
        assert_eq!(root.child("r").unwrap().child("n").unwrap().text, "Fédora — ünïcode");
    }

    #[test]
    fn pull_parser_emits_balanced_events() {
        let src = "<a><b/><c>x</c></a>";
        let mut p = XmlParser::new(src);
        let mut depth = 0i32;
        let mut starts = Vec::new();
        while let Some(ev) = p.next_event().unwrap() {
            match ev {
                Event::Start {
                    name,
                    self_closing,
                    ..
                } => {
                    starts.push(name);
                    if !self_closing {
                        depth += 1;
                    }
                }
                Event::End { .. } => depth -= 1,
                Event::Text(_) => {}
            }
            assert!(depth >= 0);
        }
        assert_eq!(depth, 0);
        assert_eq!(starts, vec!["a", "b", "c"]);
    }

    #[test]
    fn unescape_all_entities() {
        assert_eq!(unescape("&lt;&gt;&amp;&quot;&apos;"), "<>&\"'");
        assert_eq!(unescape("no entities"), "no entities");
        assert_eq!(unescape("100&#37;"), "100%");
    }

    #[test]
    fn unbalanced_document_does_not_panic() {
        let root = parse("<a><b>text").unwrap();
        let a = root.child("a").unwrap();
        assert_eq!(a.child("b").unwrap().text, "text");
    }
}

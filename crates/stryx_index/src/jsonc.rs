//! Strip `//` line comments, `/* … */` block comments, and trailing
//! commas from JSON-with-comments input. Adequate for `tsconfig.json`
//! and similar files that don't conform to strict JSON. Quoted strings
//! are honoured so `"//"` inside a string isn't mistaken for a comment.
//! This is *not* a full JSON5 parser.

pub fn strip_jsonc(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escape = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                out.push(c);
                in_string = true;
            }
            '/' if chars.peek() == Some(&'/') => {
                while let Some(&n) = chars.peek() {
                    if n == '\n' {
                        break;
                    }
                    chars.next();
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                while let Some(n) = chars.next() {
                    if n == '*' && chars.peek() == Some(&'/') {
                        chars.next();
                        break;
                    }
                }
            }
            _ => out.push(c),
        }
    }
    let bytes = out.into_bytes();
    let mut cleaned = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b',' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == b']' || bytes[j] == b'}') {
                i += 1;
                continue;
            }
        }
        cleaned.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(cleaned).expect("ascii-safe transform")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_line_and_block_comments() {
        let input = r#"{
          // line comment
          "a": 1, /* inline */ "b": 2 /* trailing */
        }"#;
        let out = strip_jsonc(input);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["a"], 1);
        assert_eq!(v["b"], 2);
    }

    #[test]
    fn preserves_comment_lookalikes_in_strings() {
        let input = r#"{"url": "https://example.com/path"}"#;
        let out = strip_jsonc(input);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["url"], "https://example.com/path");
    }

    #[test]
    fn strips_trailing_commas() {
        let input = r#"{"a": [1, 2, 3,], "b": 4,}"#;
        let out = strip_jsonc(input);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["a"][2], 3);
        assert_eq!(v["b"], 4);
    }
}

use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaderMode {
    Original,
    Reader,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReaderDocument {
    pub source_url: Option<Url>,
    pub title: Option<String>,
    pub paragraphs: Vec<String>,
}

impl ReaderDocument {
    #[must_use]
    pub fn text(&self) -> String {
        self.paragraphs.join("\n\n")
    }
    #[must_use]
    pub fn word_count(&self) -> usize {
        self.paragraphs
            .iter()
            .flat_map(|paragraph| paragraph.split_whitespace())
            .count()
    }
}

#[must_use]
pub fn reader_document_from_html(html: &str, source_url: Option<Url>) -> ReaderDocument {
    let title = extract_tag_text(html, "title");
    let mut body = html.to_owned();
    for tag in ["script", "style", "noscript", "template"] {
        body = remove_tag_blocks(&body, tag);
    }
    let mut boundaries = body;
    for marker in [
        "</title>",
        "</p>",
        "</article>",
        "</section>",
        "<br",
        "</h1>",
        "</h2>",
        "</h3>",
    ] {
        boundaries = boundaries.replace(marker, "\n");
    }
    let mut paragraphs = Vec::new();
    for chunk in boundaries.lines() {
        let text = normalize_whitespace(&strip_tags(chunk));
        if text.len() >= 2 {
            paragraphs.push(text);
        }
    }
    if paragraphs.is_empty() {
        let text = normalize_whitespace(&strip_tags(&boundaries));
        if !text.is_empty() {
            paragraphs.push(text);
        }
    }
    ReaderDocument {
        source_url,
        title,
        paragraphs,
    }
}

fn extract_tag_text(html: &str, tag: &str) -> Option<String> {
    let lowercase = html.to_ascii_lowercase();
    let start = lowercase.find(&format!("<{tag}"))?;
    let content_start = lowercase[start..].find('>')?.saturating_add(start + 1);
    let end = lowercase[content_start..]
        .find(&format!("</{tag}>"))?
        .saturating_add(content_start);
    let text = normalize_whitespace(&strip_tags(&html[content_start..end]));
    (!text.is_empty()).then_some(text)
}

fn remove_tag_blocks(input: &str, tag: &str) -> String {
    let mut output = input.to_owned();
    loop {
        let lowercase = output.to_ascii_lowercase();
        let Some(start) = lowercase.find(&format!("<{tag}")) else {
            break;
        };
        let Some(end_offset) = lowercase[start..].find(&format!("</{tag}>")) else {
            output.replace_range(start.., "");
            break;
        };
        let end = start + end_offset + tag.len() + 3;
        output.replace_range(start..end, " ");
    }
    output
}

fn strip_tags(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut inside_tag = false;
    for character in input.chars() {
        match character {
            '<' => inside_tag = true,
            '>' => inside_tag = false,
            _ if !inside_tag => output.push(character),
            _ => {}
        }
    }
    output
}

fn normalize_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::reader_document_from_html;

    #[test]
    fn reader_removes_code_and_keeps_article_text() {
        let document = reader_document_from_html(
            "<title>Story</title><script>bad()</script><article><p>Hello <b>reader</b>.</p><p>Second.</p></article>",
            None,
        );
        assert_eq!(document.title.as_deref(), Some("Story"));
        assert_eq!(document.paragraphs, ["Story", "Hello reader.", "Second."]);
        assert_eq!(document.word_count(), 4);
    }
}

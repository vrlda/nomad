//! Local PDF viewer support for the native Servo embedder.
//!
//! PDF.js is distributed under the Apache License 2.0. The source bundled in
//! Servo's WPT fixtures is used here as an interim engine asset until Nomad
//! carries a separately versioned viewer resource package.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use std::fmt::{Display, Formatter};
use url::Url;

const PDF_JS: &str =
    include_str!("../../../vendor/servo/tests/wpt/tests/tools/third_party/pdf_js/pdf.js");
const PDF_WORKER_JS: &str =
    include_str!("../../../vendor/servo/tests/wpt/tests/tools/third_party/pdf_js/pdf.worker.js");

/// Maximum PDF size that Nomad will copy into the isolated local viewer.
///
/// The viewer is data-backed instead of allowing PDF.js to fetch arbitrary
/// URLs. The bound prevents a navigation from causing unbounded browser-side
/// base64, canvas, and text-layer allocations.
pub(crate) const MAX_PDF_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PdfValidationError {
    Empty,
    TooLarge { size: usize, limit: usize },
    MissingHeader,
    MissingEndMarker,
}

impl Display for PdfValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("the downloaded file is empty"),
            Self::TooLarge { size, limit } => {
                write!(
                    formatter,
                    "the PDF is too large ({size} bytes; limit {limit} bytes)"
                )
            }
            Self::MissingHeader => formatter.write_str("the file does not contain a PDF header"),
            Self::MissingEndMarker => {
                formatter.write_str("the file does not contain a complete PDF end marker")
            }
        }
    }
}

fn validate_pdf_bytes_with_limit(bytes: &[u8], limit: usize) -> Result<(), PdfValidationError> {
    if bytes.is_empty() {
        return Err(PdfValidationError::Empty);
    }
    if bytes.len() > limit {
        return Err(PdfValidationError::TooLarge {
            size: bytes.len(),
            limit,
        });
    }
    if !bytes.starts_with(b"%PDF-") {
        return Err(PdfValidationError::MissingHeader);
    }
    if !bytes
        .windows(b"%%EOF".len())
        .any(|window| window == b"%%EOF")
    {
        return Err(PdfValidationError::MissingEndMarker);
    }
    Ok(())
}

pub(crate) fn validate_pdf_bytes(bytes: &[u8]) -> Result<(), PdfValidationError> {
    validate_pdf_bytes_with_limit(bytes, MAX_PDF_BYTES)
}

pub(crate) fn is_pdf_navigation(url: &Url, is_for_main_frame: bool) -> bool {
    is_for_main_frame
        && url
            .path_segments()
            .and_then(|mut segments| segments.next_back())
            .is_some_and(|name| name.to_ascii_lowercase().ends_with(".pdf"))
}

#[allow(clippy::too_many_lines)] // Body is a single embedded HTML document template.
pub(crate) fn viewer_html(source_url: &Url, bytes: &[u8]) -> String {
    let encoded_pdf = BASE64.encode(bytes);
    let encoded_worker = BASE64.encode(PDF_WORKER_JS.as_bytes());
    let source_url_raw = source_url.as_str();
    let source_url = html_escape(source_url_raw);
    let source_url_js = javascript_string(source_url_raw);
    let pdf_js = PDF_JS;
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PDF — {source_url}</title>
<style>
:root {{ color-scheme: light dark; }}
* {{ box-sizing: border-box; }}
html, body {{ margin: 0; min-height: 100%; background: #202124; color: #f1f3f4; font: 14px system-ui, sans-serif; }}
body {{ display: flex; flex-direction: column; }}
header {{ position: sticky; top: 0; z-index: 2; display: flex; gap: 12px; align-items: center; padding: 10px 14px; background: #292a2d; border-bottom: 1px solid #45464a; }}
header strong {{ overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }}
button {{ border: 1px solid #686a70; border-radius: 5px; background: #35363a; color: inherit; padding: 5px 9px; cursor: pointer; }}
button:disabled {{ opacity: .5; cursor: default; }}
#pages {{ display: grid; gap: 18px; justify-items: center; padding: 22px; }}
.page {{ position: relative; min-height: 120px; width: min(100%, 920px); display: grid; place-items: center; background: white; box-shadow: 0 2px 14px #0008; }}
.page canvas {{ display: block; max-width: 100%; height: auto; }}
.textLayer {{ position: absolute; inset: 0; overflow: hidden; line-height: 1; user-select: text; cursor: text; }}
.textLayer span, .textLayer br {{ position: absolute; white-space: pre; transform-origin: 0% 0%; color: transparent; }}
.textLayer ::selection {{ background: rgba(0, 96, 255, .35); }}
.error {{ color: #ffb4ab; padding: 30px; text-align: center; }}
@media print {{
  header {{ display: none; }}
  html, body {{ background: white; color: black; }}
  #pages {{ display: block; padding: 0; }}
  .page {{ width: 100%; min-height: 0; box-shadow: none; break-after: page; }}
}}
</style>
</head>
<body>
<header>
  <strong id="title">PDF</strong>
  <span id="page-count">Loading…</span>
  <button id="previous" disabled>Previous</button>
  <button id="next" disabled>Next</button>
  <button id="zoom-out">−</button>
  <button id="zoom-in">+</button>
  <input id="search" type="search" placeholder="Find in PDF" aria-label="Find in PDF" disabled>
  <button id="search-previous" disabled aria-label="Previous match">↑</button>
  <button id="search-next" disabled aria-label="Next match">↓</button>
  <span id="search-status" role="status"></span>
  <button id="download" disabled>Download</button>
  <button id="print" disabled>Print</button>
</header>
<main id="pages" aria-live="polite"></main>
<script>{pdf_js}</script>
<script>
(() => {{
  const pdfBytes = Uint8Array.from(atob("{encoded_pdf}"), value => value.charCodeAt(0));
  const workerSource = atob("{encoded_worker}");
  const workerUrl = URL.createObjectURL(new Blob([workerSource], {{ type: "application/javascript" }}));
  pdfjsLib.GlobalWorkerOptions.workerSrc = workerUrl;
  const pages = document.getElementById("pages");
  const title = document.getElementById("title");
  const pageCount = document.getElementById("page-count");
  const previous = document.getElementById("previous");
  const next = document.getElementById("next");
  const search = document.getElementById("search");
  const searchPrevious = document.getElementById("search-previous");
  const searchNext = document.getElementById("search-next");
  const searchStatus = document.getElementById("search-status");
  const download = document.getElementById("download");
  const print = document.getElementById("print");
  let documentProxy;
  let currentPage = 1;
  let scale = 1.25;
  const rendered = new Map();
  const textCache = new Map();
  let searchMatches = [];
  let searchCursor = 0;

  const renderPage = async (pageNumber) => {{
    if (!documentProxy || rendered.has(pageNumber)) return;
    const page = await documentProxy.getPage(pageNumber);
    const viewport = page.getViewport({{ scale }});
    const container = document.createElement("section");
    container.className = "page";
    container.dataset.page = pageNumber;
    container.setAttribute("aria-label", `Page ${{pageNumber}}`);
    const canvas = document.createElement("canvas");
    canvas.width = viewport.width;
    canvas.height = viewport.height;
    const textLayer = document.createElement("div");
    textLayer.className = "textLayer";
    textLayer.setAttribute("aria-label", `Selectable text for page ${{pageNumber}}`);
    container.appendChild(canvas);
    container.appendChild(textLayer);
    pages.appendChild(container);
    await page.render({{ canvasContext: canvas.getContext("2d"), viewport }}).promise;
    const textContent = await page.getTextContent();
    const textTask = pdfjsLib.renderTextLayer({{
      textContent,
      container: textLayer,
      viewport,
      enhanceTextSelection: true,
    }});
    await textTask.promise;
    textCache.set(pageNumber, textContent.items.map(item => item.str).join(" "));
    rendered.set(pageNumber, container);
  }};

  const updatePager = () => {{
    if (!documentProxy) return;
    pageCount.textContent = `Page ${{currentPage}} / ${{documentProxy.numPages}}`;
    previous.disabled = currentPage <= 1;
    next.disabled = currentPage >= documentProxy.numPages;
  }};
  const renderVisible = () => renderPage(currentPage).then(() => {{
    updatePager();
    rendered.get(currentPage)?.scrollIntoView({{ block: "start", behavior: "smooth" }});
  }}).catch(showError);
  const rerender = () => {{
    pages.replaceChildren();
    rendered.clear();
    textCache.clear();
    return renderVisible();
  }};
  const showError = error => {{
    pages.textContent = "";
    const message = document.createElement("p");
    message.className = "error";
    message.textContent = `Unable to render this PDF: ${{error}}`;
    pages.appendChild(message);
  }};

  const pageText = async pageNumber => {{
    if (textCache.has(pageNumber)) return textCache.get(pageNumber);
    const page = await documentProxy.getPage(pageNumber);
    const content = await page.getTextContent();
    const text = content.items.map(item => item.str).join(" ");
    textCache.set(pageNumber, text);
    return text;
  }};

  const focusMatch = async () => {{
    if (!searchMatches.length) return;
    currentPage = searchMatches[searchCursor];
    updatePager();
    await renderVisible();
    searchStatus.textContent = `${{searchCursor + 1}} / ${{searchMatches.length}}`;
  }};

  const findMatches = async () => {{
    const query = search.value.trim().toLocaleLowerCase();
    searchMatches = [];
    searchCursor = 0;
    if (!query) {{
      searchStatus.textContent = "";
      searchPrevious.disabled = true;
      searchNext.disabled = true;
      return;
    }}
    searchStatus.textContent = "Searching…";
    for (let pageNumber = 1; pageNumber <= documentProxy.numPages; pageNumber += 1) {{
      const text = (await pageText(pageNumber)).toLocaleLowerCase();
      if (text.includes(query)) searchMatches.push(pageNumber);
    }}
    searchPrevious.disabled = !searchMatches.length;
    searchNext.disabled = !searchMatches.length;
    if (!searchMatches.length) {{
      searchStatus.textContent = "No matches";
      return;
    }}
    await focusMatch();
  }};

  const printAllPages = async () => {{
    print.disabled = true;
    try {{
      for (let pageNumber = 1; pageNumber <= documentProxy.numPages; pageNumber += 1) {{
        await renderPage(pageNumber);
      }}
      window.print();
    }} finally {{
      print.disabled = false;
    }}
  }};

  pdfjsLib.getDocument({{ data: pdfBytes }}).promise.then(async loaded => {{
    documentProxy = loaded;
    title.textContent = {source_url_js};
    search.disabled = false;
    download.disabled = false;
    print.disabled = false;
    searchNext.disabled = false;
    updatePager();
    await renderPage(currentPage);
    updatePager();
  }}).catch(showError);

  previous.onclick = () => {{
    if (currentPage > 1) {{ currentPage -= 1; renderVisible(); }}
  }};
  next.onclick = () => {{
    if (documentProxy && currentPage < documentProxy.numPages) {{ currentPage += 1; renderVisible(); }}
  }};
  document.getElementById("zoom-in").onclick = () => {{ scale = Math.min(3, scale + .15); rerender(); }};
  document.getElementById("zoom-out").onclick = () => {{ scale = Math.max(.5, scale - .15); rerender(); }};
  search.addEventListener("change", () => findMatches().catch(showError));
  search.addEventListener("keydown", event => {{
    if (event.key === "Enter") findMatches().catch(showError);
  }});
  searchPrevious.onclick = () => {{
    if (!searchMatches.length) return;
    searchCursor = (searchCursor - 1 + searchMatches.length) % searchMatches.length;
    focusMatch().catch(showError);
  }};
  searchNext.onclick = () => {{
    if (!searchMatches.length) {{ findMatches().catch(showError); return; }}
    searchCursor = (searchCursor + 1) % searchMatches.length;
    focusMatch().catch(showError);
  }};
  download.onclick = () => {{
    const blob = new Blob([pdfBytes], {{ type: "application/pdf" }});
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "document.pdf";
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 0);
  }};
  print.onclick = () => printAllPages().catch(showError);
}})();
</script>
</body>
</html>"#,
    )
}

pub(crate) fn viewer_error_html(source_url: &Url, message: &str) -> String {
    let source_url = html_escape(source_url.as_str());
    let message = html_escape(message);
    format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PDF error — {source_url}</title>
<style>body {{ margin: 0; padding: 3rem; background: #202124; color: #f1f3f4; font: 16px system-ui, sans-serif; }} main {{ max-width: 46rem; margin: auto; }} p {{ color: #ffb4ab; }} code {{ overflow-wrap: anywhere; }}</style>
</head><body><main><h1>Unable to open this PDF</h1><p>{message}</p><p><code>{source_url}</code></p></main></body></html>"#
    )
}

fn javascript_string(value: &str) -> String {
    serde_json::to_string(value)
        .expect("URL strings are always serializable")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::{
        is_pdf_navigation, validate_pdf_bytes, validate_pdf_bytes_with_limit, viewer_error_html,
        viewer_html, PdfValidationError,
    };
    use url::Url;

    #[test]
    fn only_main_frame_pdf_urls_use_the_viewer() {
        let url = Url::parse("https://example.test/docs/Guide.PDF?download=1").unwrap();
        assert!(is_pdf_navigation(&url, true));
        assert!(!is_pdf_navigation(&url, false));
        assert!(!is_pdf_navigation(
            &Url::parse("https://example.test/docs/guide.html").unwrap(),
            true
        ));
    }

    #[test]
    fn viewer_contains_pdf_data_and_local_engine_assets() {
        let html = viewer_html(
            &Url::parse("https://example.test/guide.pdf").unwrap(),
            b"%PDF-1.7\n%%EOF",
        );
        assert!(html.contains("pdfjsLib.getDocument"));
        assert!(html.contains("JVBERi0xLjcKJSVFT0Y="));
        assert!(html.contains("GlobalWorkerOptions.workerSrc"));
        assert!(html.contains("const rerender"));
        assert!(html.contains("renderTextLayer"));
        assert!(html.contains("Find in PDF"));
        assert!(html.contains("window.print"));
        assert!(html.contains("application/pdf"));
    }

    #[test]
    fn validation_rejects_malformed_and_oversized_documents() {
        assert_eq!(
            validate_pdf_bytes(b"not a pdf"),
            Err(PdfValidationError::MissingHeader)
        );
        assert_eq!(
            validate_pdf_bytes(b"%PDF-1.7\nbody"),
            Err(PdfValidationError::MissingEndMarker)
        );
        assert_eq!(
            validate_pdf_bytes_with_limit(b"%PDF-1.7\n%%EOF", 4),
            Err(PdfValidationError::TooLarge { size: 14, limit: 4 })
        );
        assert!(validate_pdf_bytes(b"%PDF-1.7\n%%EOF").is_ok());
    }

    #[test]
    fn viewer_error_html_escapes_source_and_error_text() {
        let html = viewer_error_html(
            &Url::parse("https://example.test/a%3Cscript%3E.pdf").unwrap(),
            "bad <pdf>",
        );
        assert!(html.contains("bad &lt;pdf&gt;"));
        assert!(!html.contains("<script>"));
    }
}

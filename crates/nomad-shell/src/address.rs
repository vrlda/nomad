use std::fmt::{Display, Formatter};
use std::net::IpAddr;

use nomad_engine::{BookmarkId, TabId};
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserCommand {
    NewTab,
    NewWorkspace,
    Back,
    Forward,
    ToggleBookmark,
    ToggleSplit,
    ToggleReader,
    TranslatePage,
    OpenDevTools,
    OpenDownloads,
    OpenHistory,
    OpenMemory,
    OpenPrivacy,
    OpenBookmarks,
    OpenSettings,
    OpenPermissions,
    OpenWorkspaces,
    OpenCommandPalette,
}

impl BrowserCommand {
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            ":new-tab" | ":newtab" => Some(Self::NewTab),
            ":new-workspace" | ":workspace" => Some(Self::NewWorkspace),
            ":back" => Some(Self::Back),
            ":forward" => Some(Self::Forward),
            ":bookmark" | ":toggle-bookmark" => Some(Self::ToggleBookmark),
            ":split" | ":toggle-split" => Some(Self::ToggleSplit),
            ":reader" | ":toggle-reader" => Some(Self::ToggleReader),
            ":translate" | ":translate-page" => Some(Self::TranslatePage),
            ":devtools" | ":dev-tools" => Some(Self::OpenDevTools),
            ":downloads" | ":download-panel" => Some(Self::OpenDownloads),
            ":history" => Some(Self::OpenHistory),
            ":memory" | ":ram" => Some(Self::OpenMemory),
            ":privacy" | ":security" | ":route" | ":network" | ":tunnel" => Some(Self::OpenPrivacy),
            ":bookmarks" => Some(Self::OpenBookmarks),
            ":settings" => Some(Self::OpenSettings),
            ":permissions" | ":site-permissions" => Some(Self::OpenPermissions),
            ":workspaces" => Some(Self::OpenWorkspaces),
            ":commands" | ":command-palette" | ":palette" => Some(Self::OpenCommandPalette),
            _ => None,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NewTab => "New tab",
            Self::NewWorkspace => "New workspace",
            Self::Back => "Go back",
            Self::Forward => "Go forward",
            Self::ToggleBookmark => "Toggle bookmark",
            Self::ToggleSplit => "Toggle split browsing",
            Self::ToggleReader => "Toggle reader mode",
            Self::TranslatePage => "Translate page",
            Self::OpenDevTools => "Open DevTools",
            Self::OpenDownloads => "Open downloads",
            Self::OpenHistory => "Open history",
            Self::OpenMemory => "Open memory panel",
            Self::OpenPrivacy => "Open privacy panel",
            Self::OpenBookmarks => "Open bookmarks",
            Self::OpenSettings => "Open settings",
            Self::OpenPermissions => "Open permissions",
            Self::OpenWorkspaces => "Open workspaces",
            Self::OpenCommandPalette => "Open command palette",
        }
    }

    #[must_use]
    pub const fn command(self) -> &'static str {
        match self {
            Self::NewTab => ":new-tab",
            Self::NewWorkspace => ":new-workspace",
            Self::Back => ":back",
            Self::Forward => ":forward",
            Self::ToggleBookmark => ":bookmark",
            Self::ToggleSplit => ":split",
            Self::ToggleReader => ":reader",
            Self::TranslatePage => ":translate",
            Self::OpenDevTools => ":devtools",
            Self::OpenDownloads => ":downloads",
            Self::OpenHistory => ":history",
            Self::OpenMemory => ":memory",
            Self::OpenPrivacy => ":privacy",
            Self::OpenBookmarks => ":bookmarks",
            Self::OpenSettings => ":settings",
            Self::OpenPermissions => ":permissions",
            Self::OpenWorkspaces => ":workspaces",
            Self::OpenCommandPalette => ":commands",
        }
    }

    #[must_use]
    pub const fn all() -> [Self; 18] {
        [
            Self::NewTab,
            Self::NewWorkspace,
            Self::Back,
            Self::Forward,
            Self::ToggleBookmark,
            Self::ToggleSplit,
            Self::ToggleReader,
            Self::TranslatePage,
            Self::OpenDevTools,
            Self::OpenDownloads,
            Self::OpenHistory,
            Self::OpenMemory,
            Self::OpenPrivacy,
            Self::OpenBookmarks,
            Self::OpenSettings,
            Self::OpenPermissions,
            Self::OpenWorkspaces,
            Self::OpenCommandPalette,
        ]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UniversalSuggestionKind {
    Tab,
    Bookmark,
    History,
    Command,
    Address,
    Search,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UniversalTarget {
    Navigate(String),
    SelectTab(TabId),
    OpenBookmark(BookmarkId),
    Command(BrowserCommand),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniversalSuggestion {
    pub kind: UniversalSuggestionKind,
    pub title: String,
    pub detail: String,
    pub target: UniversalTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressInputError {
    Empty,
    ControlCharacter,
    InvalidSearchTemplate,
    InvalidSearchUrl,
}

impl Display for AddressInputError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::Empty => "address input is empty",
            Self::ControlCharacter => "address input contains a control character",
            Self::InvalidSearchTemplate => "search URL must contain a {query} placeholder",
            Self::InvalidSearchUrl => "search URL is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AddressInputError {}

/// Converts user-entered address-bar text into a safe navigation candidate.
///
/// Fully qualified URLs remain unchanged except for URL canonicalization. Bare
/// public hosts become HTTPS URLs, local development hosts use HTTP, and
/// ordinary text becomes an explicit search URL.
/// Search suggestions are never fetched here; network access starts only after
/// the user submits the resulting URL.
///
/// # Errors
///
/// Returns an error when input is empty, contains control characters, or the
/// configured search URL is malformed.
pub fn normalize_address_input(
    raw: &str,
    search_url_template: &str,
) -> Result<String, AddressInputError> {
    let input = raw.trim();
    if input.is_empty() {
        return Err(AddressInputError::Empty);
    }
    if input.chars().any(char::is_control) {
        return Err(AddressInputError::ControlCharacter);
    }

    if looks_like_host(input) {
        let scheme = if is_local_address(input) {
            "http"
        } else {
            "https"
        };
        let url = Url::parse(&format!("{scheme}://{input}"))
            .map_err(|_| AddressInputError::InvalidSearchUrl)?;
        return Ok(url.to_string());
    }

    if let Ok(url) = Url::parse(input) {
        return Ok(url.to_string());
    }

    let Some((_, _)) = search_url_template.split_once("{query}") else {
        return Err(AddressInputError::InvalidSearchTemplate);
    };
    let encoded_query: String = url::form_urlencoded::byte_serialize(input.as_bytes()).collect();
    let search_url = search_url_template.replace("{query}", &encoded_query);
    Url::parse(&search_url)
        .map(|url| url.to_string())
        .map_err(|_| AddressInputError::InvalidSearchUrl)
}

fn is_local_address(input: &str) -> bool {
    let authority = input.split(['/', '?', '#']).next().unwrap_or(input);
    let host = authority
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|(host, _)| host))
        .unwrap_or_else(|| {
            authority
                .split_once(':')
                .map_or(authority, |(host, _)| host)
        });
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

pub(crate) fn looks_like_host(input: &str) -> bool {
    let authority = input.split(['/', '?', '#']).next().unwrap_or(input);
    if authority.is_empty() || authority.contains('@') || authority.chars().any(char::is_whitespace)
    {
        return false;
    }
    let host = authority
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|(host, _)| host))
        .unwrap_or_else(|| {
            authority
                .split_once(':')
                .map_or(authority, |(host, _)| host)
        });
    host == "localhost"
        || host.parse::<IpAddr>().is_ok()
        || host.contains('.')
        || authority.starts_with("localhost:")
}

#[cfg(test)]
mod tests {
    use super::{normalize_address_input, BrowserCommand};

    #[test]
    fn test_normalize_address_input_accepts_bare_hosts_and_local_services() {
        assert_eq!(
            normalize_address_input("example.com/docs", "https://search.example/?q={query}")
                .unwrap(),
            "https://example.com/docs"
        );
        assert_eq!(
            normalize_address_input("localhost:3000", "https://search.example/?q={query}").unwrap(),
            "http://localhost:3000/"
        );
    }

    #[test]
    fn test_normalize_address_input_turns_plain_text_into_explicit_search() {
        assert_eq!(
            normalize_address_input("servo memory usage", "https://search.example/?q={query}")
                .unwrap(),
            "https://search.example/?q=servo+memory+usage"
        );
    }

    #[test]
    fn test_normalize_address_input_preserves_supported_schemes_and_rejects_controls() {
        assert_eq!(
            normalize_address_input("umc://service-id/app", "https://search.example/?q={query}")
                .unwrap(),
            "umc://service-id/app"
        );
        assert_eq!(
            normalize_address_input(
                "file:///tmp/nomad.html",
                "https://search.example/?q={query}"
            )
            .unwrap(),
            "file:///tmp/nomad.html"
        );
        assert!(
            normalize_address_input("bad\ninput", "https://search.example/?q={query}").is_err()
        );
    }

    #[test]
    fn test_browser_command_parser_is_explicit_and_case_insensitive() {
        assert_eq!(
            BrowserCommand::parse(":new-tab"),
            Some(BrowserCommand::NewTab)
        );
        assert_eq!(BrowserCommand::parse(":BACK"), Some(BrowserCommand::Back));
        assert_eq!(BrowserCommand::parse(":not-a-command"), None);
    }

    #[test]
    fn test_browser_command_parser_exposes_browser_panels() {
        assert_eq!(
            BrowserCommand::parse(":downloads"),
            Some(BrowserCommand::OpenDownloads)
        );
        assert_eq!(
            BrowserCommand::parse(":privacy"),
            Some(BrowserCommand::OpenPrivacy)
        );
        assert_eq!(
            BrowserCommand::parse(":route"),
            Some(BrowserCommand::OpenPrivacy)
        );
        assert_eq!(
            BrowserCommand::parse(":palette"),
            Some(BrowserCommand::OpenCommandPalette)
        );
        assert!(BrowserCommand::all().len() >= 17);
    }
}

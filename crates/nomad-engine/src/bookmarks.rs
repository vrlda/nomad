use url::Url;

use crate::TabId;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BookmarkId(u64);

impl BookmarkId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BookmarkFolderId(u64);

impl BookmarkFolderId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookmarkFolder {
    pub id: BookmarkFolderId,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bookmark {
    pub id: BookmarkId,
    pub url: Url,
    pub title: String,
    pub folder_id: Option<BookmarkFolderId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BookmarkError {
    MissingBookmark(BookmarkId),
    MissingUrl(TabId),
    MissingFolder(BookmarkFolderId),
    InvalidFolderName(String),
}

pub struct BookmarkManager {
    next_id: u64,
    folders: Vec<BookmarkFolder>,
    bookmarks: Vec<Bookmark>,
}

impl Default for BookmarkManager {
    fn default() -> Self {
        Self {
            next_id: 1,
            folders: Vec::new(),
            bookmarks: Vec::new(),
        }
    }
}

impl BookmarkManager {
    #[must_use]
    pub fn bookmarks(&self) -> &[Bookmark] {
        &self.bookmarks
    }

    #[must_use]
    pub fn folders(&self) -> &[BookmarkFolder] {
        &self.folders
    }

    #[must_use]
    pub fn folder(&self, id: BookmarkFolderId) -> Option<&BookmarkFolder> {
        self.folders.iter().find(|folder| folder.id == id)
    }

    #[must_use]
    pub fn get(&self, id: BookmarkId) -> Option<&Bookmark> {
        self.bookmarks.iter().find(|bookmark| bookmark.id == id)
    }

    #[must_use]
    pub fn contains_url(&self, url: &Url) -> bool {
        self.bookmarks.iter().any(|bookmark| bookmark.url == *url)
    }

    #[must_use]
    pub fn search(&self, query: &str) -> Vec<Bookmark> {
        let query = query.trim().to_ascii_lowercase();
        self.bookmarks
            .iter()
            .filter(|bookmark| {
                query.is_empty()
                    || bookmark.title.to_ascii_lowercase().contains(&query)
                    || bookmark.url.as_str().to_ascii_lowercase().contains(&query)
            })
            .cloned()
            .collect()
    }

    /// Adds a bookmark, updating an existing bookmark for the same URL.
    ///
    /// # Panics
    ///
    /// This method cannot panic for the unassigned folder used here.
    pub fn add(&mut self, url: Url, title: impl Into<String>) -> BookmarkId {
        self.add_in_folder(url, title, None)
            .expect("the unassigned bookmark folder is always valid")
    }

    /// Adds or updates a bookmark in a folder.
    ///
    /// # Errors
    ///
    /// Returns [`BookmarkError::MissingFolder`] when the folder does not exist.
    pub fn add_in_folder(
        &mut self,
        url: Url,
        title: impl Into<String>,
        folder_id: Option<BookmarkFolderId>,
    ) -> Result<BookmarkId, BookmarkError> {
        if let Some(folder_id) = folder_id {
            self.folder(folder_id)
                .ok_or(BookmarkError::MissingFolder(folder_id))?;
        }
        let title = title.into();
        let title = normalize_title(&title, &url);
        if let Some(bookmark) = self
            .bookmarks
            .iter_mut()
            .find(|bookmark| bookmark.url == url)
        {
            bookmark.title = title;
            bookmark.folder_id = folder_id;
            return Ok(bookmark.id);
        }

        let id = BookmarkId::new(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        self.bookmarks.push(Bookmark {
            id,
            url,
            title,
            folder_id,
        });
        Ok(id)
    }

    /// Creates a named bookmark folder.
    ///
    /// # Errors
    ///
    /// Returns [`BookmarkError::InvalidFolderName`] for empty or unsafe names.
    pub fn create_folder(
        &mut self,
        name: impl Into<String>,
    ) -> Result<BookmarkFolderId, BookmarkError> {
        let name = safe_folder_name(&name.into())?;
        if let Some(folder) = self.folders.iter().find(|folder| folder.name == name) {
            return Ok(folder.id);
        }
        let id = BookmarkFolderId::new(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        self.folders.push(BookmarkFolder { id, name });
        Ok(id)
    }

    /// Renames an existing bookmark folder.
    ///
    /// # Errors
    ///
    /// Returns an error when the folder is missing or the name is invalid.
    pub fn rename_folder(
        &mut self,
        id: BookmarkFolderId,
        name: impl Into<String>,
    ) -> Result<(), BookmarkError> {
        let name = safe_folder_name(&name.into())?;
        let folder = self
            .folders
            .iter_mut()
            .find(|folder| folder.id == id)
            .ok_or(BookmarkError::MissingFolder(id))?;
        folder.name = name;
        Ok(())
    }

    /// Removes a folder and moves its bookmarks to the unassigned section.
    ///
    /// # Errors
    ///
    /// Returns [`BookmarkError::MissingFolder`] when the folder is absent.
    pub fn remove_folder(&mut self, id: BookmarkFolderId) -> Result<(), BookmarkError> {
        let index = self
            .folders
            .iter()
            .position(|folder| folder.id == id)
            .ok_or(BookmarkError::MissingFolder(id))?;
        self.folders.remove(index);
        for bookmark in &mut self.bookmarks {
            if bookmark.folder_id == Some(id) {
                bookmark.folder_id = None;
            }
        }
        Ok(())
    }

    /// Moves a bookmark to a folder or back to the unassigned section.
    ///
    /// # Errors
    ///
    /// Returns an error when the bookmark or target folder is missing.
    pub fn move_to_folder(
        &mut self,
        id: BookmarkId,
        folder_id: Option<BookmarkFolderId>,
    ) -> Result<(), BookmarkError> {
        if let Some(folder_id) = folder_id {
            self.folder(folder_id)
                .ok_or(BookmarkError::MissingFolder(folder_id))?;
        }
        let bookmark = self
            .bookmarks
            .iter_mut()
            .find(|bookmark| bookmark.id == id)
            .ok_or(BookmarkError::MissingBookmark(id))?;
        bookmark.folder_id = folder_id;
        Ok(())
    }

    /// Replaces a bookmark's URL without changing its identity or folder.
    ///
    /// # Errors
    ///
    /// Returns [`BookmarkError::MissingBookmark`] when the id is not present.
    pub fn set_url(&mut self, id: BookmarkId, url: Url) -> Result<(), BookmarkError> {
        let bookmark = self
            .bookmarks
            .iter_mut()
            .find(|bookmark| bookmark.id == id)
            .ok_or(BookmarkError::MissingBookmark(id))?;
        bookmark.url = url;
        Ok(())
    }

    /// Renames a bookmark without changing its URL or folder.
    ///
    /// # Errors
    ///
    /// Returns [`BookmarkError::MissingBookmark`] when the id is not present.
    pub fn rename(
        &mut self,
        id: BookmarkId,
        title: impl Into<String>,
    ) -> Result<(), BookmarkError> {
        let bookmark = self
            .bookmarks
            .iter_mut()
            .find(|bookmark| bookmark.id == id)
            .ok_or(BookmarkError::MissingBookmark(id))?;
        bookmark.title = normalize_title(&title.into(), &bookmark.url);
        Ok(())
    }

    /// Removes a bookmark by id.
    ///
    /// # Errors
    ///
    /// Returns [`BookmarkError::MissingBookmark`] when the id is not present.
    pub fn remove(&mut self, id: BookmarkId) -> Result<(), BookmarkError> {
        let index = self
            .bookmarks
            .iter()
            .position(|bookmark| bookmark.id == id)
            .ok_or(BookmarkError::MissingBookmark(id))?;
        self.bookmarks.remove(index);
        Ok(())
    }

    /// Removes the bookmark for a URL, returning whether one existed.
    pub fn remove_url(&mut self, url: &Url) -> bool {
        let Some(index) = self
            .bookmarks
            .iter()
            .position(|bookmark| bookmark.url == *url)
        else {
            return false;
        };
        self.bookmarks.remove(index);
        true
    }
}

fn normalize_title(title: &str, url: &Url) -> String {
    let title = title.trim();
    if title.is_empty() {
        url.host_str().unwrap_or(url.as_str()).to_owned()
    } else {
        title.to_owned()
    }
}

fn safe_folder_name(name: &str) -> Result<String, BookmarkError> {
    let name = name.trim();
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(BookmarkError::InvalidFolderName(name.to_owned()));
    }
    Ok(name.to_owned())
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::{BookmarkError, BookmarkManager};

    #[test]
    fn test_add_updates_existing_url_without_duplicates() {
        let mut manager = BookmarkManager::default();
        let url = Url::parse("https://example.com/").unwrap();

        let first_id = manager.add(url.clone(), "Example");
        let second_id = manager.add(url, "Updated");

        assert_eq!(first_id, second_id);
        assert_eq!(manager.bookmarks().len(), 1);
        assert_eq!(manager.bookmarks()[0].title, "Updated");
        assert_eq!(manager.bookmarks()[0].folder_id, None);
    }

    #[test]
    fn test_search_matches_title_and_url() {
        let mut manager = BookmarkManager::default();
        manager.add(Url::parse("https://example.com/docs").unwrap(), "Reference");
        manager.add(Url::parse("https://rust-lang.org").unwrap(), "Rust");

        assert_eq!(manager.search("reference").len(), 1);
        assert_eq!(manager.search("rust-lang").len(), 1);
        assert_eq!(manager.search("missing"), Vec::new());
    }

    #[test]
    fn test_remove_reports_missing_ids() {
        let mut manager = BookmarkManager::default();
        let missing = super::BookmarkId::new(7);

        assert_eq!(
            manager.remove(missing),
            Err(BookmarkError::MissingBookmark(missing))
        );
    }

    #[test]
    fn test_folder_assignment_and_rename() {
        let mut manager = BookmarkManager::default();
        let folder = manager.create_folder("Research").unwrap();
        let bookmark = manager
            .add_in_folder(
                Url::parse("https://example.com").unwrap(),
                "Example",
                Some(folder),
            )
            .unwrap();

        manager.rename(bookmark, "Updated").unwrap();
        manager.move_to_folder(bookmark, None).unwrap();

        assert_eq!(manager.bookmarks()[0].title, "Updated");
        assert_eq!(manager.bookmarks()[0].folder_id, None);
    }

    #[test]
    fn test_removing_folder_unassigns_bookmarks() {
        let mut manager = BookmarkManager::default();
        let folder = manager.create_folder("Research").unwrap();
        manager
            .add_in_folder(
                Url::parse("https://example.com").unwrap(),
                "Example",
                Some(folder),
            )
            .unwrap();

        manager.remove_folder(folder).unwrap();

        assert_eq!(manager.bookmarks()[0].folder_id, None);
        assert!(manager.folders().is_empty());
    }
}

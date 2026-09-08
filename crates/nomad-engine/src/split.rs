#![allow(clippy::missing_errors_doc)]

use crate::TabId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SplitOrientation {
    /// Panes are arranged left-to-right (a split "to the right").
    Horizontal,
    /// Panes are arranged top-to-bottom (a split "below", i.e. rows).
    Vertical,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SplitPaneId(u64);

impl SplitPaneId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SplitPane {
    pub id: SplitPaneId,
    pub tab_id: TabId,
}

/// Axis-aligned pane rectangle in the coordinate space of the caller
/// (chrome passes the content viewport origin and size).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SplitRect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SplitError {
    MissingPane(SplitPaneId),
    DuplicateTab(TabId),
    LastPane,
}

/// Pane tree: leaves hold tabs, groups divide their extent along one
/// orientation. Nested groups with different orientations produce mixed
/// layouts (for example two columns whose right column stacks two rows).
#[derive(Clone, Debug, Eq, PartialEq)]
enum SplitNode {
    Pane(SplitPane),
    Group {
        orientation: SplitOrientation,
        children: Vec<SplitNode>,
    },
}

pub struct SplitLayout {
    root: SplitNode,
    active_pane: SplitPaneId,
    next_pane_id: u64,
}

impl SplitLayout {
    #[must_use]
    pub fn single(tab_id: TabId) -> Self {
        Self {
            root: SplitNode::Pane(SplitPane {
                id: SplitPaneId::new(1),
                tab_id,
            }),
            active_pane: SplitPaneId::new(1),
            next_pane_id: 2,
        }
    }

    #[must_use]
    pub fn panes(&self) -> Vec<SplitPane> {
        let mut panes = Vec::new();
        Self::collect_panes(&self.root, &mut panes);
        panes
    }

    #[must_use]
    pub fn contains_tab(&self, tab_id: TabId) -> bool {
        self.pane_for_tab(tab_id).is_some()
    }

    #[must_use]
    pub fn pane_for_tab(&self, tab_id: TabId) -> Option<SplitPaneId> {
        self.panes()
            .into_iter()
            .find(|pane| pane.tab_id == tab_id)
            .map(|pane| pane.id)
    }

    #[must_use]
    pub const fn active_pane(&self) -> SplitPaneId {
        self.active_pane
    }

    /// Appends `tab_id` as a new pane at the root level, divided along
    /// `orientation`. A root group of a different orientation is wrapped so
    /// repeated root-level splits keep nesting instead of discarding the
    /// previous arrangement.
    pub fn split(
        &mut self,
        tab_id: TabId,
        orientation: SplitOrientation,
    ) -> Result<SplitPaneId, SplitError> {
        if self.contains_tab(tab_id) {
            return Err(SplitError::DuplicateTab(tab_id));
        }
        let pane_id = SplitPaneId::new(self.next_pane_id);
        self.next_pane_id = self.next_pane_id.saturating_add(1);
        let new_pane = SplitNode::Pane(SplitPane {
            id: pane_id,
            tab_id,
        });
        // Placeholder leaf is replaced in the same statement below; the id is
        // never observable.
        let old_root = std::mem::replace(
            &mut self.root,
            SplitNode::Pane(SplitPane {
                id: pane_id,
                tab_id,
            }),
        );
        self.root = match old_root {
            SplitNode::Pane(pane) => SplitNode::Group {
                orientation,
                children: vec![SplitNode::Pane(pane), new_pane],
            },
            SplitNode::Group {
                orientation: root_orientation,
                children,
            } if root_orientation == orientation => SplitNode::Group {
                orientation: root_orientation,
                children: {
                    let mut children = children;
                    children.push(new_pane);
                    children
                },
            },
            other @ SplitNode::Group { .. } => SplitNode::Group {
                orientation,
                children: vec![other, new_pane],
            },
        };
        self.active_pane = pane_id;
        Ok(pane_id)
    }

    /// Divides the pane `pane_id` itself, replacing it with a group that
    /// contains the original pane and a new pane for `tab_id`. This is what
    /// produces mixed-orientation layouts (a vertical split inside one
    /// column of a horizontal split).
    pub fn split_pane(
        &mut self,
        pane_id: SplitPaneId,
        tab_id: TabId,
        orientation: SplitOrientation,
    ) -> Result<SplitPaneId, SplitError> {
        if self.contains_tab(tab_id) {
            return Err(SplitError::DuplicateTab(tab_id));
        }
        if !self.panes().iter().any(|pane| pane.id == pane_id) {
            return Err(SplitError::MissingPane(pane_id));
        }
        let new_pane_id = SplitPaneId::new(self.next_pane_id);
        self.next_pane_id = self.next_pane_id.saturating_add(1);
        let new_pane = SplitPane {
            id: new_pane_id,
            tab_id,
        };
        Self::split_leaf(&mut self.root, pane_id, orientation, new_pane);
        self.active_pane = new_pane_id;
        Ok(new_pane_id)
    }

    pub fn close(&mut self, pane_id: SplitPaneId) -> Result<TabId, SplitError> {
        let panes = self.panes();
        if panes.len() == 1 {
            return Err(SplitError::LastPane);
        }
        let index = panes
            .iter()
            .position(|pane| pane.id == pane_id)
            .ok_or(SplitError::MissingPane(pane_id))?;
        let removed = panes[index];
        Self::remove_leaf(&mut self.root, pane_id);
        if self.active_pane == pane_id {
            self.active_pane = panes[index.saturating_sub(1)].id;
        }
        Ok(removed.tab_id)
    }

    pub fn activate(&mut self, pane_id: SplitPaneId) -> Result<TabId, SplitError> {
        let pane = self
            .panes()
            .into_iter()
            .find(|pane| pane.id == pane_id)
            .ok_or(SplitError::MissingPane(pane_id))?;
        self.active_pane = pane_id;
        Ok(pane.tab_id)
    }

    pub fn remove_tab(&mut self, tab_id: TabId) -> Option<SplitPaneId> {
        let pane_id = self.pane_for_tab(tab_id)?;
        if self.panes().len() > 1 {
            let _ = self.close(pane_id);
        }
        Some(pane_id)
    }

    /// Lays every pane out inside the rectangle at (`x`, `y`) with the given
    /// size, dividing each group's extent equally along its orientation.
    /// Returns panes in tree order paired with their rects.
    #[must_use]
    pub fn pane_rects(
        &self,
        x: f32,
        y: f32,
        width: f32,
        height: f32,
    ) -> Vec<(SplitPane, SplitRect)> {
        let mut layout = Vec::new();
        Self::layout_node(
            &self.root,
            SplitRect {
                x,
                y,
                width,
                height,
            },
            &mut layout,
        );
        layout
    }

    fn collect_panes(node: &SplitNode, panes: &mut Vec<SplitPane>) {
        match node {
            SplitNode::Pane(pane) => panes.push(*pane),
            SplitNode::Group { children, .. } => {
                for child in children {
                    Self::collect_panes(child, panes);
                }
            }
        }
    }

    fn split_leaf(
        node: &mut SplitNode,
        pane_id: SplitPaneId,
        orientation: SplitOrientation,
        new_pane: SplitPane,
    ) {
        match node {
            SplitNode::Pane(pane) if pane.id == pane_id => {
                *node = SplitNode::Group {
                    orientation,
                    children: vec![SplitNode::Pane(*pane), SplitNode::Pane(new_pane)],
                };
            }
            SplitNode::Group { children, .. } => {
                for child in children {
                    Self::split_leaf(child, pane_id, orientation, new_pane);
                }
            }
            SplitNode::Pane(_) => {}
        }
    }

    /// Removes the leaf and collapses every group left with a single child so
    /// the tree never keeps empty structure around.
    fn remove_leaf(node: &mut SplitNode, pane_id: SplitPaneId) {
        if let SplitNode::Group { children, .. } = node {
            children.retain(|child| !matches!(child, SplitNode::Pane(pane) if pane.id == pane_id));
            for child in &mut *children {
                Self::remove_leaf(child, pane_id);
            }
            if children.len() == 1 {
                if let Some(child) = children.pop() {
                    *node = child;
                }
            }
        }
    }

    // Equal division of an extent by child count; the usize-to-f32 casts are
    // exact for any realistic pane count.
    #[allow(clippy::cast_precision_loss)]
    fn layout_node(node: &SplitNode, rect: SplitRect, layout: &mut Vec<(SplitPane, SplitRect)>) {
        match node {
            SplitNode::Pane(pane) => layout.push((*pane, rect)),
            SplitNode::Group {
                orientation,
                children,
            } => {
                let count = children.len();
                for (index, child) in children.iter().enumerate() {
                    let child_rect = match orientation {
                        SplitOrientation::Horizontal => {
                            let slice = rect.width / count as f32;
                            let offset = slice * index as f32;
                            let width = if index + 1 == count {
                                rect.width - offset
                            } else {
                                slice
                            };
                            SplitRect {
                                x: rect.x + offset,
                                y: rect.y,
                                width,
                                height: rect.height,
                            }
                        }
                        SplitOrientation::Vertical => {
                            let slice = rect.height / count as f32;
                            let offset = slice * index as f32;
                            let height = if index + 1 == count {
                                rect.height - offset
                            } else {
                                slice
                            };
                            SplitRect {
                                x: rect.x,
                                y: rect.y + offset,
                                width: rect.width,
                                height,
                            }
                        }
                    };
                    Self::layout_node(child, child_rect, layout);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SplitError, SplitLayout, SplitOrientation, SplitPaneId};
    use crate::TabId;

    fn assert_near(left: f32, right: f32) {
        assert!((left - right).abs() < 0.001, "{left} != {right}");
    }

    #[test]
    fn split_adds_and_activates_second_tab() {
        let mut layout = SplitLayout::single(TabId::new(1));
        let pane = layout
            .split(TabId::new(2), SplitOrientation::Vertical)
            .unwrap();
        assert_eq!(layout.active_pane(), pane);
        assert_eq!(layout.panes().len(), 2);
    }

    #[test]
    fn split_rejects_duplicate_tab_and_last_pane_close() {
        let mut layout = SplitLayout::single(TabId::new(1));
        assert_eq!(
            layout.split(TabId::new(1), SplitOrientation::Horizontal),
            Err(SplitError::DuplicateTab(TabId::new(1)))
        );
        assert_eq!(
            layout.close(layout.active_pane()),
            Err(SplitError::LastPane)
        );
    }

    #[test]
    fn root_splits_stack_two_rows_vertically() {
        let mut layout = SplitLayout::single(TabId::new(1));
        layout
            .split(TabId::new(2), SplitOrientation::Vertical)
            .unwrap();
        let rects = layout.pane_rects(0.0, 0.0, 100.0, 200.0);
        assert_eq!(rects.len(), 2);
        assert_near(rects[0].1.height, 100.0);
        assert_near(rects[1].1.y, 100.0);
        assert_near(rects[1].1.height, 100.0);
    }

    #[test]
    fn pane_split_produces_mixed_orientation_tree() {
        let mut layout = SplitLayout::single(TabId::new(1));
        layout
            .split(TabId::new(2), SplitOrientation::Horizontal)
            .unwrap();
        let first_pane = layout.pane_for_tab(TabId::new(1)).unwrap();
        layout
            .split_pane(first_pane, TabId::new(3), SplitOrientation::Vertical)
            .unwrap();
        assert_eq!(layout.panes().len(), 3);
        let rects = layout.pane_rects(0.0, 0.0, 100.0, 100.0);
        let first = &rects[0].1;
        let nested_second_row = &rects[1].1;
        assert_near(first.width, 50.0);
        assert_near(first.height, 50.0);
        assert_near(nested_second_row.x, 0.0);
        assert_near(nested_second_row.y, 50.0);
        assert_near(nested_second_row.height, 50.0);
    }

    #[test]
    fn closing_middle_pane_keeps_remaining_panes_active() {
        let mut layout = SplitLayout::single(TabId::new(1));
        layout
            .split(TabId::new(2), SplitOrientation::Horizontal)
            .unwrap();
        let middle = layout.pane_for_tab(TabId::new(2)).unwrap();
        layout.activate(middle).unwrap();
        let removed = layout.close(middle).unwrap();
        assert_eq!(removed, TabId::new(2));
        assert_eq!(layout.panes().len(), 1);
        assert_eq!(
            layout.active_pane(),
            layout.pane_for_tab(TabId::new(1)).unwrap()
        );
    }

    #[test]
    fn close_collapse_keeps_tree_orientation_of_surviving_group() {
        let mut layout = SplitLayout::single(TabId::new(1));
        layout
            .split(TabId::new(2), SplitOrientation::Horizontal)
            .unwrap();
        let second = layout.pane_for_tab(TabId::new(2)).unwrap();
        layout
            .split_pane(second, TabId::new(3), SplitOrientation::Vertical)
            .unwrap();
        let removed = layout.close(layout.pane_for_tab(TabId::new(2)).unwrap());
        assert!(removed.is_ok());
        assert_eq!(layout.panes().len(), 2);
        let rects = layout.pane_rects(0.0, 0.0, 100.0, 100.0);
        assert_near(rects[0].1.height, 100.0);
    }

    #[test]
    fn split_pane_rejects_unknown_pane_and_duplicate_tab() {
        let mut layout = SplitLayout::single(TabId::new(1));
        let pane = layout
            .split(TabId::new(2), SplitOrientation::Horizontal)
            .unwrap();
        let unknown = SplitPaneId::new(99);
        assert_eq!(
            layout.split_pane(unknown, TabId::new(3), SplitOrientation::Vertical),
            Err(SplitError::MissingPane(unknown))
        );
        assert_eq!(
            layout.split_pane(pane, TabId::new(1), SplitOrientation::Vertical),
            Err(SplitError::DuplicateTab(TabId::new(1)))
        );
    }

    #[test]
    fn remove_tab_keeps_last_pane_but_reports_it() {
        let mut layout = SplitLayout::single(TabId::new(1));
        let pane = layout.remove_tab(TabId::new(1));
        assert_eq!(pane, Some(layout.active_pane()));
        assert_eq!(layout.panes().len(), 1);
    }
}

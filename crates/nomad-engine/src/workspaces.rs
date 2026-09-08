#![allow(clippy::missing_errors_doc)]

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::dns::ResolverSettings;
use crate::network::SiteRoutePolicy;
use crate::TabId;

const DEFAULT_WORKSPACE_NAME: &str = "Default";
const DEFAULT_CONTAINER_NAME: &str = "Personal";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct WorkspaceId(u64);

impl WorkspaceId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ContainerId(u64);

impl ContainerId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One workspace: a named tab context with per-workspace route and
/// resolver overrides. `resolver: None` inherits the global browser
/// resolver settings. An override takes effect through the shell's
/// config-validation chain only (an unusable override falls back to the
/// global settings, then the platform resolver); once a usable
/// explicit-mode override is active, its transport failures fail closed
/// — queries never fall back to the system resolver.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub name: String,
    pub route_policy: SiteRoutePolicy,
    #[serde(default)]
    pub resolver: Option<ResolverSettings>,
}

impl Workspace {
    /// The resolver governing this workspace: its own pinned override when
    /// present, otherwise the global browser resolver settings.
    #[must_use]
    pub fn effective_resolver<'a>(&'a self, global: &'a ResolverSettings) -> &'a ResolverSettings {
        self.resolver.as_ref().unwrap_or(global)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Container {
    pub id: ContainerId,
    pub name: String,
    pub ephemeral: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TabContext {
    pub workspace_id: WorkspaceId,
    pub container_id: ContainerId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceError {
    InvalidName,
    MissingWorkspace(WorkspaceId),
    MissingContainer(ContainerId),
    LastWorkspace,
    WorkspaceInUse(WorkspaceId),
}

pub struct WorkspaceManager {
    workspaces: Vec<Workspace>,
    containers: Vec<Container>,
    tab_contexts: HashMap<TabId, TabContext>,
    active_workspace: WorkspaceId,
    next_workspace_id: u64,
    next_container_id: u64,
}

impl Default for WorkspaceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkspaceManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            workspaces: vec![Workspace {
                id: WorkspaceId::new(1),
                name: DEFAULT_WORKSPACE_NAME.to_owned(),
                route_policy: SiteRoutePolicy::default(),
                resolver: None,
            }],
            containers: vec![Container {
                id: ContainerId::new(1),
                name: DEFAULT_CONTAINER_NAME.to_owned(),
                ephemeral: false,
            }],
            tab_contexts: HashMap::new(),
            active_workspace: WorkspaceId::new(1),
            next_workspace_id: 2,
            next_container_id: 2,
        }
    }

    #[must_use]
    pub fn workspaces(&self) -> &[Workspace] {
        &self.workspaces
    }
    #[must_use]
    pub fn containers(&self) -> &[Container] {
        &self.containers
    }
    #[must_use]
    pub const fn active_workspace(&self) -> WorkspaceId {
        self.active_workspace
    }
    #[must_use]
    pub fn workspace(&self, id: WorkspaceId) -> Option<&Workspace> {
        self.workspaces.iter().find(|workspace| workspace.id == id)
    }
    #[must_use]
    pub fn container(&self, id: ContainerId) -> Option<&Container> {
        self.containers.iter().find(|container| container.id == id)
    }

    pub fn create_workspace(
        &mut self,
        name: impl Into<String>,
    ) -> Result<WorkspaceId, WorkspaceError> {
        let name = name.into();
        let name = normalized_name(&name)?;
        let id = WorkspaceId::new(self.next_workspace_id);
        self.next_workspace_id = self.next_workspace_id.saturating_add(1);
        self.workspaces.push(Workspace {
            id,
            name,
            route_policy: SiteRoutePolicy::default(),
            resolver: None,
        });
        Ok(id)
    }

    pub fn create_container(
        &mut self,
        name: impl Into<String>,
        ephemeral: bool,
    ) -> Result<ContainerId, WorkspaceError> {
        let name = name.into();
        let name = normalized_name(&name)?;
        let id = ContainerId::new(self.next_container_id);
        self.next_container_id = self.next_container_id.saturating_add(1);
        self.containers.push(Container {
            id,
            name,
            ephemeral,
        });
        Ok(id)
    }

    pub fn select_workspace(&mut self, id: WorkspaceId) -> Result<(), WorkspaceError> {
        if self.workspace(id).is_none() {
            return Err(WorkspaceError::MissingWorkspace(id));
        }
        self.active_workspace = id;
        Ok(())
    }

    pub fn set_route_policy(
        &mut self,
        id: WorkspaceId,
        policy: SiteRoutePolicy,
    ) -> Result<(), WorkspaceError> {
        let workspace = self
            .workspaces
            .iter_mut()
            .find(|workspace| workspace.id == id)
            .ok_or(WorkspaceError::MissingWorkspace(id))?;
        workspace.route_policy = policy;
        Ok(())
    }

    /// Pins (or clears) the workspace resolver override. `None` inherits
    /// the global browser resolver settings.
    pub fn set_resolver(
        &mut self,
        id: WorkspaceId,
        resolver: Option<ResolverSettings>,
    ) -> Result<(), WorkspaceError> {
        let workspace = self
            .workspaces
            .iter_mut()
            .find(|workspace| workspace.id == id)
            .ok_or(WorkspaceError::MissingWorkspace(id))?;
        workspace.resolver = resolver;
        Ok(())
    }

    pub fn assign_tab(
        &mut self,
        tab_id: TabId,
        workspace_id: WorkspaceId,
        container_id: ContainerId,
    ) -> Result<(), WorkspaceError> {
        if self.workspace(workspace_id).is_none() {
            return Err(WorkspaceError::MissingWorkspace(workspace_id));
        }
        if self.container(container_id).is_none() {
            return Err(WorkspaceError::MissingContainer(container_id));
        }
        self.tab_contexts.insert(
            tab_id,
            TabContext {
                workspace_id,
                container_id,
            },
        );
        Ok(())
    }

    #[must_use]
    pub fn tab_context(&self, tab_id: TabId) -> TabContext {
        self.tab_contexts
            .get(&tab_id)
            .copied()
            .unwrap_or(TabContext {
                workspace_id: self.active_workspace,
                container_id: self.containers[0].id,
            })
    }

    #[must_use]
    pub fn tab_belongs_to(&self, tab_id: TabId, workspace_id: WorkspaceId) -> bool {
        self.tab_context(tab_id).workspace_id == workspace_id
    }

    pub fn forget_tab(&mut self, tab_id: TabId) {
        self.tab_contexts.remove(&tab_id);
    }

    pub fn remove_workspace(&mut self, id: WorkspaceId) -> Result<(), WorkspaceError> {
        if self.workspaces.len() == 1 {
            return Err(WorkspaceError::LastWorkspace);
        }
        if self
            .tab_contexts
            .values()
            .any(|context| context.workspace_id == id)
        {
            return Err(WorkspaceError::WorkspaceInUse(id));
        }
        let index = self
            .workspaces
            .iter()
            .position(|workspace| workspace.id == id)
            .ok_or(WorkspaceError::MissingWorkspace(id))?;
        self.workspaces.remove(index);
        if self.active_workspace == id {
            self.active_workspace = self.workspaces[0].id;
        }
        Ok(())
    }

    /// Restores persistent workspace and container identities without carrying
    /// tab bindings across a session boundary.
    pub fn restore_state(
        &mut self,
        workspaces: Vec<Workspace>,
        containers: Vec<Container>,
        active_workspace: WorkspaceId,
    ) -> Result<(), WorkspaceError> {
        if workspaces.is_empty() || containers.is_empty() {
            return Err(WorkspaceError::InvalidName);
        }
        if !workspaces
            .iter()
            .any(|workspace| workspace.id == active_workspace)
        {
            return Err(WorkspaceError::MissingWorkspace(active_workspace));
        }
        if workspaces
            .iter()
            .map(|workspace| workspace.id)
            .collect::<std::collections::HashSet<_>>()
            .len()
            != workspaces.len()
        {
            return Err(WorkspaceError::InvalidName);
        }
        if containers
            .iter()
            .map(|container| container.id)
            .collect::<std::collections::HashSet<_>>()
            .len()
            != containers.len()
        {
            return Err(WorkspaceError::InvalidName);
        }
        self.next_workspace_id = workspaces
            .iter()
            .map(|workspace| workspace.id.get())
            .max()
            .unwrap_or_default()
            .saturating_add(1);
        self.next_container_id = containers
            .iter()
            .map(|container| container.id.get())
            .max()
            .unwrap_or_default()
            .saturating_add(1);
        self.workspaces = workspaces;
        self.containers = containers;
        self.tab_contexts.clear();
        self.active_workspace = active_workspace;
        Ok(())
    }
}

fn normalized_name(name: &str) -> Result<String, WorkspaceError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(WorkspaceError::InvalidName);
    }
    Ok(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{ContainerId, Workspace, WorkspaceError, WorkspaceId, WorkspaceManager};
    use crate::dns::{ResolverMode, ResolverSettings};
    use crate::TabId;

    #[test]
    fn default_workspace_and_container_exist() {
        let manager = WorkspaceManager::new();
        assert_eq!(manager.active_workspace(), WorkspaceId::new(1));
        assert_eq!(manager.workspaces()[0].name, "Default");
        assert_eq!(manager.containers()[0].name, "Personal");
    }

    #[test]
    fn tab_context_is_explicitly_assignable() {
        let mut manager = WorkspaceManager::new();
        let workspace = manager.create_workspace("Work").unwrap();
        let container = manager.create_container("Corporate", false).unwrap();
        manager
            .assign_tab(TabId::new(9), workspace, container)
            .unwrap();
        assert_eq!(manager.tab_context(TabId::new(9)).workspace_id, workspace);
        assert_eq!(manager.tab_context(TabId::new(9)).container_id, container);
    }

    #[test]
    fn non_empty_workspace_cannot_be_removed() {
        let mut manager = WorkspaceManager::new();
        let workspace = manager.create_workspace("Work").unwrap();
        manager
            .assign_tab(TabId::new(1), workspace, ContainerId::new(1))
            .unwrap();
        assert_eq!(
            manager.remove_workspace(workspace),
            Err(WorkspaceError::WorkspaceInUse(workspace))
        );
    }
    #[test]
    fn workspace_resolver_override_precedence() {
        let mut manager = WorkspaceManager::new();
        let pinned = manager.create_workspace("Pinned").unwrap();
        let inherited = manager.create_workspace("Inherited").unwrap();

        // Without an override every workspace falls back to the global
        // resolver settings.
        let global = ResolverSettings::default();
        for workspace in manager.workspaces() {
            assert!(workspace.resolver.is_none());
            assert_eq!(
                workspace.effective_resolver(&global).mode,
                ResolverMode::System
            );
        }

        // A pinned override wins over the global settings.
        let override_settings = ResolverSettings {
            mode: ResolverMode::Dot,
            server_host: "dns.example".to_owned(),
            ..ResolverSettings::default()
        };
        manager
            .set_resolver(pinned, Some(override_settings.clone()))
            .unwrap();
        assert_eq!(
            manager
                .workspace(pinned)
                .unwrap()
                .effective_resolver(&global),
            &override_settings
        );
        // A workspace without an override keeps inheriting the global.
        assert!(manager.workspace(inherited).unwrap().resolver.is_none());
        assert_eq!(
            manager
                .workspace(inherited)
                .unwrap()
                .effective_resolver(&global),
            &global
        );

        // Clearing the override returns the workspace to global inheritance.
        manager.set_resolver(pinned, None).unwrap();
        assert!(manager.workspace(pinned).unwrap().resolver.is_none());
    }

    #[test]
    fn workspace_resolver_survives_serialization_and_legacy_snapshots() {
        let mut manager = WorkspaceManager::new();
        let id = manager.create_workspace("Work").unwrap();
        let override_settings = ResolverSettings {
            mode: ResolverMode::Custom,
            custom_server: "1.1.1.1:5353".to_owned(),
            ..ResolverSettings::default()
        };
        manager
            .set_resolver(id, Some(override_settings.clone()))
            .unwrap();

        let serialized = serde_json::to_string(&manager.workspace(id).unwrap()).unwrap();
        let restored: Workspace = serde_json::from_str(&serialized).unwrap();
        assert_eq!(restored.resolver, Some(override_settings));

        // Snapshots written before the override existed parse with
        // `resolver: None` and keep inheriting the global settings.
        let mut legacy = serde_json::to_value(manager.workspace(id).unwrap()).unwrap();
        legacy.as_object_mut().unwrap().remove("resolver");
        let restored: Workspace = serde_json::from_value(legacy).unwrap();
        assert_eq!(restored.resolver, None);
    }
}

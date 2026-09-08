/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! The service worker manager persists the descriptor of any registered service workers.
//! It also stores an active workers map, which holds descriptors of running service workers.
//! If an active service worker timeouts, then it removes the descriptor entry from its
//! active_workers map

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use crossbeam_channel::{Receiver, Sender, select, unbounded};
use devtools_traits::{DevtoolsPageInfo, ScriptToDevtoolsControlMsg};
use fonts::FontContext;
use http::{HeaderName, HeaderValue, StatusCode};
use ipc_channel::ipc;
use ipc_channel::router::ROUTER;
use net_traits::request::{Destination, RequestBuilder, RequestId, ServiceWorkersMode};
use net_traits::{
    CoreResourceMsg, CustomResponse, CustomResponseMediator, FetchChannels, FetchResponseMsg,
    ResourceThreads,
};
use servo_base::generic_channel::{
    self, GenericCallback, GenericSender, ReceiveError, RoutedReceiver,
};
use servo_base::id::{PipelineId, PipelineNamespace, ServiceWorkerId, ServiceWorkerRegistrationId};
use servo_config::pref;
use servo_constellation_traits::{
    DOMMessage, Job, JobError, JobResult, JobResultValue, JobType, SWManagerSenders, ScopeThings,
    ServiceWorkerAlgorithm, ServiceWorkerAlgorithmResult, ServiceWorkerManagerFactory,
    ServiceWorkerMsg, ServiceWorkerRegistrationInfo,
};
use servo_url::{ImmutableOrigin, ServoUrl};

use crate::dom::abstractworker::{MessageData, WorkerScriptMsg};
use crate::dom::serviceworkerglobalscope::{
    ServiceWorkerControlMsg, ServiceWorkerGlobalScope, ServiceWorkerScriptMsg,
};
use crate::dom::serviceworkerregistration::longest_prefix_match;
use crate::script_runtime::ThreadSafeJSContext;

enum Message {
    FromResource(CustomResponseMediator),
    FromConstellation(Box<ServiceWorkerMsg>),
}

/// <https://w3c.github.io/ServiceWorker/#dfn-service-worker>
#[derive(Clone)]
pub(crate) struct ServiceWorker {
    /// A unique identifer.
    pub(crate) id: ServiceWorkerId,
    /// <https://w3c.github.io/ServiceWorker/#dfn-script-url>
    pub(crate) script_url: ServoUrl,
    /// A sender to the running service worker scope.
    pub(crate) sender: Sender<ServiceWorkerScriptMsg>,
}

impl ServiceWorker {
    fn new(
        script_url: ServoUrl,
        sender: Sender<ServiceWorkerScriptMsg>,
        id: ServiceWorkerId,
    ) -> ServiceWorker {
        ServiceWorker {
            id,
            script_url,
            sender,
        }
    }

    /// Forward a DOM message to the running service worker scope.
    fn forward_dom_message(&self, msg: DOMMessage) {
        let DOMMessage {
            origin,
            data,
            pipeline_id,
        } = msg;
        let _ = self.sender.send(ServiceWorkerScriptMsg::CommonWorker(
            WorkerScriptMsg::DOMMessage(MessageData {
                origin,
                pipeline_id,
                data: Box::new(data),
            }),
        ));
    }

    /// Send a message to the running service worker scope.
    fn send_message(&self, msg: ServiceWorkerScriptMsg) {
        let _ = self.sender.send(msg);
    }
}

/// When updating a registration, which worker are we targetting?
enum RegistrationUpdateTarget {
    Installing,
    Waiting,
    Active,
}

fn should_request_activation(
    has_active_worker: bool,
    has_waiting_worker: bool,
    has_activating_worker: bool,
    skip_waiting_requested: bool,
) -> bool {
    skip_waiting_requested || (!has_active_worker && !has_waiting_worker && !has_activating_worker)
}

fn registration_reuses_script(
    newest_script_url: Option<&ServoUrl>,
    requested_script_url: &ServoUrl,
) -> bool {
    newest_script_url.is_some_and(|script_url| script_url == requested_script_url)
}

fn registration_info(
    scope_url: &ServoUrl,
    registration: &ServiceWorkerRegistration,
) -> Option<ServiceWorkerRegistrationInfo> {
    let worker = registration.get_newest_worker()?;
    Some(ServiceWorkerRegistrationInfo {
        id: registration.id,
        installing_worker: registration
            .installing_worker
            .as_ref()
            .map(|worker| worker.id),
        waiting_worker: registration
            .waiting_worker
            .as_ref()
            .or(registration.activating_worker.as_ref())
            .map(|worker| worker.id),
        active_worker: registration.active_worker.as_ref().map(|worker| worker.id),
        storage_key: scope_url.origin(),
        scope_url: scope_url.clone(),
        script_url: worker.script_url,
    })
}

impl Drop for ServiceWorkerRegistration {
    /// <https://html.spec.whatwg.org/multipage/#terminate-a-worker>
    fn drop(&mut self) {
        for (_, worker) in self.workers.drain() {
            if worker
                .control_sender
                .send(ServiceWorkerControlMsg::Exit)
                .is_err()
            {
                warn!("Failed to send exit message to service worker scope.");
            }

            worker.closing.store(true, Ordering::SeqCst);
            worker.context.request_interrupt_callback();

            // TODO: Step 1, 2 and 3.
            if worker.join_handle.join().is_err() {
                warn!("Failed to join on service worker thread.");
            }
        }
    }
}

/// <https://w3c.github.io/ServiceWorker/#service-worker-registration-concept>
struct ServiceWorkerRegistration {
    /// A unique identifer.
    id: ServiceWorkerRegistrationId,
    /// <https://w3c.github.io/ServiceWorker/#dfn-active-worker>
    active_worker: Option<ServiceWorker>,
    /// <https://w3c.github.io/ServiceWorker/#dfn-waiting-worker>
    waiting_worker: Option<ServiceWorker>,
    /// Worker whose activate event is currently running.
    activating_worker: Option<ServiceWorker>,
    /// <https://w3c.github.io/ServiceWorker/#dfn-installing-worker>
    installing_worker: Option<ServiceWorker>,
    /// `skipWaiting()` was requested before installation completed.
    skip_waiting_requested: bool,
    /// Runtime resources for every worker belonging to this registration.
    ///
    /// An update can create a new worker while the previous active worker is
    /// still running. Keeping only one set of resources here made a second
    /// update panic the service-worker manager.
    workers: HashMap<ServiceWorkerId, WorkerRuntime>,
    /// Navigation-preload configuration persisted with this registration.
    navigation_preload_enabled: bool,
    navigation_preload_header_value: Option<Vec<u8>>,
    /// Registration job waiting for the worker's install lifecycle result.
    install_job: Option<Job>,
    /// Update jobs that arrive while this registration is installing a
    /// worker. Equivalent updates are coalesced onto the active install.
    pending_update_jobs: Vec<Job>,
    /// <https://w3c.github.io/ServiceWorker/#serviceworkercontainer-service-worker-client>
    /// The client of the container to which this registration belongs.
    client: GenericCallback<ServiceWorkerAlgorithmResult>,
}

struct WorkerRuntime {
    /// A channel to send control messages to the worker, currently only used
    /// to signal shutdown.
    control_sender: Sender<ServiceWorkerControlMsg>,
    /// A handle to join on the worker thread.
    join_handle: JoinHandle<()>,
    /// A context to request an interrupt.
    context: ThreadSafeJSContext,
    /// The closing flag for the worker.
    closing: Arc<AtomicBool>,
}

impl ServiceWorkerRegistration {
    pub(crate) fn new(
        client: GenericCallback<ServiceWorkerAlgorithmResult>,
        id: ServiceWorkerRegistrationId,
    ) -> ServiceWorkerRegistration {
        ServiceWorkerRegistration {
            id,
            active_worker: None,
            waiting_worker: None,
            activating_worker: None,
            installing_worker: None,
            skip_waiting_requested: false,
            workers: HashMap::new(),
            navigation_preload_enabled: false,
            navigation_preload_header_value: None,
            install_job: None,
            pending_update_jobs: Vec::new(),
            client,
        }
    }

    fn note_worker_thread(
        &mut self,
        worker_id: ServiceWorkerId,
        join_handle: JoinHandle<()>,
        control_sender: Sender<ServiceWorkerControlMsg>,
        context: ThreadSafeJSContext,
        closing: Arc<AtomicBool>,
    ) {
        let previous = self.workers.insert(
            worker_id,
            WorkerRuntime {
                control_sender,
                join_handle,
                context,
                closing,
            },
        );
        debug_assert!(previous.is_none(), "service worker ID must be unique");
    }

    fn stop_worker(&mut self, worker_id: ServiceWorkerId) {
        let Some(worker) = self.workers.remove(&worker_id) else {
            return;
        };
        if worker
            .control_sender
            .send(ServiceWorkerControlMsg::Exit)
            .is_err()
        {
            warn!("Failed to send exit message to service worker scope.");
        }
        worker.closing.store(true, Ordering::SeqCst);
        worker.context.request_interrupt_callback();
        if worker.join_handle.join().is_err() {
            warn!("Failed to join on service worker thread.");
        }
    }

    fn stop_all_workers(&mut self) {
        let worker_ids: Vec<_> = self.workers.keys().cloned().collect();
        for worker_id in worker_ids {
            self.stop_worker(worker_id);
        }
    }

    /// <https://w3c.github.io/ServiceWorker/#get-newest-worker>
    fn get_newest_worker(&self) -> Option<ServiceWorker> {
        if let Some(worker) = self.active_worker.as_ref() {
            return Some(worker.clone());
        }
        if let Some(worker) = self.activating_worker.as_ref() {
            return Some(worker.clone());
        }
        if let Some(worker) = self.waiting_worker.as_ref() {
            return Some(worker.clone());
        }
        if let Some(worker) = self.installing_worker.as_ref() {
            return Some(worker.clone());
        }
        None
    }

    /// <https://w3c.github.io/ServiceWorker/#update-registration-state>
    fn update_registration_state(
        &mut self,
        target: RegistrationUpdateTarget,
        worker: Option<ServiceWorker>,
    ) {
        match target {
            RegistrationUpdateTarget::Active => {
                self.active_worker = worker;
            },
            RegistrationUpdateTarget::Waiting => {
                self.waiting_worker = worker;
            },
            RegistrationUpdateTarget::Installing => {
                self.installing_worker = worker;
            },
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RegistrationKey {
    scope_url: ServoUrl,
    partition_key: Option<String>,
}

impl RegistrationKey {
    fn new(scope_url: ServoUrl, partition_key: Option<String>) -> Self {
        Self {
            scope_url,
            partition_key,
        }
    }
}

/// Durable descriptor for a service-worker registration.
///
/// Worker threads cannot survive a browser restart, but the scope-to-script
/// mapping can: on the next navigation the manager lazily re-registers the
/// worker from these descriptors instead of reporting no registration.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct PersistedRegistration {
    scope_url: String,
    partition_key: Option<String>,
    script_url: String,
    navigation_preload_enabled: bool,
    navigation_preload_header_value: Option<Vec<u8>>,
}

/// Environment variable selecting the JSON file used for the registration
/// registry. Unset means persistence is disabled (in-memory only).
const REGISTRY_ENV_VAR: &str = "NOMAD_SW_REGISTRY";

fn persisted_registry_path() -> Option<PathBuf> {
    std::env::var_os(REGISTRY_ENV_VAR).map(PathBuf::from)
}

fn save_persisted_registrations(
    path: &PathBuf,
    descriptors: &[PersistedRegistration],
) -> Result<(), String> {
    let data = serde_json::to_string_pretty(descriptors).map_err(|error| error.to_string())?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    std::fs::write(path, data).map_err(|error| error.to_string())
}

fn load_persisted_registrations(path: &PathBuf) -> Result<Vec<PersistedRegistration>, String> {
    let data = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    serde_json::from_str(&data).map_err(|error| error.to_string())
}

/// Snapshot live registrations into durable descriptors, preserving the
/// manager's enumeration order. Registrations without a live worker (still
/// installing with no script yet) are skipped: they have no script URL to
/// re-fetch after a restart.
fn persisted_descriptors(
    registrations: &HashMap<RegistrationKey, ServiceWorkerRegistration>,
    registration_order: &[RegistrationKey],
) -> Vec<PersistedRegistration> {
    ordered_registration_keys(registrations.keys(), registration_order)
        .into_iter()
        .filter_map(|key| {
            let registration = registrations.get(&key)?;
            let worker = registration.get_newest_worker()?;
            Some(PersistedRegistration {
                scope_url: key.scope_url.as_str().to_owned(),
                partition_key: key.partition_key.clone(),
                script_url: worker.script_url.as_str().to_owned(),
                navigation_preload_enabled: registration.navigation_preload_enabled,
                navigation_preload_header_value: registration
                    .navigation_preload_header_value
                    .clone(),
            })
        })
        .collect()
}

/// A registration restored from the on-disk registry after a restart.
///
/// Workers cannot survive a restart, so restored entries carry no live worker
/// ids. They stay queryable through match/get-registration until a live
/// registration for the same scope replaces them (adopting the restored id so
/// DOM identity stays stable) or an unregister drops them.
#[derive(Clone, Debug)]
struct RestoredRegistration {
    id: ServiceWorkerRegistrationId,
    script_url: ServoUrl,
    navigation_preload_enabled: bool,
    navigation_preload_header_value: Option<Vec<u8>>,
}

fn restore_registrations(
    descriptors: Vec<PersistedRegistration>,
) -> Vec<(RegistrationKey, RestoredRegistration)> {
    descriptors
        .into_iter()
        .filter_map(|descriptor| {
            let scope_url = ServoUrl::parse(&descriptor.scope_url).ok()?;
            let script_url = ServoUrl::parse(&descriptor.script_url).ok()?;
            if scope_url.origin() != script_url.origin() {
                return None;
            }
            let key = RegistrationKey::new(scope_url, descriptor.partition_key);
            let entry = RestoredRegistration {
                id: ServiceWorkerRegistrationId::new(),
                script_url,
                navigation_preload_enabled: descriptor.navigation_preload_enabled,
                navigation_preload_header_value: descriptor.navigation_preload_header_value,
            };
            Some((key, entry))
        })
        .collect()
}

fn restored_registration_info(
    key: &RegistrationKey,
    entry: &RestoredRegistration,
    storage_key: ImmutableOrigin,
) -> ServiceWorkerRegistrationInfo {
    ServiceWorkerRegistrationInfo {
        id: entry.id,
        installing_worker: None,
        waiting_worker: None,
        active_worker: None,
        storage_key,
        scope_url: key.scope_url.clone(),
        script_url: entry.script_url.clone(),
    }
}

#[cfg(test)]
fn select_restored_match<'a>(
    restored: &'a HashMap<RegistrationKey, RestoredRegistration>,
    load_url: &ServoUrl,
    partition_key: Option<&str>,
) -> Option<(&'a RegistrationKey, &'a RestoredRegistration)> {
    restored
        .iter()
        .filter(|(key, _)| {
            key.partition_key.as_deref() == partition_key
                && longest_prefix_match(&key.scope_url, load_url)
        })
        .max_by_key(|(key, _)| key.scope_url.path().len())
}

/// A structure managing all registrations and workers for a given origin.
pub struct ServiceWorkerManager {
    /// <https://w3c.github.io/ServiceWorker/#dfn-scope-to-registration-map>
    registrations: HashMap<RegistrationKey, ServiceWorkerRegistration>,
    /// Keep enumeration order separate from the keyed registration lookup.
    registration_order: Vec<RegistrationKey>,
    /// Documents whose controller scope must receive same-origin subresource
    /// fetch events even when the requested URL is outside that scope path.
    controlled_clients: HashMap<PipelineId, (RegistrationKey, ServiceWorkerId)>,
    // own sender to send messages here
    own_sender: GenericSender<ServiceWorkerMsg>,
    // receiver to receive messages from constellation
    own_port: RoutedReceiver<ServiceWorkerMsg>,
    // to receive resource messages
    resource_receiver: Receiver<CustomResponseMediator>,
    /// Resource thread used for parallel navigation-preload fetches.
    resource_threads: ResourceThreads,
    /// A shared [`FontContext`] to use for all service workers spawned by this [`ServiceWorkerManager`].
    font_context: Arc<FontContext>,
    /// Optional on-disk registry path (`NOMAD_SW_REGISTRY`). Best-effort only.
    registry_path: Option<PathBuf>,
    /// Registrations restored from disk that have no live worker yet. They
    /// stay visible to match/get-registration until replaced or unregistered.
    restored: HashMap<RegistrationKey, RestoredRegistration>,
    /// File order of restored entries, so enumeration stays stable.
    restored_order: Vec<RegistrationKey>,
}

impl ServiceWorkerManager {
    fn new(
        own_sender: GenericSender<ServiceWorkerMsg>,
        from_constellation_receiver: RoutedReceiver<ServiceWorkerMsg>,
        resource_port: Receiver<CustomResponseMediator>,
        font_context: Arc<FontContext>,
        resource_threads: ResourceThreads,
    ) -> ServiceWorkerManager {
        // Install a pipeline-namespace in the current thread.
        PipelineNamespace::auto_install();

        let registry_path = persisted_registry_path();
        // Best-effort rehydration: descriptors are validated here so a corrupt
        // registry never blocks startup. Restored entries stay queryable and
        // are adopted (same id) when the scope re-registers; live workers
        // re-spawn through the normal register/update flow afterwards.
        let mut restored = HashMap::new();
        let mut restored_order = Vec::new();
        if let Some(path) = registry_path.as_ref() {
            match load_persisted_registrations(path) {
                Ok(descriptors) if !descriptors.is_empty() => {
                    warn!(
                        "Restored {} service-worker descriptors from registry; workers re-spawn on next navigation",
                        descriptors.len()
                    );
                    for (key, entry) in restore_registrations(descriptors) {
                        restored_order.push(key.clone());
                        restored.insert(key, entry);
                    }
                },
                Ok(_) => {},
                Err(error) => {
                    warn!("Ignoring unreadable service-worker registry: {error}");
                },
            }
        }

        ServiceWorkerManager {
            registrations: HashMap::new(),
            registration_order: Vec::new(),
            controlled_clients: HashMap::new(),
            own_sender,
            own_port: from_constellation_receiver,
            resource_receiver: resource_port,
            font_context,
            resource_threads,
            registry_path,
            restored,
            restored_order,
        }
    }

    /// Best-effort snapshot of live registrations to the on-disk registry.
    /// Persistence disabled when `NOMAD_SW_REGISTRY` is unset; IO failures
    /// only warn so registration itself never fails for storage reasons.
    fn persist_registrations(&self) {
        let Some(path) = self.registry_path.as_ref() else {
            return;
        };
        let descriptors = persisted_descriptors(&self.registrations, &self.registration_order);
        if let Err(error) = save_persisted_registrations(path, &descriptors) {
            warn!("Failed to persist service-worker registrations: {error}");
        }
    }

    fn get_matching_registration_key(
        &self,
        load_url: &ServoUrl,
        partition_key: Option<&str>,
    ) -> Option<RegistrationKey> {
        select_longest_matching_registration_key(self.registrations.keys(), load_url, partition_key)
    }

    fn registration_key_for_worker(
        &self,
        scope_url: &ServoUrl,
        worker_id: ServiceWorkerId,
    ) -> Option<RegistrationKey> {
        self.registrations
            .iter()
            .find(|(key, registration)| {
                key.scope_url == *scope_url
                    && [
                        registration.active_worker.as_ref(),
                        registration.waiting_worker.as_ref(),
                        registration.activating_worker.as_ref(),
                        registration.installing_worker.as_ref(),
                    ]
                    .into_iter()
                    .flatten()
                    .any(|worker| worker.id == worker_id)
            })
            .map(|(key, _)| key.clone())
    }

    fn handle_message(&mut self) {
        while let Ok(message) = self.receive_message() {
            let should_continue = match message {
                Message::FromConstellation(msg) => self.handle_message_from_constellation(*msg),
                Message::FromResource(msg) => self.handle_message_from_resource(msg),
            };
            if !should_continue {
                for registration in self.registrations.drain() {
                    // Signal shut-down, and join on the thread.
                    drop(registration);
                }
                break;
            }
        }
    }

    fn handle_message_from_resource(&mut self, mediator: CustomResponseMediator) -> bool {
        let partition_key = mediator
            .request
            .client
            .as_ref()
            .and_then(|client| client.top_level_partition_key.as_deref());
        let navigation_key = self.get_matching_registration_key(&mediator.load_url, partition_key);
        let controlled_key = mediator
            .request
            .pipeline_id
            .and_then(|pipeline_id| self.controlled_clients.get(&pipeline_id))
            .map(|(key, _)| key.clone());
        let key = navigation_key.clone().or(controlled_key);

        if serviceworker_enabled()
            && let Some(key) = key
            && let Some(registration) = self.registrations.get(&key)
            && let Some(ref worker) = registration.active_worker
        {
            if let (Some(pipeline_id), Some(navigation_key)) =
                (mediator.request.pipeline_id, navigation_key)
                && matches!(
                    mediator.request.destination,
                    Destination::Document
                        | Destination::Embed
                        | Destination::Frame
                        | Destination::IFrame
                        | Destination::Object
                )
            {
                self.controlled_clients
                    .insert(pipeline_id, (navigation_key, worker.id));
            }
            let preload_receiver = if registration.navigation_preload_enabled
                && matches!(
                    mediator.request.destination,
                    Destination::Document | Destination::Frame | Destination::IFrame
                ) {
                let (sender, receiver) = unbounded();
                let resource_threads = self.resource_threads.clone();
                let request = mediator.request.clone();
                let header_value = navigation_preload_header_value(
                    true,
                    registration.navigation_preload_header_value.as_deref(),
                );
                thread::spawn(move || {
                    let response =
                        fetch_navigation_preload(resource_threads, request, header_value);
                    let _ = sender.send(response);
                });
                Some(receiver)
            } else {
                None
            };
            worker.send_message(ServiceWorkerScriptMsg::Response(mediator, preload_receiver));
            return true;
        }
        let _ = mediator.response_chan.send(None);
        true
    }

    fn receive_message(&mut self) -> generic_channel::ReceiveResult<Message> {
        select! {
            recv(self.own_port) -> result_msg => generic_channel::to_receive_result::<ServiceWorkerMsg>(result_msg).map(|msg| Message::FromConstellation(Box::new(msg))),
            recv(self.resource_receiver) -> msg => msg.map(Message::FromResource).map_err(|_e| ReceiveError::Disconnected),
        }
    }

    fn handle_message_from_constellation(&mut self, msg: ServiceWorkerMsg) -> bool {
        match msg {
            ServiceWorkerMsg::ControllerChanged {
                pipeline_id,
                scope_url,
                worker_id,
            } => {
                if let Some(worker_id) = worker_id {
                    let Some(key) = self.registration_key_for_worker(&scope_url, worker_id) else {
                        return true;
                    };
                    self.controlled_clients
                        .insert(pipeline_id, (key, worker_id));
                } else if self
                    .controlled_clients
                    .get(&pipeline_id)
                    .is_some_and(|(controlled_key, _)| controlled_key.scope_url == scope_url)
                {
                    self.controlled_clients.remove(&pipeline_id);
                }
            },
            ServiceWorkerMsg::Timeout(_scope) => {
                // TODO: https://w3c.github.io/ServiceWorker/#terminate-service-worker
            },
            ServiceWorkerMsg::ForwardDOMMessage(msg, scope_url, partition_key) => {
                let key = RegistrationKey::new(scope_url, partition_key);
                if let Some(registration) = self.registrations.get_mut(&key) {
                    if let Some(ref worker) = registration.active_worker {
                        worker.forward_dom_message(msg);
                    } else if let Some(ref worker) = registration.waiting_worker {
                        worker.forward_dom_message(msg);
                    } else if let Some(ref worker) = registration.activating_worker {
                        worker.forward_dom_message(msg);
                    } else if let Some(ref worker) = registration.installing_worker {
                        worker.forward_dom_message(msg);
                    }
                }
            },
            ServiceWorkerMsg::ForwardWorkerMessage {
                data,
                url,
                source,
                origin,
            } => {
                let Some(key) = self.registration_key_for_worker(&url, source) else {
                    warn!("No registration found for scope URL when forwarding message to worker.");
                    return true;
                };
                let Some(registration) = self.registrations.get(&key) else {
                    return true;
                };
                let script_url = if let Some(worker) = registration.active_worker.as_ref() {
                    worker.script_url.clone()
                } else if let Some(worker) = registration.waiting_worker.as_ref() {
                    worker.script_url.clone()
                } else if let Some(worker) = registration.activating_worker.as_ref() {
                    worker.script_url.clone()
                } else if let Some(worker) = registration.installing_worker.as_ref() {
                    worker.script_url.clone()
                } else {
                    warn!("No worker found for scope URL when forwarding message to worker.");
                    return true;
                };
                if registration
                    .client
                    .send(ServiceWorkerAlgorithmResult::MessageFromWorker {
                        message: data,
                        source,
                        scope_url: url,
                        script_url,
                        origin,
                    })
                    .is_err()
                {
                    warn!("Failed to forward message from worker to script.");
                }
            },
            ServiceWorkerMsg::SkipWaiting {
                scope_url,
                worker_id,
            } => {
                if let Some(key) = self.registration_key_for_worker(&scope_url, worker_id) {
                    self.activate_waiting_worker(&key, worker_id);
                }
            },
            ServiceWorkerMsg::InstallFinished {
                scope_url,
                worker_id,
                succeeded,
                scope_allowed,
            } => {
                if let Some(key) = self.registration_key_for_worker(&scope_url, worker_id) {
                    self.finish_installation(&key, worker_id, succeeded, scope_allowed);
                }
            },
            ServiceWorkerMsg::ActivateFinished {
                scope_url,
                worker_id,
                succeeded,
            } => {
                if let Some(key) = self.registration_key_for_worker(&scope_url, worker_id) {
                    self.finish_activation(&key, worker_id, succeeded);
                }
            },
            ServiceWorkerMsg::HandleAlgorithm(algorithm) => match algorithm {
                ServiceWorkerAlgorithm::StartRegister(job) => {
                    self.handle_register_job(job);
                },
                ServiceWorkerAlgorithm::Update(job) => {
                    self.handle_update_job(job);
                },
                ServiceWorkerAlgorithm::Activate {
                    partition_key,
                    scope_url,
                    worker_id,
                    ..
                } => {
                    let key = RegistrationKey::new(scope_url, partition_key);
                    self.request_activation(&key, worker_id);
                },
                ServiceWorkerAlgorithm::Unregister(job) => {
                    self.handle_unregister_job(job);
                },
                ServiceWorkerAlgorithm::MatchServiceWorkerRegistration {
                    storage_key,
                    partition_key,
                    client_url,
                    result_handler,
                } => {
                    self.handle_match_registration(
                        storage_key,
                        partition_key,
                        client_url,
                        result_handler,
                    );
                },
                ServiceWorkerAlgorithm::GetRegistrations {
                    storage_key,
                    partition_key,
                    result_handler,
                } => {
                    self.handle_get_registrations(storage_key, partition_key, result_handler);
                },
                ServiceWorkerAlgorithm::SetNavigationPreload {
                    storage_key,
                    partition_key,
                    scope_url,
                    enabled,
                    header_value,
                } => {
                    self.handle_set_navigation_preload(
                        storage_key,
                        partition_key,
                        scope_url,
                        enabled,
                        header_value,
                    );
                },
            },
            ServiceWorkerMsg::Exit => return false,
        }
        true
    }

    fn handle_set_navigation_preload(
        &mut self,
        storage_key: ImmutableOrigin,
        partition_key: Option<String>,
        scope_url: ServoUrl,
        enabled: bool,
        header_value: Option<Vec<u8>>,
    ) {
        if storage_key != scope_url.origin() {
            warn!("Ignoring navigation-preload state for a cross-origin scope.");
            return;
        }
        let key = RegistrationKey::new(scope_url, partition_key);
        let Some(registration) = self.registrations.get_mut(&key) else {
            return;
        };
        registration.navigation_preload_enabled = enabled;
        registration.navigation_preload_header_value = header_value;
    }

    fn activate_waiting_worker(&mut self, key: &RegistrationKey, worker_id: ServiceWorkerId) {
        let request_now = {
            let Some(registration) = self.registrations.get_mut(key) else {
                warn!("No registration found for skipWaiting request.");
                return;
            };

            if registration
                .activating_worker
                .as_ref()
                .is_some_and(|worker| worker.id == worker_id)
            {
                false
            } else if registration
                .installing_worker
                .as_ref()
                .is_some_and(|worker| worker.id == worker_id)
            {
                registration.skip_waiting_requested = true;
                false
            } else {
                true
            }
        };

        if request_now {
            self.request_activation(key, worker_id);
        }
    }

    fn request_activation(&mut self, key: &RegistrationKey, worker_id: ServiceWorkerId) {
        let Some(registration) = self.registrations.get_mut(key) else {
            return;
        };
        if registration.activating_worker.is_some() {
            return;
        }

        let Some(waiting_worker) = registration.waiting_worker.take() else {
            return;
        };
        if waiting_worker.id != worker_id {
            registration.waiting_worker = Some(waiting_worker);
            warn!("Ignoring activation request from a non-waiting worker.");
            return;
        }

        waiting_worker.send_message(ServiceWorkerScriptMsg::Activate);
        registration.activating_worker = Some(waiting_worker);
    }

    fn finish_activation(
        &mut self,
        key: &RegistrationKey,
        worker_id: ServiceWorkerId,
        succeeded: bool,
    ) {
        let Some(registration) = self.registrations.get_mut(key) else {
            return;
        };
        let Some(worker) = registration.activating_worker.take() else {
            return;
        };
        if worker.id != worker_id {
            registration.activating_worker = Some(worker);
            return;
        }

        if succeeded {
            // The old active worker remains alive until its running tasks
            // finish; subsequent events use the newly promoted worker.
            registration.update_registration_state(RegistrationUpdateTarget::Active, Some(worker));
        } else {
            registration.waiting_worker = Some(worker);
        }

        let info = registration_info(&key.scope_url, registration);
        let client = registration.client.clone();
        if let Some(info) = info
            && client
                .send(ServiceWorkerAlgorithmResult::RegistrationStateChanged(info))
                .is_err()
        {
            warn!("Failed to notify client of service worker state change.");
        }
    }

    /// <https://w3c.github.io/ServiceWorker/#unregister>
    fn handle_unregister_job(&mut self, job: Job) {
        // Step 1: Let registration be the result of running Get Registration given job’s storage key and job’s scope url.
        let key = RegistrationKey::new(job.scope_url.clone(), job.partition_key.clone());
        let Some(mut registration) = self.registrations.remove(&key) else {
            // Step 2: If registration is null, then:
            // A restored (post-restart, workerless) entry counts as a
            // registration here: drop it so unregister really removes the
            // scope instead of leaving it visible after a restart.
            let restored = self.restored.remove(&key);
            self.restored_order.retain(|ordered| ordered != &key);
            let removed = restored.is_some();
            if removed {
                self.persist_registrations();
            }
            // Step 2.1: Invoke Resolve Job Promise with job and false.
            if job
                .client
                .send(ServiceWorkerAlgorithmResult::Job(
                    JobResult::ResolvePromise(JobResultValue::Unregister(removed)),
                ))
                .is_err()
            {
                warn!("Failed to send unregister result to script.");
            }
            // Step 2.2: Invoke Finish Job with job and abort these steps.
            // TODO: Finish Job.
            return;
        };
        self.registration_order
            .retain(|registered_key| registered_key != &key);
        self.restored.remove(&key);
        self.restored_order.retain(|ordered| ordered != &key);

        registration.stop_all_workers();

        // Step 3: Remove registration map[(registration’s storage key, job’s scope url)].
        // Note: done by removing the registration from the map above.

        // Step 4: Invoke Resolve Job Promise with job and true.
        if job
            .client
            .send(ServiceWorkerAlgorithmResult::Job(
                JobResult::ResolvePromise(JobResultValue::Unregister(true)),
            ))
            .is_err()
        {
            warn!("Failed to send unregister result to script.");
        }

        // Step 5: Invoke Try Clear Registration with registration.
        // TODO: Try Clear Registration.

        // Step 6: Invoke Finish Job with job.
        // TODO: Finish Job.
        self.persist_registrations();
    }

    /// <https://w3c.github.io/ServiceWorker/#match-service-worker-registration>
    fn handle_match_registration(
        &self,
        storage_key: ImmutableOrigin,
        partition_key: Option<String>,
        client_url: ServoUrl,
        result_handler: GenericCallback<ServiceWorkerAlgorithmResult>,
    ) {
        // Step 1: Run the following steps atomically.
        // Note: done using the channel from which this message was received.

        // Step 2: Let clientURLString be serialized clientURL.
        let client_url_string = client_url.as_str();

        // Step 3: Let matchingScopeString be the empty string.
        let mut matching_scope_string = String::new();

        // Step 4: Let scopeStringSet be an empty list.
        let mut scope_string_set = Vec::new();

        // Step 5: For each (entry storage key, entry scope) of registration map’s keys:
        // Restored (post-restart, workerless) entries participate so a
        // restarted browser still matches scopes it knew before shutdown.
        for entry_scope in self.registrations.keys().chain(self.restored.keys()) {
            // Step 5.1. If storage key equals entry storage key, then append entry scope to the end of scopeStringSet.
            if registration_matches_storage_partition(
                entry_scope,
                &storage_key,
                partition_key.as_deref(),
            ) {
                scope_string_set.push(entry_scope.scope_url.as_str());
            }
        }

        // Step 6: Set matchingScopeString to the longest value in scopeStringSet which the value of clientURLString starts with, if it exists.
        for scope in scope_string_set {
            if client_url_string.starts_with(scope) && scope.len() > matching_scope_string.len() {
                matching_scope_string = scope.to_owned();
            }
        }

        // Step 7: Let matchingScope be null.
        let mut matching_scope = None;

        // Step 8: If matchingScopeString is not the empty string, then:
        if !matching_scope_string.is_empty() {
            // Step 8.1. Set matchingScope to the result of parsing matchingScopeString.
            let Ok(parsed_matching_scope) = ServoUrl::parse(&matching_scope_string) else {
                error!("Failed to parse matching scope string as URL.");
                if result_handler
                    .send(ServiceWorkerAlgorithmResult::MatchServiceWorkerRegistration(None))
                    .is_err()
                {
                    warn!("Failed to send match registration result to script.");
                }
                return;
            };
            matching_scope = Some(parsed_matching_scope);

            // Step 8.2: Assert: matchingScope’s origin and clientURL’s origin are same origin.
            debug_assert_eq!(
                matching_scope.as_ref().unwrap().origin(),
                client_url.origin()
            );
        }

        let Some(matching_scope) = matching_scope else {
            if result_handler
                .send(ServiceWorkerAlgorithmResult::MatchServiceWorkerRegistration(None))
                .is_err()
            {
                warn!("Failed to send match registration result to script.");
            }
            return;
        };

        // Step 9: Return the result of running Get Registration given storage key and matchingScope.
        // A live registration without a worker yet (or a restored,
        // post-restart entry) resolves to a workerless registration object
        // instead of panicking: enumeration and identity survive the restart
        // while workers re-spawn through register/update.
        let key = RegistrationKey::new(matching_scope.clone(), partition_key);
        let info = self
            .registrations
            .get(&key)
            .and_then(|registration| {
                let worker = registration.get_newest_worker()?;
                Some(ServiceWorkerRegistrationInfo {
                    scope_url: matching_scope.clone(),
                    script_url: worker.script_url,
                    storage_key: storage_key.clone(),
                    id: registration.id,
                    installing_worker: registration
                        .installing_worker
                        .as_ref()
                        .map(|worker| worker.id),
                    waiting_worker: registration
                        .waiting_worker
                        .as_ref()
                        .or(registration.activating_worker.as_ref())
                        .map(|worker| worker.id),
                    active_worker: registration.active_worker.as_ref().map(|worker| worker.id),
                })
            })
            .or_else(|| {
                let entry = self.restored.get(&key)?;
                if key.scope_url.origin() != storage_key {
                    return None;
                }
                Some(restored_registration_info(&key, entry, storage_key))
            });
        if result_handler
            .send(ServiceWorkerAlgorithmResult::MatchServiceWorkerRegistration(info))
            .is_err()
        {
            warn!("Failed to send match registration result to script.");
        }
    }

    /// <https://w3c.github.io/ServiceWorker/#get-registrations-algorithm>
    fn handle_get_registrations(
        &self,
        storage_key: ImmutableOrigin,
        partition_key: Option<String>,
        result_handler: GenericCallback<ServiceWorkerAlgorithmResult>,
    ) {
        let mut registrations =
            ordered_registration_keys(self.registrations.keys(), &self.registration_order)
                .into_iter()
                .filter(|key| {
                    registration_matches_storage_partition(
                        key,
                        &storage_key,
                        partition_key.as_deref(),
                    )
                })
                .filter_map(|key| {
                    self.registrations
                        .get(&key)
                        .and_then(|registration| registration_info(&key.scope_url, registration))
                })
                .collect::<Vec<_>>();
        // Restored (post-restart, workerless) entries stay enumerable until a
        // live registration replaces them. File order keeps enumeration
        // stable across the restart.
        for key in &self.restored_order {
            if self.registrations.contains_key(key) {
                continue;
            }
            let Some(entry) = self.restored.get(key) else {
                continue;
            };
            if !registration_matches_storage_partition(key, &storage_key, partition_key.as_deref())
            {
                continue;
            }
            registrations.push(restored_registration_info(key, entry, storage_key.clone()));
        }
        if result_handler
            .send(ServiceWorkerAlgorithmResult::GetRegistrations(
                registrations,
            ))
            .is_err()
        {
            warn!("Failed to send service worker registrations result to script.");
        }
    }

    /// <https://w3c.github.io/ServiceWorker/#register-algorithm>
    fn handle_register_job(&mut self, mut job: Job) {
        // Step 1: If the result of running potentially trustworthy origin with the origin of job’s script url as the argument is Not Trusted, then:
        if !job.script_url.origin().is_potentially_trustworthy() {
            // Step 1.1: Invoke Reject Job Promise with job and "SecurityError" DOMException.
            if job
                .client
                .send(ServiceWorkerAlgorithmResult::Job(JobResult::RejectPromise(
                    JobError::SecurityError,
                )))
                .is_err()
            {
                warn!("Failed to send reject job promise result to script.");
            }

            // TODO Step 1.2: Invoke Finish Job with job and abort these steps.
            // TODO: Finish Job.
            return;
        }

        // Step 2: If job’s script url’s origin and job’s referrer’s origin are not same origin, then:
        // Step 3: If job’s scope url’s origin and job’s referrer’s origin are not same origin, then:
        // Note: both steps done in one conditional.
        if job.script_url.origin() != job.referrer.origin()
            || job.scope_url.origin() != job.referrer.origin()
        {
            // Step 2.1: Invoke Reject Job Promise with job and "SecurityError" DOMException
            if job
                .client
                .send(ServiceWorkerAlgorithmResult::Job(JobResult::RejectPromise(
                    JobError::SecurityError,
                )))
                .is_err()
            {
                warn!("Failed to send reject job promise result to script.");
            }

            // TODO Step 2.2: Invoke Finish Job with job and abort these steps.
            return;
        }

        // Step 4: Let registration be the result of running Get Registration given job’s storage key and job’s scope url.
        let key = RegistrationKey::new(job.scope_url.clone(), job.partition_key.clone());
        let reuses_existing_registration = self.registrations.get(&key).map(|registration| {
            let newest_script_url = registration
                .get_newest_worker()
                .map(|worker| worker.script_url);
            registration_reuses_script(newest_script_url.as_ref(), &job.script_url)
        });

        if reuses_existing_registration == Some(true) {
            let Some(registration) = self.registrations.get(&key) else {
                return;
            };
            let Some(info) = registration_info(&key.scope_url, registration) else {
                let _ =
                    job.client
                        .send(ServiceWorkerAlgorithmResult::Job(JobResult::RejectPromise(
                            JobError::TypeError,
                        )));
                return;
            };
            let _ = job.client.send(ServiceWorkerAlgorithmResult::Job(
                JobResult::ResolvePromise(JobResultValue::Register(info)),
            ));
            return;
        }

        if self.registrations.contains_key(&key) {
            // A different script URL at an existing scope starts a replacement update.
            job.job_type = JobType::Update;
            self.handle_update_job(job);
            return;
        }

        // Step 6: Else
        // Step 6.1: Invoke Set Registration algorithm with job’s storage key, job’s scope url, and job’s update via cache mode.
        // A scope restored from disk adopts its restored id so DOM identity
        // stays stable across the restart.
        let restored_entry = self.restored.remove(&key);
        self.restored_order.retain(|ordered| ordered != &key);
        let registration_id = restored_entry
            .as_ref()
            .map(|entry| entry.id)
            .or_else(|| {
                job.scope_things
                    .as_ref()
                    .map(|scope_things| scope_things.registration_id)
            })
            .unwrap_or_else(ServiceWorkerRegistrationId::new);
        let mut new_registration =
            ServiceWorkerRegistration::new(job.client.clone(), registration_id);
        if let Some(entry) = restored_entry {
            new_registration.navigation_preload_enabled = entry.navigation_preload_enabled;
            new_registration.navigation_preload_header_value =
                entry.navigation_preload_header_value;
        }
        self.registration_order.push(key.clone());
        self.registrations.insert(key, new_registration);
        self.persist_registrations();

        // Step 7: Invoke Update algorithm passing job as the argument.
        job.job_type = JobType::Update;
        self.handle_update_job(job);
    }

    /// <https://www.w3.org/TR/service-workers/#install>
    fn install(&mut self, job: Job, new_worker: ServiceWorker) {
        let key = RegistrationKey::new(job.scope_url.clone(), job.partition_key.clone());
        let Some(registration) = self.registrations.get_mut(&key) else {
            error!("Registration should exist when installing a worker.");
            let _ = job
                .client
                .send(ServiceWorkerAlgorithmResult::Job(JobResult::RejectPromise(
                    JobError::TypeError,
                )));
            return;
        };

        if registration.install_job.is_some() || registration.installing_worker.is_some() {
            let worker_id = new_worker.id;
            registration.stop_worker(worker_id);
            let _ = job
                .client
                .send(ServiceWorkerAlgorithmResult::Job(JobResult::RejectPromise(
                    JobError::TypeError,
                )));
            return;
        }

        // Keep the registration promise pending until the worker reports the
        // result of its install event. Resolving it before that point exposed
        // failed workers as installed and allowed activation to race ahead of
        // install-time waitUntil() work.
        registration
            .update_registration_state(RegistrationUpdateTarget::Installing, Some(new_worker));
        registration.install_job = Some(job);
    }

    fn finish_installation(
        &mut self,
        key: &RegistrationKey,
        worker_id: ServiceWorkerId,
        succeeded: bool,
        scope_allowed: bool,
    ) {
        let has_controlled_clients = self
            .controlled_clients
            .values()
            .any(|(controlled_key, _)| controlled_key == key);
        let (
            job,
            pending_update_jobs,
            activate_after_install,
            failed_worker,
            installing_info,
            update_state_info,
        ) = {
            let Some(registration) = self.registrations.get_mut(key) else {
                return;
            };
            let Some(worker) = registration.installing_worker.take() else {
                warn!("Install result received without an installing worker.");
                return;
            };
            if worker.id != worker_id {
                registration.installing_worker = Some(worker);
                warn!("Ignoring install result from a non-installing worker.");
                return;
            }
            let Some(job) = registration.install_job.take() else {
                warn!("Install result received without a registration job.");
                registration.installing_worker = Some(worker);
                return;
            };

            let pending_update_jobs = std::mem::take(&mut registration.pending_update_jobs);
            if !succeeded || !scope_allowed {
                registration.skip_waiting_requested = false;
                (
                    Some(job),
                    pending_update_jobs,
                    false,
                    Some(worker.id),
                    None,
                    None,
                )
            } else {
                let activate_after_install = should_request_activation(
                    registration.active_worker.is_some() && has_controlled_clients,
                    registration.waiting_worker.is_some() && has_controlled_clients,
                    registration.activating_worker.is_some() && has_controlled_clients,
                    registration.skip_waiting_requested || !has_controlled_clients,
                );
                // `register()` resolves with a registration whose installing
                // slot still exposes the worker that completed the install
                // job.  The manager can promote that worker immediately, but
                // the client must observe the installing object before the
                // subsequent lifecycle-state notification is delivered.
                let installing_info = ServiceWorkerRegistrationInfo {
                    id: registration.id,
                    installing_worker: Some(worker.id),
                    // The update job resolves while the new worker is still
                    // installing. The subsequent registration-state
                    // notification promotes it to waiting (or activation),
                    // so do not expose it in both slots here.
                    waiting_worker: registration.waiting_worker.as_ref().map(|worker| worker.id),
                    active_worker: registration.active_worker.as_ref().map(|worker| worker.id),
                    storage_key: key.scope_url.origin(),
                    scope_url: key.scope_url.clone(),
                    script_url: worker.script_url.clone(),
                };
                registration.skip_waiting_requested = false;
                registration
                    .update_registration_state(RegistrationUpdateTarget::Waiting, Some(worker));
                let update_state_info = registration_info(&key.scope_url, registration);
                (
                    Some(job),
                    pending_update_jobs,
                    activate_after_install,
                    None,
                    Some(installing_info),
                    update_state_info,
                )
            }
        };

        let Some(job) = job else {
            return;
        };

        if let Some(worker_id) = failed_worker {
            if let Some(registration) = self.registrations.get_mut(key) {
                registration.stop_worker(worker_id);
            }
            for job in std::iter::once(job).chain(pending_update_jobs) {
                if job
                    .client
                    .send(ServiceWorkerAlgorithmResult::Job(JobResult::RejectPromise(
                        JobError::TypeError,
                    )))
                    .is_err()
                {
                    warn!("Failed to send failed-install result to script.");
                }
            }
        } else {
            let Some(info) = installing_info else {
                return;
            };
            let has_update_result = job.expect_update_result
                || pending_update_jobs
                    .iter()
                    .any(|pending_job| pending_job.expect_update_result);
            if activate_after_install && !has_update_result {
                self.request_activation(key, worker_id);
            }
            for job in std::iter::once(job).chain(pending_update_jobs) {
                let result = if job.expect_update_result {
                    JobResultValue::Update {
                        registration: info.clone(),
                        state: update_state_info
                            .clone()
                            .expect("successful installation has a registration state"),
                        activate_after_install,
                    }
                } else {
                    JobResultValue::Register(info.clone())
                };
                if job
                    .client
                    .send(ServiceWorkerAlgorithmResult::Job(
                        JobResult::ResolvePromise(result),
                    ))
                    .is_err()
                {
                    warn!("Failed to send resolve job promise result to script.");
                }
            }
            if has_update_result {
                return;
            }
        }

        if let Some(registration) = self.registrations.get(key)
            && let Some(info) = registration_info(&key.scope_url, registration)
            && registration
                .client
                .send(ServiceWorkerAlgorithmResult::RegistrationStateChanged(info))
                .is_err()
        {
            warn!("Failed to notify client of service worker install state.");
        }
        self.persist_registrations();
    }

    /// <https://w3c.github.io/ServiceWorker/#update>
    fn handle_update_job(&mut self, job: Job) {
        // Step 1: Get registation
        let key = RegistrationKey::new(job.scope_url.clone(), job.partition_key.clone());
        let (job, new_worker) = if let Some(registration) = self.registrations.get_mut(&key) {
            if registration.install_job.is_some() || registration.installing_worker.is_some() {
                if job.expect_update_result {
                    registration.pending_update_jobs.push(job);
                } else if job
                    .client
                    .send(ServiceWorkerAlgorithmResult::Job(JobResult::RejectPromise(
                        JobError::TypeError,
                    )))
                    .is_err()
                {
                    warn!("Failed to send duplicate service worker update rejection.");
                }
                return;
            }
            let scope_things = job
                .scope_things
                .clone()
                .expect("Update job should have scope things.");

            // Very roughly steps 5 to 18.
            // TODO: implement all steps precisely.
            let (new_worker, join_handle, control_sender, context, closing) = update_serviceworker(
                self.own_sender.clone(),
                job.scope_url.clone(),
                scope_things,
                registration.id,
                self.font_context.clone(),
            );

            // Since we've just started the worker thread, ensure we can shut it down later.
            registration.note_worker_thread(
                new_worker.id,
                join_handle,
                control_sender,
                context,
                closing,
            );

            (job, new_worker)
        } else {
            // Step 2
            let _ = job
                .client
                .send(ServiceWorkerAlgorithmResult::Job(JobResult::RejectPromise(
                    JobError::TypeError,
                )));
            return;
        };
        // Step 17: Else, invoke Install algorithm with job, worker, and registration as its arguments.
        self.install(job, new_worker);
    }
}

fn select_longest_matching_registration_key<'a>(
    keys: impl Iterator<Item = &'a RegistrationKey>,
    load_url: &ServoUrl,
    partition_key: Option<&str>,
) -> Option<RegistrationKey> {
    keys.filter(|key| key.partition_key.as_deref() == partition_key)
        .filter(|key| longest_prefix_match(&key.scope_url, load_url))
        .max_by_key(|key| key.scope_url.path().len())
        .cloned()
}

fn registration_matches_storage_partition(
    key: &RegistrationKey,
    storage_key: &ImmutableOrigin,
    partition_key: Option<&str>,
) -> bool {
    key.scope_url.origin() == *storage_key && key.partition_key.as_deref() == partition_key
}

fn ordered_registration_keys<'a>(
    keys: impl Iterator<Item = &'a RegistrationKey>,
    registration_order: &[RegistrationKey],
) -> Vec<RegistrationKey> {
    let available = keys.collect::<HashSet<_>>();
    registration_order
        .iter()
        .filter(|key| available.contains(key))
        .cloned()
        .collect()
}

/// <https://w3c.github.io/ServiceWorker/#update-algorithm>
fn update_serviceworker(
    own_sender: GenericSender<ServiceWorkerMsg>,
    scope_url: ServoUrl,
    mut scope_things: ScopeThings,
    registration_id: ServiceWorkerRegistrationId,
    font_context: Arc<FontContext>,
) -> (
    ServiceWorker,
    JoinHandle<()>,
    Sender<ServiceWorkerControlMsg>,
    ThreadSafeJSContext,
    Arc<AtomicBool>,
) {
    scope_things.registration_id = registration_id;
    let (sender, receiver) = unbounded();
    let (devtools_sender, devtools_receiver) = generic_channel::channel().unwrap();
    scope_things.init.from_devtools_sender = Some(devtools_sender);

    if let Some(ref chan) = scope_things.devtools_chan
        && let Some(ref sender) = scope_things.init.from_devtools_sender
    {
        let page_info = DevtoolsPageInfo {
            title: format!("Service Worker for {}", scope_things.script_url),
            url: scope_things.script_url.clone(),
            is_top_level_global: false,
            is_service_worker: true,
        };
        let _ = chan.send(ScriptToDevtoolsControlMsg::NewGlobal(
            (
                scope_things.browsing_context_id,
                scope_things.init.pipeline_id,
                Some(scope_things.worker_id),
                scope_things.webview_id,
            ),
            sender.clone(),
            page_info,
        ));
    }

    let worker_id = ServiceWorkerId::new();

    let (control_sender, control_receiver) = unbounded();
    let (context_sender, context_receiver) = unbounded();
    let closing = Arc::new(AtomicBool::new(false));

    let join_handle = ServiceWorkerGlobalScope::run_serviceworker_scope(
        scope_things.clone(),
        sender.clone(),
        receiver,
        devtools_receiver,
        own_sender,
        scope_url,
        control_receiver,
        context_sender,
        closing.clone(),
        font_context,
        worker_id,
    );

    let context = context_receiver
        .recv()
        .expect("Couldn't receive a context for worker.");

    (
        ServiceWorker::new(scope_things.script_url, sender, worker_id),
        join_handle,
        control_sender,
        context,
        closing,
    )
}

impl ServiceWorkerManagerFactory for ServiceWorkerManager {
    fn create(sw_senders: SWManagerSenders, origin: ImmutableOrigin) {
        let (resource_chan, resource_port) = ipc::channel().unwrap();

        let SWManagerSenders {
            resource_threads,
            own_sender,
            receiver,
            system_font_service_sender,
            paint_api,
        } = sw_senders;

        let from_constellation = receiver.route_preserving_errors();
        let resource_port = ROUTER.route_ipc_receiver_to_new_crossbeam_receiver(resource_port);
        let _ = resource_threads
            .core_thread
            .send(CoreResourceMsg::NetworkMediator(resource_chan, origin));

        let font_context = Arc::new(FontContext::new(
            Arc::new(system_font_service_sender.to_proxy()),
            paint_api,
            resource_threads.clone(),
        ));

        let swmanager_thread = move || {
            ServiceWorkerManager::new(
                own_sender,
                from_constellation,
                resource_port,
                font_context,
                resource_threads,
            )
            .handle_message()
        };
        if thread::Builder::new()
            .name("SvcWorkerManager".to_owned())
            .spawn(swmanager_thread)
            .is_err()
        {
            warn!("ServiceWorkerManager thread spawning failed");
        }
    }
}

fn navigation_preload_header_value(
    enabled: bool,
    configured_value: Option<&[u8]>,
) -> Option<Vec<u8>> {
    enabled.then(|| configured_value.unwrap_or(b"true").to_vec())
}

fn fetch_navigation_preload(
    resource_threads: ResourceThreads,
    request: RequestBuilder,
    header_value: Option<Vec<u8>>,
) -> Option<CustomResponse> {
    let mut request = request.service_workers_mode(ServiceWorkersMode::None);
    request.id = RequestId::default();
    request.preload_id = None;

    if let Some(header_value) = header_value
        && let Ok(header_value) = HeaderValue::from_bytes(&header_value)
    {
        request.headers.insert(
            HeaderName::from_static("service-worker-navigation-preload"),
            header_value,
        );
    }
    // Navigation preload is a document navigation, so carry the fetch
    // metadata header that the normal navigation path adds before the request
    // is handed to the service-worker manager.
    request.headers.insert(
        HeaderName::from_static("upgrade-insecure-requests"),
        HeaderValue::from_static("1"),
    );
    let (callback, receiver) = GenericCallback::new_blocking().ok()?;
    resource_threads
        .core_thread
        .send(CoreResourceMsg::Fetch(
            request,
            FetchChannels::ResponseMsg(callback),
        ))
        .ok()?;

    let mut metadata = None;
    let mut body = Vec::new();
    loop {
        match receiver.recv().ok()? {
            FetchResponseMsg::ProcessResponse(_, Ok(fetch_metadata)) => {
                metadata = Some(fetch_metadata.metadata().clone());
            },
            FetchResponseMsg::ProcessResponse(_, Err(_)) => return None,
            FetchResponseMsg::ProcessResponseChunk(_, chunk) => body.extend_from_slice(&chunk),
            FetchResponseMsg::ProcessResponseEOF(_, Ok(_), _) => {
                let metadata = metadata?;
                let status = StatusCode::from_u16(metadata.status.raw_code()).ok()?;
                let headers = metadata
                    .headers
                    .map(|headers| headers.into_inner())
                    .unwrap_or_default();
                return Some(CustomResponse::new(
                    headers,
                    (
                        status,
                        String::from_utf8_lossy(metadata.status.message()).into_owned(),
                    ),
                    body,
                ));
            },
            FetchResponseMsg::ProcessResponseEOF(_, Err(_), _) => return None,
            _ => {},
        }
    }
}

pub(crate) fn serviceworker_enabled() -> bool {
    pref!(dom_serviceworker_enabled)
}

#[cfg(test)]
fn select_longest_matching_scope<'a>(
    scopes: impl Iterator<Item = &'a ServoUrl>,
    load_url: &ServoUrl,
) -> Option<ServoUrl> {
    scopes
        .filter(|scope| longest_prefix_match(scope, load_url))
        .max_by_key(|scope| scope.path().len())
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::{
        PersistedRegistration, RegistrationKey, ServoUrl, load_persisted_registrations,
        navigation_preload_header_value, ordered_registration_keys,
        registration_matches_storage_partition, registration_reuses_script, restore_registrations,
        save_persisted_registrations, select_longest_matching_registration_key,
        select_longest_matching_scope, select_restored_match, should_request_activation,
    };

    #[test]
    fn matching_scope_prefers_longest_same_origin_prefix() {
        let root = ServoUrl::parse("https://example.com/").expect("valid root scope");
        let app = ServoUrl::parse("https://example.com/app/").expect("valid app scope");
        let document = ServoUrl::parse("https://example.com/app/settings").expect("valid URL");

        assert_eq!(
            select_longest_matching_scope([&root, &app].into_iter(), &document),
            Some(app)
        );
    }

    #[test]
    fn matching_scope_isolated_by_top_level_partition() {
        let root = RegistrationKey::new(
            ServoUrl::parse("https://example.com/").expect("valid root scope"),
            Some("https://top-a.test".to_owned()),
        );
        let app = RegistrationKey::new(
            ServoUrl::parse("https://example.com/app/").expect("valid app scope"),
            Some("https://top-a.test".to_owned()),
        );
        let other_partition = RegistrationKey::new(
            ServoUrl::parse("https://example.com/app/").expect("valid app scope"),
            Some("https://top-b.test".to_owned()),
        );
        let document = ServoUrl::parse("https://example.com/app/settings").expect("valid URL");
        let keys = [&root, &app, &other_partition];

        assert_eq!(
            select_longest_matching_registration_key(
                keys.iter().copied(),
                &document,
                Some("https://top-a.test"),
            ),
            Some(app.clone())
        );
        assert_eq!(
            select_longest_matching_registration_key(
                keys.iter().copied(),
                &document,
                Some("https://top-b.test"),
            ),
            Some(other_partition.clone())
        );
        assert_eq!(
            select_longest_matching_registration_key(keys.iter().copied(), &document, None),
            None
        );
    }

    #[test]
    fn registration_enumeration_and_matching_share_partition_filter() {
        let scope = ServoUrl::parse("https://example.com/app/").expect("valid scope");
        let origin = scope.origin();
        let first_partition =
            RegistrationKey::new(scope.clone(), Some("https://top-a.test".to_owned()));
        let second_partition = RegistrationKey::new(scope, Some("https://top-b.test".to_owned()));

        assert!(registration_matches_storage_partition(
            &first_partition,
            &origin,
            Some("https://top-a.test"),
        ));
        assert!(!registration_matches_storage_partition(
            &first_partition,
            &origin,
            Some("https://top-b.test"),
        ));
        assert!(registration_matches_storage_partition(
            &second_partition,
            &origin,
            Some("https://top-b.test"),
        ));
    }

    #[test]
    fn registration_enumeration_preserves_registration_order() {
        let scope1 = RegistrationKey::new(
            ServoUrl::parse("https://example.com/scope1").expect("valid scope"),
            None,
        );
        let scope2 = RegistrationKey::new(
            ServoUrl::parse("https://example.com/scope2").expect("valid scope"),
            None,
        );
        let scope12 = RegistrationKey::new(
            ServoUrl::parse("https://example.com/scope12").expect("valid scope"),
            None,
        );
        let available = [&scope1, &scope2, &scope12];
        let expected = [scope1.clone(), scope2.clone(), scope12.clone()];

        assert_eq!(
            ordered_registration_keys(available.into_iter(), &expected),
            expected,
        );
    }

    #[test]
    fn first_worker_activation_is_requested_after_install() {
        assert!(should_request_activation(false, false, false, false));
        assert!(!should_request_activation(true, false, false, false));
        assert!(!should_request_activation(false, true, false, false));
        assert!(should_request_activation(true, true, false, true));
    }

    #[test]
    fn navigation_preload_header_uses_true_by_default() {
        assert_eq!(
            navigation_preload_header_value(true, None),
            Some(b"true".to_vec())
        );
        assert_eq!(
            navigation_preload_header_value(true, Some(b"nomad")),
            Some(b"nomad".to_vec())
        );
        assert_eq!(navigation_preload_header_value(false, None), None);
    }

    #[test]
    fn registration_reuse_requires_matching_script_url() {
        let current = ServoUrl::parse("https://example.com/sw.js").expect("valid script URL");
        let replacement =
            ServoUrl::parse("https://example.com/sw-v2.js").expect("valid replacement URL");

        assert!(registration_reuses_script(Some(&current), &current));
        assert!(!registration_reuses_script(Some(&current), &replacement));
        assert!(!registration_reuses_script(None, &current));
    }

    fn persisted_fixture() -> Vec<PersistedRegistration> {
        vec![
            PersistedRegistration {
                scope_url: "https://example.com/scope1".to_owned(),
                partition_key: None,
                script_url: "https://example.com/sw.js".to_owned(),
                navigation_preload_enabled: false,
                navigation_preload_header_value: None,
            },
            PersistedRegistration {
                scope_url: "https://example.com/app/".to_owned(),
                partition_key: Some("https://top-a.test".to_owned()),
                script_url: "https://example.com/app-sw.js".to_owned(),
                navigation_preload_enabled: true,
                navigation_preload_header_value: Some(b"nomad".to_vec()),
            },
        ]
    }

    #[test]
    fn persisted_registry_round_trip_preserves_order_and_partitions() {
        let dir = std::env::temp_dir().join(format!(
            "nomad-sw-registry-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = dir.join("registry.json");
        let descriptors = persisted_fixture();

        save_persisted_registrations(&path, &descriptors).expect("save registry");
        let loaded = load_persisted_registrations(&path).expect("load registry");
        assert_eq!(loaded, descriptors);
        // Partitions survive the round trip so rehydrated lookups stay isolated.
        assert_eq!(loaded[0].partition_key, None);
        assert_eq!(
            loaded[1].partition_key,
            Some("https://top-a.test".to_owned())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persisted_registry_rejects_corrupt_data() {
        let dir = std::env::temp_dir().join(format!(
            "nomad-sw-registry-corrupt-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = dir.join("registry.json");
        std::fs::create_dir_all(&dir).expect("create dir");
        std::fs::write(&path, "{ not json").expect("write corrupt");
        assert!(load_persisted_registrations(&path).is_err());
        assert!(
            load_persisted_registrations(&dir.join("missing.json")).is_err(),
            "missing registry file must error so startup falls back to empty"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restored_entries_keep_partition_isolation_and_scope_matching() {
        let descriptors = vec![
            PersistedRegistration {
                scope_url: "https://example.com/app/".to_owned(),
                partition_key: Some("https://top-a.test".to_owned()),
                script_url: "https://example.com/app-sw.js".to_owned(),
                navigation_preload_enabled: false,
                navigation_preload_header_value: None,
            },
            PersistedRegistration {
                scope_url: "https://example.com/".to_owned(),
                partition_key: Some("https://top-a.test".to_owned()),
                script_url: "https://example.com/root-sw.js".to_owned(),
                navigation_preload_enabled: false,
                navigation_preload_header_value: None,
            },
            PersistedRegistration {
                scope_url: "https://example.com/app/".to_owned(),
                partition_key: Some("https://top-b.test".to_owned()),
                script_url: "https://example.com/app-sw.js".to_owned(),
                navigation_preload_enabled: false,
                navigation_preload_header_value: None,
            },
        ];
        let restored: std::collections::HashMap<RegistrationKey, super::RestoredRegistration> =
            restore_registrations(descriptors).into_iter().collect();
        assert_eq!(restored.len(), 3);

        let document = ServoUrl::parse("https://example.com/app/settings").expect("valid URL");
        let (key, _) = select_restored_match(&restored, &document, Some("https://top-a.test"))
            .expect("partition A matches");
        assert_eq!(key.scope_url.as_str(), "https://example.com/app/");
        let (key, _) = select_restored_match(&restored, &document, Some("https://top-b.test"))
            .expect("partition B matches");
        assert_eq!(key.partition_key.as_deref(), Some("https://top-b.test"));
        assert!(
            select_restored_match(&restored, &document, None).is_none(),
            "restored entries must not leak across partitions"
        );
    }

    #[test]
    fn restore_drops_cross_origin_and_malformed_descriptors() {
        let descriptors = vec![
            PersistedRegistration {
                scope_url: "https://example.com/app/".to_owned(),
                partition_key: None,
                script_url: "https://other.example/app-sw.js".to_owned(),
                navigation_preload_enabled: false,
                navigation_preload_header_value: None,
            },
            PersistedRegistration {
                scope_url: "not a url".to_owned(),
                partition_key: None,
                script_url: "https://example.com/app-sw.js".to_owned(),
                navigation_preload_enabled: false,
                navigation_preload_header_value: None,
            },
        ];
        let restored = restore_registrations(descriptors);
        assert!(
            restored.is_empty(),
            "cross-origin and malformed descriptors must never rehydrate"
        );
    }
}

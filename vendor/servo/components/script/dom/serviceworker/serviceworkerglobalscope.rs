/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender, after};
use devtools_traits::DevtoolScriptControlMsg;
use devtools_traits::WorkerId;
use dom_struct::dom_struct;
use fonts::FontContext;
use js::context::{JSContext, RawJSContext};
use js::jsapi::JS_AddInterruptCallback;
use js::jsval::UndefinedValue;
use js::realm::CurrentRealm;
use net_traits::CustomResponseMediator;
use net_traits::blob_url_store::UrlWithBlobClaim;
use net_traits::request::{
    CredentialsMode, Destination, InsecureRequestsPolicy, ParserMetadata, Referrer, RequestBuilder,
};
use rand::random;
use script_bindings::cell::DomRefCell;
use script_bindings::interfaces::HasOrigin;
use script_bindings::script_runtime::temp_cx;
use servo_base::generic_channel::{GenericReceiver, GenericSend, GenericSender, RoutedReceiver};
use servo_base::id::{
    BrowsingContextId, PipelineId, ServiceWorkerId, ServiceWorkerRegistrationId, WebViewId,
};
use servo_config::pref;
use servo_constellation_traits::{
    ScopeThings, ServiceWorkerMsg, WorkerGlobalScopeInit, WorkerScriptLoadOrigin,
};
use servo_url::{MutableOrigin, ServoUrl};
use style::thread_state::{self, ThreadState};
use stylo_atoms::Atom;

use crate::dom::abstractworker::WorkerScriptMsg;
use crate::dom::abstractworkerglobalscope::{WorkerEventLoopMethods, run_worker_event_loop};
use crate::dom::bindings::codegen::Bindings::ClientBinding::FrameType;
use crate::dom::bindings::codegen::Bindings::ServiceWorkerGlobalScopeBinding;
use crate::dom::bindings::codegen::Bindings::ServiceWorkerGlobalScopeBinding::ServiceWorkerGlobalScopeMethods;
use crate::dom::bindings::codegen::Bindings::WorkerBinding::WorkerType;
use crate::dom::bindings::codegen::UnionTypes::ClientOrServiceWorkerOrMessagePort;
use crate::dom::bindings::inheritance::Castable;
use crate::dom::bindings::root::{DomRoot, MutNullableDom};
use crate::dom::bindings::str::DOMString;
use crate::dom::bindings::structuredclone;
use crate::dom::bindings::trace::CustomTraceable;
use crate::dom::bindings::utils::define_all_exposed_interfaces;
use crate::dom::client::Client;
use crate::dom::csp::Violation;
use crate::dom::debugger::debuggerglobalscope::DebuggerGlobalScope;
use crate::dom::dedicatedworkerglobalscope::AutoWorkerReset;
use crate::dom::event::Event;
use crate::dom::eventtarget::EventTarget;
use crate::dom::extendableevent::ExtendableEvent;
use crate::dom::extendablemessageevent::ExtendableMessageEvent;
use crate::dom::fetch::request::Request;
use crate::dom::globalscope::GlobalScope;
use crate::dom::globalscope::script_execution::{ErrorReporting, RethrowErrors};
use crate::dom::promise::Promise;
use crate::dom::serviceworker::clients::Clients;
use crate::dom::serviceworker::fetchevent::FetchEvent;
use crate::dom::serviceworker::serviceworkerregistration::{
    ServiceWorkerRegistration, scope_allowed_by_response,
};
#[cfg(feature = "webgpu")]
use crate::dom::webgpu::identityhub::IdentityHub;
use crate::dom::worker::TrustedWorkerAddress;
use crate::dom::workerglobalscope::{WorkerGlobalScope, prepare_workerscope_init};
use crate::fetch::{CspViolationsProcessor, load_whole_resource};
use crate::messaging::{CommonScriptMsg, ScriptEventLoopSender};
use crate::modules::script_module::ScriptFetchOptions;
use crate::realms::enter_auto_realm;
use crate::script_runtime::{IntroductionType, Runtime, ThreadSafeJSContext};
use crate::tasks::task_queue::{QueuedTask, QueuedTaskConversion, TaskQueue};
use crate::tasks::task_source::TaskSourceName;

/// Messages used to control service worker event loop
pub(crate) enum ServiceWorkerScriptMsg {
    /// Message common to all workers
    CommonWorker(WorkerScriptMsg),
    /// Message to request a custom response by the service worker
    Response(
        CustomResponseMediator,
        Option<Receiver<Option<net_traits::CustomResponse>>>,
    ),
    /// Run the activate lifecycle event.
    Activate,
    /// Wake-up call from the task queue.
    WakeUp,
    /// Result of a `clients.matchAll()` query.
    ClientsMatchAllResult(Result<Vec<servo_constellation_traits::ServiceWorkerClientInfo>, String>),
    /// Result of a `clients.claim()` request.
    ClientsClaimResult(Result<(), String>),
    /// Result of a `clients.openWindow()` request.
    ClientsOpenWindowResult(
        Result<Option<servo_constellation_traits::ServiceWorkerClientInfo>, String>,
    ),
}

impl QueuedTaskConversion for ServiceWorkerScriptMsg {
    fn task_source_name(&self) -> Option<&TaskSourceName> {
        let script_msg = match self {
            ServiceWorkerScriptMsg::CommonWorker(WorkerScriptMsg::Common(script_msg)) => script_msg,
            _ => return None,
        };
        match script_msg {
            CommonScriptMsg::Task(_category, _boxed, _pipeline_id, task_source) => {
                Some(task_source)
            },
            _ => None,
        }
    }

    fn pipeline_id(&self) -> Option<PipelineId> {
        // Workers always return None, since the pipeline_id is only used to check for document activity,
        // and this check does not apply to worker event-loops.
        None
    }

    fn into_queued_task(self) -> Option<QueuedTask> {
        let script_msg = match self {
            ServiceWorkerScriptMsg::CommonWorker(WorkerScriptMsg::Common(script_msg)) => script_msg,
            _ => return None,
        };
        let (event_category, task, pipeline_id, task_source) = match script_msg {
            CommonScriptMsg::Task(category, boxed, pipeline_id, task_source) => {
                (category, boxed, pipeline_id, task_source)
            },
            _ => return None,
        };
        Some(QueuedTask {
            worker: None,
            event_category,
            task,
            pipeline_id,
            task_source,
        })
    }

    fn from_queued_task(queued_task: QueuedTask) -> Self {
        let script_msg = CommonScriptMsg::Task(
            queued_task.event_category,
            queued_task.task,
            queued_task.pipeline_id,
            queued_task.task_source,
        );
        ServiceWorkerScriptMsg::CommonWorker(WorkerScriptMsg::Common(script_msg))
    }

    fn inactive_msg() -> Self {
        // Inactive is only relevant in the context of a browsing-context event-loop.
        panic!("Workers should never receive messages marked as inactive");
    }

    fn wake_up_msg() -> Self {
        ServiceWorkerScriptMsg::WakeUp
    }

    fn is_wake_up(&self) -> bool {
        matches!(self, ServiceWorkerScriptMsg::WakeUp)
    }
}

/// Messages sent from the owning registration.
pub(crate) enum ServiceWorkerControlMsg {
    /// Shutdown.
    Exit,
}

pub(crate) enum MixedMessage {
    ServiceWorker(ServiceWorkerScriptMsg),
    Devtools(DevtoolScriptControlMsg),
    Control(ServiceWorkerControlMsg),
    Timer,
}

struct ServiceWorkerCspProcessor {}

fn lifecycle_event_succeeded(
    prerequisites_succeeded: bool,
    timed_out: bool,
    closing: bool,
    promise_rejected: bool,
) -> bool {
    prerequisites_succeeded && !timed_out && !closing && !promise_rejected
}

impl CspViolationsProcessor for ServiceWorkerCspProcessor {
    fn process_csp_violations(&self, _cx: &mut JSContext, _violations: Vec<Violation>) {}
}

#[dom_struct]
pub(crate) struct ServiceWorkerGlobalScope {
    workerglobalscope: WorkerGlobalScope,

    #[ignore_malloc_size_of = "Defined in std"]
    #[no_trace]
    task_queue: TaskQueue<ServiceWorkerScriptMsg>,

    own_sender: Sender<ServiceWorkerScriptMsg>,

    /// A port on which a single "time-out" message can be received,
    /// indicating the sw should stop running,
    /// while still draining the task-queue
    // and running all enqueued, and not cancelled, tasks.
    #[no_trace]
    time_out_port: Receiver<Instant>,

    #[no_trace]
    swmanager_sender: GenericSender<ServiceWorkerMsg>,

    #[no_trace]
    scope_url: ServoUrl,

    /// A receiver of control messages,
    /// currently only used to signal shutdown.
    #[no_trace]
    control_receiver: Receiver<ServiceWorkerControlMsg>,

    #[no_trace]
    worker_id: ServiceWorkerId,

    #[no_trace]
    devtools_worker_id: WorkerId,

    #[no_trace]
    registration_id: ServiceWorkerRegistrationId,

    #[no_trace]
    browsing_context_id: BrowsingContextId,

    #[no_trace]
    webview_id: WebViewId,

    registration: MutNullableDom<ServiceWorkerRegistration>,
    clients: MutNullableDom<Clients>,

    /// Promises passed to `ExtendableEvent.waitUntil()` keep their native
    /// roots alive until they settle or the worker lifetime expires.
    #[conditional_malloc_size_of]
    pending_extendable_promises: DomRefCell<Vec<Rc<Promise>>>,

    /// The service-worker lifetime timer is one-shot; preserve the observed
    /// timeout after consuming its channel message.
    timed_out: Cell<bool>,

    /// Install must complete before activation can be requested by the
    /// manager.
    install_succeeded: Cell<bool>,

    /// Activation requests received while install is draining are deferred
    /// until the install lifecycle has completed.
    install_complete: Cell<bool>,
    activation_requested: Cell<bool>,

    /// Whether a promise extended by the current lifecycle event rejected.
    extendable_promise_rejected: Cell<bool>,
}

impl WorkerEventLoopMethods for ServiceWorkerGlobalScope {
    type WorkerMsg = ServiceWorkerScriptMsg;
    type ControlMsg = ServiceWorkerControlMsg;
    type Event = MixedMessage;

    fn task_queue(&self) -> &TaskQueue<ServiceWorkerScriptMsg> {
        &self.task_queue
    }

    fn handle_event(&self, event: MixedMessage, cx: &mut JSContext) -> bool {
        self.handle_mixed_message(event, cx)
    }

    fn handle_worker_post_event(
        &self,
        _worker: &TrustedWorkerAddress,
    ) -> Option<AutoWorkerReset<'_>> {
        None
    }

    fn from_control_msg(msg: ServiceWorkerControlMsg) -> MixedMessage {
        MixedMessage::Control(msg)
    }

    fn from_worker_msg(msg: ServiceWorkerScriptMsg) -> MixedMessage {
        MixedMessage::ServiceWorker(msg)
    }

    fn from_devtools_msg(msg: DevtoolScriptControlMsg) -> MixedMessage {
        MixedMessage::Devtools(msg)
    }

    fn from_timer_msg() -> MixedMessage {
        MixedMessage::Timer
    }

    fn control_receiver(&self) -> &Receiver<ServiceWorkerControlMsg> {
        &self.control_receiver
    }
}

impl ServiceWorkerGlobalScope {
    pub(crate) fn client_result_sender(&self) -> Sender<ServiceWorkerScriptMsg> {
        self.own_sender.clone()
    }

    pub(crate) fn service_worker_id(&self) -> ServiceWorkerId {
        self.worker_id
    }

    pub(crate) fn registration_id(&self) -> ServiceWorkerRegistrationId {
        self.registration_id
    }

    pub(crate) fn script_url(&self) -> ServoUrl {
        self.upcast::<WorkerGlobalScope>().get_url().clone()
    }

    pub(crate) fn scope_url(&self) -> &ServoUrl {
        &self.scope_url
    }

    pub(crate) fn webview_id(&self) -> servo_base::id::WebViewId {
        self.webview_id
    }

    pub(crate) fn scope_things_for_update(&self, script_url: ServoUrl) -> ScopeThings {
        let global = self.upcast::<GlobalScope>();
        let worker_load_origin = WorkerScriptLoadOrigin {
            referrer_url: match global.get_referrer() {
                Referrer::Client(url) => Some(url),
                Referrer::ReferrerUrl(url) => Some(url),
                _ => None,
            },
            referrer_policy: global.get_referrer_policy(),
            pipeline_id: global.pipeline_id(),
        };
        let init = prepare_workerscope_init(
            global,
            None,
            Some(self.devtools_worker_id),
            #[cfg(feature = "webgl")]
            None,
        );
        ScopeThings {
            script_url,
            worker_load_origin,
            init,
            devtools_chan: global.devtools_chan().cloned(),
            worker_id: self.devtools_worker_id,
            registration_id: self.registration_id,
            browsing_context_id: self.browsing_context_id,
            webview_id: self.webview_id,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn new_inherited(
        init: WorkerGlobalScopeInit,
        worker_url: ServoUrl,
        from_devtools_receiver: RoutedReceiver<DevtoolScriptControlMsg>,
        runtime: Runtime,
        own_sender: Sender<ServiceWorkerScriptMsg>,
        receiver: Receiver<ServiceWorkerScriptMsg>,
        time_out_port: Receiver<Instant>,
        swmanager_sender: GenericSender<ServiceWorkerMsg>,
        scope_url: ServoUrl,
        control_receiver: Receiver<ServiceWorkerControlMsg>,
        closing: Arc<AtomicBool>,
        font_context: Arc<FontContext>,
        worker_id: ServiceWorkerId,
        devtools_worker_id: WorkerId,
        registration_id: ServiceWorkerRegistrationId,
        browsing_context_id: BrowsingContextId,
        webview_id: WebViewId,
    ) -> ServiceWorkerGlobalScope {
        ServiceWorkerGlobalScope {
            workerglobalscope: WorkerGlobalScope::new_inherited(
                init,
                DOMString::new(),
                WorkerType::Classic, // FIXME(cybai): Should be provided from `Run Service Worker`
                worker_url,
                runtime,
                from_devtools_receiver,
                closing,
                #[cfg(feature = "webgpu")]
                Arc::new(IdentityHub::default()),
                // FIXME: investigate what environment this value comes from for service workers.
                InsecureRequestsPolicy::DoNotUpgrade,
                font_context,
                Some(ScriptEventLoopSender::ServiceWorker(own_sender.clone())),
            ),
            task_queue: TaskQueue::new(receiver, own_sender.clone()),
            own_sender,
            time_out_port,
            swmanager_sender,
            scope_url,
            control_receiver,
            worker_id,
            devtools_worker_id,
            registration_id,
            browsing_context_id,
            webview_id,
            registration: MutNullableDom::new(None),
            clients: MutNullableDom::new(None),
            pending_extendable_promises: DomRefCell::new(Vec::new()),
            timed_out: Cell::new(false),
            install_succeeded: Cell::new(true),
            install_complete: Cell::new(false),
            activation_requested: Cell::new(false),
            extendable_promise_rejected: Cell::new(false),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        init: WorkerGlobalScopeInit,
        worker_url: ServoUrl,
        from_devtools_receiver: RoutedReceiver<DevtoolScriptControlMsg>,
        runtime: Runtime,
        own_sender: Sender<ServiceWorkerScriptMsg>,
        receiver: Receiver<ServiceWorkerScriptMsg>,
        time_out_port: Receiver<Instant>,
        swmanager_sender: GenericSender<ServiceWorkerMsg>,
        scope_url: ServoUrl,
        control_receiver: Receiver<ServiceWorkerControlMsg>,
        closing: Arc<AtomicBool>,
        font_context: Arc<FontContext>,
        debugger_global: &DebuggerGlobalScope,
        worker_id: ServiceWorkerId,
        registration_id: ServiceWorkerRegistrationId,
        browsing_context_id: BrowsingContextId,
        webview_id: WebViewId,
        devtools_worker_id: WorkerId,
        cx: &mut JSContext,
    ) -> DomRoot<ServiceWorkerGlobalScope> {
        let scope = Box::new(ServiceWorkerGlobalScope::new_inherited(
            init,
            worker_url,
            from_devtools_receiver,
            runtime,
            own_sender,
            receiver,
            time_out_port,
            swmanager_sender,
            scope_url,
            control_receiver,
            closing,
            font_context,
            worker_id,
            devtools_worker_id,
            registration_id,
            browsing_context_id,
            webview_id,
        ));
        let scope = ServiceWorkerGlobalScopeBinding::Wrap::<crate::DomTypeHolder>(
            cx,
            &scope.origin(),
            scope,
        );
        scope
            .upcast::<WorkerGlobalScope>()
            .init_debugger_global(debugger_global, cx);

        let registration = ServiceWorkerRegistration::new(
            cx,
            scope.upcast(),
            scope.scope_url.clone(),
            registration_id,
        );
        scope.registration.set(Some(&registration));
        let clients = Clients::new(cx, scope.upcast());
        scope.clients.set(Some(&clients));

        scope
    }

    /// <https://w3c.github.io/ServiceWorker/#run-service-worker-algorithm>
    #[expect(unsafe_code)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn run_serviceworker_scope(
        scope_things: ScopeThings,
        own_sender: Sender<ServiceWorkerScriptMsg>,
        receiver: Receiver<ServiceWorkerScriptMsg>,
        devtools_receiver: GenericReceiver<DevtoolScriptControlMsg>,
        swmanager_sender: GenericSender<ServiceWorkerMsg>,
        scope_url: ServoUrl,
        control_receiver: Receiver<ServiceWorkerControlMsg>,
        context_sender: Sender<ThreadSafeJSContext>,
        closing: Arc<AtomicBool>,
        font_context: Arc<FontContext>,
        worker_id: ServiceWorkerId,
    ) -> JoinHandle<()> {
        let ScopeThings {
            script_url,
            init,
            worker_load_origin,
            worker_id: devtools_worker_id,
            registration_id,
            browsing_context_id,
            webview_id,
            ..
        } = scope_things;

        let serialized_worker_url = script_url.to_string();
        let origin = scope_url.origin();
        thread::Builder::new()
            .name(format!("SW:{}", script_url.debug_compact()))
            .spawn(move || {
                thread_state::initialize(ThreadState::SCRIPT | ThreadState::IN_WORKER);
                let runtime = Runtime::new(None);
                // SAFETY: We are in a new thread, so this first cx.
                // It is OK to have it separated of runtime here,
                // because it will never outlive it (runtime destruction happens at the end of this function
                let mut cx = unsafe { runtime.cx() };
                let cx = &mut cx;
                let context_for_interrupt = runtime.thread_safe_js_context();
                let _ = context_sender.send(context_for_interrupt);

                let WorkerScriptLoadOrigin {
                    referrer_url,
                    referrer_policy,
                    pipeline_id,
                } = worker_load_origin;

                let debugger_global = DebuggerGlobalScope::new(
                    pipeline_id,
                    init.to_devtools_sender.clone(),
                    init.from_devtools_sender
                        .clone()
                        .expect("Guaranteed by update_serviceworker"),
                    init.mem_profiler_chan.clone(),
                    init.time_profiler_chan.clone(),
                    init.script_to_constellation_chan.clone(),
                    init.script_to_embedder_chan.clone(),
                    init.resource_threads.clone(),
                    init.storage_threads.clone(),
                    #[cfg(feature = "webgpu")]
                    Arc::new(IdentityHub::default()),
                    cx,
                );
                debugger_global.execute(cx);

                // Service workers are time limited
                // https://w3c.github.io/ServiceWorker/#service-worker-lifetime
                let sw_lifetime_timeout = pref!(dom_serviceworker_timeout_seconds) as u64;
                let time_out_port = after(Duration::new(sw_lifetime_timeout, 0));

                let devtools_mpsc_port = devtools_receiver.route_preserving_errors();

                let resource_threads_sender = init.resource_threads.sender();
                let devtools_enabled = init.to_devtools_sender.is_some();
                let global = ServiceWorkerGlobalScope::new(
                    init,
                    script_url.clone(),
                    devtools_mpsc_port,
                    runtime,
                    own_sender,
                    receiver,
                    time_out_port,
                    swmanager_sender,
                    scope_url,
                    control_receiver,
                    closing,
                    font_context,
                    &debugger_global,
                    worker_id,
                    registration_id,
                    browsing_context_id,
                    webview_id,
                    devtools_worker_id,
                    cx,
                );

                let worker_scope = global.upcast::<WorkerGlobalScope>();
                let global_scope = global.upcast::<GlobalScope>();

                if devtools_enabled {
                    debugger_global.fire_add_debuggee(
                        cx,
                        global_scope,
                        pipeline_id,
                        Some(worker_scope.worker_id()),
                    );
                }

                let referrer = referrer_url
                    .map(Referrer::ReferrerUrl)
                    .unwrap_or_else(|| global_scope.get_referrer());

                let request = RequestBuilder::new(
                    None,
                    UrlWithBlobClaim::from_url_without_having_claimed_blob(script_url),
                    referrer,
                )
                .destination(Destination::ServiceWorker)
                .credentials_mode(CredentialsMode::Include)
                .parser_metadata(ParserMetadata::NotParserInserted)
                .use_url_credentials(true)
                .pipeline_id(Some(pipeline_id))
                .referrer_policy(referrer_policy)
                // TODO: Use policy container from ScopeThings
                .policy_container(global_scope.policy_container())
                .origin(origin);

                let (url, source, scope_allowed) = match load_whole_resource(
                    request,
                    &resource_threads_sender,
                    global.upcast(),
                    &ServiceWorkerCspProcessor {},
                    cx,
                ) {
                    Err(_) => {
                        error!("error loading script {}", serialized_worker_url);
                        let _ = global
                            .swmanager_sender
                            .send(ServiceWorkerMsg::InstallFinished {
                                scope_url: global.scope_url.clone(),
                                worker_id,
                                succeeded: false,
                                scope_allowed: false,
                            });
                        worker_scope.clear_js_runtime();
                        return;
                    },
                    Ok((metadata, bytes, _)) => {
                        let script_url = metadata.final_url.clone();
                        let scope_allowed = scope_allowed_by_response(
                            &script_url,
                            &global.scope_url,
                            metadata.headers.as_ref(),
                        );
                        if !scope_allowed {
                            let _ =
                                global
                                    .swmanager_sender
                                    .send(ServiceWorkerMsg::InstallFinished {
                                        scope_url: global.scope_url.clone(),
                                        worker_id,
                                        succeeded: false,
                                        scope_allowed: false,
                                    });
                            worker_scope.clear_js_runtime();
                            return;
                        }
                        (script_url, bytes, scope_allowed)
                    },
                };

                unsafe {
                    // Handle interrupt requests
                    JS_AddInterruptCallback(cx.raw_cx(), Some(interrupt_callback));
                }

                {
                    // TODO: use AutoWorkerReset as in dedicated worker?
                    let mut auto_realm = enter_auto_realm(cx, worker_scope);
                    let mut realm = auto_realm.current_realm();
                    define_all_exposed_interfaces(&mut realm, global_scope);

                    let script = global_scope.create_a_classic_script(
                        &mut realm,
                        String::from_utf8_lossy(&source),
                        url,
                        ScriptFetchOptions::default_classic_script(),
                        ErrorReporting::Unmuted,
                        Some(IntroductionType::WORKER),
                        1,
                        true,
                    );
                    let script_succeeded =
                        global_scope.run_a_classic_script(&mut realm, script, RethrowErrors::No);
                    if script_succeeded.is_err() {
                        let _ = global
                            .swmanager_sender
                            .send(ServiceWorkerMsg::InstallFinished {
                                scope_url: global.scope_url.clone(),
                                worker_id,
                                succeeded: false,
                                scope_allowed,
                            });
                        drop(realm);
                        drop(auto_realm);
                        worker_scope.clear_js_runtime();
                        return;
                    }
                    global.dispatch_install(&mut realm);
                    let install_succeeded = global.wait_for_extendable_promises(&mut *realm);
                    let activation_requested = global.activation_requested.replace(false);
                    drop(realm);
                    drop(auto_realm);
                    global.install_succeeded.set(install_succeeded);
                    global.install_complete.set(true);
                    let _ = global
                        .swmanager_sender
                        .send(ServiceWorkerMsg::InstallFinished {
                            scope_url: global.scope_url.clone(),
                            worker_id,
                            succeeded: install_succeeded,
                            scope_allowed,
                        });
                    if activation_requested {
                        global.handle_activate(cx);
                    }
                }

                let reporter_name = format!("service-worker-reporter-{}", random::<u64>());
                global_scope.mem_profiler_chan().run_with_memory_reporting(
                    || {
                        // Step 18, Run the responsible event loop specified
                        // by inside settings until it is destroyed.
                        // The worker processing model remains on this step
                        // until the event loop is destroyed,
                        // which happens after the closing flag is set to true,
                        // or until the worker has run beyond its allocated time.
                        while !worker_scope.is_closing() && !global.has_timed_out() {
                            run_worker_event_loop(&*global, None, cx);
                        }
                    },
                    reporter_name,
                    global.event_loop_sender(),
                    CommonScriptMsg::CollectReports,
                );

                worker_scope.clear_js_runtime();
            })
            .expect("Thread spawning failed")
    }

    fn handle_mixed_message(&self, msg: MixedMessage, cx: &mut JSContext) -> bool {
        match msg {
            MixedMessage::Devtools(msg) => self
                .upcast::<WorkerGlobalScope>()
                .handle_devtools_message(msg, cx),
            MixedMessage::ServiceWorker(ServiceWorkerScriptMsg::Activate) => {
                if self.install_complete.get() {
                    self.handle_activate(cx);
                } else {
                    self.activation_requested.set(true);
                }
            },
            MixedMessage::ServiceWorker(msg) => self.handle_script_event(msg, cx),
            MixedMessage::Control(ServiceWorkerControlMsg::Exit) => {
                return false;
            },
            MixedMessage::Timer => {},
        }
        true
    }

    fn has_timed_out(&self) -> bool {
        if self.timed_out.get() {
            return true;
        }
        self.reap_extendable_promises();
        if self.time_out_port.try_recv().is_ok() {
            self.timed_out.set(true);
        }
        self.timed_out.get()
    }

    pub(crate) fn track_extendable_promise(&self, promise: Rc<Promise>) {
        self.pending_extendable_promises.borrow_mut().push(promise);
    }

    fn reap_extendable_promises(&self) {
        self.pending_extendable_promises
            .borrow_mut()
            .retain(|promise| {
                if promise.is_rejected() {
                    self.extendable_promise_rejected.set(true);
                }
                !promise.is_fulfilled()
            });
    }

    fn pending_extendable_promise_count(&self) -> usize {
        self.reap_extendable_promises();
        self.pending_extendable_promises.borrow().len()
    }

    fn wait_for_extendable_promises(&self, cx: &mut JSContext) -> bool {
        self.extendable_promise_rejected.set(false);
        while !self.workerglobalscope.is_closing() && !self.has_timed_out() {
            if self.pending_extendable_promise_count() == 0 {
                return lifecycle_event_succeeded(
                    true,
                    false,
                    false,
                    self.extendable_promise_rejected.get(),
                );
            }
            run_worker_event_loop(self, None, cx);
        }
        false
    }

    fn handle_activate(&self, cx: &mut JSContext) {
        let mut succeeded = lifecycle_event_succeeded(
            self.install_succeeded.get(),
            self.has_timed_out(),
            self.workerglobalscope.is_closing(),
            false,
        );
        if succeeded {
            let scope = self.upcast::<WorkerGlobalScope>();
            let mut realm = enter_auto_realm(cx, scope);
            let current_realm = &mut realm.current_realm();
            self.dispatch_activate(current_realm);
            succeeded = self.wait_for_extendable_promises(&mut *current_realm);
        }
        let _ = self
            .swmanager_sender
            .send(ServiceWorkerMsg::ActivateFinished {
                scope_url: self.scope_url.clone(),
                worker_id: self.worker_id,
                succeeded,
            });
    }

    fn handle_script_event(&self, msg: ServiceWorkerScriptMsg, cx: &mut JSContext) {
        use self::ServiceWorkerScriptMsg::*;

        match msg {
            CommonWorker(WorkerScriptMsg::DOMMessage(msg)) => {
                let scope = self.upcast::<WorkerGlobalScope>();
                let target = self.upcast();

                let mut realm = enter_auto_realm(cx, scope);
                let cx = &mut realm.current_realm();

                rooted!(&in(cx) let mut message = UndefinedValue());
                let client = Client::new(
                    cx,
                    scope.upcast(),
                    self.scope_url.clone(),
                    FrameType::None,
                    msg.pipeline_id,
                );
                if let Ok(ports) =
                    structuredclone::read(cx, scope.upcast(), *msg.data, message.handle_mut())
                {
                    ExtendableMessageEvent::dispatch_jsval(
                        cx,
                        target,
                        scope.upcast(),
                        message.handle(),
                        Some(&ClientOrServiceWorkerOrMessagePort::Client(client)),
                        ports,
                    );
                } else {
                    ExtendableMessageEvent::dispatch_error(cx, target, scope.upcast());
                }
            },
            CommonWorker(WorkerScriptMsg::Common(msg)) => {
                self.upcast::<WorkerGlobalScope>().process_event(msg, cx);
            },
            Activate => {
                if self.install_complete.get() {
                    self.handle_activate(cx);
                } else {
                    self.activation_requested.set(true);
                }
            },
            Response(mediator, preload_receiver) => {
                let scope = self.upcast::<WorkerGlobalScope>();
                let mut realm = enter_auto_realm(cx, scope);
                let cx = &mut realm.current_realm();
                let global = self.upcast::<GlobalScope>();
                // Preserve the complete network request when exposing it to
                // the worker. Reconstructing from only `load_url` silently
                // discarded the method, headers, mode, credentials, redirect
                // policy, and body metadata needed by real fetch handlers.
                let request =
                    Request::from_net_request(cx, global, None, mediator.request.clone().build());
                let event = FetchEvent::new(cx, self, request, mediator, preload_receiver);
                event
                    .upcast::<Event>()
                    .dispatch(cx, self.upcast::<EventTarget>(), false);
                event.finish_dispatch();
                event.fail_if_unhandled();
            },
            WakeUp => {},
            ClientsMatchAllResult(result) => {
                if let Some(clients) = self.clients.get() {
                    clients.handle_match_all_response(cx, result);
                }
            },
            ClientsClaimResult(result) => {
                if let Some(clients) = self.clients.get() {
                    clients.handle_claim_response(cx, result);
                }
            },
            ClientsOpenWindowResult(result) => {
                if let Some(clients) = self.clients.get() {
                    clients.handle_open_window_response(cx, result);
                }
            },
        }
    }

    pub(crate) fn event_loop_sender(&self) -> ScriptEventLoopSender {
        ScriptEventLoopSender::ServiceWorker(self.own_sender.clone())
    }

    fn dispatch_install(&self, cx: &mut CurrentRealm) {
        let event = ExtendableEvent::new(cx, self, Atom::from("install"), false, false);
        event.upcast::<Event>().dispatch(cx, self.upcast(), false);
        event.finish_dispatch();
    }

    fn dispatch_activate(&self, cx: &mut CurrentRealm) {
        let event = ExtendableEvent::new(cx, self, atom!("activate"), false, false);
        event.upcast::<Event>().dispatch(cx, self.upcast(), false);
        event.finish_dispatch();
    }
}

#[expect(unsafe_code)]
unsafe extern "C" fn interrupt_callback(cx: *mut RawJSContext) -> bool {
    // SAFETY: it is safe to construct a JSContext from engine hook.
    let mut cx = unsafe { JSContext::from_ptr(std::ptr::NonNull::new(cx).unwrap()) };
    let mut realm = CurrentRealm::assert(&mut cx);

    let global = GlobalScope::from_current_realm(&mut realm);
    let worker =
        DomRoot::downcast::<WorkerGlobalScope>(global).expect("global is not a worker scope");
    assert!(worker.is::<ServiceWorkerGlobalScope>());

    // A false response causes the script to terminate
    !worker.is_closing()
}

impl ServiceWorkerGlobalScopeMethods<crate::DomTypeHolder> for ServiceWorkerGlobalScope {
    /// <https://w3c.github.io/ServiceWorker/#dom-serviceworkerglobalscope-clients>
    fn Clients(&self) -> DomRoot<Clients> {
        self.clients
            .get()
            .expect("service worker clients object is initialized before script runs")
    }

    /// <https://w3c.github.io/ServiceWorker/#dom-serviceworkerglobalscope-registration>
    fn Registration(&self) -> DomRoot<ServiceWorkerRegistration> {
        self.registration
            .get()
            .expect("service worker registration is initialized before script runs")
    }

    /// <https://w3c.github.io/ServiceWorker/#dom-serviceworkerglobalscope-skipwaiting>
    fn SkipWaiting(&self) -> Rc<Promise> {
        // The generated binding does not pass a context for this no-argument
        // promise method. Servo's temporary context helper is the established
        // bridge for these legacy binding signatures.
        #[expect(unsafe_code)]
        let mut cx = unsafe { temp_cx() };
        let promise = Promise::new(&mut cx, self.upcast());
        let _ = self.swmanager_sender.send(ServiceWorkerMsg::SkipWaiting {
            scope_url: self.scope_url.clone(),
            worker_id: self.worker_id,
        });
        promise.resolve_native(&mut cx, &());
        promise
    }

    // https://w3c.github.io/ServiceWorker/#service-worker-global-scope-install-event
    event_handler!(install, GetOninstall, SetOninstall);

    // https://w3c.github.io/ServiceWorker/#service-worker-global-scope-activate-event
    event_handler!(activate, GetOnactivate, SetOnactivate);

    // https://w3c.github.io/ServiceWorker/#service-worker-global-scope-fetch-event
    event_handler!(fetch, GetOnfetch, SetOnfetch);

    // https://w3c.github.io/ServiceWorker/#dom-serviceworkerglobalscope-onmessage
    event_handler!(message, GetOnmessage, SetOnmessage);

    // https://w3c.github.io/ServiceWorker/#dom-serviceworkerglobalscope-onmessageerror
    event_handler!(messageerror, GetOnmessageerror, SetOnmessageerror);
}

impl HasOrigin for ServiceWorkerGlobalScope {
    fn origin(&self) -> MutableOrigin {
        self.upcast::<WorkerGlobalScope>().origin()
    }
}

#[cfg(test)]
mod tests {
    use super::lifecycle_event_succeeded;

    #[test]
    fn rejected_extendable_promise_fails_lifecycle_event() {
        assert!(!lifecycle_event_succeeded(true, false, false, true));
    }

    #[test]
    fn lifecycle_event_requires_worker_to_remain_alive() {
        assert!(!lifecycle_event_succeeded(true, true, false, false));
        assert!(!lifecycle_event_succeeded(true, false, true, false));
        assert!(lifecycle_event_succeeded(true, false, false, false));
    }
}

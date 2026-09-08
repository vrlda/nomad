/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::default::Default;
use std::rc::Rc;

use dom_struct::dom_struct;
use js::context::JSContext;
use js::jsval::UndefinedValue;
use js::realm::CurrentRealm;
use script_bindings::cell::DomRefCell;
use script_bindings::inheritance::Castable;
use script_bindings::reflector::reflect_dom_object_with_cx;
use servo_base::generic_channel::GenericCallback;
use servo_base::id::{ServiceWorkerId, ServiceWorkerRegistrationId};
use servo_constellation_traits::{
    Job, JobError, JobResult, JobResultValue, JobType, ScopeThings, ScriptToConstellationMessage,
    ServiceWorkerAlgorithm, ServiceWorkerAlgorithmResult, ServiceWorkerRegistrationInfo,
};
use servo_url::{ImmutableOrigin, ServoUrl};

use crate::dom::bindings::codegen::Bindings::ServiceWorkerContainerBinding::{
    RegistrationOptions, ServiceWorkerContainerMethods,
};
use crate::dom::bindings::error::Error;
use crate::dom::bindings::refcounted::Trusted;
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::root::{DomRoot, MutNullableDom};
use crate::dom::bindings::str::USVString;
use crate::dom::bindings::structuredclone;
use crate::dom::eventtarget::EventTarget;
use crate::dom::globalscope::GlobalScope;
use crate::dom::promise::Promise;
use crate::dom::serviceworker::ServiceWorker;
use crate::dom::serviceworkerregistration::{ServiceWorkerRegistration, longest_prefix_match};
use crate::dom::types::MessageEvent;
use crate::dom::window::Window;
use script_bindings::script_runtime::temp_cx;

#[dom_struct]
pub(crate) struct ServiceWorkerContainer {
    eventtarget: EventTarget,
    controller: MutNullableDom<ServiceWorker>,

    /// Pending results for
    /// <https://w3c.github.io/ServiceWorker/#algorithms>
    #[conditional_malloc_size_of]
    pending_algorithm_results: DomRefCell<VecDeque<Rc<Promise>>>,

    /// `getRegistrations()` has a separate response queue because algorithm
    /// results can complete independently of registration jobs.
    #[conditional_malloc_size_of]
    pending_registration_results: DomRefCell<VecDeque<Rc<Promise>>>,

    /// The stable promise returned by the `ready` attribute.
    #[conditional_malloc_size_of]
    ready: RefCell<Rc<Promise>>,

    /// Handler of algorithm results.
    #[no_trace]
    callback: DomRefCell<Option<GenericCallback<ServiceWorkerAlgorithmResult>>>,

    controller_match_pending: Cell<bool>,
}

impl ServiceWorkerContainer {
    fn partition_key(global: &GlobalScope) -> Option<String> {
        global.storage_partition_key().map(str::to_owned)
    }

    fn new_inherited(ready: Rc<Promise>) -> ServiceWorkerContainer {
        ServiceWorkerContainer {
            eventtarget: EventTarget::new_inherited(),
            controller: Default::default(),
            pending_algorithm_results: Default::default(),
            pending_registration_results: Default::default(),
            ready: RefCell::new(ready),
            callback: Default::default(),
            controller_match_pending: Cell::new(false),
        }
    }

    pub(crate) fn new(cx: &mut JSContext, global: &GlobalScope) -> DomRoot<ServiceWorkerContainer> {
        let container = reflect_dom_object_with_cx(
            Box::new(ServiceWorkerContainer::new_inherited(Promise::new(
                cx, global,
            ))),
            global,
            cx,
        );
        container
    }

    /// <https://w3c.github.io/ServiceWorker/#reject-job-promise>
    /// <https://w3c.github.io/ServiceWorker/#resolve-job-promise>
    fn handle_job_result(&self, cx: &mut JSContext, result: JobResult, promise: Rc<Promise>) {
        let global = self.global();
        match result {
            // <https://w3c.github.io/ServiceWorker/#reject-job-promise>
            // Step 2.2: Queue a task, on equivalentJob’s client’s responsible event loop
            // using the DOM manipulation task source,
            // to reject equivalentJob’s job promise with a new exception with errorData,
            // in equivalentJob’s client’s Realm.
            // Note: we are in the task already.
            JobResult::RejectPromise(error) => match error {
                JobError::TypeError => {
                    promise.reject_error(
                        cx,
                        Error::Type(c"Failed to register a ServiceWorker".to_owned()),
                    );
                },
                JobError::SecurityError => {
                    promise.reject_error(cx, Error::Security(None));
                },
            },
            // <https://w3c.github.io/ServiceWorker/#resolve-job-promise>
            JobResult::ResolvePromise(value) => {
                match value {
                    JobResultValue::Unregister(success) => {
                        promise.resolve_native(cx, &success);
                    },
                    JobResultValue::Register(value) => {
                        let ServiceWorkerRegistrationInfo {
                            id,
                            installing_worker,
                            waiting_worker,
                            active_worker,
                            storage_key: _,
                            scope_url,
                            script_url,
                        } = value;
                        // Step 2.2: If equivalentJob’s job type is either register or update,
                        // set convertedValue to the result of getting the service worker registration object
                        // that represents value in equivalentJob’s client.
                        let registration = global.get_serviceworker_registration(
                            cx,
                            &script_url,
                            &scope_url,
                            id,
                            installing_worker,
                            waiting_worker,
                            active_worker,
                        );
                        self.update_controller(
                            cx,
                            &scope_url,
                            active_worker,
                            &script_url,
                            Some(id),
                        );

                        // TODO Step 2.3: Else, set convertedValue to value, in equivalentJob’s client’s Realm.

                        // Step 2.4: Resolve equivalentJob’s job promise with convertedValue.
                        promise.resolve_native(cx, &*registration);
                    },
                    JobResultValue::Update {
                        registration: value,
                        state,
                        activate_after_install,
                    } => {
                        let ServiceWorkerRegistrationInfo {
                            id,
                            installing_worker,
                            waiting_worker,
                            active_worker,
                            storage_key: _,
                            scope_url,
                            script_url,
                        } = value;
                        let registration = global.get_serviceworker_registration(
                            cx,
                            &script_url,
                            &scope_url,
                            id,
                            installing_worker,
                            waiting_worker,
                            active_worker,
                        );
                        self.update_controller(
                            cx,
                            &scope_url,
                            active_worker,
                            &script_url,
                            // Do not resynchronize the registration slots
                            // while the update promise exposes its installing
                            // worker; the scope lookup is enough to resolve
                            // `ready` and preserve the intermediate state.
                            None,
                        );
                        // `ServiceWorkerRegistration.update()` resolves with
                        // the registration object, just like `register()`;
                        // resolving with undefined breaks callers that use
                        // the returned registration to observe the new worker.
                        promise.resolve_native(cx, &*registration);

                        // Expose the installing worker to promise continuations
                        // before promoting it to waiting in a later task.
                        let response_listener = Trusted::new(self);
                        let activation_scope = state.scope_url.clone();
                        let activation_worker = state.waiting_worker;
                        let activation_storage_key = global.obtain_storage_key();
                        let activation_partition_key = Self::partition_key(&global);
                        let task_source = global
                            .task_manager()
                            .dom_manipulation_task_source()
                            .to_sendable();
                        task_source.queue(task!(apply_update_state: move |cx| {
                            let container = response_listener.root();
                            container.apply_registration_state_changed(cx, state);
                            if activate_after_install
                                && let (Some(storage_key), Some(worker_id)) =
                                    (activation_storage_key, activation_worker)
                            {
                                let _ = container
                                    .global()
                                    .script_to_constellation_chan()
                                    .send(ScriptToConstellationMessage::ServiceWorkerAlgorithm(
                                        ServiceWorkerAlgorithm::Activate {
                                            storage_key,
                                            partition_key: activation_partition_key,
                                            scope_url: activation_scope,
                                            worker_id,
                                        },
                                    ));
                            }
                        }));
                    },
                }
            },
        }
    }

    /// Continuation of the parallel steps from
    /// <https://w3c.github.io/ServiceWorker/#dom-serviceworkercontainer-getregistration>
    fn handle_match_registration_result(
        &self,
        cx: &mut JSContext,
        registration_info: Option<ServiceWorkerRegistrationInfo>,
        promise: Rc<Promise>,
    ) {
        // Step 8.1 Let registration be the result of running Match Service Worker Registration given storage key and clientURL.
        // Note: the `registration_info` argument is the result from the parallel algorithm run.

        // Step 8.2: If registration is null, resolve promise with undefined and abort these steps.
        let Some(info) = registration_info else {
            promise.resolve_native(cx, &());
            return;
        };

        // Step 8.3: Resolve promise with the result of getting the service worker registration object
        // that represents registration in promise’s relevant settings object.
        let registration = self.global().get_serviceworker_registration(
            cx,
            &info.script_url,
            &info.scope_url,
            info.id,
            info.installing_worker,
            info.waiting_worker,
            info.active_worker,
        );
        self.update_controller(
            cx,
            &info.scope_url,
            info.active_worker,
            &info.script_url,
            Some(info.id),
        );
        promise.resolve_native(cx, &*registration);
        self.resurrect_workerless_registration(cx, &info);
    }

    /// Re-spawn the worker for a restored (post-restart) registration.
    ///
    /// The manager serves restored scopes as workerless registration objects
    /// so enumeration and identity survive a restart. The first Window client
    /// that observes such an object re-registers its script/scope through the
    /// normal register flow (which adopts the restored id); the resulting
    /// worker then serves subsequent clients. Fire-and-forget: the observing
    /// client keeps its resolved workerless object while the install
    /// proceeds, so this never changes already-resolved promises.
    fn resurrect_workerless_registration(
        &self,
        cx: &mut JSContext,
        info: &ServiceWorkerRegistrationInfo,
    ) {
        if info.installing_worker.is_some()
            || info.waiting_worker.is_some()
            || info.active_worker.is_some()
        {
            return;
        }
        let global = self.global();
        // Resurrection mints fresh worker scope context, which requires a
        // Window client.
        if global.downcast::<Window>().is_none() {
            return;
        }
        if !info.script_url.origin().is_potentially_trustworthy() {
            return;
        }
        if info.script_url.origin() != info.scope_url.origin() {
            return;
        }
        if !matches!(info.script_url.scheme(), "https" | "http") {
            return;
        }
        let Some(storage_key) = global.obtain_storage_key() else {
            return;
        };
        let promise = Promise::new(cx, &global);
        let result_handler = self.get_or_setup_callback(promise);
        let scope_things =
            ServiceWorkerRegistration::create_scope_things(&global, info.script_url.clone());
        let job = Job::create_job(
            JobType::Register,
            info.scope_url.clone(),
            info.script_url.clone(),
            result_handler,
            global.creation_url(),
            Some(scope_things),
            storage_key,
            global.storage_partition_key().map(str::to_owned),
        );
        if global
            .script_to_constellation_chan()
            .send(ScriptToConstellationMessage::ServiceWorkerAlgorithm(
                ServiceWorkerAlgorithm::StartRegister(job),
            ))
            .is_err()
        {
            self.pending_algorithm_results.borrow_mut().pop_back();
        }
    }

    pub(crate) fn update_controller(
        &self,
        cx: &mut JSContext,
        scope_url: &ServoUrl,
        active_worker: Option<ServiceWorkerId>,
        script_url: &ServoUrl,
        registration_id: Option<ServiceWorkerRegistrationId>,
    ) {
        let global = self.global();
        let client_url = global.api_base_url();
        if !longest_prefix_match(scope_url, &client_url) {
            return;
        }

        let previous_controller = self.controller.get();
        if let Some(worker_id) = active_worker {
            let worker = global.get_serviceworker(cx, script_url, scope_url, worker_id);
            worker.set_state(
                cx,
                crate::dom::bindings::codegen::Bindings::ServiceWorkerBinding::ServiceWorkerState::Activated,
            );
            self.controller.set(Some(&worker));
        } else if self
            .controller
            .get()
            .is_some_and(|worker| worker.scope_url() == *scope_url)
        {
            self.controller.set(None);
        }

        let changed = match (previous_controller.as_ref(), self.controller.get().as_ref()) {
            (Some(previous), Some(current)) => previous.worker_id() != current.worker_id(),
            (None, None) => false,
            _ => true,
        };
        if changed {
            self.upcast::<EventTarget>()
                .fire_event(cx, atom!("controllerchange"));
            let worker_id = self.controller.get().map(|worker| worker.worker_id());
            let _ = global.script_to_constellation_chan().send(
                ScriptToConstellationMessage::ServiceWorkerControllerChanged {
                    scope_url: scope_url.clone(),
                    worker_id,
                    partition_key: Self::partition_key(&global),
                },
            );
        }

        let Some(worker_id) = active_worker else {
            return;
        };
        let registration = registration_id
            .map(|registration_id| {
                global.get_serviceworker_registration(
                    cx,
                    script_url,
                    scope_url,
                    registration_id,
                    None,
                    None,
                    Some(worker_id),
                )
            })
            .or_else(|| global.get_serviceworker_registration_for_scope(scope_url));
        let Some(registration) = registration else {
            return;
        };
        self.ready.borrow().resolve_native(cx, &*registration);
    }

    pub(crate) fn handle_message_from_worker(
        &self,
        cx: &mut JSContext,
        message: servo_constellation_traits::StructuredSerializedData,
        source: ServiceWorkerId,
        scope_url: ServoUrl,
        script_url: ServoUrl,
        origin: ImmutableOrigin,
    ) {
        // <https://w3c.github.io/ServiceWorker/#dom-client-postmessage-message-options>
        let global = self.global();
        let _source = global.get_serviceworker(cx, &script_url, &scope_url, source);

        rooted!(&in(cx) let mut message_val = UndefinedValue());
        if let Ok(ports) = structuredclone::read(cx, &global, message, message_val.handle_mut()) {
            MessageEvent::dispatch_jsval(
                cx,
                self.upcast(),
                &global,
                message_val.handle(),
                Some(&origin.ascii_serialization()),
                None,
                ports,
            );
        } else {
            error!("Failed to deserialize message ports in message from service worker.");
        }
    }

    fn handle_algorithm_result(&self, cx: &mut JSContext, result: ServiceWorkerAlgorithmResult) {
        match result {
            ServiceWorkerAlgorithmResult::Job(job_result) => {
                let Some(promise) = self.pending_algorithm_results.borrow_mut().pop_front() else {
                    debug_assert!(false, "No pending algorithm result.");
                    return;
                };
                self.handle_job_result(cx, job_result, promise);
            },
            ServiceWorkerAlgorithmResult::MatchServiceWorkerRegistration(registration_info) => {
                if self.controller_match_pending.replace(false) {
                    if let Some(info) = registration_info {
                        self.update_controller(
                            cx,
                            &info.scope_url,
                            info.active_worker,
                            &info.script_url,
                            Some(info.id),
                        );
                        self.resurrect_workerless_registration(cx, &info);
                    }
                    return;
                }
                let Some(promise) = self.pending_algorithm_results.borrow_mut().pop_front() else {
                    debug_assert!(false, "No pending algorithm result.");
                    return;
                };
                self.handle_match_registration_result(cx, registration_info, promise);
            },
            ServiceWorkerAlgorithmResult::GetRegistrations(infos) => {
                let Some(promise) = self.pending_registration_results.borrow_mut().pop_front()
                else {
                    debug_assert!(false, "No pending getRegistrations result.");
                    return;
                };
                let registrations = infos
                    .into_iter()
                    .map(|info| {
                        self.global().get_serviceworker_registration(
                            cx,
                            &info.script_url,
                            &info.scope_url,
                            info.id,
                            info.installing_worker,
                            info.waiting_worker,
                            info.active_worker,
                        )
                    })
                    .collect::<Vec<_>>();
                promise.resolve_native(cx, &registrations);
            },
            ServiceWorkerAlgorithmResult::RegistrationStateChanged(info) => {
                self.apply_registration_state_changed(cx, info);
            },
            ServiceWorkerAlgorithmResult::MessageFromWorker {
                message,
                source,
                scope_url,
                script_url,
                origin,
            } => {
                self.handle_message_from_worker(cx, message, source, scope_url, script_url, origin);
            },
        }
    }

    fn apply_registration_state_changed(
        &self,
        cx: &mut JSContext,
        info: ServiceWorkerRegistrationInfo,
    ) {
        let global = self.global();
        let _ = global.get_serviceworker_registration(
            cx,
            &info.script_url,
            &info.scope_url,
            info.id,
            info.installing_worker,
            info.waiting_worker,
            info.active_worker,
        );
        self.update_controller(
            cx,
            &info.scope_url,
            info.active_worker,
            &info.script_url,
            Some(info.id),
        );
    }

    /// Setup the callback to the backend service, if this hasn't been done already.
    fn get_or_setup_callback(
        &self,
        promise: Rc<Promise>,
    ) -> GenericCallback<ServiceWorkerAlgorithmResult> {
        self.pending_algorithm_results
            .borrow_mut()
            .push_back(promise);
        self.ensure_callback()
    }

    fn ensure_callback(&self) -> GenericCallback<ServiceWorkerAlgorithmResult> {
        if let Some(cb) = self.callback.borrow_mut().as_ref() {
            return cb.clone();
        }

        let global = self.global();
        let response_listener = Trusted::new(self);

        let task_source = global
            .task_manager()
            .dom_manipulation_task_source()
            .to_sendable();
        let callback = GenericCallback::new(move |message| {
            let response_listener = response_listener.clone();
            let response = match message {
                Ok(inner) => inner,
                Err(err) => {
                    return error!(
                        "Error in Service worker algorithm result handlings {:?}.",
                        err
                    );
                },
            };
            task_source.queue(task!(set_request_result_to_database: move |cx| {
                let container = response_listener.root();
                container.handle_algorithm_result(cx, response)
            }));
        })
        .expect("Could not create callback");

        *self.callback.borrow_mut() = Some(callback.clone());

        callback
    }

    pub(crate) fn schedule_initial_controller_match(&self) {
        let global = self.global();
        let Some(storage_key) = global.obtain_storage_key() else {
            return;
        };
        let partition_key = Self::partition_key(&global);
        self.controller_match_pending.set(true);
        let result_handler = self.ensure_callback();
        if global
            .script_to_constellation_chan()
            .send(ScriptToConstellationMessage::ServiceWorkerAlgorithm(
                ServiceWorkerAlgorithm::MatchServiceWorkerRegistration {
                    client_url: global.api_base_url(),
                    storage_key,
                    partition_key,
                    result_handler,
                },
            ))
            .is_err()
        {
            self.controller_match_pending.set(false);
        }
    }

    /// Continuation for
    /// <https://w3c.github.io/ServiceWorker/#dom-serviceworkerregistration-unregister>
    pub(crate) fn create_and_schedule_unregister_job(
        &self,
        cx: &mut JSContext,
        storage_key: ImmutableOrigin,
        scope: ServoUrl,
        script_url: ServoUrl,
        promise: Rc<Promise>,
    ) {
        let global = self.global();
        let result_handler = self.get_or_setup_callback(promise);

        // Step 3: Let job be the result of running Create Job with unregister,
        // registration’s storage key, registration’s scope url, null, promise,
        // and this’s relevant settings object.
        let job = Job::create_job(
            JobType::Unregister,
            scope,
            script_url,
            result_handler,
            global.creation_url(),
            None,
            storage_key,
            Self::partition_key(&global),
        );

        // Step 4: Invoke Schedule Job with job.
        if global
            .script_to_constellation_chan()
            .send(ScriptToConstellationMessage::ServiceWorkerAlgorithm(
                ServiceWorkerAlgorithm::Unregister(job),
            ))
            .is_err()
        {
            // Note: pop the promise we just pushed, since we will not get a result back to handle it.
            self.pending_algorithm_results.borrow_mut().pop_back();

            debug_assert!(
                false,
                "Failed to send Unregister algorithm message to the constellation."
            );
            self.handle_algorithm_result(
                cx,
                ServiceWorkerAlgorithmResult::Job(JobResult::RejectPromise(JobError::TypeError)),
            );
        }
    }

    pub(crate) fn create_and_schedule_update_job(
        &self,
        cx: &mut JSContext,
        storage_key: ImmutableOrigin,
        scope: ServoUrl,
        script_url: ServoUrl,
        scope_things: ScopeThings,
        promise: Rc<Promise>,
    ) {
        let global = self.global();
        let result_handler = self.get_or_setup_callback(promise);
        let mut job = Job::create_job(
            JobType::Update,
            scope,
            script_url,
            result_handler,
            global.creation_url(),
            Some(scope_things),
            storage_key,
            Self::partition_key(&global),
        );
        job.expect_update_result = true;

        if global
            .script_to_constellation_chan()
            .send(ScriptToConstellationMessage::ServiceWorkerAlgorithm(
                ServiceWorkerAlgorithm::Update(job),
            ))
            .is_err()
        {
            self.pending_algorithm_results.borrow_mut().pop_back();
            self.handle_algorithm_result(
                cx,
                ServiceWorkerAlgorithmResult::Job(JobResult::RejectPromise(JobError::TypeError)),
            );
        }
    }
}

impl ServiceWorkerContainerMethods<crate::DomTypeHolder> for ServiceWorkerContainer {
    /// <https://w3c.github.io/ServiceWorker/#service-worker-container-controller-attribute>
    fn GetController(&self) -> Option<DomRoot<ServiceWorker>> {
        self.controller.get()
    }

    /// <https://w3c.github.io/ServiceWorker/#dom-serviceworkercontainer-ready>
    fn Ready(&self) -> Rc<Promise> {
        self.ready.borrow().clone()
    }

    // <https://w3c.github.io/ServiceWorker/#serviceworkercontainer-event-handler>
    event_handler!(
        controllerchange,
        GetOncontrollerchange,
        SetOncontrollerchange
    );
    event_handler!(error, GetOnerror, SetOnerror);
    event_handler!(message, GetOnmessage, SetOnmessage);
    event_handler!(messageerror, GetOnmessageerror, SetOnmessageerror);

    /// <https://w3c.github.io/ServiceWorker/#dom-serviceworkercontainer-register> - A
    /// and <https://w3c.github.io/ServiceWorker/#start-register> - B
    fn Register(
        &self,
        realm: &mut CurrentRealm,
        script_url: USVString,
        options: &RegistrationOptions,
    ) -> Rc<Promise> {
        // A: Step 2.
        let global = self.global();

        // A: Step 1
        let promise = Promise::new_in_realm(realm);
        let USVString(ref script_url) = script_url;

        // A: Step 3
        let api_base_url = global.api_base_url();
        let script_url = match api_base_url.join(script_url) {
            Ok(url) => url,
            Err(_) => {
                // B: Step 1
                promise.reject_error(realm, Error::Type(c"Invalid script URL".to_owned()));
                return promise;
            },
        };

        // A: Step 4-5
        let scope = match options.scope {
            Some(ref scope) => {
                let USVString(inner_scope) = scope;
                match api_base_url.join(inner_scope) {
                    Ok(url) => url,
                    Err(_) => {
                        promise.reject_error(realm, Error::Type(c"Invalid scope URL".to_owned()));
                        return promise;
                    },
                }
            },
            None => script_url.join("./").unwrap(),
        };

        // The response header is validated during the worker script fetch.
        // Keep registration asynchronous so a valid Service-Worker-Allowed
        // header can grant a broader scope without granting it speculatively.
        if script_url.origin() != scope.origin() {
            promise.reject_error(
                realm,
                Error::Type(c"ServiceWorker scope must be same-origin".to_owned()),
            );
            return promise;
        }

        // A: Step 6 -> invoke B.

        // B: Step 3
        match script_url.scheme() {
            "https" | "http" => {},
            _ => {
                promise.reject_error(
                    realm,
                    Error::Type(c"Only secure origins are allowed".to_owned()),
                );
                return promise;
            },
        }
        // B: Step 4
        if script_url.path().to_ascii_lowercase().contains("%2f")
            || script_url.path().to_ascii_lowercase().contains("%5c")
        {
            promise.reject_error(
                realm,
                Error::Type(c"Script URL contains forbidden characters".to_owned()),
            );
            return promise;
        }

        // B: Step 6
        match scope.scheme() {
            "https" | "http" => {},
            _ => {
                promise.reject_error(
                    realm,
                    Error::Type(c"Only secure origins are allowed".to_owned()),
                );
                return promise;
            },
        }
        // B: Step 7
        if scope.path().to_ascii_lowercase().contains("%2f")
            || scope.path().to_ascii_lowercase().contains("%5c")
        {
            promise.reject_error(
                realm,
                Error::Type(c"Scope URL contains forbidden characters".to_owned()),
            );
            return promise;
        }

        let result_handler = self.get_or_setup_callback(promise.clone());

        let scope_things =
            ServiceWorkerRegistration::create_scope_things(&global, script_url.clone());

        // B: Step 8 - 13

        // Step 10: Let storage key be the result of running obtain a storage key given client.
        let Some(storage_key) = global.obtain_storage_key() else {
            promise.reject_error(
                realm,
                Error::Type(c"Failed to obtain a storage key".to_owned()),
            );
            // Note: pop the promise we just pushed, since we will not get a result back to handle it.
            self.pending_algorithm_results.borrow_mut().pop_back();
            return promise;
        };

        let job = Job::create_job(
            JobType::Register,
            scope,
            script_url,
            result_handler,
            global.creation_url(),
            Some(scope_things),
            storage_key,
            Self::partition_key(&global),
        );

        // B: Step 14: schedule job.
        if global
            .script_to_constellation_chan()
            .send(ScriptToConstellationMessage::ServiceWorkerAlgorithm(
                ServiceWorkerAlgorithm::StartRegister(job),
            ))
            .is_err()
        {
            // Note: pop the promise we just pushed, since we will not get a result back to handle it.
            self.pending_algorithm_results.borrow_mut().pop_back();
            debug_assert!(
                false,
                "Failed to send StartRegister algorithm message to the constellation."
            );
            promise.reject_error(
                realm,
                Error::Type(c"Failed to register a ServiceWorker".to_owned()),
            );
        }

        // A: Step 7
        promise
    }

    /// <https://w3c.github.io/ServiceWorker/#navigator-service-worker-getRegistration>
    fn GetRegistration(&self, realm: &mut CurrentRealm, client_url: USVString) -> Rc<Promise> {
        // Step 1: Let client be this’s service worker client.
        let global = self.global();

        // Step 7: Let promise be a new promise.
        // Note: done here so it can be used to handle failure of the below steps.
        let promise = Promise::new_in_realm(realm);

        // Step 2: Let client storage key be the result of running obtain a storage key given client.
        let Some(storage_key) = global.obtain_storage_key() else {
            promise.reject_error(
                realm,
                Error::Type(c"Failed to obtain a storage key".to_owned()),
            );
            return promise;
        };

        // Step 3: Let clientURL be the result of parsing clientURL with this’s relevant settings object’s API base URL.
        let mut client_url = match global.api_base_url().join(&client_url.0) {
            Ok(url) => url,
            Err(_) => {
                // Step 4: If clientURL is failure, return a promise rejected with a TypeError.
                promise.reject_error(realm, Error::Type(c"Failed to parse clientURL".to_owned()));
                return promise;
            },
        };

        // Step 5: Set clientURL’s fragment to null.
        client_url.set_fragment(None);

        // Step 6: If the origin of clientURL is not client’s origin, return a promise rejected with a "SecurityError" DOMException.
        if &client_url.origin() != global.origin().immutable() {
            promise.reject_error(realm, Error::Security(None));
            return promise;
        }

        let result_handler = self.get_or_setup_callback(promise.clone());

        // Step 8: Run the following substeps in parallel:
        // Note: continues in parallel in the service worker manager,
        // by way of the constellation.
        if global
            .script_to_constellation_chan()
            .send(ScriptToConstellationMessage::ServiceWorkerAlgorithm(
                ServiceWorkerAlgorithm::MatchServiceWorkerRegistration {
                    client_url,
                    storage_key,
                    partition_key: Self::partition_key(&global),
                    result_handler,
                },
            ))
            .is_err()
        {
            // Note: pop the promise we just pushed, since we will not get a result back to handle it.
            self.pending_algorithm_results.borrow_mut().pop_back();
            promise.reject_error(
                realm,
                Error::Type(c"Failed to send MatchServiceWorkerRegistration algorithm".to_owned()),
            );
        }

        // Step 9: Return promise.
        promise
    }

    /// <https://w3c.github.io/ServiceWorker/#navigator-service-worker-getregistrations>
    #[expect(unsafe_code)]
    fn GetRegistrations(&self) -> Rc<Promise> {
        let mut cx = unsafe { temp_cx() };
        let global = self.global();
        let promise = Promise::new(&mut cx, &global);
        let Some(storage_key) = global.obtain_storage_key() else {
            promise.reject_error(
                &mut cx,
                Error::Type(c"Failed to obtain a storage key".to_owned()),
            );
            return promise;
        };

        let result_handler = self.ensure_callback();
        self.pending_registration_results
            .borrow_mut()
            .push_back(promise.clone());
        if global
            .script_to_constellation_chan()
            .send(ScriptToConstellationMessage::ServiceWorkerAlgorithm(
                ServiceWorkerAlgorithm::GetRegistrations {
                    storage_key,
                    partition_key: Self::partition_key(&global),
                    result_handler,
                },
            ))
            .is_err()
        {
            self.pending_registration_results.borrow_mut().pop_back();
            promise.reject_error(
                &mut cx,
                Error::Type(c"Failed to get ServiceWorker registrations".to_owned()),
            );
        }
        promise
    }
}

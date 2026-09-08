/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::cell::Cell;
use std::rc::Rc;

use devtools_traits::WorkerId;
use dom_struct::dom_struct;
use http::HeaderMap;
use hyper_serde::Serde;
use js::context::JSContext;
use net_traits::request::Referrer;
use script_bindings::cell::DomRefCell;
use script_bindings::codegen::GenericBindings::NavigatorBinding::NavigatorMethods;
use script_bindings::codegen::GenericBindings::WindowBinding::WindowMethods;
use script_bindings::reflector::reflect_dom_object_with_cx;
use script_bindings::script_runtime::temp_cx;
use servo_base::id::{ServiceWorkerId, ServiceWorkerRegistrationId};
use servo_constellation_traits::{
    ScopeThings, ScriptToConstellationMessage, ServiceWorkerAlgorithm, WorkerScriptLoadOrigin,
};
use servo_url::ServoUrl;
use stylo_atoms::Atom;
use uuid::Uuid;

use crate::dom::bindings::codegen::Bindings::ServiceWorkerBinding::ServiceWorkerState;
use crate::dom::bindings::codegen::Bindings::ServiceWorkerRegistrationBinding::{
    ServiceWorkerRegistrationMethods, ServiceWorkerUpdateViaCache,
};
use crate::dom::bindings::error::Error;
use crate::dom::bindings::inheritance::Castable;
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::root::{Dom, DomRoot, MutNullableDom};
use crate::dom::bindings::str::{ByteString, USVString};
use crate::dom::eventtarget::EventTarget;
use crate::dom::globalscope::GlobalScope;
use crate::dom::navigationpreloadmanager::NavigationPreloadManager;
use crate::dom::promise::Promise;
use crate::dom::serviceworker::ServiceWorker;
use crate::dom::serviceworker::serviceworkercontainer::ServiceWorkerContainer;
use crate::dom::serviceworker::serviceworkerglobalscope::ServiceWorkerGlobalScope;
use crate::dom::window::Window;
use crate::dom::workerglobalscope::prepare_workerscope_init;

#[dom_struct]
pub(crate) struct ServiceWorkerRegistration {
    eventtarget: EventTarget,
    active: DomRefCell<Option<Dom<ServiceWorker>>>,
    installing: DomRefCell<Option<Dom<ServiceWorker>>>,
    waiting: DomRefCell<Option<Dom<ServiceWorker>>>,
    navigation_preload: MutNullableDom<NavigationPreloadManager>,
    #[no_trace]
    scope: ServoUrl,
    navigation_preload_enabled: Cell<bool>,
    navigation_preload_header_value: DomRefCell<Option<ByteString>>,
    update_via_cache: ServiceWorkerUpdateViaCache,
    uninstalling: Cell<bool>,
    #[no_trace]
    registration_id: ServiceWorkerRegistrationId,
}

impl ServiceWorkerRegistration {
    fn new_inherited(
        scope: ServoUrl,
        registration_id: ServiceWorkerRegistrationId,
    ) -> ServiceWorkerRegistration {
        ServiceWorkerRegistration {
            eventtarget: EventTarget::new_inherited(),
            active: DomRefCell::new(None),
            installing: DomRefCell::new(None),
            waiting: DomRefCell::new(None),
            navigation_preload: MutNullableDom::new(None),
            scope,
            navigation_preload_enabled: Cell::new(false),
            navigation_preload_header_value: DomRefCell::new(None),
            update_via_cache: ServiceWorkerUpdateViaCache::Imports,
            uninstalling: Cell::new(false),
            registration_id,
        }
    }

    pub(crate) fn new(
        cx: &mut JSContext,
        global: &GlobalScope,
        scope: ServoUrl,
        registration_id: ServiceWorkerRegistrationId,
    ) -> DomRoot<ServiceWorkerRegistration> {
        reflect_dom_object_with_cx(
            Box::new(ServiceWorkerRegistration::new_inherited(
                scope,
                registration_id,
            )),
            global,
            cx,
        )
    }

    /// Does this registration have an active worker?
    pub(crate) fn is_active(&self) -> bool {
        self.active.borrow().is_some()
    }

    /// Navigation-preload configuration is also valid from the worker's
    /// activate event. The manager promotes the activating worker to the
    /// registration's `active` slot only after that event completes, so using
    /// `is_active()` alone incorrectly rejects the standard activate-time
    /// calls to `enable()` and `setHeaderValue()`.
    pub(crate) fn is_active_or_activating(&self) -> bool {
        self.is_active()
            || self
                .global()
                .downcast::<ServiceWorkerGlobalScope>()
                .is_some()
    }

    pub(crate) fn scope_url(&self) -> &ServoUrl {
        &self.scope
    }

    pub(crate) fn set_installing(&self, cx: &mut JSContext, worker: &ServiceWorker) {
        worker.set_state(cx, ServiceWorkerState::Installing);
        *self.installing.borrow_mut() = Some(Dom::from_ref(worker));
    }

    pub(crate) fn set_waiting(&self, cx: &mut JSContext, worker: &ServiceWorker) {
        worker.set_state(cx, ServiceWorkerState::Installed);
        *self.waiting.borrow_mut() = Some(Dom::from_ref(worker));
    }

    pub(crate) fn set_active(&self, cx: &mut JSContext, worker: &ServiceWorker) {
        worker.set_state(cx, ServiceWorkerState::Activated);
        *self.active.borrow_mut() = Some(Dom::from_ref(worker));
    }

    pub(crate) fn sync_workers(
        &self,
        cx: &mut JSContext,
        script_url: &ServoUrl,
        installing_worker: Option<ServiceWorkerId>,
        waiting_worker: Option<ServiceWorkerId>,
        active_worker: Option<ServiceWorkerId>,
    ) {
        let retained_worker_ids = [installing_worker, waiting_worker, active_worker];
        let previous_installing_worker = self
            .installing
            .borrow()
            .as_ref()
            .map(|worker| worker.worker_id());
        self.sync_worker_slot(
            cx,
            script_url,
            &self.installing,
            installing_worker,
            ServiceWorkerState::Installing,
            &retained_worker_ids,
        );
        self.sync_worker_slot(
            cx,
            script_url,
            &self.waiting,
            waiting_worker,
            ServiceWorkerState::Installed,
            &retained_worker_ids,
        );
        self.sync_worker_slot(
            cx,
            script_url,
            &self.active,
            active_worker,
            ServiceWorkerState::Activated,
            &retained_worker_ids,
        );
        if previous_installing_worker != installing_worker && installing_worker.is_some() {
            self.upcast::<EventTarget>()
                .fire_event(cx, Atom::from("updatefound"));
        }
    }

    fn sync_worker_slot(
        &self,
        cx: &mut JSContext,
        script_url: &ServoUrl,
        slot: &DomRefCell<Option<Dom<ServiceWorker>>>,
        worker_id: Option<ServiceWorkerId>,
        state: ServiceWorkerState,
        retained_worker_ids: &[Option<ServiceWorkerId>; 3],
    ) {
        let current_worker_id = slot.borrow().as_ref().map(|worker| worker.worker_id());
        match worker_id {
            Some(worker_id) if current_worker_id != Some(worker_id) => {
                let previous = slot
                    .borrow()
                    .as_ref()
                    .map(|previous| DomRoot::from_ref(&**previous));
                let worker =
                    self.global()
                        .get_serviceworker(cx, script_url, &self.scope, worker_id);
                *slot.borrow_mut() = Some(Dom::from_ref(&*worker));
                if let Some(previous) = previous
                    && !retained_worker_ids
                        .iter()
                        .flatten()
                        .any(|retained_id| *retained_id == previous.worker_id())
                {
                    previous.set_state(cx, ServiceWorkerState::Redundant);
                }
                worker.set_state(cx, state);
            },
            Some(_) => {
                if let Some(worker) = slot.borrow().as_ref() {
                    worker.set_state(cx, state);
                }
            },
            None => {
                let previous = slot
                    .borrow()
                    .as_ref()
                    .map(|previous| DomRoot::from_ref(&**previous));
                *slot.borrow_mut() = None;
                if let Some(previous) = previous
                    && !retained_worker_ids
                        .iter()
                        .flatten()
                        .any(|retained_id| *retained_id == previous.worker_id())
                {
                    previous.set_state(cx, ServiceWorkerState::Redundant);
                }
            },
        }
    }

    pub(crate) fn get_navigation_preload_header_value(&self) -> Option<ByteString> {
        self.navigation_preload_header_value.borrow().clone()
    }

    pub(crate) fn set_navigation_preload_header_value(&self, value: ByteString) {
        {
            let mut header_value = self.navigation_preload_header_value.borrow_mut();
            *header_value = Some(value);
        }
        self.sync_navigation_preload_state();
    }

    pub(crate) fn get_navigation_preload_enabled(&self) -> bool {
        self.navigation_preload_enabled.get()
    }

    pub(crate) fn set_navigation_preload_enabled(&self, flag: bool) {
        self.navigation_preload_enabled.set(flag);
        self.sync_navigation_preload_state();
    }

    fn sync_navigation_preload_state(&self) {
        let global = self.global();
        let header_value = self
            .navigation_preload_header_value
            .borrow()
            .as_ref()
            .map(|value| value.as_ref().to_vec());
        let _ = global.script_to_constellation_chan().send(
            ScriptToConstellationMessage::ServiceWorkerAlgorithm(
                ServiceWorkerAlgorithm::SetNavigationPreload {
                    storage_key: global.origin().immutable().clone(),
                    partition_key: global.storage_partition_key().map(str::to_owned),
                    scope_url: self.scope.clone(),
                    enabled: self.navigation_preload_enabled.get(),
                    header_value,
                },
            ),
        );
    }

    pub(crate) fn create_scope_things(global: &GlobalScope, script_url: ServoUrl) -> ScopeThings {
        let worker_load_origin = WorkerScriptLoadOrigin {
            referrer_url: match global.get_referrer() {
                Referrer::Client(url) => Some(url),
                Referrer::ReferrerUrl(url) => Some(url),
                _ => None,
            },
            referrer_policy: global.get_referrer_policy(),
            pipeline_id: global.pipeline_id(),
        };

        #[cfg(feature = "webgl")]
        let webgl_chan = global
            .downcast::<Window>()
            .and_then(|window| window.webgl_chan_value());
        let worker_id = WorkerId(Uuid::new_v4());
        let registration_id = ServiceWorkerRegistrationId::new();
        let devtools_chan = global.devtools_chan().cloned();
        let init = prepare_workerscope_init(
            global,
            None,
            Some(worker_id),
            #[cfg(feature = "webgl")]
            webgl_chan,
        );
        let browsing_context_id = global
            .downcast::<Window>()
            .map(|w: &Window| w.window_proxy().browsing_context_id())
            .expect("Service worker must be registered from a Window global");
        let webview_id = global
            .webview_id()
            .expect("Service worker must have a WebViewId");
        ScopeThings {
            script_url,
            init,
            worker_load_origin,
            devtools_chan,
            worker_id,
            registration_id,
            browsing_context_id,
            webview_id,
        }
    }

    // https://w3c.github.io/ServiceWorker/#get-newest-worker-algorithm
    pub(crate) fn get_newest_worker(&self) -> Option<DomRoot<ServiceWorker>> {
        let installing = self.installing.borrow();
        let waiting = self.waiting.borrow();
        let active = self.active.borrow();
        installing
            .as_ref()
            .map(|sw| DomRoot::from_ref(&**sw))
            .or_else(|| waiting.as_ref().map(|sw| DomRoot::from_ref(&**sw)))
            .or_else(|| active.as_ref().map(|sw| DomRoot::from_ref(&**sw)))
    }
}

pub(crate) fn longest_prefix_match(stored_scope: &ServoUrl, potential_match: &ServoUrl) -> bool {
    if stored_scope.origin() != potential_match.origin() {
        return false;
    }
    let scope_chars = stored_scope.path().chars();
    let matching_chars = potential_match.path().chars();
    if scope_chars.count() > matching_chars.count() {
        return false;
    }

    stored_scope
        .path()
        .chars()
        .zip(potential_match.path().chars())
        .all(|(scope, matched)| scope == matched)
}

/// Check the default scope limit imposed by the worker script directory.
///
/// A broader scope is only valid when the script response opts into it with
/// `Service-Worker-Allowed`.
pub(crate) fn scope_allowed_by_script_url(script_url: &ServoUrl, scope_url: &ServoUrl) -> bool {
    let Ok(default_scope) = script_url.join("./") else {
        return false;
    };
    longest_prefix_match(&default_scope, scope_url)
}

/// Check the maximum scope granted by the service worker script response.
///
/// A scope under the script directory is always allowed. A broader scope is
/// allowed only when the response contains a same-origin
/// `Service-Worker-Allowed` URL that contains the requested scope.
pub(crate) fn scope_allowed_by_response(
    script_url: &ServoUrl,
    scope_url: &ServoUrl,
    headers: Option<&Serde<HeaderMap>>,
) -> bool {
    if script_url.origin() != scope_url.origin() {
        return false;
    }
    if scope_allowed_by_script_url(script_url, scope_url) {
        return true;
    }

    let Some(headers) = headers else {
        return false;
    };
    let Some(value) = headers.get("Service-Worker-Allowed") else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Ok(max_scope) = script_url.join(value.trim()) else {
        return false;
    };
    longest_prefix_match(&max_scope, scope_url)
}

impl ServiceWorkerRegistrationMethods<crate::DomTypeHolder> for ServiceWorkerRegistration {
    /// <https://w3c.github.io/ServiceWorker/#service-worker-registration-installing-attribute>
    fn GetInstalling(&self) -> Option<DomRoot<ServiceWorker>> {
        self.installing
            .borrow()
            .as_ref()
            .map(|sw| DomRoot::from_ref(&**sw))
    }

    /// <https://w3c.github.io/ServiceWorker/#dom-serviceworkerregistration-update>
    fn Update(&self) -> Rc<Promise> {
        #[expect(unsafe_code)]
        let mut cx = unsafe { temp_cx() };
        let promise = Promise::new(&mut cx, &self.global());
        let Some(worker) = self.get_newest_worker() else {
            promise.reject_error(&mut cx, Error::InvalidState(None));
            return promise;
        };
        let global = self.global();
        let Some(storage_key) = global.obtain_storage_key() else {
            promise.reject_error(
                &mut cx,
                Error::Type(c"Failed to obtain a storage key".to_owned()),
            );
            return promise;
        };
        let script_url = worker.get_script_url();
        let scope_things = if global.downcast::<Window>().is_some() {
            Self::create_scope_things(&global, script_url.clone())
        } else if let Some(service_worker) = global.downcast::<ServiceWorkerGlobalScope>() {
            service_worker.scope_things_for_update(script_url.clone())
        } else {
            promise.reject_error(&mut cx, Error::Operation(None));
            return promise;
        };

        let container = global
            .downcast::<Window>()
            .map(|window| window.Navigator(&mut cx).ServiceWorker(&mut cx))
            .unwrap_or_else(|| ServiceWorkerContainer::new(&mut cx, &global));
        container.create_and_schedule_update_job(
            &mut cx,
            storage_key,
            self.scope.clone(),
            script_url,
            scope_things,
            promise.clone(),
        );
        promise
    }

    /// <https://w3c.github.io/ServiceWorker/#dom-serviceworkerregistration-unregister>
    fn Unregister(&self, cx: &mut JSContext) -> Rc<Promise> {
        // Step 1: Let registration be the service worker registration.
        // Note: `self` is the registration.

        // Step 2: Let promise be a new promise.
        let promise = Promise::new(cx, &self.global());

        let Some(worker) = self.get_newest_worker() else {
            promise.resolve_native(cx, &true);
            return promise;
        };

        let global = self.global();
        let Some(window) = global.downcast::<Window>() else {
            // Worker navigator does not have a service woker container yet.
            promise.resolve_native(cx, &false);
            return promise;
        };
        let service_worker_container = window.Navigator(cx).ServiceWorker(cx);

        // Step 3: Let job be the result of running Create Job with unregister,
        // registration’s storage key, registration’s scope url, null, promise,
        // and this’s relevant settings object.
        // Step 4: Invoke Schedule Job with job.
        // Note: done in the container.
        let Some(storage_key) = global.obtain_storage_key() else {
            promise.reject_error(
                cx,
                Error::Type(c"Failed to obtain a storage key".to_owned()),
            );
            return promise;
        };
        service_worker_container.create_and_schedule_unregister_job(
            cx,
            storage_key,
            self.scope.clone(),
            worker.get_script_url(),
            promise.clone(),
        );

        // A worker whose registration is removed becomes redundant before the
        // registration's worker slots are cleared. Keep the active worker
        // visible to controlled clients: unregistering a registration does
        // not detach an already-controlled client from its active worker.
        for slot in [&self.installing, &self.waiting] {
            if let Some(worker) = slot.borrow().as_ref() {
                worker.set_state(cx, ServiceWorkerState::Redundant);
            }
        }
        *self.installing.borrow_mut() = None;
        *self.waiting.borrow_mut() = None;
        if should_clear_active_worker_on_unregister() {
            if let Some(worker) = self.active.borrow().as_ref() {
                worker.set_state(cx, ServiceWorkerState::Redundant);
            }
            *self.active.borrow_mut() = None;
        }

        // Step 5: Return promise.
        promise
    }

    /// <https://w3c.github.io/ServiceWorker/#service-worker-registration-active-attribute>
    fn GetActive(&self) -> Option<DomRoot<ServiceWorker>> {
        self.active
            .borrow()
            .as_ref()
            .map(|sw| DomRoot::from_ref(&**sw))
    }

    /// <https://w3c.github.io/ServiceWorker/#service-worker-registration-waiting-attribute>
    fn GetWaiting(&self) -> Option<DomRoot<ServiceWorker>> {
        self.waiting
            .borrow()
            .as_ref()
            .map(|sw| DomRoot::from_ref(&**sw))
    }

    /// <https://w3c.github.io/ServiceWorker/#service-worker-registration-scope-attribute>
    fn Scope(&self) -> USVString {
        USVString(self.scope.as_str().to_owned())
    }

    /// <https://w3c.github.io/ServiceWorker/#service-worker-registration-updateviacache>
    fn UpdateViaCache(&self) -> ServiceWorkerUpdateViaCache {
        self.update_via_cache
    }

    event_handler!(updatefound, GetOnupdatefound, SetOnupdatefound);

    /// <https://w3c.github.io/ServiceWorker/#service-worker-registration-navigationpreload>
    fn NavigationPreload(&self, cx: &mut JSContext) -> DomRoot<NavigationPreloadManager> {
        self.navigation_preload
            .or_init(|| NavigationPreloadManager::new(cx, &self.global(), self))
    }
}

fn should_clear_active_worker_on_unregister() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue};
    use hyper_serde::Serde;

    use super::scope_allowed_by_response;
    use super::{ServoUrl, scope_allowed_by_script_url, should_clear_active_worker_on_unregister};

    #[test]
    fn default_scope_is_the_script_directory() {
        let script = ServoUrl::parse("https://example.com/assets/sw.js").unwrap();

        assert!(scope_allowed_by_script_url(
            &script,
            &ServoUrl::parse("https://example.com/assets/").unwrap()
        ));
        assert!(scope_allowed_by_script_url(
            &script,
            &ServoUrl::parse("https://example.com/assets/app/").unwrap()
        ));
        assert!(!scope_allowed_by_script_url(
            &script,
            &ServoUrl::parse("https://example.com/").unwrap()
        ));
        assert!(!scope_allowed_by_script_url(
            &script,
            &ServoUrl::parse("https://other.example/assets/").unwrap()
        ));
    }

    #[test]
    fn response_header_can_grant_a_broader_same_origin_scope() {
        let script = ServoUrl::parse("https://example.com/assets/sw.js").unwrap();
        let broad_scope = ServoUrl::parse("https://example.com/").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("Service-Worker-Allowed", HeaderValue::from_static("/"));
        let headers = Serde(headers);

        assert!(scope_allowed_by_response(
            &script,
            &broad_scope,
            Some(&headers)
        ));
    }

    #[test]
    fn response_header_cannot_grant_a_cross_origin_scope() {
        let script = ServoUrl::parse("https://example.com/assets/sw.js").unwrap();
        let cross_origin_scope = ServoUrl::parse("https://other.example/").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("Service-Worker-Allowed", HeaderValue::from_static("/"));
        let headers = Serde(headers);

        assert!(!scope_allowed_by_response(
            &script,
            &cross_origin_scope,
            Some(&headers)
        ));
    }

    #[test]
    fn unregister_retains_active_worker_for_controlled_clients() {
        assert!(!should_clear_active_worker_on_unregister());
    }
}

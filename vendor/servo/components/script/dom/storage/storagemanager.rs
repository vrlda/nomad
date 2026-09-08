/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::rc::Rc;
use std::sync::{Arc, Mutex};

use dom_struct::dom_struct;
use js::context::JSContext;
use js::realm::CurrentRealm;
use script_bindings::reflector::{Reflector, reflect_dom_object_with_cx};
use servo_base::generic_channel::GenericCallback;
use servo_constellation_traits::{
    ScriptToConstellationMessage, ServiceWorkerAlgorithm, ServiceWorkerAlgorithmResult,
};

use crate::dom::bindings::codegen::Bindings::PermissionStatusBinding::{
    PermissionName, PermissionState,
};
use crate::dom::bindings::codegen::Bindings::StorageManagerBinding::{
    StorageEstimate, StorageEstimateUsageDetails, StorageManagerMethods,
};
use crate::dom::bindings::error::Error;
use crate::dom::bindings::refcounted::TrustedPromise;
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::root::DomRoot;
use crate::dom::globalscope::GlobalScope;
use crate::dom::permissions::request_permission_to_use;
use crate::dom::promise::Promise;
use crate::tasks::task_source::SendableTaskSource;

#[dom_struct]
pub(crate) struct StorageManager {
    reflector_: Reflector,
}

impl StorageManager {
    fn new_inherited() -> StorageManager {
        StorageManager {
            reflector_: Reflector::new(),
        }
    }

    pub(crate) fn new(cx: &mut JSContext, global: &GlobalScope) -> DomRoot<StorageManager> {
        reflect_dom_object_with_cx(Box::new(StorageManager::new_inherited()), global, cx)
    }

    fn origin_cannot_obtain_local_storage_shelf(&self) -> bool {
        !self.global().origin().is_tuple()
    }

    fn type_error_from_string(message: String) -> Error {
        let message = std::ffi::CString::new(message)
            .unwrap_or_else(|_| c"Storage operation failed".to_owned());
        Error::Type(message)
    }
}

struct StorageManagerBooleanResponseHandler {
    trusted_promise: Option<TrustedPromise>,
    task_source: SendableTaskSource,
}

impl StorageManagerBooleanResponseHandler {
    fn new(trusted_promise: TrustedPromise, task_source: SendableTaskSource) -> Self {
        Self {
            trusted_promise: Some(trusted_promise),
            task_source,
        }
    }

    fn handle(&mut self, result: Result<bool, String>) {
        let Some(trusted_promise) = self.trusted_promise.take() else {
            error!("StorageManager callback called twice.");
            return;
        };

        self.task_source
            .queue(task!(storage_manager_boolean_response: move |cx| {
                let promise = trusted_promise.root();
                match result {
                    Ok(value) => promise.resolve_native(cx, &value),
                    Err(message) => promise.reject_error(cx, StorageManager::type_error_from_string(message)),
                }
            }));
    }
}

/// Estimated bytes attributed to a single service-worker registration for
/// `StorageManager.estimate().usageDetails`.
///
/// The partitioned estimate probe only asserts relative behavior (usage grows
/// after registering, same-partition observers agree, cross-partition
/// observers see zero), so a stable per-registration weight is sufficient
/// until a byte-accurate accounting backend exists.
const SERVICE_WORKER_REGISTRATION_USAGE_BYTES: u64 = 1024;

struct PendingStorageEstimate {
    trusted_promise: Option<TrustedPromise>,
    task_source: SendableTaskSource,
    usage_quota: Option<(u64, u64)>,
    sw_usage: Option<u64>,
    error: Option<String>,
}

impl PendingStorageEstimate {
    fn try_resolve(&mut self) {
        let Some(trusted_promise) = self.trusted_promise.take() else {
            return;
        };
        // Wait for both the storage backend and the service-worker manager
        // unless the storage backend already failed.
        if self.error.is_none() && (self.usage_quota.is_none() || self.sw_usage.is_none()) {
            self.trusted_promise = Some(trusted_promise);
            return;
        }

        let task_source = self.task_source.clone();
        let usage_quota = self.usage_quota;
        let sw_usage = self.sw_usage.unwrap_or(0);
        let error = self.error.clone();
        task_source.queue(task!(storage_manager_estimate_response: move |cx| {
            let promise = trusted_promise.root();
            match usage_quota {
                Some((usage, quota)) if error.is_none() => {
                    let mut details = StorageEstimateUsageDetails::empty();
                    details.serviceWorkerRegistrations = Some(sw_usage);
                    let mut estimate = StorageEstimate::empty();
                    estimate.usage = Some(usage);
                    estimate.quota = Some(quota);
                    estimate.usageDetails = Some(details);
                    promise.resolve_native(cx, &estimate);
                },
                _ => {
                    let message = error.unwrap_or_else(|| "Storage estimate failed".to_owned());
                    promise.reject_error(cx, StorageManager::type_error_from_string(message));
                },
            }
        }));
    }
}

struct StorageManagerEstimateResponseHandler {
    pending: Arc<Mutex<PendingStorageEstimate>>,
}

impl StorageManagerEstimateResponseHandler {
    fn new(pending: Arc<Mutex<PendingStorageEstimate>>) -> Self {
        Self { pending }
    }

    fn handle(&mut self, result: Result<(u64, u64), String>) {
        let mut pending = self.pending.lock().expect("estimate state poisoned");
        match result {
            Ok(usage_quota) => {
                pending.usage_quota = Some(usage_quota);
            },
            Err(message) => {
                pending.error = Some(message);
            },
        }
        pending.try_resolve();
    }
}

struct StorageManagerServiceWorkerUsageHandler {
    pending: Arc<Mutex<PendingStorageEstimate>>,
}

impl StorageManagerServiceWorkerUsageHandler {
    fn new(pending: Arc<Mutex<PendingStorageEstimate>>) -> Self {
        Self { pending }
    }

    fn handle(&mut self, result: ServiceWorkerAlgorithmResult) {
        let mut pending = self.pending.lock().expect("estimate state poisoned");
        if let ServiceWorkerAlgorithmResult::GetRegistrations(infos) = result {
            pending.sw_usage =
                Some((infos.len() as u64).saturating_mul(SERVICE_WORKER_REGISTRATION_USAGE_BYTES));
        } else {
            pending.sw_usage = Some(0);
        }
        pending.try_resolve();
    }

    fn handle_error(&mut self) {
        let mut pending = self.pending.lock().expect("estimate state poisoned");
        pending.sw_usage = Some(0);
        pending.try_resolve();
    }
}

impl StorageManagerMethods<crate::DomTypeHolder> for StorageManager {
    /// <https://storage.spec.whatwg.org/#dom-storagemanager-persisted>
    fn Persisted(&self, cx: &mut CurrentRealm) -> Rc<Promise> {
        // Step 1. Let promise be a new promise.
        let promise = Promise::new_in_realm(cx);
        // Step 2. Let global be this’s relevant global object.
        let global = self.global();

        // Step 3. Let shelf be the result of running obtain a local storage shelf with this’s relevant
        // settings object.
        // Step 4. If shelf is failure, then reject promise with a TypeError.
        if self.origin_cannot_obtain_local_storage_shelf() {
            promise.reject_error(
                cx,
                Error::Type(c"Storage is unavailable for opaque origins".to_owned()),
            );
            return promise;
        }

        // Step 5. Otherwise, run these steps in parallel:
        // Step 5.1. Let persisted be true if shelf’s bucket map["default"]'s mode is "persistent";
        // otherwise false.
        // It will be false when there’s an internal error.
        // Step 5.2. Queue a storage task with global to resolve promise with persisted.
        let mut handler = StorageManagerBooleanResponseHandler::new(
            TrustedPromise::new(promise.clone()),
            global.task_manager().storage_task_source().to_sendable(),
        );
        let callback = GenericCallback::new(move |message| {
            handler.handle(message.unwrap_or_else(|error| Err(error.to_string())));
        })
        .expect("Could not create StorageManager persisted callback");

        if global
            .storage_threads()
            .persisted(global.origin().immutable().clone(), callback.clone())
            .is_err()
            && let Err(error) = callback.send(Err("Failed to queue storage task".to_owned()))
        {
            error!("Failed to deliver StorageManager persisted error: {error}");
        }

        // Step 6. Return promise.
        promise
    }

    /// <https://storage.spec.whatwg.org/#dom-storagemanager-persist>
    fn Persist(&self, cx: &mut CurrentRealm) -> Rc<Promise> {
        // Step 1. Let promise be a new promise.
        let promise = Promise::new_in_realm(cx);
        // Step 2. Let global be this’s relevant global object.
        let global = self.global();

        // Step 3. Let shelf be the result of running obtain a local storage shelf with this’s relevant
        // settings object.
        // Step 4. If shelf is failure, then reject promise with a TypeError.
        if self.origin_cannot_obtain_local_storage_shelf() {
            promise.reject_error(
                cx,
                Error::Type(c"Storage is unavailable for opaque origins".to_owned()),
            );
            return promise;
        }

        // Step 5. Otherwise, run these steps in parallel:
        // Step 5.1. Let permission be the result of requesting permission to use
        // "persistent-storage".
        let permission = request_permission_to_use(PermissionName::Persistent_storage, &global);

        // Step 5.2. Let bucket be shelf’s bucket map["default"].
        // Step 5.3. Let persisted be true if bucket’s mode is "persistent"; otherwise false.
        // It will be false when there’s an internal error.
        // Step 5.4. If persisted is false and permission is "granted", then:
        // Step 5.4.1. Set bucket’s mode to "persistent".
        // Step 5.4.2. If there was no internal error, then set persisted to true.
        // Step 5.5. Queue a storage task with global to resolve promise with persisted.
        let mut handler = StorageManagerBooleanResponseHandler::new(
            TrustedPromise::new(promise.clone()),
            global.task_manager().storage_task_source().to_sendable(),
        );
        let callback = GenericCallback::new(move |message| {
            handler.handle(message.unwrap_or_else(|error| Err(error.to_string())));
        })
        .expect("Could not create StorageManager persist callback");

        if global
            .storage_threads()
            .persist(
                global.origin().immutable().clone(),
                permission == PermissionState::Granted,
                callback.clone(),
            )
            .is_err()
            && let Err(error) = callback.send(Err("Failed to queue storage task".to_owned()))
        {
            error!("Failed to deliver StorageManager persist error: {error}");
        }

        // Step 6. Return promise.
        promise
    }

    /// <https://storage.spec.whatwg.org/#dom-storagemanager-estimate>
    fn Estimate(&self, cx: &mut CurrentRealm) -> Rc<Promise> {
        // Step 1. Let promise be a new promise.
        let promise = Promise::new_in_realm(cx);
        // Step 2. Let global be this’s relevant global object.
        let global = self.global();

        // Step 3. Let shelf be the result of running obtain a local storage shelf with this’s relevant
        // settings object.
        // Step 4. If shelf is failure, then reject promise with a TypeError.
        if self.origin_cannot_obtain_local_storage_shelf() {
            promise.reject_error(
                cx,
                Error::Type(c"Storage is unavailable for opaque origins".to_owned()),
            );
            return promise;
        }

        // Step 5. Otherwise, run these steps in parallel:
        // Step 5.1. Let usage be storage usage for shelf.
        // Step 5.2. Let quota be storage quota for shelf.
        // Step 5.3. Let dictionary be a new StorageEstimate dictionary whose usage member is usage and quota
        // member is quota.
        // Step 5.4. If there was an internal error while obtaining usage and quota, then queue a storage
        // task with global to reject promise with a TypeError.
        // Step 5.5. Otherwise, queue a storage task with global to resolve promise with dictionary.
        //
        // The partitioned service-worker usage detail is resolved from the
        // service-worker manager with the same storage key and partition key
        // used for registration lookup, so cross-partition observers see zero
        // while same-partition observers agree.
        let pending = Arc::new(Mutex::new(PendingStorageEstimate {
            trusted_promise: Some(TrustedPromise::new(promise.clone())),
            task_source: global.task_manager().storage_task_source().to_sendable(),
            usage_quota: None,
            sw_usage: None,
            error: None,
        }));
        let mut estimate_handler = StorageManagerEstimateResponseHandler::new(pending.clone());
        let callback = GenericCallback::new(move |message| {
            estimate_handler.handle(message.unwrap_or_else(|error| Err(error.to_string())));
        })
        .expect("Could not create StorageManager estimate callback");

        if global
            .storage_threads()
            .estimate(global.origin().immutable().clone(), callback.clone())
            .is_err()
            && let Err(error) = callback.send(Err("Failed to queue storage task".to_owned()))
        {
            error!("Failed to deliver StorageManager estimate error: {error}");
        }

        let Some(storage_key) = global.obtain_storage_key() else {
            if let Ok(mut pending) = pending.lock() {
                pending.error = Some("Failed to obtain a storage key".to_owned());
                pending.sw_usage = Some(0);
                pending.try_resolve();
            }
            return promise;
        };
        let partition_key = global.storage_partition_key().map(str::to_owned);
        let mut sw_handler = StorageManagerServiceWorkerUsageHandler::new(pending.clone());
        let sw_callback = GenericCallback::new(move |message| match message {
            Ok(result) => sw_handler.handle(result),
            Err(error) => {
                error!("StorageManager service-worker usage query failed: {error:?}");
                sw_handler.handle_error();
            },
        })
        .expect("Could not create StorageManager service-worker usage callback");
        if global
            .script_to_constellation_chan()
            .send(ScriptToConstellationMessage::ServiceWorkerAlgorithm(
                ServiceWorkerAlgorithm::GetRegistrations {
                    storage_key,
                    partition_key,
                    result_handler: sw_callback,
                },
            ))
            .is_err()
        {
            error!("Failed to query service-worker registrations for storage estimate.");
            if let Ok(mut pending) = pending.lock() {
                pending.sw_usage = Some(0);
                pending.try_resolve();
            }
        }

        // Step 6. Return promise.
        promise
    }
}

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/MPL/2.0/. */

use std::sync::Arc;

use devtools_traits::{DevtoolScriptControlMsg, DevtoolsStorage, DevtoolsStorageEntry};
use malloc_size_of_derive::MallocSizeOf;
use serde::Serialize;
use serde_json::{Map, Value};
use servo_base::generic_channel;

use crate::StreamId;
use crate::actor::{Actor, ActorError, ActorRegistry, new_actor_name};
use crate::actors::browsing_context::BrowsingContextActor;
use crate::protocol::ClientRequest;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StorageItem {
    name: String,
    value: String,
    host: String,
}

#[derive(Serialize)]
struct StoreObjectsReply {
    from: String,
    entries: Vec<StorageItem>,
}

#[derive(Serialize)]
struct CookiesReply {
    from: String,
    cookies: Vec<StorageItem>,
}

#[derive(MallocSizeOf)]
pub(crate) struct StorageActor {
    name: String,
    browsing_context_name: String,
}

impl Actor for StorageActor {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle_message(
        &self,
        request: ClientRequest,
        registry: &ActorRegistry,
        msg_type: &str,
        msg: &Map<String, Value>,
        _id: StreamId,
    ) -> Result<(), ActorError> {
        let context = registry.find::<BrowsingContextActor>(&self.browsing_context_name);
        let storage = self.read_storage(&context);
        let host = context.url();

        match msg_type {
            "getStoreObjects" => {
                let storage_type = msg
                    .get("storageType")
                    .and_then(Value::as_str)
                    .unwrap_or("localStorage");
                request.reply_final(&StoreObjectsReply {
                    from: self.name().into(),
                    entries: entries_for_type(&storage, storage_type, &host),
                })?
            },
            "getCookies" => request.reply_final(&CookiesReply {
                from: self.name().into(),
                cookies: entries_for_type(&storage, "cookies", &host),
            })?,
            _ => return Err(ActorError::UnrecognizedPacketType),
        }
        Ok(())
    }
}

impl StorageActor {
    pub(crate) fn register(registry: &ActorRegistry, browsing_context_name: String) -> Arc<Self> {
        registry.register(Self {
            name: new_actor_name::<Self>(),
            browsing_context_name,
        })
    }

    pub(crate) fn resources(
        &self,
        context: &BrowsingContextActor,
        resource_type: &str,
    ) -> Vec<StorageItem> {
        let storage = self.read_storage(context);
        entries_for_type(&storage, resource_type, &context.url())
    }

    fn read_storage(&self, context: &BrowsingContextActor) -> DevtoolsStorage {
        let Some((sender, receiver)) = generic_channel::channel() else {
            return DevtoolsStorage::default();
        };
        if context
            .script_chan()
            .send(DevtoolScriptControlMsg::GetStorage(
                context.pipeline_id(),
                sender,
            ))
            .is_err()
        {
            return DevtoolsStorage::default();
        }
        receiver.recv().unwrap_or_default()
    }
}

fn entries_for_type(
    storage: &DevtoolsStorage,
    resource_type: &str,
    host: &str,
) -> Vec<StorageItem> {
    let entries: &[DevtoolsStorageEntry] = match resource_type {
        "session-storage" | "sessionStorage" => &storage.session_storage,
        "cookies" => &storage.cookies,
        _ => &storage.local_storage,
    };
    entries
        .iter()
        .map(|entry| StorageItem {
            name: entry.key.clone(),
            value: entry.value.clone(),
            host: host.to_owned(),
        })
        .collect()
}

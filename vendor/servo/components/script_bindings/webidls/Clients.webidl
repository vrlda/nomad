/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// https://w3c.github.io/ServiceWorker/#clients-interface
[Pref="dom_serviceworker_enabled", Exposed=ServiceWorker]
interface Clients {
  [NewObject] Promise<sequence<Client>> matchAll(optional ClientQueryOptions options = {});
  [NewObject] Promise<undefined> claim();
  [NewObject] Promise<WindowClient?> openWindow(USVString url);
};

dictionary ClientQueryOptions {
  boolean includeUncontrolled = false;
};

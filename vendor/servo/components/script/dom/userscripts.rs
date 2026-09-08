/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::collections::BTreeMap;

use js::jsapi::JSPROP_ENUMERATE;
use js::jsval::ObjectValue;
use js::rust::wrappers2::JS_WrapObject;
use script_bindings::reflector::DomObject;
use script_bindings::root::DomRoot;

use embedder_traits::user_contents::UserScriptWorld;

use crate::dom::bindings::inheritance::Castable;
use crate::dom::globalscope::GlobalScope;
use crate::dom::html::htmlheadelement::HTMLHeadElement;
use crate::dom::node::NodeTraits;
use crate::dom::window::Window;
use crate::realms::enter_auto_realm;

pub(crate) fn load_script(head: &HTMLHeadElement) {
    let doc = head.owner_document();
    let userscripts = doc.window().userscripts().to_owned();
    if userscripts.is_empty() {
        return;
    }
    let win = DomRoot::from_ref(doc.window());
    doc.add_delayed_task(task!(UserScriptExecute: |cx, win: DomRoot<Window>| {
        let page_scripts = userscripts
            .iter()
            .filter(|user_script| matches!(user_script.world(), UserScriptWorld::Page));
        {
            let global_scope = win.as_global_scope();
            let mut realm = enter_auto_realm(cx, global_scope);
            let cx = &mut realm.current_realm();
            for user_script in page_scripts {
                _ = global_scope.evaluate_js_on_global(
                    cx,
                    user_script.script().into(),
                    &user_script
                        .source_file()
                        .map(|path| path.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    None,
                    None,
                );
            }
        }

        let mut isolated_scripts = BTreeMap::<String, Vec<_>>::new();
        for user_script in userscripts {
            if let UserScriptWorld::Isolated(world_name) = user_script.world() {
                isolated_scripts
                    .entry(world_name.clone())
                    .or_default()
                    .push(user_script);
            }
        }

        for (world_name, scripts) in isolated_scripts {
            let world = win.user_script_world(cx, &world_name);
            let global_scope = world.upcast::<GlobalScope>();
            let mut realm = enter_auto_realm(cx, global_scope);
            let cx = &mut realm.current_realm();

            // This global is not a document Window. It gets its own
            // SpiderMonkey realm; `document` is a wrapped reference to this
            // page's Document, not a page-global object alias.
            install_document_binding(cx, global_scope, &world);

            for user_script in scripts {
                _ = global_scope.evaluate_js_on_global(
                    cx,
                    user_script.script().into(),
                    &user_script
                        .source_file()
                        .map(|path| path.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    None,
                    None,
                );
            }
        }
    }));
}

#[expect(unsafe_code)]
pub(crate) fn install_document_binding(
    cx: &mut js::context::JSContext,
    global_scope: &GlobalScope,
    world: &crate::dom::window::dissimilaroriginwindow::DissimilarOriginWindow,
) {
    let Some(document) = world.document() else {
        return;
    };

    rooted!(&in(cx) let mut document_object = document.reflector().get_jsobject().get());
    if document_object.is_null() || !unsafe { JS_WrapObject(cx, document_object.handle_mut()) } {
        return;
    }
    rooted!(&in(cx) let document_value = ObjectValue(document_object.get()));
    let global = global_scope.reflector().get_jsobject();
    unsafe {
        js::rust::wrappers2::JS_DefineProperty(
            cx,
            global,
            c"document".as_ptr(),
            document_value.handle(),
            JSPROP_ENUMERATE as u32,
        );
    }

    // A DissimilarOriginWindow's `window` WebIDL accessor points at the page
    // WindowProxy. Install an engine-owned facade on the isolated global so
    // ordinary `window.foo = ...` expandos stay in this world too. DOM and
    // platform properties continue to resolve against the page WindowProxy.
    let mut realm = enter_auto_realm(cx, global_scope);
    let cx = &mut realm.current_realm();
    _ = global_scope.evaluate_js_on_global(
        cx,
        r#"(() => {
            if (globalThis.__nomad_isolated_window_binding) return;
            const pageWindow = (globalThis.document && globalThis.document.defaultView) || globalThis.window;
            const pageDocument = globalThis.document;
            const expandos = Object.create(null);
            const isolatedWindow = new Proxy(pageWindow, {
                get(target, property) {
                    if (property === "document") return pageDocument;
                    if (Object.prototype.hasOwnProperty.call(expandos, property)) {
                        return expandos[property];
                    }
                    const value = Reflect.get(target, property, target);
                    return typeof value === "function" ? value.bind(target) : value;
                },
                set(target, property, value) {
                    if (Reflect.has(target, property)) return Reflect.set(target, property, value, target);
                    expandos[property] = value;
                    return true;
                },
                defineProperty(target, property, descriptor) {
                    if (Reflect.has(target, property)) return Reflect.defineProperty(target, property, descriptor);
                    Object.defineProperty(expandos, property, descriptor);
                    return true;
                },
                deleteProperty(target, property) {
                    if (Reflect.has(target, property)) return Reflect.deleteProperty(target, property);
                    return delete expandos[property];
                },
                has(target, property) {
                    return Object.prototype.hasOwnProperty.call(expandos, property) || Reflect.has(target, property);
                },
            });
            for (const name of ["window", "self", "frames"]) {
                try {
                    Object.defineProperty(globalThis, name, {
                        configurable: true,
                        enumerable: true,
                        value: isolatedWindow,
                    });
                } catch (_) {}
            }
            const pageApiNames = [
                "navigator", "history", "customElements", "screen", "visualViewport", "location",
                "performance", "crypto", "localStorage", "sessionStorage", "fetch",
                "XMLHttpRequest", "setTimeout", "clearTimeout", "setInterval",
                "clearInterval", "requestAnimationFrame", "cancelAnimationFrame",
                "requestIdleCallback", "cancelIdleCallback", "addEventListener",
                "removeEventListener", "dispatchEvent", "postMessage", "getComputedStyle", "matchMedia",
                "MessageEvent", "AbortController", "AbortSignal", "URL", "URLSearchParams",
            ];
            for (const name of pageApiNames) {
                try {
                    if (!(name in pageWindow)) continue;
                    Object.defineProperty(globalThis, name, {
                        configurable: true,
                        enumerable: true,
                        get() {
                            const value = pageWindow[name];
                            return typeof value === "function" ? value.bind(pageWindow) : value;
                        },
                    });
                } catch (_) {}
            }
            Object.defineProperty(globalThis, "__nomad_isolated_window_binding", {
                configurable: false,
                enumerable: false,
                value: true,
            });
        })()"#
            .into(),
        "",
        None,
        None,
    );
}

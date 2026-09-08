/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use dom_struct::dom_struct;
use html5ever::{LocalName, Prefix};
use js::context::JSContext;
use stylo_dom::ElementState;

use crate::dom::bindings::codegen::Bindings::SVGGraphicsElementBinding::{
    SVGBoundingBoxOptions, SVGGraphicsElementMethods,
};
use crate::dom::bindings::inheritance::Castable;
use crate::dom::bindings::root::DomRoot;
use crate::dom::document::Document;
use crate::dom::domrect::DOMRect;
use crate::dom::element::Element;
use crate::dom::node::NodeTraits;
use crate::dom::node::virtualmethods::VirtualMethods;
use crate::dom::svg::geometry;
use crate::dom::svg::svgelement::SVGElement;

#[dom_struct]
pub(crate) struct SVGGraphicsElement {
    svgelement: SVGElement,
}

impl SVGGraphicsElement {
    pub(crate) fn new_inherited(
        tag_name: LocalName,
        prefix: Option<Prefix>,
        document: &Document,
    ) -> SVGGraphicsElement {
        SVGGraphicsElement::new_inherited_with_state(
            ElementState::empty(),
            tag_name,
            prefix,
            document,
        )
    }

    pub(crate) fn new_inherited_with_state(
        state: ElementState,
        tag_name: LocalName,
        prefix: Option<Prefix>,
        document: &Document,
    ) -> SVGGraphicsElement {
        SVGGraphicsElement {
            svgelement: SVGElement::new_inherited_with_state(state, tag_name, prefix, document),
        }
    }
}

impl SVGGraphicsElementMethods<crate::DomTypeHolder> for SVGGraphicsElement {
    /// <https://svgwg.org/svg2-draft/types.html#__svg__SVGGraphicsElement__getBBox>
    fn GetBBox(&self, cx: &mut JSContext, _options: &SVGBoundingBoxOptions) -> DomRoot<DOMRect> {
        let element = self.upcast::<Element>();
        // The `SVGBoundingBoxOptions` (fill/stroke/markers/clipped) fields are
        // accepted for compatibility, but only the fill bounding box is
        // implemented; stroke, marker and clipped geometry is ignored.
        let bbox = geometry::bounding_box(element).unwrap_or_default();
        let window = self.upcast::<Element>().owner_window();
        DOMRect::new(
            cx,
            window.upcast(),
            bbox.min_x() as f64,
            bbox.min_y() as f64,
            bbox.width() as f64,
            bbox.height() as f64,
        )
    }
}

impl VirtualMethods for SVGGraphicsElement {
    fn super_type(&self) -> Option<&dyn VirtualMethods> {
        Some(self.upcast::<SVGElement>() as &dyn VirtualMethods)
    }
}

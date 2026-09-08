/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! SVG-local geometry computation for `getBBox()` and client-rect fallbacks.
//!
//! SVG child elements never receive layout fragments (`svg > * { display: none }` in
//! servo.css; inline `<svg>` subtrees are rasterized as a single replaced image), so
//! geometry cannot be queried from the fragment tree. Instead it is computed directly
//! from the SVG geometry attributes of the DOM tree, in user units.
//!
//! Only the fill bounding box is implemented; the `SVGBoundingBoxOptions` fields for
//! stroke, markers and clipped geometry are accepted but ignored.

use app_units::Au;
use euclid::default::{Point2D, Rect, Size2D, Transform2D};
use html5ever::{LocalName, local_name, ns};
use style::properties::{LonghandId, PropertyDeclarationId};
use style::values::generics::basic_shape::{
    CommandEndPoint, ControlPoint, ControlReference, GenericShapeCommand as Command,
};
use style::values::specified::svg_path::{SVGPathData, SVGPathPosition};
use style_traits::CSSPixel;

use crate::dom::bindings::inheritance::Castable;
use crate::dom::bindings::root::DomRoot;
use crate::dom::element::Element;
use crate::dom::iterators::ShadowIncluding;
use crate::dom::node::{Node, NodeTraits};
use crate::dom::svg::svgcircleelement::SVGCircleElement;
use crate::dom::svg::svgellipseelement::SVGEllipseElement;
use crate::dom::svg::svggraphicselement::SVGGraphicsElement;
use crate::dom::svg::svglineelement::SVGLineElement;
use crate::dom::svg::svgpathelement::SVGPathElement;
use crate::dom::svg::svgpolygonelement::SVGPolygonElement;
use crate::dom::svg::svgpolylineelement::SVGPolylineElement;
use crate::dom::svg::svgrectelement::SVGRectElement;
use crate::dom::svg::svgsvgelement::SVGSVGElement;

/// Parse the leading SVG number out of an attribute value, ignoring a trailing
/// unit such as `px`. Percentages cannot be resolved without a viewport and
/// yield `None`.
fn parse_svg_number(value: &str) -> Option<f32> {
    let trimmed = value.trim();
    let bytes = trimmed.as_bytes();
    let mut end = 0;

    if matches!(bytes.first(), Some(b'+' | b'-' | b'.' | b'0'..=b'9')) {
        if matches!(bytes[0], b'+' | b'-') {
            end += 1;
        }
        let mantissa_start = end;
        while bytes.get(end).is_some_and(|b| b.is_ascii_digit()) {
            end += 1;
        }
        if bytes.get(end) == Some(&b'.') {
            end += 1;
            while bytes.get(end).is_some_and(|b| b.is_ascii_digit()) {
                end += 1;
            }
        }
        if end == mantissa_start {
            return None;
        }
        // Optional exponent.
        if bytes.get(end).is_some_and(|b| matches!(b, b'e' | b'E'))
            && bytes
                .get(end + 1)
                .is_some_and(|b| b.is_ascii_digit() || matches!(b, b'+' | b'-'))
        {
            let exponent_start = end;
            end += 1;
            if matches!(bytes[end], b'+' | b'-') {
                end += 1;
            }
            let exponent_digits_start = end;
            while bytes.get(end).is_some_and(|b| b.is_ascii_digit()) {
                end += 1;
            }
            if end == exponent_digits_start {
                end = exponent_start;
            }
        }
    }

    if end == 0 || bytes.get(end) == Some(&b'%') {
        return None;
    }
    trimmed[..end].parse().ok()
}

/// Read an attribute value as a number in user units, or `None` if the
/// attribute is missing or not a plain number.
fn attribute_number(element: &Element, name: &LocalName) -> Option<f32> {
    let value = element.get_string_attribute(name);
    parse_svg_number(&value.str())
}

/// The convex hull of two rectangles. Unlike `Rect::union`, zero-area
/// rectangles (points and lines) always contribute: the SVG bounding box spec
/// includes zero-width and zero-height geometry.
fn union_rects(a: Rect<f32>, b: Rect<f32>) -> Rect<f32> {
    let min_x = a.min_x().min(b.min_x());
    let min_y = a.min_y().min(b.min_y());
    let max_x = a.max_x().max(b.max_x());
    let max_y = a.max_y().max(b.max_y());
    Rect::new(
        Point2D::new(min_x, min_y),
        Size2D::new(max_x - min_x, max_y - min_y),
    )
}

/// The fill bounding box of a `<rect>`: not rendered for missing, zero or
/// negative width or height. <https://svgwg.org/svg2-draft/shapes.html#RectElement>
fn rect_bbox(element: &Element) -> Option<Rect<f32>> {
    let width = attribute_number(element, &local_name!("width"))?;
    let height = attribute_number(element, &local_name!("height"))?;
    if width <= 0.0 || height <= 0.0 {
        return None;
    }
    let x = attribute_number(element, &local_name!("x")).unwrap_or(0.0);
    let y = attribute_number(element, &local_name!("y")).unwrap_or(0.0);
    Some(Rect::new(Point2D::new(x, y), Size2D::new(width, height)))
}

/// The fill bounding box of a `<circle>`: not rendered for a missing or
/// non-positive radius. <https://svgwg.org/svg2-draft/shapes.html#CircleElement>
fn circle_bbox(element: &Element) -> Option<Rect<f32>> {
    let r = attribute_number(element, &local_name!("r"))?;
    if r <= 0.0 {
        return None;
    }
    let cx = attribute_number(element, &local_name!("cx")).unwrap_or(0.0);
    let cy = attribute_number(element, &local_name!("cy")).unwrap_or(0.0);
    Some(Rect::new(
        Point2D::new(cx - r, cy - r),
        Size2D::new(2.0 * r, 2.0 * r),
    ))
}

/// The fill bounding box of an `<ellipse>`: not rendered for a missing or
/// non-positive rx or ry. <https://svgwg.org/svg2-draft/shapes.html#EllipseElement>
fn ellipse_bbox(element: &Element) -> Option<Rect<f32>> {
    let rx = attribute_number(element, &local_name!("rx"))?;
    let ry = attribute_number(element, &local_name!("ry"))?;
    if rx <= 0.0 || ry <= 0.0 {
        return None;
    }
    let cx = attribute_number(element, &local_name!("cx")).unwrap_or(0.0);
    let cy = attribute_number(element, &local_name!("cy")).unwrap_or(0.0);
    Some(Rect::new(
        Point2D::new(cx - rx, cy - ry),
        Size2D::new(2.0 * rx, 2.0 * ry),
    ))
}

/// The fill bounding box of a `<line>`: always the (possibly zero-area) box
/// around its two endpoints, which default to the origin.
/// <https://svgwg.org/svg2-draft/shapes.html#LineElement>
fn line_bbox(element: &Element) -> Rect<f32> {
    let x1 = attribute_number(element, &local_name!("x1")).unwrap_or(0.0);
    let y1 = attribute_number(element, &local_name!("y1")).unwrap_or(0.0);
    let x2 = attribute_number(element, &local_name!("x2")).unwrap_or(0.0);
    let y2 = attribute_number(element, &local_name!("y2")).unwrap_or(0.0);
    rect_from_points(x1, y1, x2, y2)
}

/// Parse a `<polygon>`/`<polyline>` `points` attribute into coordinate pairs.
/// A trailing unpaired coordinate is ignored, per the SVG points grammar.
/// <https://svgwg.org/svg2-draft/shapes.html#DataTypePoints>
fn parse_points(value: &str) -> Vec<(f32, f32)> {
    let mut points = Vec::new();
    let mut scanner = Scanner::new(value);
    loop {
        scanner.skip_separators();
        let Some(x) = scanner.parse_number() else {
            break;
        };
        scanner.skip_separators();
        // A coordinate pair is only complete once the second coordinate parsed;
        // otherwise the pair (and any trailing garbage) is dropped.
        let Some(y) = scanner.parse_number() else {
            break;
        };
        points.push((x, y));
        // Between pairs a comma is allowed but not required.
        scanner.skip_separators();
    }
    points
}

fn points_bbox(value: &str) -> Option<Rect<f32>> {
    let points = parse_points(value);
    let Some(&(first_x, first_y)) = points.first() else {
        return None;
    };
    let mut bbox = Rect::new(Point2D::new(first_x, first_y), Size2D::zero());
    for &(x, y) in points.iter().skip(1) {
        bbox = union_rects(bbox, Rect::new(Point2D::new(x, y), Size2D::zero()));
    }
    Some(bbox)
}

/// Include a point in the bounding box under construction.
fn include_point(bbox: &mut Option<Rect<f32>>, point: Point2D<f32>) {
    let point_rect = Rect::new(point, Size2D::zero());
    *bbox = Some(match *bbox {
        Some(existing) => union_rects(existing, point_rect),
        None => point_rect,
    });
}

/// The tight fill bounding box of a `<path>` `d` attribute, including curve
/// extrema and arc extrema. Returns `None` when no path segment could be
/// parsed.
/// <https://svgwg.org/svg2-draft/paths.html#PathElementBoundingBox>
fn path_bbox(value: &str) -> Option<Rect<f32>> {
    let (path, _) = SVGPathData::parse_bytes(value.as_bytes());
    // Normalizing restricts the commands to absolute M/L/C/A/Z, which is all
    // the bbox computation needs to handle.
    let normalized = path.normalize(true);

    let mut current = Point2D::new(0.0, 0.0);
    let mut subpath_start = current;
    let mut bbox: Option<Rect<f32>> = None;

    for command in normalized.commands() {
        match *command {
            Command::Move { point } => {
                current = absolute_end_point(point, current);
                subpath_start = current;
                include_point(&mut bbox, current);
            },
            Command::Line { point } => {
                current = absolute_end_point(point, current);
                include_point(&mut bbox, current);
            },
            Command::CubicCurve {
                point,
                control1,
                control2,
            } => {
                let end = absolute_end_point(point, current);
                let c1 = absolute_control_point(control1, current, end);
                let c2 = absolute_control_point(control2, current, end);
                // The extrema bound the curve itself; control points may lie
                // outside the curve and would make the box non-tight.
                for t in cubic_extrema(current, c1, c2, end) {
                    include_point(&mut bbox, cubic_point(current, c1, c2, end, t));
                }
                current = end;
            },
            Command::Arc {
                point,
                radii,
                arc_sweep,
                arc_size,
                rotate,
            } => {
                let end = absolute_end_point(point, current);
                include_point(&mut bbox, end);
                let sweep = arc_sweep == style::values::generics::basic_shape::ArcSweep::Cw;
                let large_arc = arc_size == style::values::generics::basic_shape::ArcSize::Large;
                for point in arc_extrema(
                    current,
                    end,
                    radii.rx,
                    radii.ry.into_rust().unwrap_or(radii.rx),
                    large_arc,
                    sweep,
                    rotate,
                ) {
                    include_point(&mut bbox, point);
                }
                current = end;
            },
            Command::Close => {
                current = subpath_start;
            },
            // Normalization with `reduce = true` converts H/V lines, quadratic
            // and smooth curves into lines and cubic curves, so they cannot
            // appear here.
            _ => {},
        }
    }

    bbox
}

/// Resolve a (possibly relative) command end point against the current position.
fn absolute_end_point(
    point: CommandEndPoint<SVGPathPosition, f32>,
    current: Point2D<f32>,
) -> Point2D<f32> {
    match point {
        CommandEndPoint::ToPosition(position) => {
            Point2D::new(position.horizontal, position.vertical)
        },
        CommandEndPoint::ByCoordinate(pair) => Point2D::new(current.x + pair.x, current.y + pair.y),
    }
}

/// Resolve a (possibly relative) Bézier control point. Relative control points
/// are resolved against the subpath start, the curve end point or the origin
/// depending on their reference.
fn absolute_control_point(
    control: ControlPoint<SVGPathPosition, f32>,
    current: Point2D<f32>,
    end: Point2D<f32>,
) -> Point2D<f32> {
    match control {
        ControlPoint::Absolute(position) => Point2D::new(position.horizontal, position.vertical),
        ControlPoint::Relative(relative) => {
            let reference = match relative.reference {
                ControlReference::Start => current,
                ControlReference::End => end,
                ControlReference::Origin => Point2D::zero(),
            };
            Point2D::new(
                reference.x + relative.coord.x,
                reference.y + relative.coord.y,
            )
        },
    }
}

fn cubic_point(
    p0: Point2D<f32>,
    p1: Point2D<f32>,
    p2: Point2D<f32>,
    p3: Point2D<f32>,
    t: f32,
) -> Point2D<f32> {
    let one_minus = 1.0 - t;
    let w0 = one_minus * one_minus * one_minus;
    let w1 = 3.0 * one_minus * one_minus * t;
    let w2 = 3.0 * one_minus * t * t;
    let w3 = t * t * t;
    Point2D::new(
        w0 * p0.x + w1 * p1.x + w2 * p2.x + w3 * p3.x,
        w0 * p0.y + w1 * p1.y + w2 * p2.y + w3 * p3.y,
    )
}

/// The parameter values `t` where a cubic Bézier curve has axis extrema (where
/// its x or y derivative vanishes), plus the endpoints `0.0` and `1.0`.
fn cubic_extrema(
    p0: Point2D<f32>,
    p1: Point2D<f32>,
    p2: Point2D<f32>,
    p3: Point2D<f32>,
) -> Vec<f32> {
    // The derivative along an axis is a quadratic: a·t² + b·t + c = 0.
    fn solve_axis(p0: f32, p1: f32, p2: f32, p3: f32) -> Vec<f32> {
        let a = -p0 + 3.0 * p1 - 3.0 * p2 + p3;
        let b = 2.0 * (p0 - 2.0 * p1 + p2);
        let c = p1 - p0;
        if a.abs() < f32::EPSILON {
            if b.abs() < f32::EPSILON {
                return Vec::new();
            }
            let t = -c / b;
            return (0.0..=1.0).contains(&t).then_some(t).into_iter().collect();
        }
        let discriminant = b * b - 4.0 * a * c;
        if discriminant < 0.0 {
            return Vec::new();
        }
        let root = discriminant.sqrt();
        [(-b + root) / (2.0 * a), (-b - root) / (2.0 * a)]
            .into_iter()
            .filter(|t| (0.0..=1.0).contains(t))
            .collect()
    }

    let mut extrema = vec![0.0, 1.0];
    extrema.extend(solve_axis(p0.x, p1.x, p2.x, p3.x));
    extrema.extend(solve_axis(p0.y, p1.y, p2.y, p3.y));
    extrema
}

/// The extrema of an elliptical arc, computed via the center parameterization
/// of <https://www.w3.org/TR/SVG11/implnote.html#ArcConversionEndpointToCenter>.
/// Degenerate arcs (identical endpoints or non-positive radii) contribute only
/// their endpoints, which the caller includes separately.
#[allow(clippy::too_many_arguments)]
fn arc_extrema(
    from: Point2D<f32>,
    to: Point2D<f32>,
    rx_in: f32,
    ry_in: f32,
    large_arc: bool,
    sweep: bool,
    rotation_degrees: f32,
) -> Vec<Point2D<f32>> {
    if from == to || rx_in <= 0.0 || ry_in <= 0.0 {
        return Vec::new();
    }

    let phi = rotation_degrees.to_radians();
    let (sin_phi, cos_phi) = phi.sin_cos();

    // Step 1: transform the endpoints into the (unrotated) ellipse frame.
    let dx = (from.x - to.x) / 2.0;
    let dy = (from.y - to.y) / 2.0;
    let x1p = cos_phi * dx + sin_phi * dy;
    let y1p = -sin_phi * dx + cos_phi * dy;

    // Step 2: scale the radii up so the arc can reach both endpoints.
    let lambda = x1p * x1p / (rx_in * rx_in) + y1p * y1p / (ry_in * ry_in);
    let (rx, ry) = if lambda > 1.0 {
        let scale = lambda.sqrt();
        (rx_in * scale, ry_in * scale)
    } else {
        (rx_in, ry_in)
    };

    // Step 3: compute the center in the ellipse frame and unrotate it.
    let sign = if large_arc != sweep { 1.0 } else { -1.0 };
    let numerator = rx * rx * ry * ry - rx * rx * y1p * y1p - ry * ry * x1p * x1p;
    let denominator = rx * rx * y1p * y1p + ry * ry * x1p * x1p;
    let coefficient = sign * (numerator / denominator).max(0.0).sqrt();
    let cxp = coefficient * rx * y1p / ry;
    let cyp = -coefficient * ry * x1p / rx;
    let cx = cos_phi * cxp - sin_phi * cyp + (from.x + to.x) / 2.0;
    let cy = sin_phi * cxp + cos_phi * cyp + (from.y + to.y) / 2.0;

    // Step 4: the start angle and the (signed) sweep angle.
    fn angle(ux: f32, uy: f32, vx: f32, vy: f32) -> f32 {
        let dot = ux * vx + uy * vy;
        let length = (ux * ux + uy * uy).sqrt() * (vx * vx + vy * vy).sqrt();
        let mut angle = (dot / length).clamp(-1.0, 1.0).acos();
        if ux * vy - uy * vx < 0.0 {
            angle = -angle;
        }
        angle
    }
    let theta1 = angle(1.0, 0.0, (x1p - cxp) / rx, (y1p - cyp) / ry);
    let mut delta = angle(
        (x1p - cxp) / rx,
        (y1p - cyp) / ry,
        (-x1p - cxp) / rx,
        (-y1p - cyp) / ry,
    );
    if !sweep && delta > 0.0 {
        delta -= 2.0 * std::f32::consts::PI;
    } else if sweep && delta < 0.0 {
        delta += 2.0 * std::f32::consts::PI;
    }

    // Points on the arc: P(t) = center + R(phi) · (rx·cos t, ry·sin t).
    let point_at = |t: f32| -> Point2D<f32> {
        let (sin_t, cos_t) = t.sin_cos();
        Point2D::new(
            cx + rx * cos_phi * cos_t - ry * sin_phi * sin_t,
            cy + rx * sin_phi * cos_t + ry * cos_phi * sin_t,
        )
    };

    // Is `t` within the arc's angular span [theta1, theta1 + delta]?
    let two_pi = 2.0 * std::f32::consts::PI;
    let in_span = |t: f32| -> bool {
        let offset = (t - theta1).rem_euclid(two_pi);
        if delta >= 0.0 {
            offset <= delta
        } else {
            offset >= two_pi + delta
        }
    };

    // The axis extrema occur where dx/dt or dy/dt vanishes; the endpoints are
    // always included.
    let mut candidates = vec![theta1, theta1 + delta];
    if sin_phi.abs() > f32::EPSILON {
        let base = (-ry * sin_phi).atan2(rx * cos_phi); // dx/dt = 0
        candidates.push(base);
        candidates.push(base + std::f32::consts::PI);
    }
    if cos_phi.abs() > f32::EPSILON {
        let base = (ry * cos_phi).atan2(rx * sin_phi); // dy/dt = 0
        candidates.push(base);
        candidates.push(base + std::f32::consts::PI);
    }

    candidates
        .iter()
        .filter(|t| in_span(**t))
        .map(|t| point_at(*t))
        .collect()
}

/// Build a normalized (non-negative size) rectangle from two points.
fn rect_from_points(x1: f32, y1: f32, x2: f32, y2: f32) -> Rect<f32> {
    let (min_x, max_x) = if x1 <= x2 { (x1, x2) } else { (x2, x1) };
    let (min_y, max_y) = if y1 <= y2 { (y1, y2) } else { (y2, y1) };
    Rect::new(
        Point2D::new(min_x, min_y),
        Size2D::new(max_x - min_x, max_y - min_y),
    )
}

/// A minimal scanner for the SVG number grammar, shared by the `points` and
/// `transform` attribute parsers.
struct Scanner<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Scanner<'a> {
    fn new(value: &'a str) -> Self {
        Scanner {
            bytes: value.as_bytes(),
            pos: 0,
        }
    }

    fn skip_separators(&mut self) {
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|b| b.is_ascii_whitespace() || *b == b',')
        {
            self.pos += 1;
        }
    }

    fn parse_number(&mut self) -> Option<f32> {
        self.skip_separators();
        let start = self.pos;
        if matches!(self.bytes.get(self.pos), Some(b'+' | b'-')) {
            self.pos += 1;
        }
        let mut digits = 0;
        while self.bytes.get(self.pos).is_some_and(|b| b.is_ascii_digit()) {
            self.pos += 1;
            digits += 1;
        }
        if self.bytes.get(self.pos) == Some(&b'.') {
            self.pos += 1;
            while self.bytes.get(self.pos).is_some_and(|b| b.is_ascii_digit()) {
                self.pos += 1;
                digits += 1;
            }
        }
        if digits == 0 {
            self.pos = start;
            return None;
        }
        if self
            .bytes
            .get(self.pos)
            .is_some_and(|b| matches!(b, b'e' | b'E'))
        {
            let exponent_start = self.pos;
            self.pos += 1;
            if matches!(self.bytes.get(self.pos), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            let mut exponent_digits = 0;
            while self.bytes.get(self.pos).is_some_and(|b| b.is_ascii_digit()) {
                self.pos += 1;
                exponent_digits += 1;
            }
            if exponent_digits == 0 {
                self.pos = exponent_start;
            }
        }
        // Parse just the consumed number; any trailing unit such as `px` is
        // left in the stream and ignored here.
        std::str::from_utf8(&self.bytes[start..self.pos])
            .ok()
            .and_then(|s| s.parse().ok())
    }

    fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }
}

/// Parse an SVG `transform` attribute into a 2D affine matrix, applying the
/// list left to right (i.e. the rightmost transform is applied to coordinates
/// first). Returns `None` if the attribute is missing or malformed.
/// <https://svgwg.org/svg2-draft/coords.html#TransformProperty>
fn parse_transform_attr(value: &str) -> Option<Transform2D<f32>> {
    if value.trim().is_empty() {
        return None;
    }
    let mut scanner = Scanner::new(value);
    let mut matrix = Transform2D::<f32>::identity();
    loop {
        scanner.skip_separators();
        if scanner.at_end() {
            break;
        }
        let name_start = scanner.pos;
        while scanner
            .bytes
            .get(scanner.pos)
            .is_some_and(|b| b.is_ascii_alphabetic())
        {
            scanner.pos += 1;
        }
        let name = std::str::from_utf8(&scanner.bytes[name_start..scanner.pos]).ok()?;
        scanner.skip_separators();
        if scanner.bytes.get(scanner.pos) != Some(&b'(') {
            return None;
        }
        scanner.pos += 1;

        let mut args = Vec::new();
        loop {
            scanner.skip_separators();
            if scanner.bytes.get(scanner.pos) == Some(&b')') {
                scanner.pos += 1;
                break;
            }
            let Some(number) = scanner.parse_number() else {
                return None;
            };
            args.push(number);
        }

        let transform = match name.to_ascii_lowercase().as_str() {
            "translate" => match args.len() {
                1 => Transform2D::translation(args[0], 0.0),
                2 => Transform2D::translation(args[0], args[1]),
                _ => return None,
            },
            "scale" => match args.len() {
                1 => Transform2D::scale(args[0], args[0]),
                2 => Transform2D::scale(args[0], args[1]),
                _ => return None,
            },
            "rotate" => match args.len() {
                1 => rotation(args[0]),
                3 => Transform2D::translation(-args[1], -args[2])
                    .then(&rotation(args[0]))
                    .then(&Transform2D::translation(args[1], args[2])),
                _ => return None,
            },
            "matrix" if args.len() == 6 => {
                Transform2D::new(args[0], args[1], args[2], args[3], args[4], args[5])
            },
            "skewx" if args.len() == 1 => {
                Transform2D::new(1.0, 0.0, args[0].to_radians().tan(), 1.0, 0.0, 0.0)
            },
            "skewy" if args.len() == 1 => {
                Transform2D::new(1.0, args[0].to_radians().tan(), 0.0, 1.0, 0.0, 0.0)
            },
            _ => return None,
        };
        // Each successive transform is applied after everything parsed so far.
        matrix = transform.then(&matrix);
    }
    Some(matrix)
}

fn rotation(degrees: f32) -> Transform2D<f32> {
    let (sin, cos) = degrees.to_radians().sin_cos();
    Transform2D::new(cos, sin, -sin, cos, 0.0, 0.0)
}

/// Transform a rectangle and return the bounds of its four transformed corners.
fn transform_rect(rect: Rect<f32>, matrix: &Transform2D<f32>) -> Rect<f32> {
    let corners = [
        rect.origin,
        Point2D::new(rect.max_x(), rect.min_y()),
        Point2D::new(rect.min_x(), rect.max_y()),
        Point2D::new(rect.max_x(), rect.max_y()),
    ];
    let mut result = transform_rect_corner(matrix, corners[0]);
    for corner in corners.iter().skip(1) {
        result = union_rects(result, transform_rect_corner(matrix, *corner));
    }
    result
}

fn transform_rect_corner(matrix: &Transform2D<f32>, corner: Point2D<f32>) -> Rect<f32> {
    Rect::new(matrix.transform_point(corner), Size2D::zero())
}

/// Whether `element` is one of the SVG container types that are defined but
/// never directly rendered, so their subtree contributes no geometry.
fn is_non_rendered_container(element: &Element) -> bool {
    if *element.namespace() != ns!(svg) {
        return false;
    }
    matches!(
        *element.local_name(),
        local_name!("defs")
            | local_name!("clipPath")
            | local_name!("mask")
            | local_name!("symbol")
            | local_name!("marker")
            | local_name!("pattern")
    )
}

/// Whether any inclusive ancestor of `element` is a non-rendered container
/// (`<defs>`, `<clipPath>`, `<mask>`, `<symbol>`, `<marker>` or `<pattern>`).
/// Elements in such containers do not render directly and their `getBBox()`
/// is a zero rect.
fn inside_non_rendered_container(element: &Element) -> bool {
    element
        .upcast::<Node>()
        .inclusive_ancestors(ShadowIncluding::No)
        .any(|node| {
            node.downcast::<Element>()
                .is_some_and(is_non_rendered_container)
        })
}

/// Whether `element` is hidden by author-specified CSS: the `display="none"`
/// presentation attribute or an inline `style="display: none"`. The computed
/// style cannot be used here because servo.css forces `svg > * { display: none }`
/// on every SVG child (SVG subtrees are rasterized as replaced content), which
/// would make all SVG geometry appear hidden.
fn author_display_none(element: &Element) -> bool {
    let display_attr = element.get_string_attribute(&local_name!("display"));
    if display_attr.str().trim().eq_ignore_ascii_case("none") {
        return true;
    }
    let Some(pdb) = element.style_attribute().borrow().clone() else {
        return false;
    };
    let document = element.upcast::<Node>().owner_document();
    let guard = document.style_shared_author_lock().read();
    let Some((declaration, _)) = pdb
        .read_with(&guard)
        .get(PropertyDeclarationId::Longhand(LonghandId::Display))
    else {
        return false;
    };
    let mut serialized = String::new();
    if declaration.to_css(&mut serialized).is_err() {
        return false;
    }
    serialized.trim().eq_ignore_ascii_case("none")
}

pub(crate) fn bounding_box(element: &Element) -> Option<Rect<f32>> {
    if author_display_none(element) || inside_non_rendered_container(element) {
        return None;
    }
    if element.is::<SVGRectElement>() {
        return rect_bbox(element);
    }
    if element.is::<SVGCircleElement>() {
        return circle_bbox(element);
    }
    if element.is::<SVGEllipseElement>() {
        return ellipse_bbox(element);
    }
    if element.is::<SVGLineElement>() {
        return Some(line_bbox(element));
    }
    if element.is::<SVGPathElement>() {
        let d = element.get_string_attribute(&local_name!("d"));
        return path_bbox(&d.str());
    }
    if element.is::<SVGPolygonElement>() || element.is::<SVGPolylineElement>() {
        let points = element.get_string_attribute(&local_name!("points"));
        return points_bbox(&points.str());
    }

    // `<g>`, `<use>`, `<a>`, `<switch>`, `<text>`, `<image>` and any other
    // graphics element: the union of the bounding boxes of the rendered
    // children, each transformed by its own `transform` attribute. Elements
    // without text layout support (`<text>`, `<image>`) and elements without
    // rendered children contribute nothing, matching the expectations of the
    // SVG bounding box tests for empty `<image>`/`<foreignObject>`.
    let mut result: Option<Rect<f32>> = None;
    for child in element.upcast::<Node>().child_elements() {
        if author_display_none(&child) || is_non_rendered_container(&child) {
            continue;
        }
        let Some(child_bbox) = bounding_box(&child) else {
            continue;
        };
        let transform_attr = child.get_string_attribute(&local_name!("transform"));
        let child_bbox = match parse_transform_attr(&transform_attr.str()) {
            Some(matrix) => transform_rect(child_bbox, &matrix),
            None => child_bbox,
        };
        result = Some(match result {
            Some(existing) => union_rects(existing, child_bbox),
            None => child_bbox,
        });
    }
    result
}

/// Parse a `viewBox` attribute into `(min_x, min_y, width, height)`.
fn parse_view_box(value: &str) -> Option<(f32, f32, f32, f32)> {
    let mut scanner = Scanner::new(value);
    let min_x = scanner.parse_number()?;
    let min_y = scanner.parse_number()?;
    let width = scanner.parse_number()?;
    let height = scanner.parse_number()?;
    if width <= 0.0 || height <= 0.0 {
        return None;
    }
    Some((min_x, min_y, width, height))
}

/// Compute the mapping from the user units of a root `<svg>` to its viewport:
/// `(scale_x, scale_y, translate_x, translate_y)` such that a user-space point
/// `p` maps to `(translate_x + p.x·scale_x, translate_y + p.y·scale_y)`.
/// Alignment is always centered (`xMidYMid`); `preserveAspectRatio` values
/// with non-centered alignment are not supported yet.
fn view_box_to_viewport_transform(
    view_box: Option<&str>,
    preserve_aspect_ratio: Option<&str>,
    viewport: Size2D<f32>,
) -> (f32, f32, f32, f32) {
    let Some((min_x, min_y, width, height)) = view_box.and_then(parse_view_box) else {
        // Without a viewBox one user unit is one CSS pixel.
        return (1.0, 1.0, 0.0, 0.0);
    };

    let preserve = preserve_aspect_ratio
        .map(|value| value.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if preserve == "none" {
        let scale_x = viewport.width / width;
        let scale_y = viewport.height / height;
        return (scale_x, scale_y, -min_x * scale_x, -min_y * scale_y);
    }
    let scale = if preserve.ends_with("slice") {
        (viewport.width / width).max(viewport.height / height)
    } else {
        // Default and explicit `meet` behavior.
        (viewport.width / width).min(viewport.height / height)
    };
    let translate_x = (viewport.width - width * scale) / 2.0 - min_x * scale;
    let translate_y = (viewport.height - height * scale) / 2.0 - min_y * scale;
    (scale, scale, translate_x, translate_y)
}

/// The accumulated `transform` attribute matrices from `element` itself up to
/// (but excluding) `root_svg`, in application order.
fn accumulated_transform(element: &Element, root_svg: &Element) -> Transform2D<f32> {
    let mut matrix = Transform2D::<f32>::identity();
    let root_node: &Node = root_svg.upcast::<Node>();
    for node in element
        .upcast::<Node>()
        .inclusive_ancestors(ShadowIncluding::No)
    {
        if std::ptr::eq(&*node, root_node) {
            break;
        }
        let Some(ancestor) = node.downcast::<Element>() else {
            continue;
        };
        let transform_attr = ancestor.get_string_attribute(&local_name!("transform"));
        if let Some(transform) = parse_transform_attr(&transform_attr.str()) {
            matrix = transform.then(&matrix);
        }
    }
    matrix
}

/// Find the outermost `<svg>` element that strictly contains `element`, or
/// `None` if `element` is not inside an `<svg>` element.
fn outermost_svg_ancestor(element: &Element) -> Option<DomRoot<Element>> {
    let mut result: Option<DomRoot<Element>> = None;
    for node in element.upcast::<Node>().ancestors() {
        if let Some(ancestor) = node.downcast::<SVGSVGElement>() {
            result = Some(DomRoot::from_ref(ancestor.upcast::<Element>()));
        }
    }
    result
}

/// Compute a client rect for an SVG child element that has no layout
/// fragments: the element's fill bounding box mapped through its own and its
/// ancestors' `transform` attributes and through the viewBox-to-viewport
/// mapping of its root `<svg>`, positioned at the root `<svg>`'s border box.
/// Returns `None` for non-SVG elements and for elements that are not inside a
/// rendered `<svg>`; in those cases the regular (empty) fragment result stands.
pub(crate) fn client_rect_for_svg_element(element: &Element) -> Option<euclid::Rect<Au, CSSPixel>> {
    if !element.is::<SVGGraphicsElement>() {
        return None;
    }
    // The root `<svg>` itself is a replaced element with real layout fragments;
    // only content inside an `<svg>` needs this attribute-derived path.
    let root_svg = outermost_svg_ancestor(element)?;
    let Some(bbox) = bounding_box(element) else {
        return None;
    };
    let user_rect = transform_rect(bbox, &accumulated_transform(element, &root_svg));

    let root_border_box = root_svg.upcast::<Node>().border_box()?;
    let viewport = Size2D::new(
        root_border_box.size.width.to_f32_px(),
        root_border_box.size.height.to_f32_px(),
    );
    let view_box =
        root_svg.get_attribute_string_value_with_namespace(&ns!(), &local_name!("viewBox"));
    let preserve_aspect_ratio = root_svg
        .get_attribute_string_value_with_namespace(&ns!(), &local_name!("preserveAspectRatio"));
    let (scale_x, scale_y, translate_x, translate_y) = view_box_to_viewport_transform(
        view_box.as_deref(),
        preserve_aspect_ratio.as_deref(),
        viewport,
    );

    let x = root_border_box.origin.x.to_f32_px() + translate_x + user_rect.min_x() * scale_x;
    let y = root_border_box.origin.y.to_f32_px() + translate_y + user_rect.min_y() * scale_y;
    Some(euclid::Rect::new(
        euclid::Point2D::new(Au::from_f32_px(x), Au::from_f32_px(y)),
        euclid::Size2D::new(
            Au::from_f32_px(user_rect.width() * scale_x),
            Au::from_f32_px(user_rect.height() * scale_y),
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-4
    }

    #[test]
    fn test_path_bbox_quadratic() {
        // Q from (0,0) with control (10,0) to (0,10): the curve bulges to
        // x = 5 at t = 0.5, well inside the control point at x = 10.
        assert_rect(path_bbox("M0,0 Q 10,0 0,10").unwrap(), 0.0, 0.0, 5.0, 10.0);
    }

    #[test]
    fn test_path_bbox_arc() {
        // A half circle from (-1,0) to (1,0) through (0,-1): the extrema
        // reach y = -1, which endpoints alone would miss.
        let bbox = path_bbox("M-1,0 A 1,1 0 1 1 1,0").unwrap();
        assert_rect(bbox, -1.0, -1.0, 2.0, 1.0);
    }

    #[test]
    fn test_path_bbox_arc_quarter_in_unit_square() {
        // Quarter circle from (0,1) to (1,0): its bbox is the unit square
        // spanned by its endpoints.
        let bbox = path_bbox("M0,1 A 1,1 0 0 1 1,0").unwrap();
        assert_rect(bbox, 0.0, 0.0, 1.0, 1.0);
    }

    fn assert_rect(rect: Rect<f32>, x: f32, y: f32, width: f32, height: f32) {
        assert!(approx(rect.min_x(), x), "x: {} != {}", rect.min_x(), x);
        assert!(approx(rect.min_y(), y), "y: {} != {}", rect.min_y(), y);
        assert!(
            approx(rect.width(), width),
            "width: {} != {}",
            rect.width(),
            width
        );
        assert!(
            approx(rect.height(), height),
            "height: {} != {}",
            rect.height(),
            height
        );
    }

    #[test]
    fn test_parse_svg_number() {
        assert_eq!(parse_svg_number("10"), Some(10.0));
        assert_eq!(parse_svg_number(" -5 "), Some(-5.0));
        assert_eq!(parse_svg_number("+3.5"), Some(3.5));
        assert_eq!(parse_svg_number(".5"), Some(0.5));
        assert_eq!(parse_svg_number("1e2"), Some(100.0));
        assert_eq!(parse_svg_number("1.5e-2"), Some(0.015));
        assert_eq!(parse_svg_number("10px"), Some(10.0));
        assert_eq!(parse_svg_number("50%"), None);
        assert_eq!(parse_svg_number(""), None);
        assert_eq!(parse_svg_number("abc"), None);
        assert_eq!(parse_svg_number("-"), None);
        assert_eq!(parse_svg_number("."), None);
        assert_eq!(parse_svg_number("1e"), Some(1.0));
    }

    #[test]
    fn test_parse_points() {
        assert_eq!(
            parse_points("10 20, 30 40"),
            vec![(10.0, 20.0), (30.0, 40.0)]
        );
        assert_eq!(
            parse_points("10,20,30,40"),
            vec![(10.0, 20.0), (30.0, 40.0)]
        );
        // A trailing unpaired coordinate is dropped.
        assert_eq!(parse_points("10 20 30"), vec![(10.0, 20.0)]);
        assert_eq!(parse_points("47"), Vec::<(f32, f32)>::new());
        assert_eq!(parse_points(""), Vec::<(f32, f32)>::new());
    }

    #[test]
    fn test_points_bbox() {
        assert!(points_bbox("47").is_none());
        assert!(points_bbox("").is_none());
        assert_rect(points_bbox("10 20").unwrap(), 10.0, 20.0, 0.0, 0.0);
        assert_rect(
            points_bbox("10,20 30,60 50,20").unwrap(),
            10.0,
            20.0,
            40.0,
            40.0,
        );
    }

    #[test]
    fn test_path_bbox_lines_and_moveto() {
        // MoveTo only: zero-area box at the moveto position.
        assert_rect(path_bbox("M 10 20").unwrap(), 10.0, 20.0, 0.0, 0.0);
        assert_rect(path_bbox("M40 20h0").unwrap(), 40.0, 20.0, 0.0, 0.0);
        // Invalid paths contribute nothing.
        assert!(path_bbox("").is_none());
        assert!(path_bbox("M3").is_none());
        // Horizontal and vertical lines via H/V commands.
        assert_rect(path_bbox("M10 20 H 50").unwrap(), 10.0, 20.0, 40.0, 0.0);
        assert_rect(path_bbox("M10 20 V 60").unwrap(), 10.0, 20.0, 0.0, 40.0);
    }

    #[test]
    fn test_path_bbox_cubic_extrema_are_tight() {
        // The curve M0,0 C 0,10 10,10 10,0 dips to y = 7.5 at t = 0.5; the
        // bbox is tight around the curve, not the control points (y = 10).
        assert_rect(
            path_bbox("M0,0 C 0,10 10,10 10,0").unwrap(),
            0.0,
            0.0,
            10.0,
            7.5,
        );
    }

    #[test]
    fn test_path_bbox_arc_zero_radii_is_line() {
        assert_rect(
            path_bbox("M10 20 A 0,0 0 0 1 30 40").unwrap(),
            10.0,
            20.0,
            20.0,
            20.0,
        );
    }

    #[test]
    fn test_parse_transform_attr() {
        // Empty or missing transform is identity (absent).
        assert!(parse_transform_attr("").is_none());
        assert!(parse_transform_attr("garbage").is_none());

        let translate = parse_transform_attr("translate(10,20)").unwrap();
        let rect = transform_rect(
            Rect::new(Point2D::new(0.0, 0.0), Size2D::new(5.0, 5.0)),
            &translate,
        );
        assert_rect(rect, 10.0, 20.0, 5.0, 5.0);

        // Space-separated arguments are valid SVG syntax.
        let translate = parse_transform_attr("translate(10 20)").unwrap();
        let rect = transform_rect(Rect::zero(), &translate);
        assert_rect(rect, 10.0, 20.0, 0.0, 0.0);

        // In "translate(10,20) scale(2)" the scale applies to the coordinates
        // first, then the translation.
        let combined = parse_transform_attr("translate(10,20) scale(2)").unwrap();
        let rect = transform_rect(
            Rect::new(Point2D::new(1.0, 1.0), Size2D::new(3.0, 3.0)),
            &combined,
        );
        assert_rect(rect, 12.0, 22.0, 6.0, 6.0);

        // rotate(45) around the origin.
        let rotated = parse_transform_attr("rotate(45)").unwrap();
        let point = rotated.transform_point(Point2D::new(1.0, 0.0));
        assert!(approx(point.x, std::f32::consts::FRAC_1_SQRT_2));
        assert!(approx(point.y, std::f32::consts::FRAC_1_SQRT_2));

        // rotate(a, cx, cy) rotates around the given point.
        let rotated = parse_transform_attr("rotate(90, 10, 10)").unwrap();
        let point = rotated.transform_point(Point2D::new(11.0, 10.0));
        assert!(approx(point.x, 10.0), "x: {}", point.x);
        assert!(approx(point.y, 11.0), "y: {}", point.y);

        // matrix(a,b,c,d,e,f)
        let matrix = parse_transform_attr("matrix(1,2,3,4,5,6)").unwrap();
        let point = matrix.transform_point(Point2D::new(1.0, 0.0));
        assert!(approx(point.x, 6.0));
        assert!(approx(point.y, 8.0));
    }

    #[test]
    fn test_parse_view_box() {
        assert_eq!(parse_view_box("0 0 100 50"), Some((0.0, 0.0, 100.0, 50.0)));
        assert_eq!(
            parse_view_box("10,20 200,100"),
            Some((10.0, 20.0, 200.0, 100.0))
        );
        assert_eq!(parse_view_box("0 0 0 50"), None);
        assert_eq!(parse_view_box("0 0"), None);
    }

    #[test]
    fn test_view_box_to_viewport_transform() {
        // Default meet: uniform scale, centered.
        let (sx, sy, tx, ty) =
            view_box_to_viewport_transform(Some("0 0 100 50"), None, Size2D::new(200.0, 200.0));
        assert!(approx(sx, 2.0) && approx(sy, 2.0));
        // Content is centered vertically: (200 - 50·2)/2 = 50.
        assert!(approx(tx, 0.0) && approx(ty, 50.0));

        // viewBox with an offset is subtracted.
        let (sx, sy, tx, ty) =
            view_box_to_viewport_transform(Some("10 20 100 100"), None, Size2D::new(100.0, 100.0));
        assert!(approx(sx, 1.0) && approx(sy, 1.0));
        assert!(approx(tx, -10.0) && approx(ty, -20.0));

        // preserveAspectRatio="none" stretches.
        let (sx, sy, _, _) = view_box_to_viewport_transform(
            Some("0 0 100 50"),
            Some("none"),
            Size2D::new(200.0, 200.0),
        );
        assert!(approx(sx, 2.0) && approx(sy, 4.0));

        // Without a valid viewBox, one user unit is one pixel.
        let (sx, sy, tx, ty) =
            view_box_to_viewport_transform(None, None, Size2D::new(300.0, 150.0));
        assert!(approx(sx, 1.0) && approx(sy, 1.0));
        assert!(approx(tx, 0.0) && approx(ty, 0.0));
    }
}

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// https://w3c.github.io/mediacapture-main/#dom-mediastreamtrackevent

[Exposed=Window]
interface MediaStreamTrackEvent : Event {
  constructor(DOMString type, MediaStreamTrackEventInit eventInitDict);
  [SameObject] readonly attribute MediaStreamTrack track;
};

dictionary MediaStreamTrackEventInit : EventInit {
  required MediaStreamTrack track;
};

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// https://w3c.github.io/webrtc-pc/#rtcrtpreceiver-interface

[Exposed=Window, Pref="dom_webrtc_transceiver_enabled"]
interface RTCRtpReceiver {
  [SameObject] readonly attribute MediaStreamTrack track;
  // RTCRtpReceiveParameters getParameters();
  // static RTCRtpCapabilities? getCapabilities(DOMString kind);
  // Promise<RTCStatsReport> getStats();
};

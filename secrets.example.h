#pragma once
// Copy this file to secrets.h and fill it in. secrets.h is never shared or
// committed - it holds the keys to your WiFi, your Tuya cloud project and
// your Somnus account's device.

// WiFi is not set here. On first boot, and whenever the saved network is
// out of reach, the unit opens a hotspot named Somnus-room-xxxxxx. Join it
// from your phone and pick the network there. This password protects that
// hotspot (8+ characters) so nobody nearby can reconfigure the unit.
#define PORTAL_PASSWORD "change-me-please"

// Optional: a network to try first on boot (2.4 GHz only), before the
// hotspot. Leave WIFI_SSID "" to use the hotspot only.
#define WIFI_SSID     ""
#define WIFI_PASSWORD ""

// platform.tuya.com -> Cloud -> your project -> Overview
#define TUYA_CLIENT_ID "YOUR_TUYA_CLIENT_ID"
#define TUYA_SECRET    "YOUR_TUYA_SECRET"
// platform.tuya.com -> Cloud -> your project -> Devices
#define TUYA_DEVICE_ID "YOUR_BULB_DEVICE_ID"
// Must match your project's data center, e.g. openapi.tuyaus.com,
// openapi.tuyaeu.com, openapi.tuyain.com, openapi-sg.iotbing.com
#define TUYA_HOST      "openapi.tuyaus.com"

// Somnus API and this unit's key. These are only the starting values: both
// can be changed later from the setup hotspot, and what is saved there wins.
// The hosted server works from any network; a laptop on the LAN
// (http://192.168.x.x:4000) works too, but never `localhost`.
#define API_URL          "https://somnus-api-kx6h.onrender.com"
// Shown once in the app when you add this unit on the Device tab.
#define API_DEVICE_TOKEN "room-xxxxxx.paste-the-key-here"

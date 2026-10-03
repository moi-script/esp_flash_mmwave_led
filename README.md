# Somnus room unit — XIAO ESP32-C6

A DFRobot SEN0395 24 GHz presence radar and a Tuya Wi-Fi bulb. The radar
switches the light by itself, and the unit reports presence and the bulb's
state to the Somnus API over WiFi. No phone needed.

## Setup

**Arduino IDE settings:** board **XIAO_ESP32C6** (esp32 core 3.x), and
**Tools → Partition Scheme → Huge APP (3MB No OTA/1MB SPIFFS)**. The default
scheme leaves the sketch at 96% of its space. Libraries: **ArduinoJson 7.x**
and **WiFiManager 2.0.x** (tzapu).

1. `copy secrets.example.h secrets.h` and fill in:
   - the Tuya client id, secret, bulb device id and data-centre host
   - `PORTAL_PASSWORD`: a password of your own (8+ characters) for the setup
     hotspot
   - `API_URL`: the hosted server, e.g. `https://somnus-api.onrender.com`
2. Flash, and read the id from the boot line:
   `[BOOT] Somnus room unit fw0.3.0  id=room-7c1a02`
3. In the app, Device tab → **Add a band or room unit** → enter that id.
   It shows a key once. Keep it for step 5.
4. On your phone, join the Wi-Fi network **Somnus-room-7c1a02** with the
   `PORTAL_PASSWORD`. A setup page opens (if not, browse to `192.168.4.1`).
5. **Configure WiFi** → pick the building's network and type its password.
   Paste the key from step 3 into **Device key**. Save.

The unit joins that network and starts reporting. The network, server
address and key are saved on the unit and survive reboots. `secrets.h` only
provides the first values. It is gitignored; keep it out of anything you share.

## Moving to another building

Nothing to reflash. When the saved network is out of reach for a minute, the
unit opens the **Somnus-room-xxxxxx** hotspot again: join it and pick the new
network. To open it on purpose, hold **BOOT** for 3 seconds or type `setup`
in the Serial Monitor. The radar keeps switching the light the whole time.

The hotspot only exists while the unit has no network or you asked for it.
The ESP32-C6 joins 2.4 GHz Wi-Fi only; 5 GHz-only networks will not appear
in the list.

## What it sends

Same envelope as the band (`v`, `t`, `id`, `seq`, `ms`), posted in batches to
`POST /api/v1/ingest` every 5 s, and at once when presence changes.

| Frame | When |
|---|---|
| `presence` `{present}` | on every change, and every 60 s as a heartbeat |
| `light` `{on, mode, bright, temp, color, source}` | after every change it makes, and when the 30 s Tuya poll finds the bulb changed elsewhere (`source: "external"`) |
| `status` `{sensors:{sen0395, bulb}, config:{auto, offDelayMs}}` | on boot, on request, when the radar or bulb stops or starts answering |
| `ack` | after every app command |

`seq` never repeats, even across reboots. A boot counter kept in flash gives
each boot its own block of numbers, because the server drops any frame whose
`seq` it has already stored.

Up to 64 frames wait in RAM while WiFi is down. Past that the oldest go.

## Commands from the app

The unit checks `GET /api/v1/commands/pending` every 5 s.

| Command | Effect |
|---|---|
| `{"cmd":"light","on":true,"bright":30,"temp":0}` | white light; any of `on`, `bright` 1–100, `temp` 0 warm – 100 cool |
| `{"cmd":"light","color":{"h":20,"s":90,"v":30}}` | colour; h 0–360, s 0–100, v 1–100 |
| `{"cmd":"auto","on":false}` | stop or start the radar switching the light |
| `{"cmd":"status"}` | send a status frame |

## Serial Monitor

115200 baud, Newline. `help` lists everything: `on`, `off`, `toggle`,
`bright 40`, `temp 0`, `color 30 100 25`, `red`, `auto off`, `radarlog on`,
`setup` (open the hotspot), `forget wifi` (erase the saved network), `status`
(network, server and sensor state).

To check that the radar really drives the bulb:

- `selftest` checks secrets, WiFi, clock, radar UART, Tuya token, that the bulb
  is in the cloud project and online, and blinks it ON then OFF. It prints
  PASS/FAIL for each step, and a hint when a Tuya call fails.
- A `[diag]` line every 10 s shows the radar pin, UART, presence, the bulb's
  state and the auto-off countdown. `diag off` hides it and the per-request logs.
- `dps` lists the bulb's Tuya data points. On/off needs `switch_led`.

## Limits

The SEN0395 reports presence only: no breathing, heart rate or distance. It
senses the whole room, not the bed, and can briefly lose someone lying very
still (the app ignores absences under 2 minutes). The radar counts as
"working" in status frames when its UART has spoken in the last 30 s.

## Wiring

| SEN0395 | XIAO ESP32-C6 |
|---|---|
| VIN | 5V |
| GND | GND |
| IO1 | D1 (presence, HIGH = someone there) |
| TX | D7 (XIAO RX) |
| RX | D6 (XIAO TX) |

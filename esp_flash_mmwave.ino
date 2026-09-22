/*
 * Somnus room unit
 * XIAO ESP32-C6  +  DFRobot mmWave Radar 24GHz (SEN0395)  +  Tuya Wi-Fi bulb
 *
 * - The radar is wired to the XIAO (presence output pin + UART).
 * - The bulb is Wi-Fi only. The ESP32 controls it through the Tuya Cloud
 *   OpenAPI (https://developer.tuya.com/en/docs/cloud/) over HTTPS.
 * - Presence detected -> bulb ON. Nobody for OFF_DELAY_MS -> bulb OFF.
 * - Reports presence and the bulb's state to the Somnus API over WiFi, and
 *   takes light commands queued from the app. No phone needed.
 * - No WiFi details in the code: the unit opens a setup hotspot
 *   (Somnus-room-xxxxxx) when it has no network, where the network, server
 *   address and device key are set from a phone. Hold BOOT 3 s to reopen it.
 * - Serial Monitor commands still work (115200 baud, Newline). Type "help".
 *
 * WIRING (radar SEN0395 -> XIAO ESP32-C6)
 *   VIN  -> 5V
 *   GND  -> GND
 *   IO1  -> D1  (presence output, HIGH = someone detected)
 *   TX   -> D7  (XIAO RX)
 *   RX   -> D6  (XIAO TX)
 *
 * Board: "XIAO_ESP32C6" (esp32 by Espressif, core 3.x).
 * Libraries: ArduinoJson 7.x, WiFiManager 2.0.x (tzapu).
 * Keys: copy secrets.example.h to secrets.h and fill it in.
 */

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <WiFiManager.h>
#include <ArduinoJson.h>
#include <sys/time.h>
#include "mbedtls/md.h"
#include "secrets.h"

#define ROOM_FW_VERSION "0.3.0"
static const uint8_t PAYLOAD_VERSION = 2;

// ============================ TIMING ================================
const unsigned long OFF_DELAY_MS     = 30000;  // light off after 30 s with nobody detected
const unsigned long HEARTBEAT_MS     = 60000;  // presence frame even when nothing changed
const unsigned long FLUSH_MS         = 5000;   // post buffered frames
const unsigned long COMMAND_POLL_MS  = 5000;   // ask the API for queued commands
const unsigned long TUYA_POLL_MS     = 30000;  // read the bulb's real state
const unsigned long WIFI_RETRY_MS    = 10000;
const unsigned long PORTAL_AFTER_MS  = 60000;  // open the setup hotspot after this long offline
const unsigned long BUTTON_HOLD_MS   = 3000;   // hold BOOT this long to open it on purpose
const unsigned long RADAR_UART_OK_MS = 30000;  // radar counts as present if it spoke this recently
// ====================================================================

const int RADAR_OUT_PIN = D1;
const int RADAR_RX_PIN  = D7;   // XIAO RX <- radar TX
const int RADAR_TX_PIN  = D6;   // XIAO TX -> radar RX
const int BOOT_BUTTON_PIN = 9;  // the XIAO ESP32-C6 BOOT button, LOW while pressed

// --------------------------- state ----------------------------------

char deviceId[20] = {0};

// Where to send frames and which key to use. Start from secrets.h, then
// whatever was last saved from the setup hotspot takes over.
String apiUrl = API_URL;
String apiToken = API_DEVICE_TOKEN;

WiFiManager wm;
WiFiManagerParameter paramUrl("api_url", "Somnus server address", "", 120);
WiFiManagerParameter paramToken("api_token", "Device key (leave empty to keep the current one)", "", 120);
char portalName[32] = {0};
unsigned long offlineSinceMs = 0;

// seq must never repeat for this device, even across reboots: the server
// drops a frame whose {deviceId, seq} it already has. A boot counter kept in
// flash gives every boot its own block of ten million numbers.
uint64_t seq = 0;

String accessToken;
unsigned long tokenExpiresAt = 0;

bool autoMode = true;
bool presence = false;
bool radarLog = false;
unsigned long lastPresenceMs = 0;
int lastRawPresence = LOW;
unsigned long rawChangedMs = 0;
unsigned long lastRadarUartMs = 0;

bool bulbReachable = false;
bool lastStatusRadar = false;
bool lastStatusBulb = false;

/** What the bulb is doing, in percentages (Tuya uses 10..1000). */
struct LightState {
  bool known = false;
  bool on = false;
  bool colour = false;
  int bright = 100;  // white mode, 1..100
  int temp = 0;      // white mode, 0 warm .. 100 cool
  int h = 0, s = 0, v = 100;  // colour mode
};
LightState bulb;

/** A requested change. -1 / false means "leave as is". */
struct LightChange {
  int on = -1;
  int bright = -1;
  int temp = -1;
  bool hasColor = false;
  int h = 0, s = 0, v = 100;
};

// Outgoing frames wait here until the API takes them. When WiFi is down for
// long, the oldest are dropped rather than running out of memory.
const int RING_SIZE = 64;
String ring[RING_SIZE];
int ringHead = 0;   // oldest
int ringCount = 0;
bool flushNow = false;

// ----------------------------- helpers ------------------------------

String toHex(const uint8_t* buf, size_t len, bool upper) {
  const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
  String s;
  s.reserve(len * 2);
  for (size_t i = 0; i < len; i++) {
    s += digits[buf[i] >> 4];
    s += digits[buf[i] & 0x0F];
  }
  return s;
}

String sha256Hex(const String& data) {
  uint8_t out[32];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
             (const unsigned char*)data.c_str(), data.length(), out);
  return toHex(out, sizeof(out), false);
}

String hmacSha256Upper(const String& key, const String& data) {
  uint8_t out[32];
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                  (const unsigned char*)key.c_str(), key.length(),
                  (const unsigned char*)data.c_str(), data.length(), out);
  return toHex(out, sizeof(out), true);
}

String timestampMs() {
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  char buf[24];
  snprintf(buf, sizeof(buf), "%llu", (unsigned long long)tv.tv_sec * 1000ULL + tv.tv_usec / 1000);
  return String(buf);
}

bool clockValid() { return time(nullptr) > 1700000000; }

void makeDeviceId() {
  uint64_t mac = ESP.getEfuseMac();
  snprintf(deviceId, sizeof(deviceId), "room-%02x%02x%02x",
           (uint8_t)(mac >> 24), (uint8_t)(mac >> 32), (uint8_t)(mac >> 40));
}

void initSeq() {
  Preferences prefs;
  prefs.begin("room", false);
  uint32_t boot = prefs.getUInt("boot", 0) + 1;
  prefs.putUInt("boot", boot);
  prefs.end();
  seq = (uint64_t)boot * 10000000ULL;
}

// ----------------------------- frames -------------------------------

void envelope(JsonDocument& doc, const char* type) {
  doc["v"] = PAYLOAD_VERSION;
  doc["t"] = type;
  doc["id"] = deviceId;
  doc["seq"] = ++seq;
  doc["ms"] = (uint32_t)millis();
}

void enqueue(JsonDocument& doc) {
  String line;
  serializeJson(doc, line);
  if (ringCount == RING_SIZE) {  // full: drop the oldest
    ringHead = (ringHead + 1) % RING_SIZE;
    ringCount--;
  }
  ring[(ringHead + ringCount) % RING_SIZE] = line;
  ringCount++;
}

void sendPresence() {
  JsonDocument doc;
  envelope(doc, "presence");
  doc["present"] = presence;
  enqueue(doc);
}

void sendLight(const char* source) {
  if (!bulb.known) return;
  JsonDocument doc;
  envelope(doc, "light");
  doc["on"] = bulb.on;
  doc["mode"] = bulb.colour ? "colour" : "white";
  if (bulb.colour) {
    doc["bright"] = nullptr;
    doc["temp"] = nullptr;
    JsonObject c = doc["color"].to<JsonObject>();
    c["h"] = bulb.h;
    c["s"] = bulb.s;
    c["v"] = bulb.v;
  } else {
    doc["bright"] = bulb.bright;
    doc["temp"] = bulb.temp;
    doc["color"] = nullptr;
  }
  doc["source"] = source;
  enqueue(doc);
  flushNow = true;
}

bool radarOk() { return lastRadarUartMs != 0 && millis() - lastRadarUartMs < RADAR_UART_OK_MS; }

void sendStatus() {
  JsonDocument doc;
  envelope(doc, "status");
  bool radar = radarOk();
  doc["fw"] = ROOM_FW_VERSION;
  doc["transport"] = "wifi";
  doc["online"] = (radar ? 1 : 0) + (bulbReachable ? 1 : 0);
  doc["total"] = 2;
  JsonObject sensors = doc["sensors"].to<JsonObject>();
  sensors["sen0395"] = radar;
  sensors["bulb"] = bulbReachable;
  JsonObject config = doc["config"].to<JsonObject>();
  config["auto"] = autoMode;
  config["offDelayMs"] = OFF_DELAY_MS;
  enqueue(doc);
  lastStatusRadar = radar;
  lastStatusBulb = bulbReachable;
  flushNow = true;
}

void sendAck(const char* cmd, bool ok, const String& detail) {
  JsonDocument doc;
  envelope(doc, "ack");
  doc["cmd"] = cmd;
  doc["ok"] = ok;
  if (detail.length() > 0) doc["detail"] = detail;
  enqueue(doc);
  flushNow = true;
}

// ---------------------------- Somnus API -----------------------------

/** One request to the API as this device. Returns the HTTP status, or <= 0. */
int apiRequest(const char* method, const String& path, const String& body, String* response) {
  String url = apiUrl + "/api/v1" + path;
  HTTPClient http;
  WiFiClient plain;
  WiFiClientSecure secure;
  bool ok;
  if (url.startsWith("https://")) {
    secure.setInsecure();
    ok = http.begin(secure, url);
  } else {
    ok = http.begin(plain, url);
  }
  if (!ok) return -1;
  // A TLS handshake to a hosted server takes far longer than plain HTTP on
  // the LAN; too short a timeout fails every request.
  http.setTimeout(10000);
  http.addHeader("Authorization", String("Bearer ") + apiToken);
  http.addHeader("Content-Type", "application/json");
  int code = strcmp(method, "POST") == 0 ? http.POST(body) : http.GET();
  if (response && code > 0) *response = http.getString();
  http.end();
  return code;
}

void flushFrames() {
  if (ringCount == 0 || WiFi.status() != WL_CONNECTED) return;
  int n = ringCount;
  String body = "{\"frames\":[";
  for (int i = 0; i < n; i++) {
    if (i) body += ',';
    body += ring[(ringHead + i) % RING_SIZE];
  }
  body += "]}";

  int code = apiRequest("POST", "/ingest", body, nullptr);
  if (code >= 200 && code < 300) {
    ringHead = (ringHead + n) % RING_SIZE;
    ringCount -= n;
  } else if (code == 400) {
    // The server will never accept this batch; keeping it would block the
    // queue forever.
    Serial.println("[api ] batch rejected as invalid, dropping it");
    ringHead = (ringHead + n) % RING_SIZE;
    ringCount -= n;
  } else if (code == 401) {
    Serial.println("[api ] key refused. Set the device key from the setup hotspot (type 'setup').");
  } else {
    Serial.printf("[api ] ingest failed (%d), keeping %d frames\n", code, ringCount);
  }
}

// ---------------------------- Tuya Cloud -----------------------------

// Signs and sends a request as described in Tuya's "Sign requests" docs.
String tuyaRequest(const String& method, const String& path, const String& body, bool withToken) {
  String t = timestampMs();
  String stringToSign = method + "\n" + sha256Hex(body) + "\n" + "\n" + path;
  String signStr = String(TUYA_CLIENT_ID) + (withToken ? accessToken : "") + t + stringToSign;
  String sign = hmacSha256Upper(TUYA_SECRET, signStr);

  WiFiClientSecure client;
  client.setInsecure();  // skips certificate validation
  HTTPClient http;
  http.begin(client, String("https://") + TUYA_HOST + path);
  http.setTimeout(5000);
  http.addHeader("client_id", TUYA_CLIENT_ID);
  http.addHeader("sign", sign);
  http.addHeader("t", t);
  http.addHeader("sign_method", "HMAC-SHA256");
  if (withToken) http.addHeader("access_token", accessToken);
  http.addHeader("Content-Type", "application/json");

  int code = (method == "POST") ? http.POST(body) : http.GET();
  String resp = code > 0 ? http.getString() : String("HTTP error ") + code;
  http.end();
  return resp;
}

bool tuyaGetToken() {
  JsonDocument doc;
  String resp = tuyaRequest("GET", "/v1.0/token?grant_type=1", "", false);
  if (deserializeJson(doc, resp) || !doc["success"].as<bool>()) {
    Serial.println("[tuya] token failed: " + resp);
    return false;
  }
  accessToken = doc["result"]["access_token"].as<String>();
  long expire = doc["result"]["expire_time"].as<long>();  // seconds
  tokenExpiresAt = millis() + (unsigned long)(expire - 60) * 1000UL;
  Serial.println("[tuya] got access token");
  return true;
}

bool tuyaEnsureToken() {
  if (accessToken.length() == 0 || (long)(millis() - tokenExpiresAt) >= 0) return tuyaGetToken();
  return true;
}

/** Tuya call with one retry on an expired token. Fills `doc` with the reply. */
bool tuyaCall(const String& method, const String& path, const String& body, JsonDocument& doc) {
  if (WiFi.status() != WL_CONNECTED || !clockValid() || !tuyaEnsureToken()) return false;
  String resp = tuyaRequest(method, path, body, true);
  if (deserializeJson(doc, resp)) return false;
  int code = doc["code"] | 0;
  if (code == 1010 || code == 1011) {  // token invalid/expired
    if (!tuyaGetToken()) return false;
    resp = tuyaRequest(method, path, body, true);
    if (deserializeJson(doc, resp)) return false;
  }
  bool ok = doc["success"].as<bool>();
  if (!ok) Serial.println("[tuya] failed: " + resp);
  return ok;
}

/**
 * Apply a change to the bulb. On success the known state is updated and a
 * light frame goes to the API tagged with who asked.
 */
bool setLight(const LightChange& c, const char* source) {
  JsonDocument cmds;
  JsonArray list = cmds["commands"].to<JsonArray>();
  auto add = [&](const char* code) -> JsonObject {
    JsonObject o = list.add<JsonObject>();
    o["code"] = code;
    return o;
  };

  bool turningOn = c.on == 1 || c.bright >= 0 || c.temp >= 0 || c.hasColor;
  if (c.on == 0) add("switch_led")["value"] = false;
  else if (turningOn) add("switch_led")["value"] = true;

  if (c.hasColor) {
    add("work_mode")["value"] = "colour";
    JsonObject colour = add("colour_data_v2")["value"].to<JsonObject>();
    colour["h"] = constrain(c.h, 0, 360);
    colour["s"] = constrain(c.s, 0, 100) * 10;
    colour["v"] = constrain(c.v, 1, 100) * 10;
  } else if (c.bright >= 0 || c.temp >= 0) {
    add("work_mode")["value"] = "white";
    if (c.bright >= 0) add("bright_value_v2")["value"] = map(constrain(c.bright, 1, 100), 1, 100, 10, 1000);
    if (c.temp >= 0) add("temp_value_v2")["value"] = constrain(c.temp, 0, 100) * 10;
  }

  String body;
  serializeJson(cmds, body);
  JsonDocument reply;
  bool ok = tuyaCall("POST", String("/v1.0/iot-03/devices/") + TUYA_DEVICE_ID + "/commands", body, reply);
  bulbReachable = ok;
  if (!ok) return false;

  bulb.known = true;
  if (c.on == 0) bulb.on = false;
  else if (turningOn) bulb.on = true;
  if (c.hasColor) {
    bulb.colour = true;
    bulb.h = constrain(c.h, 0, 360);
    bulb.s = constrain(c.s, 0, 100);
    bulb.v = constrain(c.v, 1, 100);
  } else if (c.bright >= 0 || c.temp >= 0) {
    bulb.colour = false;
    if (c.bright >= 0) bulb.bright = constrain(c.bright, 1, 100);
    if (c.temp >= 0) bulb.temp = constrain(c.temp, 0, 100);
  }
  Serial.printf("[led ] %s (%s)\n", bulb.on ? "on" : "off", source);
  sendLight(source);
  return true;
}

bool sameLight(const LightState& a, const LightState& b) {
  if (a.known != b.known) return false;
  if (!a.on && !b.on) return true;
  if (a.on != b.on || a.colour != b.colour) return false;
  if (a.colour) return a.h == b.h && a.s == b.s && a.v == b.v;
  return a.bright == b.bright && a.temp == b.temp;
}

/**
 * Read what the bulb is really doing. If it differs from what we last set,
 * someone changed it elsewhere - the Smart Life app, a wall switch - and the
 * API hears about it as an external change.
 */
void pollBulb() {
  JsonDocument doc;
  bool ok = tuyaCall("GET", String("/v1.0/iot-03/devices/") + TUYA_DEVICE_ID + "/status", "", doc);
  bulbReachable = ok;
  if (!ok) return;

  LightState now = bulb;
  now.known = true;
  for (JsonObject dp : doc["result"].as<JsonArray>()) {
    const char* code = dp["code"] | "";
    JsonVariant value = dp["value"];
    if (!strcmp(code, "switch_led")) now.on = value.as<bool>();
    else if (!strcmp(code, "work_mode")) now.colour = !strcmp(value | "white", "colour");
    else if (!strcmp(code, "bright_value_v2")) now.bright = constrain(map(value.as<int>(), 10, 1000, 1, 100), 1, 100);
    else if (!strcmp(code, "temp_value_v2")) now.temp = constrain(value.as<int>() / 10, 0, 100);
    else if (!strcmp(code, "colour_data_v2")) {
      // Some bulbs report this as an object, others as a JSON string.
      JsonDocument colour;
      if (value.is<const char*>()) deserializeJson(colour, value.as<const char*>());
      else colour.set(value);
      now.h = constrain(colour["h"] | 0, 0, 360);
      now.s = constrain((colour["s"] | 0) / 10, 0, 100);
      now.v = constrain((colour["v"] | 1000) / 10, 1, 100);
    }
  }

  if (!sameLight(now, bulb)) {
    bulb = now;
    Serial.printf("[led ] bulb reports %s, changed outside this unit\n", bulb.on ? "on" : "off");
    sendLight("external");
  }
}

// ------------------------------- Radar --------------------------------

void updateRadar() {
  int raw = digitalRead(RADAR_OUT_PIN);
  if (raw != lastRawPresence) {
    lastRawPresence = raw;
    rawChangedMs = millis();
  }
  if (millis() - rawChangedMs > 200) {
    bool now = (raw == HIGH);
    if (now != presence) {
      presence = now;
      Serial.println(presence ? "[radar] presence detected" : "[radar] no presence");
      sendPresence();
      flushNow = true;
    }
  }
  if (presence) lastPresenceMs = millis();

  while (Serial1.available()) {
    String line = Serial1.readStringUntil('\n');
    lastRadarUartMs = millis();
    if (radarLog) Serial.println("[radar uart] " + line);
  }

  if (!autoMode) return;
  static unsigned long lastAutoTry = 0;
  if (millis() - lastAutoTry < 5000) return;  // don't spam the cloud if a request fails
  if (presence && !(bulb.known && bulb.on)) {
    lastAutoTry = millis();
    LightChange c;
    c.on = 1;
    setLight(c, "auto");
  } else if (!presence && bulb.on && millis() - lastPresenceMs > OFF_DELAY_MS) {
    lastAutoTry = millis();
    LightChange c;
    c.on = 0;
    setLight(c, "auto");
  }
}

// ------------------------- Commands from the app -----------------------

bool runCommand(JsonObject command, String& detail) {
  const char* cmd = command["cmd"] | "";
  if (!strcmp(cmd, "light")) {
    LightChange c;
    if (command["on"].is<bool>()) c.on = command["on"].as<bool>() ? 1 : 0;
    if (command["bright"].is<int>()) c.bright = command["bright"];
    if (command["temp"].is<int>()) c.temp = command["temp"];
    if (command["color"].is<JsonObject>()) {
      c.hasColor = true;
      c.h = command["color"]["h"] | 0;
      c.s = command["color"]["s"] | 100;
      c.v = command["color"]["v"] | 100;
    }
    bool ok = setLight(c, "app");
    if (!ok) detail = "the bulb did not answer";
    return ok;
  }
  if (!strcmp(cmd, "auto")) {
    autoMode = command["on"] | true;
    detail = autoMode ? "on" : "off";
    Serial.printf("[auto] %s (app)\n", detail.c_str());
    sendStatus();
    return true;
  }
  if (!strcmp(cmd, "status")) {
    sendStatus();
    return true;
  }
  detail = "not a room unit command";
  return false;
}

void pollCommands() {
  if (WiFi.status() != WL_CONNECTED) return;
  String resp;
  int code = apiRequest("GET", "/commands/pending", "", &resp);
  if (code != 200) return;

  JsonDocument list;
  if (deserializeJson(list, resp)) return;
  for (JsonObject queued : list.as<JsonArray>()) {
    String id = queued["id"] | "";
    JsonObject command = queued["command"];
    const char* cmd = command["cmd"] | "?";
    String detail;
    bool ok = runCommand(command, detail);

    JsonDocument ack;
    ack["ok"] = ok;
    if (detail.length() > 0) ack["detail"] = detail;
    String body;
    serializeJson(ack, body);
    apiRequest("POST", "/commands/" + id + "/ack", body, nullptr);
    sendAck(cmd, ok, detail);
  }
}

// --------------------------- Serial commands --------------------------

void printHelp() {
  Serial.println(F(
    "Commands:\n"
    "  on | off | toggle\n"
    "  bright <1-100>              white brightness\n"
    "  temp <0-100>                0 = warm, 100 = cool\n"
    "  color <hue 0-360> <sat 0-100> <bright 1-100>\n"
    "  red | green | blue | white\n"
    "  auto on | auto off          radar controls the light\n"
    "  radarlog on | radarlog off  show radar UART output\n"
    "  setup                       open the setup hotspot (WiFi, server, key)\n"
    "  forget wifi                 erase the saved network, then restart\n"
    "  status"));
}

void handleCommand(String cmd) {
  cmd.trim();
  cmd.toLowerCase();
  if (cmd.length() == 0) return;

  int a = 0, b = 0, c = 0;
  LightChange change;
  bool light = true;
  if (cmd == "help") { printHelp(); light = false; }
  else if (cmd == "on") change.on = 1;
  else if (cmd == "off") change.on = 0;
  else if (cmd == "toggle") change.on = bulb.on ? 0 : 1;
  else if (sscanf(cmd.c_str(), "bright %d", &a) == 1) change.bright = a;
  else if (sscanf(cmd.c_str(), "temp %d", &a) == 1) change.temp = a;
  else if (sscanf(cmd.c_str(), "color %d %d %d", &a, &b, &c) == 3) {
    change.hasColor = true; change.h = a; change.s = b; change.v = c;
  }
  else if (cmd == "red") { change.hasColor = true; change.h = 0; change.s = 100; change.v = 100; }
  else if (cmd == "green") { change.hasColor = true; change.h = 120; change.s = 100; change.v = 100; }
  else if (cmd == "blue") { change.hasColor = true; change.h = 240; change.s = 100; change.v = 100; }
  else if (cmd == "white") change.bright = 100;
  else {
    light = false;
    if (cmd == "auto on" || cmd == "auto off") {
      autoMode = cmd == "auto on";
      Serial.printf("[auto] %s\n", autoMode ? "ON" : "OFF");
      sendStatus();
    }
    else if (cmd == "setup") startPortal();
    else if (cmd == "forget wifi") {
      Serial.println("[wifi] saved network erased, restarting");
      wm.resetSettings();
      delay(200);
      ESP.restart();
    }
    else if (cmd == "radarlog on") radarLog = true;
    else if (cmd == "radarlog off") radarLog = false;
    else if (cmd == "status") {
      Serial.printf("id=%s wifi=%s%s presence=%d light=%d auto=%d radar=%d bulb=%d queued=%d\n",
                    deviceId,
                    WiFi.status() == WL_CONNECTED ? WiFi.SSID().c_str() : "disconnected",
                    wm.getConfigPortalActive() ? " (setup hotspot open)" : "",
                    presence, bulb.on, autoMode, radarOk(), bulbReachable, ringCount);
      Serial.printf("server=%s\n", apiUrl.c_str());
    } else {
      Serial.println("Unknown command. Type 'help'.");
    }
  }
  if (light && !setLight(change, "serial")) Serial.println("[led ] the bulb did not answer");
}

// ------------------------- WiFi and setup hotspot ----------------------

void loadSettings() {
  Preferences prefs;
  prefs.begin("roomcfg", true);
  apiUrl = prefs.getString("url", API_URL);
  apiToken = prefs.getString("token", API_DEVICE_TOKEN);
  prefs.end();
  // Show the current address in the form, so it only needs typing to change.
  paramUrl.setValue(apiUrl.c_str(), 120);
}

/** Called when the setup page is saved. Empty fields keep what is there. */
void saveSettings() {
  String url = paramUrl.getValue();
  String token = paramToken.getValue();
  url.trim();
  token.trim();
  while (url.endsWith("/")) url.remove(url.length() - 1);

  Preferences prefs;
  prefs.begin("roomcfg", false);
  if (url.startsWith("http://") || url.startsWith("https://")) {
    apiUrl = url;
    prefs.putString("url", apiUrl);
  } else if (url.length() > 0) {
    Serial.println("[wifi] server address must start with http:// or https://, kept the old one");
  }
  if (token.length() > 0) {
    apiToken = token;
    prefs.putString("token", apiToken);
  }
  prefs.end();
  paramToken.setValue("", 120);  // never echo the key back into the form
  Serial.printf("[wifi] settings saved, server %s\n", apiUrl.c_str());
}

/**
 * Open the setup hotspot. Non-blocking: the radar keeps switching the light
 * and frames keep queueing while someone is on the setup page.
 */
void startPortal() {
  if (wm.getConfigPortalActive()) return;
  Serial.printf("[wifi] setup hotspot open: join \"%s\" and follow the page\n", portalName);
  wm.startConfigPortal(portalName, PORTAL_PASSWORD);
}

void setupWifi() {
  snprintf(portalName, sizeof(portalName), "Somnus-%s", deviceId);
  loadSettings();

  WiFi.mode(WIFI_STA);
  wm.setTitle("Somnus room unit");
  wm.addParameter(&paramUrl);
  wm.addParameter(&paramToken);
  wm.setSaveParamsCallback(saveSettings);
  wm.setConfigPortalBlocking(false);
  wm.setBreakAfterConfig(true);     // keep the fields even if WiFi fails
  wm.setConnectTimeout(20);
  wm.setDebugOutput(false);

  Serial.println("[wifi] connecting to the saved network");
  // Joins the saved network, or opens the setup hotspot and returns at once.
  if (wm.autoConnect(portalName, PORTAL_PASSWORD)) {
    Serial.println("[wifi] connected, IP " + WiFi.localIP().toString());
  } else {
    Serial.printf("[wifi] no saved network in reach. Join \"%s\" to set one up\n", portalName);
  }
}

/** Keeps WiFi alive, and opens the hotspot when it has been gone a while. */
void handleWifi(unsigned long now) {
  wm.process();

  if (WiFi.status() == WL_CONNECTED) {
    offlineSinceMs = 0;
    return;
  }
  if (offlineSinceMs == 0) offlineSinceMs = now;

  static unsigned long lastWifiTry = 0;
  if (!wm.getConfigPortalActive() && now - lastWifiTry > WIFI_RETRY_MS) {
    lastWifiTry = now;
    WiFi.reconnect();
  }
  // A new building: the saved network is not coming back.
  if (now - offlineSinceMs > PORTAL_AFTER_MS) startPortal();
}

/** Hold BOOT for 3 s to open the setup hotspot at any time. */
void handleButton(unsigned long now) {
  static unsigned long pressedSince = 0;
  static bool fired = false;  // once per hold, however long it lasts
  if (digitalRead(BOOT_BUTTON_PIN) == LOW) {
    if (pressedSince == 0) pressedSince = now;
    if (!fired && now - pressedSince > BUTTON_HOLD_MS) {
      fired = true;
      startPortal();
    }
  } else {
    pressedSince = 0;
    fired = false;
  }
}

// ------------------------------- Setup --------------------------------

void setup() {
  Serial.begin(115200);
  delay(1500);

  makeDeviceId();
  initSeq();
  Serial.printf("[BOOT] Somnus room unit fw%s  id=%s\n", ROOM_FW_VERSION, deviceId);

  pinMode(RADAR_OUT_PIN, INPUT_PULLDOWN);
  Serial1.begin(115200, SERIAL_8N1, RADAR_RX_PIN, RADAR_TX_PIN);
  Serial1.setTimeout(20);

  pinMode(BOOT_BUTTON_PIN, INPUT_PULLUP);
  // The radar and Serial commands work offline; WiFi is joined, or the setup
  // hotspot opened, without holding anything else up.
  setupWifi();

  // Tuya signatures need the real time.
  configTime(0, 0, "pool.ntp.org", "time.google.com");
  for (int i = 0; i < 20 && !clockValid(); i++) delay(500);

  if (WiFi.status() == WL_CONNECTED && clockValid()) {
    tuyaGetToken();
    pollBulb();  // learn the bulb's state before the first report
  }
  sendStatus();
  sendPresence();
  printHelp();
}

void loop() {
  unsigned long now = millis();

  handleWifi(now);
  handleButton(now);

  if (Serial.available()) handleCommand(Serial.readStringUntil('\n'));

  updateRadar();

  static unsigned long lastHeartbeat = 0;
  if (now - lastHeartbeat >= HEARTBEAT_MS) {
    lastHeartbeat = now;
    sendPresence();
  }

  static unsigned long lastTuyaPoll = 0;
  if (now - lastTuyaPoll >= TUYA_POLL_MS) {
    lastTuyaPoll = now;
    pollBulb();
  }

  // A sensor dropping out or coming back is worth a fresh status frame.
  if (radarOk() != lastStatusRadar || bulbReachable != lastStatusBulb) sendStatus();

  static unsigned long lastFlush = 0;
  if (flushNow || now - lastFlush >= FLUSH_MS) {
    lastFlush = now;
    flushNow = false;
    flushFrames();
  }

  static unsigned long lastCommandPoll = 0;
  if (now - lastCommandPoll >= COMMAND_POLL_MS) {
    lastCommandPoll = now;
    pollCommands();
  }

  delay(20);
}

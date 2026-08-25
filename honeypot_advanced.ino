/*
  ESP32 LAN Honeypot (Final)
  Fake services: SSH(22), Telnet(23), HTTP admin(80), SMB(445), RDP(3389)

  v2 additions:
  - SSH: realistic OpenSSH banner + best-effort HASSH-style client
    fingerprint (kex/host-key/encryption algorithm lists) parsed from the
    unencrypted SSH_MSG_KEXINIT packet. No real login is ever captured -
    SSH encrypts everything after this point, so the connection is closed
    once the fingerprint (or raw garbage, for non-SSH scanners) is captured.
  - Telnet: full interactive session. Accepts a login after 1-2 tries (or
    immediately for common weak creds), then drops the attacker into a
    fake BusyBox shell with canned responses to common commands, logging
    every command they type. Implemented as a small non-blocking
    per-connection state machine so a slow interactive attacker never
    stalls the other fake services.
  - HTTP: cosmetic realism (Server header, firmware-style copy).
  - SMB/RDP: unchanged, banner/raw-capture only.
*/

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <time.h>

// ---------- CONFIG ----------
const char* WIFI_SSID     = "guesto";
const char* WIFI_PASSWORD = "i4bg4hxgyhf8k";
const char* WORKER_URL = "https://honeypot-worker.mara-75f.workers.dev/ingest";
const char* DEVICE_LABEL  = "honeypot-esp32-01";

// ---- Pins: VERIFY PER BOARD BEFORE WIRING ----
// Standard ESP32 dev board:   LED_PIN = 2   (active HIGH)
// ESP32-C3 SuperMini:         LED_PIN = 8   (often active LOW — check with a blink test)
// ESP32-CAM:                  avoid GPIO 2/4 (SD card conflict) — use GPIO 33 (onboard red LED,
//                             active LOW) or an external LED on a free pin instead
const int LED_PIN         = 2;      // WROOM onboard LED
const bool LED_ACTIVE_LOW  = false;  // WROOM LED is active HIGH
const int BUZZER_PIN      = 4;      // unchanged - GPIO4 is safe on WROOM
const int TEST_BUTTON_PIN = 13;     // moved off GPIO7 - see note below


// Behavior
const int READ_TIMEOUT_MS   = 300;
const int HEADER_SEARCH_MAX = 1024; // room for real browser/tool headers
const int MAX_CAPTURE_BYTES = 384;  // cap on what actually gets logged upstream
// -----------------------------

WiFiServer sshServer(22);
WiFiServer telnetServer(23);
WiFiServer httpServer(80);
WiFiServer smbServer(445);
WiFiServer rdpServer(3389);

unsigned long alarmStartTime = 0;
bool alarmActive = false;

bool lastButtonState = HIGH;
unsigned long lastButtonPress = 0;

// ---------- Type definitions ----------
// Declared here, before any function bodies, because Arduino's IDE
// auto-generates function prototypes and inserts them at the very top of
// the file - which breaks for any function whose parameter or return type
// is a struct/enum defined later in the sketch. Declaring the types here
// and hand-writing the prototypes below makes the IDE skip its own
// (broken) auto-generated ones for these functions.
enum TelnetState { TS_WAIT_USER, TS_WAIT_PASS, TS_SHELL };
enum TelnetIacState { IAC_NONE, IAC_CMD, IAC_OPT };

struct SSHKexInfo {
  bool valid = false;
  String kexAlgos;
  String hostKeyAlgos;
  String encC2S;
};

struct TelnetSession {
  WiFiClient client;
  bool active = false;
  String ip;
  TelnetState state = TS_WAIT_USER;
  TelnetIacState iacState = IAC_NONE;
  String lineBuf;
  String user;
  String pass;
  int loginAttempts = 0;
  int commandCount = 0;
  String transcript;
  unsigned long lastActivity = 0;
};

// Manual prototypes for every function whose signature involves one of the
// custom types above.
SSHKexInfo parseSSHKexInit(uint8_t* buf, size_t len);
void telnetSendPrompt(TelnetSession &s);
void appendTranscript(TelnetSession &s, const String &line);
void finishTelnetSession(TelnetSession &s, const String &reason);
void handleTelnetLine(TelnetSession &s, const String &lineIn);
void processTelnetByte(TelnetSession &s, uint8_t c);
void telnetAcceptNewClients();
void telnetServiceSessions();

void ledWrite(bool on) {
  digitalWrite(LED_PIN, (on != LED_ACTIVE_LOW) ? HIGH : LOW);
}

void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(TEST_BUTTON_PIN, INPUT_PULLUP);
  ledWrite(false);
  digitalWrite(BUZZER_PIN, LOW);

  WiFi.mode(WIFI_STA);
  WiFi.setHostname("server1");

  connectWiFi();

  configTime(0, 0, "pool.ntp.org", "time.nist.gov");

  sshServer.begin();
  telnetServer.begin();
  httpServer.begin();
  smbServer.begin();
  rdpServer.begin();

  Serial.println("Honeypot listening on ports 22, 23, 80, 445, 3389");
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) connectWiFi();

  handleSSH();
  telnetAcceptNewClients();
  telnetServiceSessions();
  handleHTTP();
  handleBannerOnly(smbServer, 445, "smb");
  handleBannerOnly(rdpServer, 3389, "rdp");

  checkTestButton();
  updateAlarm();
}

bool wifiStarted = false; // tracks whether we've called WiFi.begin() at least once

void connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) return;

  if (!wifiStarted) {
    // Only the very first attempt sets credentials via begin().
    Serial.print("Connecting to WiFi");
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    wifiStarted = true;
  } else {
    // Subsequent retries reconnect using the already-stored config,
    // instead of calling begin() again — which is what triggers
    // "sta is connecting, cannot set config" if the driver is still
    // mid-attempt from the previous call.
    Serial.print("Retrying WiFi");
    WiFi.reconnect();
  }

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 40) { // ~10s
    delay(250);
    Serial.print(".");
    attempts++;
  }

  Serial.println(
    WiFi.status() == WL_CONNECTED
      ? "\nWiFi connected: " + WiFi.localIP().toString()
      : "\nWiFi connect failed, retrying in loop."
  );
}

void checkTestButton() {
  bool state = digitalRead(TEST_BUTTON_PIN);
  if (state == LOW && lastButtonState == HIGH && (millis() - lastButtonPress > 1000)) {
    lastButtonPress = millis();
    Serial.println("[TEST] Manual trigger button pressed");
    logEvent("192.168.1.199", 22, "ssh", "TEST_EVENT manual_trigger_button");
  }
  lastButtonState = state;
}

// ---------- Non-blocking alarm ----------
void triggerReaction() {
  alarmActive = true;
  alarmStartTime = millis();
  ledWrite(true);
  digitalWrite(BUZZER_PIN, HIGH);
}

void updateAlarm() {
  if (!alarmActive) return;
  unsigned long elapsed = millis() - alarmStartTime;
  if (elapsed >= 150 && elapsed < 300) {
    digitalWrite(BUZZER_PIN, LOW);
  } else if (elapsed >= 300) {
    ledWrite(false);
    digitalWrite(BUZZER_PIN, LOW);
    alarmActive = false;
  }
}

// ---------- SSH fingerprinting ----------
// Realistic banner. We can't go further than this for a real login: the SSH
// protocol switches to encrypted binary traffic immediately after the
// SSH_MSG_KEXINIT exchange, so no genuine SSH client will ever send a
// plaintext username/password here. What we *can* do is parse the client's
// unencrypted KEXINIT packet for its offered algorithms — the same idea
// behind "HASSH" SSH client fingerprinting — which is a solid signal of
// what client/library is connecting even without completing the handshake.
const char* SSH_BANNER          = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5";
const size_t SSH_CAPTURE_BYTES  = 1024;
const int SSH_READ_TIMEOUT_MS   = 500; // KEXINIT can take a beat longer than a bare banner grab

// (SSHKexInfo is declared near the top of the file, with the other types.)

// Best-effort parse of the first SSH_MSG_KEXINIT packet. info.valid stays
// false if the buffer doesn't look like a real KEXINIT (e.g. a non-SSH
// scanner just sent random bytes at port 22) — in that case the caller
// falls back to logging the raw bytes, same as before.
SSHKexInfo parseSSHKexInit(uint8_t* buf, size_t len) {
  SSHKexInfo info;
  if (len < 22) return info; // too short for packet header + msg type + cookie

  size_t pos = 4;              // skip uint32 packet_length
  pos += 1;                    // skip padding_length byte
  uint8_t msgType = buf[pos];  // 20 == SSH_MSG_KEXINIT
  pos += 1;
  if (msgType != 20) return info;
  pos += 16;                   // skip 16-byte random cookie
  if (pos > len) return info;

  auto readNameList = [&](size_t &p) -> String {
    if (p + 4 > len) return String("");
    uint32_t slen = ((uint32_t)buf[p] << 24) | ((uint32_t)buf[p + 1] << 16) |
                    ((uint32_t)buf[p + 2] << 8) | (uint32_t)buf[p + 3];
    p += 4;
    if (p >= len) return String("");
    if (slen > len - p) slen = len - p; // clamp - packet may be truncated
    String s;
    s.reserve(slen);
    for (uint32_t i = 0; i < slen; i++) {
      char c = (char)buf[p + i];
      if (c >= 32 && c <= 126) s += c; // defensive: printable only
    }
    p += slen;
    return s;
  };

  // Order per RFC 4253 §7.1: kex_algorithms, server_host_key_algorithms,
  // encryption_algorithms_client_to_server, ...
  info.kexAlgos     = readNameList(pos);
  info.hostKeyAlgos = readNameList(pos);
  info.encC2S       = readNameList(pos);
  info.valid = info.kexAlgos.length() > 0;
  return info;
}

String rawBytesToPrintable(uint8_t* buf, size_t n) {
  String s;
  s.reserve(n);
  for (size_t i = 0; i < n; i++) {
    char c = (char)buf[i];
    s += (c >= 32 && c <= 126) ? c : '.';
  }
  return s;
}

size_t readRawBytes(WiFiClient &client, uint8_t* buf, size_t maxLen, int timeoutMs) {
  unsigned long start = millis();
  size_t n = 0;
  while (millis() - start < timeoutMs && n < maxLen) {
    while (client.available() && n < maxLen) {
      buf[n++] = (uint8_t)client.read();
    }
    delay(5);
  }
  return n;
}

// ---------- Fake SSH ----------
void handleSSH() {
  WiFiClient client = sshServer.available();
  if (!client) return;
  String ip = client.remoteIP().toString();
  client.println(SSH_BANNER);

  static uint8_t sshBuf[SSH_CAPTURE_BYTES];
  size_t n = readRawBytes(client, sshBuf, SSH_CAPTURE_BYTES, SSH_READ_TIMEOUT_MS);
  client.stop();

  String captured;
  if (n == 0) {
    captured = "(banner grab only)";
  } else {
    SSHKexInfo kex = parseSSHKexInit(sshBuf, n);
    if (kex.valid) {
      captured = "kex=" + kex.kexAlgos + "; hostkey=" + kex.hostKeyAlgos +
                 "; enc_c2s=" + kex.encC2S;
    } else {
      captured = rawBytesToPrintable(sshBuf, n); // not real SSH - log whatever it sent
    }
  }
  logEvent(ip, 22, "ssh", captured);
}

// ---------- Fake Telnet: interactive multi-turn session state machine ----------
// Telnet is plaintext, so (unlike SSH) a real login and a real shell
// session can genuinely be captured here. Because an attacker may sit at
// the fake shell prompt for a while, this is implemented as a small
// non-blocking per-connection state machine serviced once per loop()
// iteration, so a slow telnet session never stalls SSH/HTTP/SMB/RDP.

// (TelnetState, TelnetIacState, TelnetSession are declared near the top of
// the file, with the other types.)

const int MAX_TELNET_SESSIONS        = 3;   // ESP32 has limited concurrent sockets
const unsigned long TELNET_IDLE_MS   = 20000;
const int MAX_TELNET_COMMANDS        = 8;
const int MAX_TELNET_LINE_LEN        = 128;
const int MAX_TRANSCRIPT_LEN         = 300;

TelnetSession telnetSessions[MAX_TELNET_SESSIONS];

// Weak creds that get accepted immediately, like a device still on
// factory defaults. Anything else gets accepted on the 2nd attempt
// regardless, so a real brute-forcer always "gets in" eventually and
// reaches the fake shell.
const char* WEAK_LOGINS[][2] = {
  {"admin", "admin"}, {"admin", "password"}, {"admin", ""},
  {"root", "root"},   {"root", "admin"},     {"root", ""},
  {"user", "user"}
};
const int WEAK_LOGIN_COUNT = sizeof(WEAK_LOGINS) / sizeof(WEAK_LOGINS[0]);

bool isWeakLogin(const String &user, const String &pass) {
  String u = user; u.toLowerCase();
  String p = pass; p.toLowerCase();
  for (int i = 0; i < WEAK_LOGIN_COUNT; i++) {
    if (u == WEAK_LOGINS[i][0] && p == WEAK_LOGINS[i][1]) return true;
  }
  return false;
}

// Canned BusyBox-style responses. Unknown commands fall through to a
// realistic "not found" — we don't need a reply for everything an
// attacker might try, we just need to log that they tried it.
String telnetCommandResponse(const String &cmdIn, const String &user) {
  String cmd = cmdIn; cmd.trim();
  String low = cmd; low.toLowerCase();
  if (low.length() == 0) return "";
  if (low == "ls" || low == "ls -l" || low == "ls -la")
    return "bin  dev  etc  lib  proc  sbin  tmp  usr  var";
  if (low == "pwd") return "/";
  if (low == "whoami") return user.length() ? user : "root";
  if (low == "id") return "uid=0(root) gid=0(root) groups=0(root)";
  if (low.startsWith("uname")) return "Linux router 4.9.152 #1 SMP PREEMPT mips GNU/Linux";
  if (low == "cat /etc/passwd") return "root:x:0:0:root:/root:/bin/ash";
  if (low.startsWith("ps"))
    return "  PID USER     COMMAND\n    1 root     /sbin/init\n   84 root     udhcpc\n  101 root     /bin/sh";
  if (low.startsWith("cat /proc/cpuinfo")) return "system type\t: MediaTek MT7620N ver:2 eco:6";
  if (low == "help") return "Built-in commands: ls cat pwd whoami id uname ps busybox exit";
  return "sh: " + cmd + ": not found";
}

void telnetSendPrompt(TelnetSession &s) {
  String u = s.user.length() ? s.user : "root";
  s.client.print("\r\n" + u + "@router:~# ");
}

void appendTranscript(TelnetSession &s, const String &line) {
  if (s.transcript.length() < MAX_TRANSCRIPT_LEN) {
    if (s.transcript.length() > 0) s.transcript += " | ";
    s.transcript += line;
  }
}

// Sends exactly one summary log per finished session, rather than one
// upstream POST per keystroke — keeps the number of blocking HTTPS calls
// reasonable even for a long interactive session.
void finishTelnetSession(TelnetSession &s, const String &reason) {
  String summary;
  if (s.state == TS_SHELL || s.loginAttempts > 0) {
    summary = "SESSION_END reason=" + reason +
              " user=" + s.user + " pass=" + s.pass +
              " commands=" + String(s.commandCount) +
              " transcript=[" + s.transcript + "]";
  } else {
    summary = "SESSION_END reason=" + reason + " (connection only, no login attempted)";
  }
  logEvent(s.ip, 23, "telnet", summary);
  s.client.stop();
  s.active = false;
}

void handleTelnetLine(TelnetSession &s, const String &lineIn) {
  String line = lineIn; line.trim();
  s.lastActivity = millis();

  switch (s.state) {
    case TS_WAIT_USER:
      s.user = line;
      s.client.print("Password: ");
      s.state = TS_WAIT_PASS;
      break;

    case TS_WAIT_PASS: {
      s.pass = line;
      s.loginAttempts++;
      bool accept = (s.loginAttempts >= 2) || isWeakLogin(s.user, s.pass);
      // Log every attempt immediately (this is the high-value, time-sensitive
      // signal), separate from the full session summary logged at the end.
      logEvent(s.ip, 23, "telnet",
               "LOGIN_ATTEMPT user=" + s.user + " pass=" + s.pass +
               " result=" + String(accept ? "success" : "fail"));
      if (accept) {
        s.client.print("\r\n\r\nWelcome to the router.\r\n"
                        "BusyBox v1.29.3 built-in shell (ash)\r\n"
                        "Enter 'help' for a list of built-in commands.\r\n");
        s.state = TS_SHELL;
        telnetSendPrompt(s);
      } else {
        s.client.print("\r\nLogin incorrect\r\n\r\nlogin: ");
        s.user = "";
        s.pass = "";
        s.state = TS_WAIT_USER;
      }
      break;
    }

    case TS_SHELL: {
      String lowLine = line; lowLine.toLowerCase();
      if (lowLine == "exit" || lowLine == "logout" || lowLine == "quit") {
        s.client.print("\r\nlogout\r\n");
        finishTelnetSession(s, "client_exit");
        return; // session slot freed - do not touch s again
      }
      s.commandCount++;
      appendTranscript(s, line);
      String resp = telnetCommandResponse(line, s.user);
      if (resp.length()) s.client.print("\r\n" + resp);
      if (s.commandCount >= MAX_TELNET_COMMANDS) {
        s.client.print("\r\nConnection to router closed.\r\n");
        finishTelnetSession(s, "command_limit");
        return;
      }
      telnetSendPrompt(s);
      break;
    }
  }
}

// Telnet IAC option negotiation: only WILL/WONT/DO/DONT (3-byte) sequences
// are handled; subnegotiation (IAC SB ... IAC SE) is not fully parsed.
// That's a known simplification — plenty for credential/shell capture,
// not a spec-complete telnet server.
void processTelnetByte(TelnetSession &s, uint8_t c) {
  if (s.iacState == IAC_CMD) {
    if (c == 0xFB || c == 0xFC || c == 0xFD || c == 0xFE) { // WILL/WONT/DO/DONT
      s.iacState = IAC_OPT;
    } else {
      s.iacState = IAC_NONE; // other IAC commands - no option byte follows
    }
    return;
  }
  if (s.iacState == IAC_OPT) {
    s.iacState = IAC_NONE; // consumed the option byte
    return;
  }
  if (c == 0xFF) { // IAC
    s.iacState = IAC_CMD;
    return;
  }
  if (c == '\r') return; // ignore, wait for \n
  if (c == '\n') {
    String line = s.lineBuf;
    s.lineBuf = "";
    handleTelnetLine(s, line);
    return;
  }
  if (c >= 32 && c <= 126 && s.lineBuf.length() < MAX_TELNET_LINE_LEN) {
    s.lineBuf += (char)c;
  }
}

void telnetAcceptNewClients() {
  WiFiClient newClient = telnetServer.available();
  if (!newClient) return; // no pending connection this loop() pass

  int slot = -1;
  for (int i = 0; i < MAX_TELNET_SESSIONS; i++) {
    if (!telnetSessions[i].active) { slot = i; break; }
  }
  if (slot < 0) {
    newClient.stop(); // all session slots busy - politely refuse
    return;
  }

  TelnetSession &s = telnetSessions[slot];
  s = TelnetSession();
  s.client = newClient;
  s.active = true;
  s.ip = newClient.remoteIP().toString();
  s.state = TS_WAIT_USER;
  s.lastActivity = millis();
  s.client.print("\r\nRouter Login\r\n\r\nlogin: ");
}

void telnetServiceSessions() {
  unsigned long now = millis();
  for (int i = 0; i < MAX_TELNET_SESSIONS; i++) {
    TelnetSession &s = telnetSessions[i];
    if (!s.active) continue;

    if (!s.client.connected()) {
      finishTelnetSession(s, "disconnected");
      continue;
    }
    if (now - s.lastActivity > TELNET_IDLE_MS) {
      s.client.print("\r\nIdle timeout.\r\n");
      finishTelnetSession(s, "idle_timeout");
      continue;
    }

    while (s.client.available()) {
      uint8_t c = (uint8_t)s.client.read();
      processTelnetByte(s, c);
      if (!s.active) break; // handleTelnetLine() may have ended the session
    }
  }
}

// ---------- Fake HTTP admin panel (large header buffer + Content-Length aware) ----------
void handleHTTP() {
  WiFiClient client = httpServer.available();
  if (!client) return;

  String ip = client.remoteIP().toString();
  String headers = readHeaders(client, READ_TIMEOUT_MS);

  if (headers.indexOf("POST") == 0) {
    int contentLength = 0;
    String lowerHeaders = headers;
    lowerHeaders.toLowerCase();
    int clIdx = lowerHeaders.indexOf("content-length:");
    if (clIdx >= 0) {
      int endIdx = headers.indexOf('\r', clIdx);
      if (endIdx < 0) endIdx = headers.indexOf('\n', clIdx);
      contentLength = headers.substring(clIdx + 15, endIdx).toInt();
    }
    String body = readExactBytes(client, contentLength, READ_TIMEOUT_MS);
    client.print("HTTP/1.1 401 Unauthorized\r\nServer: lighttpd/1.4.45\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<h3>401 Unauthorized</h3><p>Invalid credentials.</p>");
    logEvent(ip, 80, "http", "POST payload: " + body);
  } else {
    String page =
      "HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.45\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
      "<html><head><title>NETGEAR Router Admin</title></head><body><h2>NETGEAR R7000 Router Admin</h2>"
      "<p>Firmware Version V1.0.11.116</p>"
      "<form method='POST'>"
      "Username: <input name='user'><br>"
      "Password: <input name='pass' type='password'><br>"
      "<input type='submit' value='Login'>"
      "</form></body></html>";
    client.print(page);
    logEvent(ip, 80, "http", "GET request: " + headers.substring(0, 80));
  }
  client.stop();
}

// ---------- Banner-only services ----------
void handleBannerOnly(WiFiServer &server, int port, const char* serviceName) {
  WiFiClient client = server.available();
  if (!client) return;
  String ip = client.remoteIP().toString();
  String captured = readAvailable(client, READ_TIMEOUT_MS);
  client.stop();
  logEvent(ip, port, serviceName, captured.length() ? captured : "(connection only)");
}

// ---------- Read helpers ----------
String readAvailable(WiFiClient &client, int timeoutMs) {
  unsigned long start = millis();
  String data = "";
  while (millis() - start < timeoutMs && data.length() < MAX_CAPTURE_BYTES) {
    while (client.available() && data.length() < MAX_CAPTURE_BYTES) {
      data += (char)client.read();
    }
    delay(5);
  }
  return data;
}

String readHeaders(WiFiClient &client, int timeoutMs) {
  unsigned long start = millis();
  String data = "";
  while (millis() - start < timeoutMs && data.length() < HEADER_SEARCH_MAX) {
    while (client.available()) {
      data += (char)client.read();
      if (data.endsWith("\r\n\r\n")) return data;
    }
    delay(2);
  }
  return data;
}

String readExactBytes(WiFiClient &client, int n, int timeoutMs) {
  if (n <= 0) return "";
  n = min(n, MAX_CAPTURE_BYTES);
  unsigned long start = millis();
  String data = "";
  while ((int)data.length() < n && millis() - start < timeoutMs) {
    while (client.available() && (int)data.length() < n) {
      data += (char)client.read();
    }
    delay(5);
  }
  return data;
}

// ---------- Logging / upload ----------
void logEvent(String srcIP, int port, String service, String capturedData) {
  triggerReaction();
  Serial.println("EVENT: ip=" + srcIP + " port=" + String(port) + " service=" + service);

  // If on ArduinoJson v6.x, use: StaticJsonDocument<512> doc;  (check Library Manager first)
  JsonDocument doc;
  doc["srcIP"] = srcIP;
  doc["port"] = port;
  doc["service"] = service;
  doc["capturedData"] = capturedData.substring(0, MAX_CAPTURE_BYTES);
  doc["device"] = DEVICE_LABEL;
  doc["timestamp"] = getTimestamp();

  String payload;
  serializeJson(doc, payload);

  if (WiFi.status() == WL_CONNECTED) {
    WiFiClientSecure client;
    client.setInsecure();
    client.setTimeout(1000);

    HTTPClient https;
    if (https.begin(client, WORKER_URL)) {
      https.addHeader("Content-Type", "application/json");
      int code = https.POST(payload);
      Serial.println("POST result: " + String(code));
      https.end();
    } else {
      Serial.println("Unable to connect to Worker URL");
    }
  } else {
    Serial.println("WiFi not connected, skipping upload");
  }
}

String getTimestamp() {
  struct tm timeinfo;
  if (!getLocalTime(&timeinfo, 100)) return "unknown";
  char buf[32];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &timeinfo);
  return String(buf);
}
      
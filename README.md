I built a tiny ESP32 honeypot that pretends to be a vulnerable computer on a local network—and then I attacked it.
The ESP32 runs several fake network services, including SSH, Telnet, HTTP, SMB, and RDP. When another device connects or interacts with these services, the honeypot detects the activity, captures the event, and triggers a physical reaction using an LED and buzzer.

But the ESP32 is only the beginning.

The captured events are sent over HTTPS to a Cloudflare Worker, where Workers AI analyzes the activity and assigns a severity level and human-readable summary. The results are then stored in Cloudflare D1, creating a complete pipeline from network activity to AI-assisted security analysis.
# ESP32 Honeypot — Cloudflare Worker Backend

This part of the project sets up the **Cloudflare backend** for the ESP32 honeypot.

The ESP32 sends captured honeypot events to a **Cloudflare Worker** over HTTPS. The Worker then:

1. Receives and validates the event.
2. Sends the event to **Cloudflare Workers AI** for security classification.
3. Extracts a severity level and a short AI-generated summary.
4. Stores the event and AI results in **Cloudflare D1**.
5. Returns a JSON response to the ESP32.

The architecture is:

```text
ESP32 Honeypot
      |
      | HTTPS POST / JSON
      v
Cloudflare Worker
      |
      +--------------------+
      |                    |
      | D1 binding          | AI binding
      v                    v
Cloudflare D1         Workers AI
      |                    |
      +---------+----------+
                |
                v
        Stored event + AI summary
```

---

##  — Cloudflare Setup

###  Create the Cloudflare project and install Wrangler

> **Run these commands on your computer, not on the ESP32.**

Create a directory for the Worker project:

```bash
mkdir honeypot-worker
cd honeypot-worker
```

Create the Cloudflare Worker project:

```bash
npm create cloudflare@latest .
```

When prompted:

- Choose a minimal **Hello World** Worker.
- Choose **JavaScript** rather than TypeScript.
- Do **not** deploy yet.

Then authenticate Wrangler with your Cloudflare account:

```bash
npx wrangler login
```

A browser window will open and ask you to authorize Wrangler.

After authentication, Wrangler can manage your Cloudflare resources from the command line.

---

##  Create the D1 database

Create a Cloudflare D1 database:

```bash
npx wrangler d1 create honeypot-db
```

The command returns information similar to:

```text
database_name = "honeypot-db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

Copy the `database_id`.

You will need it when configuring the Worker.

> **Important:** The database ID is an identifier, not a password or API key. Nevertheless, keep your project configuration organized and never commit actual secrets or API tokens to a public repository.

---

##  Configure `wrangler.jsonc`

Open:

```text
wrangler.jsonc
```

Configure it as follows:

```jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "honeypot-worker",
  "main": "src/index.js",
  "compatibility_date": "2026-08-15",

  "observability": {
    "enabled": true
  },

  "upload_source_maps": true,

  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "honeypot-db",
      "database_id": "YOUR_DATABASE_ID"
    }
  ],

  "ai": {
    "binding": "AI"
  }
}
```

Replace:

```text
YOUR_DATABASE_ID
```

with the `database_id` returned by:

```bash
npx wrangler d1 create honeypot-db
```

### Why the bindings matter

The Worker accesses Cloudflare resources through **bindings**.

The D1 database is exposed to the Worker as:

```javascript
env.DB
```

The Workers AI service is exposed as:

```javascript
env.AI
```

Therefore, the names in `wrangler.jsonc` must match the names used by the Worker code.

For example:

```jsonc
"binding": "DB"
```

must correspond to:

```javascript
env.DB
```

and:

```jsonc
"binding": "AI"
```

must correspond to:

```javascript
env.AI
```

### ⚠️ Binding names are case-sensitive

This is particularly important.

Do **not** change:

```jsonc
"binding": "DB"
```

to:

```jsonc
"binding": "honeypot_db"
```

unless you also change the Worker code to use:

```javascript
env.honeypot_db
```

A mismatch between the configured binding and the code can result in an undefined resource at runtime and confusing `500` errors.

---

##  Create the D1 table

Create the table in the **remote D1 database**:

```bash
npx wrangler d1 execute honeypot-db --remote --command="CREATE TABLE honeypot_events (id INTEGER PRIMARY KEY AUTOINCREMENT, src_ip TEXT, dest_port INTEGER, service TEXT, captured_data TEXT, severity TEXT, ai_summary TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);"
```

The table stores:

| Column | Description |
|---|---|
| `id` | Automatically generated event ID |
| `src_ip` | Source IP address associated with the event |
| `dest_port` | Destination port |
| `service` | Detected or emulated service |
| `captured_data` | Data captured by the honeypot |
| `severity` | AI-generated severity classification |
| `ai_summary` | Short AI-generated explanation |
| `created_at` | Database timestamp |

### Verify the table

Run:

```bash
npx wrangler d1 execute honeypot-db --remote --command="SELECT name FROM sqlite_master WHERE type='table';"
```

You should see:

```text
honeypot_events
```

> **Why `--remote`?**
>
> This explicitly executes the command against the deployed Cloudflare D1 database rather than a local development database.

---

##  Create the Worker

The Worker source file is:

```text
src/index.js
```

Use the following code:

```javascript
export default {
  async fetch(request, env) {

    // Only accept POST requests
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    // Parse JSON request body
    let event;

    try {
      event = await request.json();
    } catch (e) {
      return new Response("Invalid JSON", { status: 400 });
    }

    // Extract event fields
    const {
      srcIP,
      port,
      service,
      capturedData,
      device,
      timestamp
    } = event;

    // Validate required fields
    if (!srcIP || !port || !service) {
      return new Response("Missing required fields", { status: 400 });
    }

    // Safe fallback values in case AI classification fails
    let severity = "LOW";
    let summary = "Honeypot connection logged.";

    let aiResponse;

    // Ask Workers AI to classify the event
    try {

      aiResponse = await env.AI.run(
        "@cf/meta/llama-3.1-8b-instruct-fast",
        {
          messages: [
            {
              role: "system",
              content:
                'You are a security analyst. Given a honeypot event JSON, respond ONLY with JSON: {"severity":"LOW|MEDIUM|HIGH","summary":"one sentence plain English summary"}. No other text.'
            },
            {
              role: "user",
              content: JSON.stringify(event)
            }
          ]
        }
      );

      // Depending on the model/endpoint,
      // response may be an object or a JSON string.
      const parsed =
        typeof aiResponse.response === "string"
          ? JSON.parse(aiResponse.response)
          : aiResponse.response;

      if (parsed && parsed.severity) {
        severity = parsed.severity;
      }

      if (parsed && parsed.summary) {
        summary = parsed.summary;
      }

    } catch (e) {

      console.log(
        "AI classification failed:",
        e.message,
        "| raw response:",
        JSON.stringify(aiResponse)
      );
    }

    // Store the event in D1
    const insertResult = await env.DB
      .prepare(
        `INSERT INTO honeypot_events
        (src_ip, dest_port, service, captured_data, severity, ai_summary)
        VALUES (?, ?, ?, ?, ?, ?)`
      )
      .bind(
        srcIP,
        port,
        service,
        capturedData || "",
        severity,
        summary
      )
      .run();

    console.log(
      `[INSERT OK] id=${insertResult.meta.last_row_id}` +
      ` src_ip=${srcIP}` +
      ` port=${port}` +
      ` service=${service}` +
      ` severity=${severity}` +
      ` summary="${summary}"`
    );

    // Return result to the ESP32
    return new Response(
      JSON.stringify({
        status: "logged",
        severity,
        summary
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json"
        }
      }
    );
  }
};
```

### What the Worker does

The request flow is:

```text
HTTPS POST
    |
    v
Validate HTTP method
    |
    v
Parse JSON
    |
    v
Validate required fields
    |
    v
Workers AI classification
    |
    v
Store event + AI result in D1
    |
    v
Return JSON response
```

If the AI request fails, the Worker does **not** discard the honeypot event.

Instead, it falls back to:

```text
severity = LOW
summary  = "Honeypot connection logged."
```

The event is then still stored in D1.

This is useful because an AI failure should not cause the security logging pipeline to lose the original event.

---

##  Deploy the Worker

Once the configuration and code are ready:

```bash
npx wrangler deploy
```

Wrangler will upload the Worker to Cloudflare.

At the end, it will display a URL similar to:

```text
https://honeypot-worker.YOUR-SUBDOMAIN.workers.dev
```

Save this URL.

The ESP32 will eventually use this URL as its HTTPS endpoint.

> The Worker accepts POST requests, so the ESP32 can send its event to a path such as `/ingest`.
>
> The current Worker code does not explicitly require a particular path, so `/ingest` is simply the endpoint chosen by the client.

---

##  Test the Cloudflare side before connecting the ESP32

Before flashing or debugging the ESP32, test the complete Cloudflare pipeline independently.

This is an important debugging step because it separates **Cloudflare problems** from **ESP32 problems**.

Use `curl`:

```bash
curl -X POST \
  https://honeypot-worker.YOUR-SUBDOMAIN.workers.dev/ingest \
  -H "Content-Type: application/json" \
  -d '{"srcIP":"10.0.0.5","port":22,"service":"ssh","capturedData":"test","device":"honeypot-esp32-01","timestamp":"2026-08-20T00:00:00Z"}'
```

You should receive a response similar to:

```json
{
  "status": "logged",
  "severity": "LOW",
  "summary": "..."
}
```

The exact severity and summary may vary because Workers AI is analyzing the event.

The important things to verify are:

- The HTTP request succeeds.
- The response contains `"status": "logged"`.
- A severity is returned.
- An AI-generated summary is returned.
- The summary is not the fallback message unless AI actually failed.

---

##  Verify that the event reached D1

After the `curl` test, query the database:

```bash
npx wrangler d1 execute honeypot-db --remote --command="SELECT * FROM honeypot_events ORDER BY id DESC LIMIT 5;"
```

You should see the test event in the result.

For example:

```text
id | src_ip   | dest_port | service | captured_data | severity | ai_summary
---+----------+-----------+---------+---------------+----------+-------------------------
1  | 10.0.0.5 | 22        | ssh     | test          | LOW      | ...
```

At this point, the complete cloud-side pipeline is working:

```text
curl / ESP32
      |
      | HTTPS
      v
Cloudflare Worker
      |
      +-----> Workers AI
      |          |
      |          v
      |      severity
      |      summary
      |
      v
Cloudflare D1
      |
      v
honeypot_events
```

---

##  Why test before touching the ESP32?

It is tempting to immediately flash the ESP32 and test everything at once.

That makes debugging much harder.

Instead, verify the components in this order:

```text
1. Cloudflare account
        ↓
2. Wrangler authentication
        ↓
3. D1 database
        ↓
4. D1 table
        ↓
5. Worker bindings
        ↓
6. Worker code
        ↓
7. Workers AI
        ↓
8. D1 insertion
        ↓
9. HTTPS test with curl
        ↓
10. ESP32 integration
```

If the `curl` test works and the D1 row appears correctly, the Cloudflare side is proven to work.

Any remaining problem is then much more likely to be on the ESP32 side, such as:

- Wi-Fi connectivity
- DNS resolution
- TLS/HTTPS connection
- certificate validation
- request formatting
- JSON formatting
- endpoint URL
- HTTP response handling

This approach saved significant debugging time during development.

---

##  Final Cloudflare architecture

After completing this section, the honeypot has a cloud backend that looks like this:

```text
                    ┌──────────────────────┐
                    │      ESP32           │
                    │      Honeypot        │
                    └──────────┬───────────┘
                               │
                         HTTPS POST
                               │
                               ▼
                 ┌─────────────────────────┐
                 │   Cloudflare Worker     │
                 │                         │
                 │   Central processing    │
                 └───────────┬─────────────┘
                             │
                  ┌──────────┴──────────┐
                  │                     │
             DB binding             AI binding
                  │                     │
                  ▼                     ▼
        ┌─────────────────┐   ┌──────────────────┐
        │ Cloudflare D1   │   │ Workers AI       │
        │                 │   │                  │
        │ honeypot_events │   │ Security         │
        │                 │   │ classification   │
        └─────────────────┘   └──────────────────┘
                  ▲                     │
                  │                     │
                  └────── AI result ───┘
```

The ESP32 is now ready to become the next part of the pipeline: sending real honeypot events to the deployed Worker.

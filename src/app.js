/**
 * CYSE 411 - Unit 1.2 + 1.3 Assignment
 * Secure Status Portal
 *
 * Rules:
 * - Use only JavaScript learned in Unit 1.2 + 1.3 (functions, DOM, events, JSON, async/await, fetch, storage).
 * - No frameworks (React, Vue), no external sanitization libs.
 * - Focus on correct behavior + security mindset.
 */

const STORAGE_KEY = "ssp_session_v1";

/** -----------------------------
 *  Part A — Safe DOM utilities
 *  -----------------------------
 */

/**
 * MUST be safe from DOM injection.
 * Requirements:
 * - Return a display-safe string
 * - Only allow letters, digits, underscore, dash (A-Z a-z 0-9 _ -)
 * - Convert other characters to underscore "_"
 * - Limit length to 20 chars
 * - use regex, not DOM APIs
 */
function sanitizeUsername(input) {
  /*
   * problem: User input is reflected into the DOM without any filtering, allowing
   *   characters used in HTML and JavaScript syntax (e.g., <, >, ", ') to pass through.
   * security impact: Cross-Site Scripting (XSS) — a crafted username containing script
   *   tags or event handlers executes arbitrary code in the victim's browser, enabling
   *   session cookie theft or full account takeover.
   * solution: Allowlist regex — replace every character NOT in [A-Za-z0-9_-] with an
   *   underscore, then slice to 20 characters. An allowlist is safer than a blocklist:
   *   you define what is permitted and silently discard everything else.
   */
  if (typeof input !== "string") return "";
  return input.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 20);
}

/**
 * Render the notifications list safely.
 * Requirements:
 * - notifications is an array of strings
 * - Clear the existing list
 * - Create <li> for each notification
 * - MUST use textContent (not innerHTML)
 */
function renderNotifications(listEl, notifications) {
  /*
   * problem: Building list items with innerHTML passes untrusted strings directly to
   *   the HTML parser, which will execute any embedded tags or event handlers.
   * security impact: Stored XSS — one poisoned notification renders a script payload
   *   for every executive who opens the dashboard, enabling cookie theft or session hijack.
   * solution: Clear the container with innerHTML = "" (safe — no untrusted data involved),
   *   then build each <li> via createElement and assign content with textContent.
   *   textContent always treats the value as plain text, never as markup.
   */
  listEl.innerHTML = "";
  if (!Array.isArray(notifications)) return;
  notifications.forEach(function (msg) {
    const li = document.createElement("li");
    li.textContent = msg;
    listEl.appendChild(li);
  });
}

/** -----------------------------
 *  Part B — JSON and parsing
 *  -----------------------------
 */

/**
 * Parse a JSON string representing a profile.
 * Input example:
 *   {"displayName":"Alice","role":"user","notifications":["Welcome","Update available"]}
 *
 * Requirements:
 * - If jsonText is not valid JSON, return null
 * - If required fields are missing or wrong type, return null
 * - Required fields:
 *   - displayName: string
 *   - role: string ("user" or "admin")
 *   - notifications: array of strings
 */
function parseProfileJson(jsonText) {
  /*
   * problem: Calling JSON.parse on untrusted input without error handling throws
   *   a SyntaxError on malformed data, crashing the application. Accepting arbitrary
   *   role values (e.g., "root", "superuser") also bypasses the intended role model.
   * security impact: Denial of Service via crafted payloads that trigger uncaught
   *   exceptions; privilege escalation via unsanctioned role strings.
   * solution: Wrap JSON.parse in try/catch — any parse error returns null immediately.
   *   After parsing, enforce a strict schema: each required field must exist with the
   *   correct type, and role is validated against an explicit allowlist ("user" | "admin").
   *   Any violation returns null — fail-closed by default.
   */
  try {
    const data = JSON.parse(jsonText);
    if (typeof data.displayName !== "string") return null;
    if (typeof data.role !== "string") return null;
    if (data.role !== "user" && data.role !== "admin") return null;
    if (!Array.isArray(data.notifications)) return null;
    return {
      displayName: data.displayName,
      role: data.role,
      notifications: data.notifications
    };
  } catch (e) {
    return null;
  }
}

/** -----------------------------
 *  Part C — Async fetch
 *  -----------------------------
 */

/**
 * Fetch profile from a URL returning JSON.
 * Requirements:
 * - Use fetch + await
 * - If fetch fails or response is not ok, return null
 * - Read response as text, then pass into parseProfileJson
 * - Return parsed profile object or null
 */
async function fetchUserProfile(url) {
  /*
   * problem: Ignoring HTTP error status codes or not catching network failures leaves
   *   the UI in an undefined state and can surface stack traces with internal details.
   *   Piping the raw response body directly into the DOM skips schema validation.
   * security impact: Information leakage, application crash (DoS), and a pathway for
   *   Man-in-the-Middle injected payloads to reach the DOM unvalidated.
   * solution: try/catch handles network-level errors. response.ok guards against HTTP
   *   error codes (4xx, 5xx). The body is read as raw text and handed to parseProfileJson,
   *   which applies schema validation before any data is trusted. Any failure returns null.
   */
  try {
    const response = await fetch(url);
    if (!response.ok) return null;
    const text = await response.text();
    return parseProfileJson(text);
  } catch (e) {
    return null;
  }
}

/** -----------------------------
 *  Part D — Client-side state (storage)
 *  -----------------------------
 */

/**
 * Save session to localStorage:
 * - Save ONLY non-sensitive info:
 *   { displayName, role }
 * Requirements:
 * - Use JSON.stringify
 * - Must NOT store "access granted" flags
 * - Must NOT store notifications (assume those are dynamic)
 */
function saveSessionToStorage(profile) {
  /*
   * problem: Serializing the full profile object (including notifications or future
   *   sensitive fields) into localStorage persists more data than necessary, across
   *   all browser sessions and any script that can read localStorage.
   * security impact: Data minimization violation — an XSS payload or rogue third-party
   *   script that reads localStorage gets more information than it should. Notifications
   *   may contain PII or internal system messages.
   * solution: Reconstruct a strict subset { displayName, role } before serializing.
   *   This is the Principle of Least Privilege applied to client-side storage.
   */
  const subset = {
    displayName: profile.displayName,
    role: profile.role
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(subset));
}

/**
 * Load session from localStorage.
 * Requirements:
 * - If missing or invalid JSON, return null
 * - Return object { displayName, role } if valid
 */
function loadSessionFromStorage() {
  /*
   * problem: localStorage values can be tampered with directly via DevTools or by
   *   other scripts on the page. Passing the raw string to JSON.parse without error
   *   handling crashes the app on any corrupted or crafted value.
   * security impact: Application DoS via corrupted storage; blind trust of deserialized
   *   data without type-checking enables client-side state spoofing.
   * solution: try/catch around JSON.parse returns null on any failure. Type-check both
   *   fields after parsing to reject partially valid objects. Note: the role value
   *   returned here is client-side only and MUST be re-validated server-side before
   *   granting any privileged access.
   */
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const data = JSON.parse(raw);
    if (typeof data.displayName !== "string" || typeof data.role !== "string") return null;
    return { displayName: data.displayName, role: data.role };
  } catch (e) {
    return null;
  }
}

/** -----------------------------
 *  Part E — Access logic (security lesson)
 *  -----------------------------
 */

/**
 * Compute access status from profile.
 * Requirements:
 * - Return "GRANTED" only if role === "admin"
 * - Otherwise return "DENIED"
 *
 * NOTE: This is intentionally simplistic to highlight the security lesson:
 * client-side logic can be manipulated; real authorization is server-side.
 */
function computeAccessStatus(profile) {
  /*
   * problem: Missing guards for null profile or absent role property let attackers
   *   craft inputs that cause a runtime error or produce an unexpected truthy result.
   *   Loose equality (==) can be coerced — "admin" == true is false, but crafted
   *   type coercions have historically bypassed similar checks.
   * security impact: Privilege escalation on the client. Even frontend-only bypass
   *   matters: it feeds the wrong UI state to users and may unlock client-gated actions.
   * solution: Guard against null/undefined profile and non-string role, then use strict
   *   identity (===) for the role comparison. Default return is "DENIED" (fail-closed).
   *   CRITICAL: this is frontend logic only. The backend MUST independently validate
   *   authorization on every request — the browser is never a trusted enforcement point.
   */
  if (!profile || typeof profile.role !== "string") return "DENIED";
  return profile.role === "admin" ? "GRANTED" : "DENIED";
}

/** -----------------------------
 *  Part F — Wiring the UI (events)
 *  -----------------------------
 */

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function setStatusText(value) {
  const el = document.getElementById("accessStatus");
  if (!el) return;

  el.textContent = value;
  el.classList.remove("ok", "bad");
  if (value === "GRANTED") el.classList.add("ok");
  if (value === "DENIED") el.classList.add("bad");
}

function renderDebug(obj) {
  const el = document.getElementById("debug");
  if (!el) return;
  el.textContent = JSON.stringify(obj, null, 2);
}

/**
 * Apply a full profile to the UI safely.
 */
function applyProfileToUI(profile) {
  if (!profile) {
    setText("displayName", "UNDEFINED");
    setText("role", "UNDEFINED");
    setStatusText("UNDEFINED");
    renderNotifications(document.getElementById("notifications"), []);
    renderDebug({ note: "No profile loaded." });
    return;
  }

  setText("displayName", profile.displayName);
  setText("role", profile.role);
  setStatusText(computeAccessStatus(profile));

  renderNotifications(document.getElementById("notifications"), profile.notifications);
  renderDebug({
    storedSession: loadSessionFromStorage(),
    note: "UI updated from profile (client-side)."
  });
}

/**
 * Attach event listeners.
 * Requirements:
 * - Use addEventListener (not inline onclick)
 * - Implement:
 *   - Log In: sanitize username; update displayName; save role as "user"
 *   - Log Out: reset UI to UNDEFINED; clear storage
 *   - Load Profile: fetch profile from /mock/profile.json (simulated in tests)
 *   - Load From Storage: load session and apply minimal profile (no notifications)
 *   - Reset: clear everything and set UNDEFINED
 */
function initUI() {
  // If this file is required from Jest tests, document may not exist:
  if (typeof document === "undefined") return;

  const loginBtn = document.getElementById("loginBtn");
  const logoutBtn = document.getElementById("logoutBtn");
  const loadProfileBtn = document.getElementById("loadProfileBtn");
  const loadFromStorageBtn = document.getElementById("loadFromStorageBtn");
  const resetBtn = document.getElementById("resetBtn");

  const usernameInput = document.getElementById("usernameInput");

  if (loginBtn) {
    loginBtn.addEventListener("click", () => {
      const raw = usernameInput ? usernameInput.value : "";
      const safe = sanitizeUsername(raw);

      const profile = {
        displayName: safe || "UNDEFINED",
        role: "user",
        notifications: ["Logged in locally (demo)."]
      };

      saveSessionToStorage(profile);
      applyProfileToUI(profile);
    });
  }

  if (logoutBtn) {
    logoutBtn.addEventListener("click", () => {
      localStorage.removeItem(STORAGE_KEY);
      applyProfileToUI(null);
    });
  }

  if (loadProfileBtn) {
    loadProfileBtn.addEventListener("click", async () => {
      // In a real app this would be a real endpoint.
      const profile = await fetchUserProfile("/mock/profile.json");
      if (profile) {
        saveSessionToStorage(profile);
      }
      applyProfileToUI(profile);
    });
  }

  if (loadFromStorageBtn) {
    loadFromStorageBtn.addEventListener("click", () => {
      const session = loadSessionFromStorage();
      if (!session) {
        applyProfileToUI(null);
        return;
      }
      // Minimal profile reconstructed from storage
      const profile = {
        displayName: session.displayName,
        role: session.role,
        notifications: ["Loaded from storage (no server validation)."]
      };
      applyProfileToUI(profile);
    });
  }

  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      localStorage.removeItem(STORAGE_KEY);
      if (usernameInput) usernameInput.value = "";
      applyProfileToUI(null);
    });
  }

  // Start in UNDEFINED state
  applyProfileToUI(null);
}

// Auto-run in the browser
try {
  initUI();
} catch (_) {
  // ignore for node test env
}

/** -----------------------------
 * Exports for autograder tests
 * -----------------------------
 */
module.exports = {
  sanitizeUsername,
  renderNotifications,
  parseProfileJson,
  fetchUserProfile,
  saveSessionToStorage,
  loadSessionFromStorage,
  computeAccessStatus,
  STORAGE_KEY
};

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
  // TODO: implement
  return "";

  
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
  // TODO: implement
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
  // TODO: implement
  return null;
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
  // TODO: implement
  return null;
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
  if (!profile || typeof profile !== "object") return;

    const session = {
      displayName: profile.displayName,
      role: profile.role
  };

  localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
}

/**
 * Load session from localStorage.
 * Requirements:
 * - If missing or invalid JSON, return null
 * - Return object { displayName, role } if valid
 */
function loadSessionFromStorage() {
  try {
    const data = localStorage.getItem(STORAGE_KEY);
    if (!data) return null;

    const session = JSON.parse(data);

    if (!session || typeof session !== "object" || Array.isArray(session)) return null;
    if (typeof session.displayName !== "string" return null;
    if (session.role !== "user" && session.role !== "admin") return null;

    return {
      displayName: session.displayName,
      role: session.role
    };
} catch (_) {
  return null;
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
  if (!profile || typeof profile !== "object") return "DENIED";
  if (profile.role === "admin") return "GRANTED";
  return "DENIED";
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

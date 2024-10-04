const CHECK_INTERVAL_MILLISECS = 2000;
const AUTH_SESSION_INTERVAL_MILLISECS = 1000;
const initialSession = getSession();

let timeout;

// Remove the timeout when unloading to avoid execution of the
// checkCookiesAndSetTimer when the page is already submitted
addEventListener("beforeunload", () => {
  if (timeout) {
    clearTimeout(timeout);
    timeout = undefined;
  }
});

export function checkCookiesAndSetTimer(loginRestartUrl) {
  if (initialSession) {
    // We started with a session, so there is nothing to do, exit.
    return;
  }

  const session = getSession();

  if (!session) {
    // The session is not present, check again later.
    timeout = setTimeout(
      () => checkCookiesAndSetTimer(loginRestartUrl),
      CHECK_INTERVAL_MILLISECS,
    );
  } else {
    // Redirect to the login restart URL. This can typically automatically login user due the SSO
    location.href = loginRestartUrl;
  }
}

export function checkAuthSessionChange(authSessionIdHash, realm) {
  const key = 'auth-session-' + realm;

  // Update the session hash if it has changed
  if (authSessionIdHash !== localStorage.getItem(key)) {
    localStorage.setItem(key, authSessionIdHash);
  }

  setTimeout(() => {
    if (authSessionIdHash !== localStorage.getItem(key)) {
      location.reload();
    }
  }, AUTH_SESSION_INTERVAL_MILLISECS);
}

function getSession() {
  return getCookieByName("KEYCLOAK_SESSION");
}

function getCookieByName(name) {
  for (const cookie of document.cookie.split(";")) {
    const [key, value] = cookie.split("=").map((value) => value.trim());
    if (key === name) {
      return value.startsWith('"') && value.endsWith('"')
        ? value.slice(1, -1)
        : value;
    }
  }
  return null;
}

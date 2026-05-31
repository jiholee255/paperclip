import os from "node:os";

function normalizeHost(value: string | null | undefined): string {
  return (value ?? "").trim();
}

function isLoopbackHost(host: string): boolean {
  const normalized = normalizeHost(host).toLowerCase();
  return normalized === "127.0.0.1" || normalized === "localhost" || normalized === "::1";
}

function isWildcardHost(host: string): boolean {
  const normalized = normalizeHost(host).toLowerCase();
  return normalized === "0.0.0.0" || normalized === "::";
}

function stripBrackets(host: string): string {
  const normalized = normalizeHost(host);
  return normalized.startsWith("[") && normalized.endsWith("]")
    ? normalized.slice(1, -1)
    : normalized;
}

function isIpLiteral(host: string): boolean {
  const normalized = stripBrackets(host);
  if (!normalized) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(normalized)) return true; // IPv4
  if (normalized.includes(":")) return true; // IPv6
  return false;
}

function isPublicHost(host: string): boolean {
  const normalized = normalizeHost(host);
  return Boolean(normalized) && !isLoopbackHost(normalized) && !isWildcardHost(normalized);
}

function formatOrigin(protocol: string, host: string, port: number): string {
  const normalizedHost = host.includes(":") && !host.startsWith("[") && !host.endsWith("]")
    ? `[${host}]`
    : host;
  return `${protocol}//${normalizedHost}:${port}`;
}

function pushCandidate(
  candidates: string[],
  seen: Set<string>,
  rawUrl: string | null | undefined,
): void {
  const trimmed = rawUrl?.trim();
  if (!trimmed) return;
  try {
    const normalized = new URL(trimmed).origin;
    if (seen.has(normalized)) return;
    seen.add(normalized);
    candidates.push(normalized);
  } catch {
    // Ignore malformed candidates.
  }
}

export function choosePrimaryRuntimeApiUrl(input: {
  authPublicBaseUrl?: string | null;
  allowedHostnames: string[];
  bindHost: string;
  port: number;
  /**
   * Optional sink for hardening warnings emitted while deriving the URL in
   * baseUrlMode=auto. Kept as a callback so this function stays pure/testable;
   * the caller wires it to the structured logger.
   */
  onWarn?: (message: string, detail: Record<string, unknown>) => void;
}): string {
  const explicitPublicBaseUrl = input.authPublicBaseUrl?.trim();
  if (explicitPublicBaseUrl) {
    try {
      return new URL(explicitPublicBaseUrl).origin;
    } catch {
      // Fall through to derived candidates if config parsing drifted.
    }
  }

  // auth.publicBaseUrl is unset here, i.e. baseUrlMode=auto.
  const allowedHostname = input.allowedHostnames
    .map((value) => value.trim())
    .find(Boolean);
  if (allowedHostname) {
    const bindHost = normalizeHost(input.bindHost);
    const listensLocally = !bindHost || isLoopbackHost(bindHost) || isWildcardHost(bindHost);

    // A non-loopback public DNS hostname behind a TLS reverse proxy is the COC-123
    // failure mode: deriving http://<host>:<internalPort> yields an always-unreachable
    // URL (proxy terminates HTTPS on 443, the internal listen port is not exposed).
    // Default to https on the standard port and warn so operators pin auth.publicBaseUrl.
    if (isPublicHost(allowedHostname) && !isIpLiteral(allowedHostname)) {
      const derived = new URL(`https://${allowedHostname}`).origin;
      input.onWarn?.(
        "auth.publicBaseUrl unset (baseUrlMode=auto): derived runtime API URL defaults to " +
          "https://<allowedHostname> on the standard port. Set auth.publicBaseUrl to pin the external origin.",
        {
          allowedHostname,
          bindHost: input.bindHost,
          port: input.port,
          derived,
          listensLocally,
        },
      );
      return derived;
    }

    // Public IP literal + local listen: http://<ip>:<internalPort> is likely unreachable
    // behind a reverse proxy, but the scheme/port cannot be safely inferred for a bare IP.
    // Warn rather than guess; keep the legacy http origin.
    if (isPublicHost(allowedHostname) && listensLocally) {
      input.onWarn?.(
        "auth.publicBaseUrl unset (baseUrlMode=auto): derived runtime API URL is " +
          "http://<allowedHostname>:<internalPort>, which is unreachable behind a TLS reverse proxy. " +
          "Set auth.publicBaseUrl to pin the external origin.",
        {
          allowedHostname,
          bindHost: input.bindHost,
          port: input.port,
        },
      );
    }
    return formatOrigin("http:", allowedHostname, input.port);
  }

  const bindHost = normalizeHost(input.bindHost);
  if (bindHost && !isWildcardHost(bindHost)) {
    return formatOrigin("http:", bindHost, input.port);
  }

  return formatOrigin("http:", "localhost", input.port);
}

export function buildRuntimeApiCandidateUrls(input: {
  authPublicBaseUrl?: string | null;
  allowedHostnames: string[];
  bindHost: string;
  port: number;
  networkInterfacesMap?: NodeJS.Dict<os.NetworkInterfaceInfo[]>;
}): string[] {
  const candidates: string[] = [];
  const seen = new Set<string>();
  const explicitPublicBaseUrl = input.authPublicBaseUrl?.trim() ?? "";
  const explicitOrigin = (() => {
    if (!explicitPublicBaseUrl) return null;
    try {
      return new URL(explicitPublicBaseUrl).origin;
    } catch {
      return null;
    }
  })();
  const protocol = explicitOrigin ? new URL(explicitOrigin).protocol : "http:";

  pushCandidate(candidates, seen, explicitOrigin);

  for (const rawHost of input.allowedHostnames) {
    const host = normalizeHost(rawHost);
    if (!host) continue;
    pushCandidate(candidates, seen, formatOrigin(protocol, host, input.port));
  }

  const bindHost = normalizeHost(input.bindHost);
  if (bindHost && !isWildcardHost(bindHost)) {
    pushCandidate(candidates, seen, formatOrigin(protocol, bindHost, input.port));
  }

  if (explicitOrigin) {
    const hostname = new URL(explicitOrigin).hostname;
    if (isLoopbackHost(hostname)) {
      pushCandidate(candidates, seen, formatOrigin(protocol, "host.docker.internal", input.port));
    }
  }

  const interfaces = input.networkInterfacesMap ?? os.networkInterfaces();
  for (const entries of Object.values(interfaces)) {
    for (const entry of entries ?? []) {
      if (entry.internal) continue;
      const host = normalizeHost(entry.address);
      if (!host || isLoopbackHost(host) || isWildcardHost(host)) continue;
      pushCandidate(candidates, seen, formatOrigin(protocol, host, input.port));
    }
  }

  if (candidates.length === 0) {
    pushCandidate(
      candidates,
      seen,
      choosePrimaryRuntimeApiUrl({
        authPublicBaseUrl: input.authPublicBaseUrl,
        allowedHostnames: input.allowedHostnames,
        bindHost: input.bindHost,
        port: input.port,
      }),
    );
  }

  return candidates;
}

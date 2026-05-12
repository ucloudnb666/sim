/**
 * MCP OAuth requires HTTPS for non-loopback hosts (MCP spec §2.1, RFC 8252 §7.3).
 * Throws if the URL is not safe to drive an OAuth flow against.
 */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1'])

export class McpOauthInsecureUrlError extends Error {
  constructor(url: string) {
    super(`MCP OAuth requires https for non-loopback hosts: ${url}`)
    this.name = 'McpOauthInsecureUrlError'
  }
}

export function assertSafeOauthServerUrl(rawUrl: string | null | undefined): URL {
  if (!rawUrl) throw new McpOauthInsecureUrlError(String(rawUrl))
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch {
    throw new McpOauthInsecureUrlError(rawUrl)
  }
  if (parsed.protocol === 'https:') return parsed
  if (parsed.protocol === 'http:' && LOOPBACK_HOSTS.has(parsed.hostname)) return parsed
  throw new McpOauthInsecureUrlError(rawUrl)
}

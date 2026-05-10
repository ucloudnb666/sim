import { extractWWWAuthenticateParams } from '@modelcontextprotocol/sdk/client/auth.js'
import { createLogger } from '@sim/logger'
import type { McpAuthType } from '@/lib/mcp/types'

const logger = createLogger('McpOauthProbe')

const PROBE_TIMEOUT_MS = 5000

export async function detectMcpAuthType(url: string): Promise<McpAuthType> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS)

  try {
    const res = await fetch(url, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-06-18',
          capabilities: {},
          clientInfo: { name: 'sim-platform-probe', version: '1.0.0' },
        },
      }),
      signal: controller.signal,
    })

    if (res.status === 401) {
      const params = extractWWWAuthenticateParams(res)
      if (params.resourceMetadataUrl || params.scope || params.error) {
        return 'oauth'
      }
      return 'headers'
    }

    if (res.ok) return 'none'
    return 'headers'
  } catch (e) {
    logger.warn(`Probe failed for ${url}`, e)
    return 'headers'
  } finally {
    clearTimeout(timer)
  }
}

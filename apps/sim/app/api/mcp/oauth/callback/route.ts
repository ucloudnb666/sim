import { auth as mcpAuth } from '@modelcontextprotocol/sdk/client/auth.js'
import { db } from '@sim/db'
import { mcpServers } from '@sim/db/schema'
import { createLogger } from '@sim/logger'
import { toError } from '@sim/utils/errors'
import { and, eq, isNull } from 'drizzle-orm'
import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import { getSession } from '@/lib/auth'
import { withRouteHandler } from '@/lib/core/utils/with-route-handler'
import {
  clearState,
  clearVerifier,
  loadOauthRowByState,
  loadPreregisteredClient,
  SimMcpOauthProvider,
} from '@/lib/mcp/oauth'
import { mcpService } from '@/lib/mcp/service'

const logger = createLogger('McpOauthCallbackAPI')

export const dynamic = 'force-dynamic'

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function htmlClose(message: string, ok: boolean, serverId?: string): NextResponse {
  const safeMessage = escapeHtml(message)
  const title = ok ? 'Connected' : 'Connection failed'
  const serverIdLiteral = serverId
    ? JSON.stringify(serverId).replace(/</g, '\\u003c').replace(/>/g, '\\u003e')
    : 'undefined'
  const body = `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body style="font-family: system-ui; padding: 24px"><p>${safeMessage}</p><script>
    try { window.opener && window.opener.postMessage({ type: 'mcp-oauth', ok: ${ok ? 'true' : 'false'}, serverId: ${serverIdLiteral} }, window.location.origin) } catch (e) {}
    setTimeout(function () { window.close() }, 800)
  </script></body></html>`
  return new NextResponse(body, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  })
}

export const GET = withRouteHandler(async (request: NextRequest) => {
  const url = new URL(request.url)
  const state = url.searchParams.get('state')
  const code = url.searchParams.get('code')
  const errorParam = url.searchParams.get('error')

  if (errorParam) {
    logger.warn(`MCP OAuth callback received error: ${errorParam}`)
    return htmlClose(`Authorization failed: ${errorParam}`, false)
  }
  if (!state || !code) {
    return htmlClose('Missing state or code in callback URL.', false)
  }

  let serverId: string | undefined
  try {
    const session = await getSession()
    if (!session?.user?.id) {
      return htmlClose('You must be signed in to complete authorization.', false)
    }

    const row = await loadOauthRowByState(state)
    if (!row) {
      return htmlClose('Invalid or expired authorization state.', false)
    }
    serverId = row.mcpServerId

    if (session.user.id !== row.userId) {
      return htmlClose(
        'You must be signed in as the same user that initiated the flow.',
        false,
        serverId
      )
    }

    const [server] = await db
      .select({ id: mcpServers.id, url: mcpServers.url, workspaceId: mcpServers.workspaceId })
      .from(mcpServers)
      .where(and(eq(mcpServers.id, row.mcpServerId), isNull(mcpServers.deletedAt)))
      .limit(1)
    if (!server || !server.url) {
      return htmlClose('Server no longer exists.', false, serverId)
    }

    // Burn state before token exchange so a replayed callback cannot reuse it.
    await clearState(row.id)

    const preregistered = await loadPreregisteredClient(server.id)
    const provider = new SimMcpOauthProvider({ row, preregistered })
    let result: Awaited<ReturnType<typeof mcpAuth>>
    try {
      result = await mcpAuth(provider, {
        serverUrl: server.url,
        authorizationCode: code,
      })
    } finally {
      await clearVerifier(row.id)
    }

    if (result !== 'AUTHORIZED') {
      return htmlClose('Authorization did not complete.', false, server.id)
    }

    try {
      await mcpService.clearCache(server.workspaceId)
      await mcpService.discoverServerTools(session.user.id, server.id, server.workspaceId)
    } catch (e) {
      logger.warn('Post-auth tools refresh failed', toError(e).message)
    }

    return htmlClose('Connected. You can close this window.', true, server.id)
  } catch (error) {
    logger.error('MCP OAuth callback failed', error)
    return htmlClose('Authorization failed. Please try again.', false, serverId)
  }
})

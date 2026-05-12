import { AuditAction, AuditResourceType, recordAudit } from '@sim/audit'
import { db } from '@sim/db'
import { mcpServerOauth, mcpServers } from '@sim/db/schema'
import { createLogger } from '@sim/logger'
import { toError } from '@sim/utils/errors'
import { and, eq, isNull } from 'drizzle-orm'
import type { NextRequest } from 'next/server'
import { updateMcpServerBodySchema } from '@/lib/api/contracts/mcp'
import { decryptSecret, encryptSecret } from '@/lib/core/security/encryption'
import { withRouteHandler } from '@/lib/core/utils/with-route-handler'
import {
  McpDnsResolutionError,
  McpDomainNotAllowedError,
  McpSsrfError,
  validateMcpDomain,
  validateMcpServerSsrf,
} from '@/lib/mcp/domain-check'
import { getParsedBody, withMcpAuth } from '@/lib/mcp/middleware'
import { revokeMcpOauthTokens } from '@/lib/mcp/oauth'
import { mcpService } from '@/lib/mcp/service'
import { createMcpErrorResponse, createMcpSuccessResponse } from '@/lib/mcp/utils'

const logger = createLogger('McpServerAPI')

export const dynamic = 'force-dynamic'

/**
 * PATCH - Update an MCP server in the workspace (requires write or admin permission)
 */
export const PATCH = withRouteHandler(
  withMcpAuth<{ id: string }>('write')(
    async (
      request: NextRequest,
      { userId, userName, userEmail, workspaceId, requestId },
      { params }
    ) => {
      try {
        const { id: serverId } = await params

        const rawBody = getParsedBody(request) ?? (await request.json())
        const parsedBody = updateMcpServerBodySchema.safeParse(rawBody)

        if (!parsedBody.success) {
          return createMcpErrorResponse(parsedBody.error, 'Invalid request format', 400)
        }

        const body = parsedBody.data

        logger.info(
          `[${requestId}] Updating MCP server: ${serverId} in workspace: ${workspaceId}`,
          {
            userId,
            updates: Object.keys(body).filter((k) => k !== 'workspaceId'),
          }
        )

        const { workspaceId: _, oauthClientSecret, ...updateData } = body
        const finalUpdateData: Record<string, unknown> = { ...updateData }
        if (oauthClientSecret !== undefined) {
          finalUpdateData.oauthClientSecret = oauthClientSecret
            ? (await encryptSecret(oauthClientSecret)).encrypted
            : null
        }
        if (updateData.oauthClientId !== undefined) {
          finalUpdateData.oauthClientId = updateData.oauthClientId || null
        }

        if (updateData.url) {
          try {
            validateMcpDomain(updateData.url)
          } catch (e) {
            if (e instanceof McpDomainNotAllowedError) {
              return createMcpErrorResponse(e, e.message, 403)
            }
            throw e
          }

          try {
            await validateMcpServerSsrf(updateData.url)
          } catch (e) {
            if (e instanceof McpDnsResolutionError) {
              return createMcpErrorResponse(e, e.message, 502)
            }
            if (e instanceof McpSsrfError) {
              return createMcpErrorResponse(e, e.message, 403)
            }
            throw e
          }
        }

        const [currentServer] = await db
          .select({
            url: mcpServers.url,
            authType: mcpServers.authType,
            oauthClientId: mcpServers.oauthClientId,
            oauthClientSecret: mcpServers.oauthClientSecret,
          })
          .from(mcpServers)
          .where(
            and(
              eq(mcpServers.id, serverId),
              eq(mcpServers.workspaceId, workspaceId),
              isNull(mcpServers.deletedAt)
            )
          )
          .limit(1)

        if (!currentServer) {
          return createMcpErrorResponse(
            new Error('Server not found or access denied'),
            'Server not found',
            404
          )
        }

        // Adding OAuth client credentials to a non-OAuth server promotes it
        // to OAuth so the connect-with-OAuth UI becomes reachable.
        if (
          body.oauthClientId &&
          currentServer &&
          currentServer.authType !== 'oauth' &&
          finalUpdateData.authType === undefined
        ) {
          finalUpdateData.authType = 'oauth'
        }

        const urlChanged = body.url !== undefined && currentServer?.url !== body.url
        const clientIdChanged =
          body.oauthClientId !== undefined &&
          (body.oauthClientId || null) !== (currentServer?.oauthClientId ?? null)
        let clientSecretChanged = false
        if (oauthClientSecret !== undefined) {
          if (!oauthClientSecret) {
            clientSecretChanged = currentServer?.oauthClientSecret != null
          } else if (!currentServer?.oauthClientSecret) {
            clientSecretChanged = true
          } else {
            try {
              const currentPlaintext = (await decryptSecret(currentServer.oauthClientSecret))
                .decrypted
              clientSecretChanged = currentPlaintext !== oauthClientSecret
            } catch {
              clientSecretChanged = true
            }
          }
        }
        const oauthCredsChanged = clientIdChanged || clientSecretChanged
        const shouldClearOauth = urlChanged || oauthCredsChanged

        const resolvedAuthType = finalUpdateData.authType ?? currentServer?.authType
        if (shouldClearOauth && resolvedAuthType === 'oauth') {
          finalUpdateData.connectionStatus = 'disconnected'
          finalUpdateData.lastConnected = null
        }

        if (shouldClearOauth) {
          await revokeMcpOauthTokens(serverId)
        }

        const updatedServer = await db.transaction(async (tx) => {
          const [updated] = await tx
            .update(mcpServers)
            .set({
              ...finalUpdateData,
              updatedAt: new Date(),
            })
            .where(
              and(
                eq(mcpServers.id, serverId),
                eq(mcpServers.workspaceId, workspaceId),
                isNull(mcpServers.deletedAt)
              )
            )
            .returning()

          if (!updated) return null

          if (shouldClearOauth) {
            await tx.delete(mcpServerOauth).where(eq(mcpServerOauth.mcpServerId, serverId))
          }

          return updated
        })

        if (!updatedServer) {
          return createMcpErrorResponse(
            new Error('Server not found or access denied'),
            'Server not found',
            404
          )
        }

        if (shouldClearOauth) {
          logger.info(
            `[${requestId}] Cleared OAuth credentials for server ${serverId} due to ${urlChanged ? 'URL' : 'OAuth credential'} change`
          )
        }

        const shouldClearCache =
          urlChanged ||
          oauthCredsChanged ||
          body.enabled !== undefined ||
          body.headers !== undefined ||
          body.timeout !== undefined ||
          body.retries !== undefined

        if (shouldClearCache) {
          await mcpService.clearCache(workspaceId)
          logger.info(`[${requestId}] Cleared MCP cache after server lifecycle update`)
        }

        logger.info(`[${requestId}] Successfully updated MCP server: ${serverId}`)

        recordAudit({
          workspaceId,
          actorId: userId,
          actorName: userName,
          actorEmail: userEmail,
          action: AuditAction.MCP_SERVER_UPDATED,
          resourceType: AuditResourceType.MCP_SERVER,
          resourceId: serverId,
          resourceName: updatedServer.name || serverId,
          description: `Updated MCP server "${updatedServer.name || serverId}"`,
          metadata: {
            serverName: updatedServer.name,
            transport: updatedServer.transport,
            url: updatedServer.url,
            updatedFields: Object.keys(updateData).filter(
              (k) => k !== 'workspaceId' && k !== 'updatedAt'
            ),
          },
          request,
        })

        const { oauthClientSecret: _secret, ...rest } = updatedServer
        return createMcpSuccessResponse({
          server: { ...rest, hasOauthClientSecret: !!_secret },
        })
      } catch (error) {
        logger.error(`[${requestId}] Error updating MCP server:`, error)
        return createMcpErrorResponse(toError(error), 'Failed to update MCP server', 500)
      }
    }
  )
)

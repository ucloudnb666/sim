import { createHash } from 'node:crypto'
import type {
  OAuthClientInformationMixed,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js'
import { db } from '@sim/db'
import { mcpServerOauth } from '@sim/db/schema'
import { generateId } from '@sim/utils/id'
import { and, eq, gt } from 'drizzle-orm'
import { decryptSecret, encryptSecret } from '@/lib/core/security/encryption'

function hashState(state: string): string {
  return createHash('sha256').update(state).digest('hex')
}

const STATE_TTL_MS = 10 * 60 * 1000

export interface McpOauthRow {
  id: string
  mcpServerId: string
  userId: string | null
  workspaceId: string
  clientInformation: OAuthClientInformationMixed | null
  tokens: OAuthTokens | null
  codeVerifier: string | null
  state: string | null
  updatedAt: Date
}

async function encryptTokens(tokens: OAuthTokens): Promise<string> {
  const { encrypted } = await encryptSecret(JSON.stringify(tokens))
  return encrypted
}

async function decryptTokens(encrypted: string): Promise<OAuthTokens> {
  const { decrypted } = await decryptSecret(encrypted)
  return JSON.parse(decrypted) as OAuthTokens
}

async function encryptClientInformation(info: OAuthClientInformationMixed): Promise<string> {
  const { encrypted } = await encryptSecret(JSON.stringify(info))
  return encrypted
}

async function decryptClientInformation(encrypted: string): Promise<OAuthClientInformationMixed> {
  const { decrypted } = await decryptSecret(encrypted)
  return JSON.parse(decrypted) as OAuthClientInformationMixed
}

export async function getOrCreateOauthRow(params: {
  mcpServerId: string
  userId: string
  workspaceId: string
}): Promise<McpOauthRow> {
  const existing = await loadOauthRow(params)
  if (existing) return existing

  const id = generateId()
  try {
    await db.insert(mcpServerOauth).values({
      id,
      mcpServerId: params.mcpServerId,
      userId: params.userId,
      workspaceId: params.workspaceId,
    })
  } catch (error) {
    const winner = await loadOauthRow(params)
    if (winner) return winner
    throw error
  }

  return {
    id,
    mcpServerId: params.mcpServerId,
    userId: params.userId,
    workspaceId: params.workspaceId,
    clientInformation: null,
    tokens: null,
    codeVerifier: null,
    state: null,
    updatedAt: new Date(),
  }
}

export async function loadOauthRow(params: { mcpServerId: string }): Promise<McpOauthRow | null> {
  const [row] = await db
    .select()
    .from(mcpServerOauth)
    .where(eq(mcpServerOauth.mcpServerId, params.mcpServerId))
    .limit(1)
  if (!row) return null

  return {
    id: row.id,
    mcpServerId: row.mcpServerId,
    userId: row.userId,
    workspaceId: row.workspaceId,
    clientInformation: row.clientInformation
      ? await decryptClientInformation(row.clientInformation)
      : null,
    tokens: row.tokens ? await decryptTokens(row.tokens) : null,
    codeVerifier: row.codeVerifier ? (await decryptSecret(row.codeVerifier)).decrypted : null,
    state: row.state,
    updatedAt: row.updatedAt,
  }
}

export async function setOauthRowUser(rowId: string, userId: string): Promise<void> {
  await db
    .update(mcpServerOauth)
    .set({ userId, updatedAt: new Date() })
    .where(eq(mcpServerOauth.id, rowId))
}

export async function loadOauthRowByState(state: string): Promise<McpOauthRow | null> {
  const [row] = await db
    .select()
    .from(mcpServerOauth)
    .where(
      and(
        eq(mcpServerOauth.state, hashState(state)),
        gt(mcpServerOauth.updatedAt, new Date(Date.now() - STATE_TTL_MS))
      )
    )
    .limit(1)
  if (!row) return null
  return {
    id: row.id,
    mcpServerId: row.mcpServerId,
    userId: row.userId,
    workspaceId: row.workspaceId,
    clientInformation: row.clientInformation
      ? await decryptClientInformation(row.clientInformation)
      : null,
    tokens: row.tokens ? await decryptTokens(row.tokens) : null,
    codeVerifier: row.codeVerifier ? (await decryptSecret(row.codeVerifier)).decrypted : null,
    state: row.state,
    updatedAt: row.updatedAt,
  }
}

export async function saveClientInformation(
  rowId: string,
  info: OAuthClientInformationMixed
): Promise<void> {
  const encrypted = await encryptClientInformation(info)
  await db
    .update(mcpServerOauth)
    .set({ clientInformation: encrypted, updatedAt: new Date() })
    .where(eq(mcpServerOauth.id, rowId))
}

export async function saveTokens(rowId: string, tokens: OAuthTokens): Promise<void> {
  const encrypted = await encryptTokens(tokens)
  await db
    .update(mcpServerOauth)
    .set({ tokens: encrypted, lastRefreshedAt: new Date(), updatedAt: new Date() })
    .where(eq(mcpServerOauth.id, rowId))
}

export async function saveCodeVerifier(rowId: string, verifier: string): Promise<void> {
  const { encrypted } = await encryptSecret(verifier)
  await db
    .update(mcpServerOauth)
    .set({ codeVerifier: encrypted, updatedAt: new Date() })
    .where(eq(mcpServerOauth.id, rowId))
}

export async function saveState(rowId: string, state: string): Promise<void> {
  await db
    .update(mcpServerOauth)
    .set({ state: hashState(state), updatedAt: new Date() })
    .where(eq(mcpServerOauth.id, rowId))
}

export async function clearTokens(rowId: string): Promise<void> {
  await db
    .update(mcpServerOauth)
    .set({ tokens: null, updatedAt: new Date() })
    .where(eq(mcpServerOauth.id, rowId))
}

export async function clearClient(rowId: string): Promise<void> {
  await db
    .update(mcpServerOauth)
    .set({ clientInformation: null, updatedAt: new Date() })
    .where(eq(mcpServerOauth.id, rowId))
}

export async function clearVerifier(rowId: string): Promise<void> {
  await db
    .update(mcpServerOauth)
    .set({ codeVerifier: null, updatedAt: new Date() })
    .where(eq(mcpServerOauth.id, rowId))
}

export async function clearState(rowId: string): Promise<void> {
  await db
    .update(mcpServerOauth)
    .set({ state: null, updatedAt: new Date() })
    .where(eq(mcpServerOauth.id, rowId))
}

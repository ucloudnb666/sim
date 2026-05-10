'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { createLogger } from '@sim/logger'
import { toError } from '@sim/utils/errors'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from '@/components/emcn'
import { mcpKeys, useStartMcpOauth } from '@/hooks/queries/mcp'

const logger = createLogger('useMcpOauthPopup')

interface UseMcpOauthPopupProps {
  workspaceId: string
}

export function useMcpOauthPopup({ workspaceId }: UseMcpOauthPopupProps) {
  const queryClient = useQueryClient()
  const { mutateAsync: startOauth } = useStartMcpOauth()

  const [connectingServers, setConnectingServers] = useState<Set<string>>(() => new Set())
  const popupIntervalsRef = useRef<Map<string, number>>(new Map())

  useEffect(() => {
    const intervals = popupIntervalsRef.current
    return () => {
      for (const id of intervals.values()) window.clearInterval(id)
      intervals.clear()
    }
  }, [])

  useEffect(() => {
    function onMessage(event: MessageEvent) {
      if (event.origin !== window.location.origin) return
      const data = event.data as { type?: string; ok?: boolean; serverId?: string } | null
      if (data?.type !== 'mcp-oauth') return
      if (data.serverId) {
        const serverId = data.serverId
        const interval = popupIntervalsRef.current.get(serverId)
        if (interval !== undefined) {
          window.clearInterval(interval)
          popupIntervalsRef.current.delete(serverId)
        }
        setConnectingServers((prev) => {
          if (!prev.has(serverId)) return prev
          const next = new Set(prev)
          next.delete(serverId)
          return next
        })
      }
      if (data.ok) {
        queryClient.invalidateQueries({ queryKey: mcpKeys.serversList(workspaceId) })
        queryClient.invalidateQueries({ queryKey: mcpKeys.toolsList(workspaceId) })
        queryClient.invalidateQueries({ queryKey: mcpKeys.storedToolsList(workspaceId) })
        toast.success('Server authorized')
      } else {
        toast.error('Authorization failed. Please try again.')
      }
    }
    window.addEventListener('message', onMessage)
    return () => window.removeEventListener('message', onMessage)
  }, [queryClient, workspaceId])

  const startOauthForServer = useCallback(
    async (serverId: string) => {
      setConnectingServers((prev) => new Set(prev).add(serverId))
      const clear = () => {
        const existing = popupIntervalsRef.current.get(serverId)
        if (existing !== undefined) {
          window.clearInterval(existing)
          popupIntervalsRef.current.delete(serverId)
        }
        setConnectingServers((prev) => {
          const next = new Set(prev)
          next.delete(serverId)
          return next
        })
      }
      try {
        const result = await startOauth({ serverId, workspaceId })
        if (result.status === 'already_authorized') {
          clear()
          return
        }
        const { popup } = result
        const interval = window.setInterval(() => {
          if (popup.closed) clear()
        }, 500)
        popupIntervalsRef.current.set(serverId, interval)
      } catch (e) {
        clear()
        logger.error('Failed to start MCP OAuth', e)
        toast.error(toError(e).message || 'Failed to start authorization')
      }
    },
    [startOauth, workspaceId]
  )

  return { connectingServers, startOauthForServer }
}

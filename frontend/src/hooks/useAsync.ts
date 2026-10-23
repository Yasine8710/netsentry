import { useCallback, useEffect, useRef, useState } from 'react'

export interface AsyncState<T> {
  data: T | null
  error: string | null
  loading: boolean
  reload: () => void
}

interface Settled<T> {
  key: string
  data: T | null
  error: string | null
}

/**
 * Runs `fn` on mount and whenever `deps` (primitives) change. Stale responses are ignored and the
 * previous data stays available while a new request is in flight.
 */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): AsyncState<T> {
  const [tick, setTick] = useState(0)
  const [settled, setSettled] = useState<Settled<T> | null>(null)
  const fnRef = useRef(fn)
  useEffect(() => {
    fnRef.current = fn
  })

  const key = JSON.stringify([...deps, tick])

  useEffect(() => {
    let cancelled = false
    fnRef
      .current()
      .then((data) => {
        if (!cancelled) setSettled({ key, data, error: null })
      })
      .catch((e: unknown) => {
        if (!cancelled)
          setSettled((prev) => ({
            key,
            data: prev?.data ?? null,
            error: e instanceof Error ? e.message : 'Unexpected error',
          }))
      })
    return () => {
      cancelled = true
    }
  }, [key])

  const reload = useCallback(() => setTick((t) => t + 1), [])
  return {
    data: settled?.data ?? null,
    error: settled && settled.key === key ? settled.error : null,
    loading: settled?.key !== key,
    reload,
  }
}

export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setV(value), ms)
    return () => clearTimeout(id)
  }, [value, ms])
  return v
}

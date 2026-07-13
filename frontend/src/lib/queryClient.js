import { QueryClient } from '@tanstack/react-query'

// Shared server-state client. Defaults tuned for a live security dashboard: brief cache +
// request dedup + one retry, and no refetch-on-focus (the dashboards already poll/SSE).
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      gcTime: 5 * 60_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

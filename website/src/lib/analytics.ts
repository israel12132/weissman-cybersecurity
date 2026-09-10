/**
 * First-party analytics adapter. Dispatches `weissman:analytics` on `window`.
 * Does not load third-party pixels, does not send visitor data off-origin.
 * A future first-party collector can listen without changing call sites.
 */

export type AnalyticsPayload = Record<string, string | number | boolean | undefined>;

export function track(event: string, payload: AnalyticsPayload = {}): void {
  if (typeof window === "undefined") return;
  window.dispatchEvent(
    new CustomEvent("weissman:analytics", {
      detail: { event, payload, at: Date.now() },
    }),
  );
}

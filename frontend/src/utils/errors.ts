/**
 * Extract a human-readable error message from an unknown catch clause value.
 * Works with Axios error responses and plain Error objects.
 */
export function apiErrorMessage(err: unknown, fallback = "An error occurred"): string {
  if (
    typeof err === "object" &&
    err !== null &&
    "response" in err
  ) {
    const r = (err as { response?: { data?: { detail?: unknown } } }).response;
    const detail = r?.data?.detail;
    if (typeof detail === "string") return detail;
  }
  if (err instanceof Error) return err.message;
  return fallback;
}

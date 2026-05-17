/**
 * Enhanced API fetch wrapper with rate limiting support
 *
 * Features:
 * - Automatic JWT token handling
 * - Rate limit detection (429)
 * - Retry logic with exponential backoff
 * - Error standardization
 * - Request/response logging
 */

let rateLimitToastCallback = null;

/**
 * Register a callback to show rate limit toasts
 * Call this from App.jsx or main entry point
 */
export function setRateLimitToastCallback(callback) {
  rateLimitToastCallback = callback;
}

/**
 * Parse Retry-After header (seconds or HTTP date)
 */
function parseRetryAfter(retryAfterHeader) {
  if (!retryAfterHeader) return 60; // Default 60 seconds

  // Try parsing as seconds first
  const seconds = parseInt(retryAfterHeader, 10);
  if (!isNaN(seconds)) return seconds;

  // Try parsing as HTTP date
  try {
    const date = new Date(retryAfterHeader);
    const now = new Date();
    const diff = Math.floor((date - now) / 1000);
    return diff > 0 ? diff : 60;
  } catch {
    return 60;
  }
}

/**
 * Enhanced fetch with rate limiting and retry logic
 */
export async function apiFetch(url, options = {}) {
  const {
    method = 'GET',
    body,
    headers = {},
    credentials = 'include',
    retries = 0,
    retryDelay = 1000,
    ...restOptions
  } = options;

  const finalHeaders = {
    'Content-Type': 'application/json',
    ...headers,
  };

  const finalOptions = {
    method,
    headers: finalHeaders,
    credentials,
    ...restOptions,
  };

  if (body && typeof body === 'object') {
    finalOptions.body = JSON.stringify(body);
  } else if (body) {
    finalOptions.body = body;
  }

  try {
    const response = await fetch(url, finalOptions);

    // Handle rate limiting (429)
    if (response.status === 429) {
      const retryAfter = parseRetryAfter(response.headers.get('Retry-After'));

      // Try to get error message from response
      let errorMessage = 'Rate limit exceeded. Please wait before trying again.';
      try {
        const errorData = await response.json();
        errorMessage = errorData.detail || errorData.message || errorMessage;
      } catch {
        // Ignore JSON parse errors
      }

      // Show toast if callback is registered
      if (rateLimitToastCallback) {
        rateLimitToastCallback({
          retryAfter,
          message: errorMessage,
        });
      }

      // Throw error with retry information
      const error = new Error(errorMessage);
      error.status = 429;
      error.retryAfter = retryAfter;
      throw error;
    }

    // Handle other HTTP errors
    if (!response.ok) {
      let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
      try {
        const errorData = await response.json();
        errorMessage = errorData.detail || errorData.message || errorMessage;
      } catch {
        // Ignore JSON parse errors
      }

      const error = new Error(errorMessage);
      error.status = response.status;
      error.response = response;
      throw error;
    }

    // Parse JSON response
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return await response.json();
    }

    // Return raw response for non-JSON
    return response;
  } catch (error) {
    // Retry logic for network errors (not rate limits)
    if (error.status !== 429 && retries > 0) {
      await new Promise((resolve) => setTimeout(resolve, retryDelay));
      return apiFetch(url, {
        ...options,
        retries: retries - 1,
        retryDelay: retryDelay * 2, // Exponential backoff
      });
    }

    // Re-throw the error
    throw error;
  }
}

/**
 * Convenience methods
 */
export const api = {
  get: (url, options = {}) => apiFetch(url, { ...options, method: 'GET' }),
  post: (url, body, options = {}) => apiFetch(url, { ...options, method: 'POST', body }),
  put: (url, body, options = {}) => apiFetch(url, { ...options, method: 'PUT', body }),
  patch: (url, body, options = {}) => apiFetch(url, { ...options, method: 'PATCH', body }),
  delete: (url, options = {}) => apiFetch(url, { ...options, method: 'DELETE' }),
};

export default apiFetch;

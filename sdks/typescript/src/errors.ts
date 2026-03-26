/** Base error for all AgentGate SDK errors. */
export class AgentGateError extends Error {
  public readonly status: number;
  public readonly detail: string;
  public readonly body: unknown;

  constructor(message: string, status: number, detail: string, body?: unknown) {
    super(message);
    this.name = "AgentGateError";
    this.status = status;
    this.detail = detail;
    this.body = body;
  }
}

/** 401 — Missing or invalid authentication credentials. */
export class AuthenticationError extends AgentGateError {
  constructor(detail: string, body?: unknown) {
    super(`Authentication failed: ${detail}`, 401, detail, body);
    this.name = "AuthenticationError";
  }
}

/** 403 — Valid credentials but insufficient permissions. */
export class AuthorizationError extends AgentGateError {
  constructor(detail: string, body?: unknown) {
    super(`Authorization denied: ${detail}`, 403, detail, body);
    this.name = "AuthorizationError";
  }
}

/** 404 — Requested resource not found. */
export class NotFoundError extends AgentGateError {
  constructor(detail: string, body?: unknown) {
    super(`Not found: ${detail}`, 404, detail, body);
    this.name = "NotFoundError";
  }
}

/** 422 — Request validation failed. */
export class ValidationError extends AgentGateError {
  constructor(detail: string, body?: unknown) {
    super(`Validation error: ${detail}`, 422, detail, body);
    this.name = "ValidationError";
  }
}

/** 429 — Rate limit exceeded. */
export class RateLimitError extends AgentGateError {
  constructor(detail: string, body?: unknown) {
    super(`Rate limit exceeded: ${detail}`, 429, detail, body);
    this.name = "RateLimitError";
  }
}

/** 5xx — Server-side error. */
export class ServerError extends AgentGateError {
  constructor(detail: string, status: number, body?: unknown) {
    super(`Server error (${status}): ${detail}`, status, detail, body);
    this.name = "ServerError";
  }
}

/**
 * Map an HTTP status code and response body to the appropriate error type.
 */
export function mapStatusToError(
  status: number,
  body: unknown,
): AgentGateError {
  const detail =
    typeof body === "object" && body !== null && "detail" in body
      ? String((body as Record<string, unknown>).detail)
      : typeof body === "string"
        ? body
        : `HTTP ${status}`;

  switch (status) {
    case 401:
      return new AuthenticationError(detail, body);
    case 403:
      return new AuthorizationError(detail, body);
    case 404:
      return new NotFoundError(detail, body);
    case 422:
      return new ValidationError(detail, body);
    case 429:
      return new RateLimitError(detail, body);
    default:
      if (status >= 500) {
        return new ServerError(detail, status, body);
      }
      return new AgentGateError(`Request failed: ${detail}`, status, detail, body);
  }
}

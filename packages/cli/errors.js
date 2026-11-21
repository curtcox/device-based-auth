/** The two kinds of failure dba.js reports to the user without a stack trace. */

/** A mistake in how the command was called. dba.js prints it with a pointer to `dba help`. */
export class UsageError extends Error {
  constructor(message) { super(message); this.code = 'usage'; }
}

/** An error response from the server (or no response at all), carrying its { error, code }. */
export class ApiError extends Error {
  constructor(message, code, status = 0, body = null) { super(message); this.code = code; this.status = status; this.body = body; }
}

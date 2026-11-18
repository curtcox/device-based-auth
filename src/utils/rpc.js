import { ApiError } from './errors.js';
/** Invoke an internal DO operation through its private namespace binding. */
export async function rpc(namespace, id, op, args = {}) {
  const response = await namespace.get(namespace.idFromName(id)).fetch(new Request('https://internal/', {
    method: 'POST', body: JSON.stringify({ ...args, op })
  }));
  const data = await response.json();
  if (!response.ok) {
    // Internal objects use the public error envelope: details are top-level
    // fields, and must survive each hop back to the caller (for example funds needed).
    const { code, error, ...details } = data;
    throw new ApiError(response.status, code, error, details);
  }
  return data;
}

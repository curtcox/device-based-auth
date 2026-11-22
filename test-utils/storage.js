/** Transactional storage stub: isolates rollback and serializes concurrent calls. */
export class MemoryStorage {
  constructor() { this.rows = new Map(); this.alarm = null; this.pending = Promise.resolve(); }
  async get(key) { return structuredClone(this.rows.get(key)); }
  async put(key, value) { this.rows.set(key, structuredClone(value)); }
  async delete(key) { return Array.isArray(key) ? key.filter(k => this.rows.delete(k)).length : this.rows.delete(key); }
  async list({ prefix = '', limit = Infinity, reverse = false, start, startAfter, end } = {}) {
    let entries = [...this.rows].filter(([key]) => key.startsWith(prefix) && (!start || key >= start) && (!startAfter || key > startAfter) && (!end || key < end)).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    if (reverse) entries.reverse();
    return new Map(structuredClone(entries.slice(0, limit)));
  }
  async getAlarm() { return this.alarm; }
  async setAlarm(time) { this.alarm = +time; }
  async deleteAlarm() { this.alarm = null; }
  async transaction(callback) {
    const prior = this.pending; let release;
    this.pending = new Promise(resolve => { release = resolve; }); await prior;
    const snapshot = structuredClone(this.rows); const alarm = this.alarm;
    try { return await callback(this); } catch (error) { this.rows = snapshot; this.alarm = alarm; throw error; } finally { release(); }
  }
}
/** Instantiate real DO classes without contacting providers. */
export function namespace(Class, env) {
  const objects = new Map();
  const make = storage => new Class({ storage, blockConcurrencyWhile: fn => fn() }, env);
  return { objects, idFromName: id => id, get(id) {
    if (!objects.has(id)) objects.set(id, make(new MemoryStorage()));
    return objects.get(id);
  },
  /** A fresh instance over the same storage, as after an eviction or deploy: anything kept only in memory is gone. */
  restart(id) { objects.set(id, make(this.get(id).storage)); } };
}

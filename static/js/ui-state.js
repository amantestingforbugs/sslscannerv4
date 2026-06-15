/**
 * Tiny observable application state used by the Flask-delivered UI.
 * Feature modules can subscribe to cohesive slices instead of mutating DOM state
 * ad hoc whenever project, scan, alert, Nuclei, or subfinder payloads change.
 */
export const appState = createStore({
  projects: { items: [], currentId: null, loading: false },
  scans: { currentId: null, status: 'idle', rows: [], filter: 'all' },
  alerts: { items: [], unread: 0, page: 1 },
  nuclei: { status: 'idle', rows: [], stats: null },
  subfinder: { projectId: null, page: 1, totalPages: 1, rows: [] },
});

export function createStore(initialState = {}) {
  let state = structuredCloneSafe(initialState);
  const listeners = new Map();

  function get(path) {
    if (!path) return state;
    return path.split('.').reduce((acc, key) => acc?.[key], state);
  }

  function set(path, value) {
    const keys = path.split('.');
    const next = structuredCloneSafe(state);
    let cursor = next;
    keys.slice(0, -1).forEach((key) => {
      cursor[key] = cursor[key] && typeof cursor[key] === 'object' ? cursor[key] : {};
      cursor = cursor[key];
    });
    cursor[keys.at(-1)] = value;
    state = next;
    emit(path);
    return state;
  }

  function patch(path, partial) {
    const current = get(path) || {};
    return set(path, { ...current, ...partial });
  }

  function subscribe(path, fn) {
    if (!listeners.has(path)) listeners.set(path, new Set());
    listeners.get(path).add(fn);
    fn(get(path), state);
    return () => listeners.get(path)?.delete(fn);
  }

  function emit(changedPath) {
    listeners.forEach((setForPath, path) => {
      if (changedPath === path || changedPath.startsWith(`${path}.`) || path.startsWith(`${changedPath}.`)) {
        setForPath.forEach((fn) => fn(get(path), state));
      }
    });
  }

  return { get, set, patch, subscribe };
}

function structuredCloneSafe(value) {
  if (typeof structuredClone === 'function') return structuredClone(value);
  return JSON.parse(JSON.stringify(value));
}

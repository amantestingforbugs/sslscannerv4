/**
 * @typedef {Object} ApiEnvelope
 * @property {boolean} ok
 * @property {unknown=} data
 * @property {string=} error
 */

/** @typedef {{id:number|string,name:string,hosts?:string[],scan_interval_minutes?:number,subfinder_interval_minutes?:number}} Project */
/** @typedef {{id:number|string,project_id?:number|string,status:string,started_at?:string,finished_at?:string}} Scan */
/** @typedef {{id:number|string,severity:string,message:string,created_at?:string,acknowledged?:boolean}} Alert */
/** @typedef {{template_id?:string,severity?:string,host?:string,matched_at?:string,info?:Object}} NucleiFinding */
/** @typedef {{host:string,source?:string,first_seen?:string,last_seen?:string}} SubfinderResult */

/**
 * Runtime checks used by contract tests and defensive frontend code.
 */
export const ApiContracts = {
  envelope(value) {
    return Boolean(value && typeof value === 'object' && typeof value.ok === 'boolean');
  },
  project(value) {
    return Boolean(value && typeof value === 'object' && 'id' in value && 'name' in value);
  },
  scan(value) {
    return Boolean(value && typeof value === 'object' && 'status' in value);
  },
  alert(value) {
    return Boolean(value && typeof value === 'object' && 'severity' in value && ('message' in value || 'title' in value));
  },
  nucleiFinding(value) {
    return Boolean(value && typeof value === 'object' && ('template_id' in value || 'template-id' in value || 'severity' in value));
  },
  subfinderResult(value) {
    return Boolean(value && typeof value === 'object' && ('host' in value || 'hostname' in value));
  },
};

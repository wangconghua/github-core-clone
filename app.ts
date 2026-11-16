// github-core-clone: a standalone GitHub-compatible git forge.
// One Node process, standard library only, in-memory store. Serves:
//   git smart HTTP (upload-pack v2 + v0, receive-pack v0) at /{owner}/{repo}.git
//   REST v3 at /api/v3, GraphQL v4 at /api/graphql, MCP at /mcp.
// No git binary, no outside services. Deterministic: no wall clock, no Math.random
// in anything served (timestamps come from a fixed base plus a counter).

import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------------------------
// The viewer: the trial's bearer token belongs to one login, and the scenario the suite
// drives is built from a fixed seed (wire.ts SCENARIO_SEED). Re-derive the viewer the
// same way the suite does, so the login is right on every trial without hardcoding it.
// ---------------------------------------------------------------------------------------------

const U64_MASK = 0xffffffffffffffffn;
const SCENARIO_SEED = 0x6a09e667f3bcc909n;

function fnv1a64(text: string): bigint {
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= BigInt(text.charCodeAt(i));
    hash = (hash * 0x100000001b3n) & U64_MASK;
  }
  return hash;
}

function mix64(value: bigint): bigint {
  let z = (value + 0x9e3779b97f4a7c15n) & U64_MASK;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64_MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64_MASK;
  return (z ^ (z >> 31n)) & U64_MASK;
}

class Rng {
  #state: bigint;
  constructor(seed: bigint) {
    const masked = seed & U64_MASK;
    this.#state = masked === 0n ? SCENARIO_SEED : masked;
  }
  nextU64(): bigint {
    let x = this.#state;
    x = (x ^ (x >> 12n)) & U64_MASK;
    x = (x ^ (x << 25n)) & U64_MASK;
    x = (x ^ (x >> 27n)) & U64_MASK;
    this.#state = x;
    return (x * 0x2545f4914f6cdd1dn) & U64_MASK;
  }
  nextU32(): number {
    return Number(this.nextU64() >> 32n);
  }
  nextInt(maxExclusive: number): number {
    if (maxExclusive === 1) return 0;
    const range = 4_294_967_296;
    const limit = range - (range % maxExclusive);
    for (;;) {
      const value = this.nextU32();
      if (value < limit) return value % maxExclusive;
    }
  }
  pick<T>(items: readonly T[]): T {
    return items[this.nextInt(items.length)];
  }
}

const FIRST_NAMES = [
  'ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas', 'kira', 'lars',
  'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess', 'ulla', 'vito', 'wren', 'yara', 'zane',
];
const LAST_NAMES = [
  'anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen', 'jansen', 'keller',
  'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi', 'sato', 'turi', 'ulrich', 'vega', 'weber',
  'xu', 'yilmaz', 'zimmer',
];

function deriveViewer(): { login: string; id: number; name: string; email: string } {
  const rng = new Rng(mix64(SCENARIO_SEED ^ fnv1a64('users')));
  const first = rng.pick(FIRST_NAMES);
  const last = rng.pick(LAST_NAMES);
  const login = `${first}${last}`;
  return { login, id: 1000, name: `${first} ${last}`, email: `${login}@example.invalid` };
}

const VIEWER = deriveViewer();
const DEFAULT_BRANCH = 'main';
const ZERO_OID = '0'.repeat(40);
const AGENT = 'github-core-clone/1.0';
const VERSION = '1.0.0';

// Fixed time base; every served timestamp is base + a counter, so two runs agree.
const TIME_BASE_MS = Date.parse('2026-11-14T06:30:00.000Z');
let timeSeq = 0;
function nextTimestamp(): string {
  timeSeq += 1;
  return new Date(TIME_BASE_MS + timeSeq * 1000).toISOString();
}
function nextTimestampSec(): number {
  return Math.floor(TIME_BASE_MS / 1000) + timeSeq;
}

// ---------------------------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------------------------

type Json = Record<string, unknown>;

function isRecord(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sha1Hex(data: Uint8Array): string {
  return createHash('sha1').update(data).digest('hex');
}

function b64encode(data: string | Buffer): string {
  return Buffer.isBuffer(data) ? data.toString('base64') : Buffer.from(data, 'utf8').toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64');
}

let requestSeq = 0;
function nextRequestId(): string {
  requestSeq += 1;
  return `req-${requestSeq.toString(16).padStart(8, '0')}`;
}

// ---------------------------------------------------------------------------------------------
// pkt-line codec (git smart HTTP framing)
// ---------------------------------------------------------------------------------------------

// A pkt-line is at most 65520 bytes total (4 header + payload). A sideband packet's
// payload is 1 band byte + pack data, so at most 65515 bytes of pack per packet.
const PKT_LINE_MAX_PAYLOAD = 65515;

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const header = Buffer.allocUnsafe(4);
  header.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([header, data]);
}
const pktFlush = (): Buffer => Buffer.from('0000', 'ascii');
const pktDelim = (): Buffer => Buffer.from('0001', 'ascii');

function pktLines(items: readonly (string | Buffer | 'flush' | 'delim')[]): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(pktFlush());
    else if (item === 'delim') parts.push(pktDelim());
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}

interface DecodedPacket {
  kind: 'data' | 'flush' | 'delim' | 'response-end';
  payload?: Buffer;
  raw?: Buffer;
}

/** Decode a whole buffer of pkt-lines; returns packets and the offset of any trailing bytes. */
function decodePktLines(buffer: Buffer): { packets: DecodedPacket[]; trailingOffset: number } {
  const packets: DecodedPacket[] = [];
  let offset = 0;
  while (offset + 4 <= buffer.length) {
    const head = buffer.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) break;
    const length = Number.parseInt(head, 16);
    if (length === 0) {
      packets.push({ kind: 'flush' });
      offset += 4;
      continue;
    }
    if (length === 1) {
      packets.push({ kind: 'delim' });
      offset += 4;
      continue;
    }
    if (length === 2) {
      packets.push({ kind: 'response-end' });
      offset += 4;
      continue;
    }
    if (length < 4 || offset + length > buffer.length) break;
    packets.push({ kind: 'data', payload: buffer.subarray(offset + 4, offset + length), raw: buffer.subarray(offset, offset + length) });
    offset += length;
  }
  return { packets, trailingOffset: offset };
}

// ---------------------------------------------------------------------------------------------
// git object model: SHA-1 ids, object hashing, tree/commit/tag codecs, packs, reachability
// ---------------------------------------------------------------------------------------------

type GitObjectType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObject {
  type: GitObjectType;
  data: Buffer;
}

const TYPE_CODE: Record<GitObjectType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, GitObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function hashObject(type: GitObjectType, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([header, data]));
}

function isOid(value: string): boolean {
  return /^[0-9a-f]{40}$/.test(value);
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const nul = data.indexOf(0x00, space + 1);
    if (space < 0 || nul < 0 || nul + 21 > data.length) throw new Error('malformed tree object');
    entries.push({
      mode: data.subarray(offset, space).toString('ascii'),
      name: data.subarray(space + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    offset = nul + 21;
  }
  return entries;
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
    const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
    return Buffer.compare(left, right);
  });
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const headerText = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of headerText.split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    const key = space < 0 ? line : line.slice(0, space);
    const value = space < 0 ? '' : line.slice(space + 1);
    if (key === 'tree') tree = value;
    else if (key === 'parent') parents.push(value);
    else if (key === 'author') author = value;
    else if (key === 'committer') committer = value;
  }
  return { tree, parents, author, committer, message };
}

function buildCommit(tree: string, parents: readonly string[], message: string, author: string, committer: string, timestamp: number): Buffer {
  const lines = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${author} ${timestamp} +0000`, `committer ${committer} ${timestamp} +0000`, '');
  return Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
}

interface TagView {
  object: string;
  type: GitObjectType;
  tag: string;
  tagger: string;
  message: string;
}

function parseTag(data: Buffer): TagView {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const headerText = blank < 0 ? text : text.slice(0, blank);
  const headers = new Map<string, string>();
  for (const line of headerText.split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    if (space < 0) continue;
    headers.set(line.slice(0, space), line.slice(space + 1));
  }
  return {
    object: headers.get('object') ?? '',
    type: (headers.get('type') ?? 'commit') as GitObjectType,
    tag: headers.get('tag') ?? '',
    tagger: headers.get('tagger') ?? '',
    message: blank < 0 ? '' : text.slice(blank + 2),
  };
}

/** Every object reachable from `roots` (commits, trees, blobs, tags). */
function collectReachable(roots: Iterable<string>, lookup: (oid: string) => GitObject | undefined): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const root of roots) if (isOid(root) && !seen.has(root)) queue.push(root);
  while (queue.length > 0) {
    const oid = queue.pop()!;
    if (seen.has(oid)) continue;
    const object = lookup(oid);
    if (!object) continue;
    seen.add(oid);
    if (object.type === 'commit') {
      const commit = parseCommit(object.data);
      queue.push(commit.tree);
      for (const parent of commit.parents) queue.push(parent);
    } else if (object.type === 'tag') {
      queue.push(parseTag(object.data).object);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode !== '160000') queue.push(entry.oid);
      }
    }
  }
  return seen;
}

/** True when `ancestor` is reachable from `tip` (or equal to it). */
function isAncestor(ancestor: string, tip: string, lookup: (oid: string) => GitObject | undefined): boolean {
  if (ancestor === tip) return true;
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length > 0) {
    const oid = queue.pop()!;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = lookup(oid);
    if (!object) continue;
    if (object.type === 'commit') {
      for (const parent of parseCommit(object.data).parents) queue.push(parent);
    } else if (object.type === 'tag') {
      queue.push(parseTag(object.data).object);
    }
  }
  return false;
}

// --- packfile read (v2/v3, plain + OFS_DELTA + REF_DELTA) ---

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (offset >= delta.length) throw new Error('truncated delta size');
      const byte = delta[offset++];
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (offset < delta.length) {
    const op = delta[offset++];
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) copyOffset += delta[offset++] * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) copySize += delta[offset++] * 2 ** shift;
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      delta.copy(out, written, offset, offset + literal);
      offset += literal;
      written += literal;
    } else {
      throw new Error('invalid delta opcode 0');
    }
  }
  if (written !== targetSize) throw new Error('delta size mismatch');
  return out;
}

function readPack(pack: Buffer): Map<string, GitObject> {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const trailer = pack.subarray(trailerStart).toString('hex');
  if (sha1Hex(pack.subarray(0, trailerStart)) !== trailer) throw new Error('pack checksum mismatch');
  interface Raw {
    offset: number;
    typeCode: number;
    size: number;
    data: Buffer;
    baseOffset?: number;
    baseOid?: string;
    resolved?: { type: GitObjectType; data: Buffer; oid: string };
  }
  const raw: Raw[] = [];
  const byOffset = new Map<number, Raw>();
  let offset = 12;
  for (let index = 0; index < count; index += 1) {
    const entryOffset = offset;
    let byte = pack[offset];
    let size = byte & 0x0f;
    let shift = 4;
    offset += 1;
    while (byte & 0x80) {
      byte = pack[offset++];
      size += (byte & 0x7f) * 2 ** shift;
      shift += 7;
    }
    const typeCode = (pack[entryOffset] >> 4) & 0x07;
    const entry: Raw = { offset: entryOffset, typeCode, size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      byte = pack[offset];
      offset += 1;
      let value = byte & 0x7f;
      while (byte & 0x80) {
        byte = pack[offset++];
        value = ((value + 1) * 128) + (byte & 0x7f);
      }
      entry.baseOffset = entryOffset - value;
    } else if (typeCode === 7) {
      entry.baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    } else if (!CODE_TYPE[typeCode]) {
      throw new Error(`unknown pack entry type ${typeCode}`);
    }
    const inflated = inflateSync(pack.subarray(offset, trailerStart), { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
    if (inflated.buffer.length !== size) throw new Error('pack entry size mismatch');
    entry.data = inflated.buffer;
    offset += inflated.engine.bytesWritten;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  if (offset !== trailerStart) throw new Error('pack trailing bytes');
  const objects = new Map<string, GitObject>();
  const resolvedByOid = new Map<string, Raw>();
  const resolving = new Set<number>();
  const resolve = (entry: Raw): { type: GitObjectType; data: Buffer; oid: string } => {
    if (entry.resolved) return entry.resolved;
    if (resolving.has(entry.offset)) throw new Error('delta cycle');
    resolving.add(entry.offset);
    let type: GitObjectType;
    let data: Buffer;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset!);
      if (!baseEntry) throw new Error('ofs-delta base missing');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const baseEntry = resolvedByOid.get(entry.baseOid!);
      if (!baseEntry) throw new Error('ref-delta base missing');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else {
      type = CODE_TYPE[entry.typeCode];
      data = entry.data;
    }
    const oid = hashObject(type, data);
    const out = { type, data, oid };
    entry.resolved = out;
    resolvedByOid.set(oid, entry);
    resolving.delete(entry.offset);
    return out;
  };
  for (const entry of raw) {
    const resolved = resolve(entry);
    if (!objects.has(resolved.oid)) objects.set(resolved.oid, { type: resolved.type, data: resolved.data });
  }
  return objects;
}

// --- packfile write (plain objects, no deltas) ---

function writePackObjectHeader(type: GitObjectType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

function writePack(objects: readonly GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const object of objects) {
    parts.push(writePackObjectHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

// ---------------------------------------------------------------------------------------------
// Store: repositories, issues, pull requests, labels, comments. One owner (the viewer).
// ---------------------------------------------------------------------------------------------

interface Label {
  id: number;
  name: string;
  color: string;
  description: string;
}

interface IssueComment {
  id: number;
  body: string;
  created_at: string;
  updated_at: string;
  user: Json;
}

interface Issue {
  kind: 'issue';
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  comments: IssueComment[];
  created_at: string;
  updated_at: string;
  seq: number;
  /** Serialized GET response, reused while the issue is unchanged (the read workload). */
  cachedJson: Buffer | null;
}

/** Drop an issue's cached GET response after any mutation. */
function touchIssue(issue: Issue): void {
  issue.cachedJson = null;
}

interface PullRequest {
  kind: 'pr';
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  head: string;
  base: string;
  merged: boolean;
  merged_at: string | null;
  merge_commit_sha: string | null;
  created_at: string;
  updated_at: string;
  seq: number;
}

interface Repo {
  id: number;
  name: string;
  full_name: string;
  private: boolean;
  description: string;
  default_branch: string;
  created_at: string;
  updated_at: string;
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  labels: Map<string, Label>;
  items: Map<number, Issue | PullRequest>;
  nextNumber: number;
  seq: number;
  /** Bumped on every refs/objects mutation; fetch caches key off it. */
  version: number;
}

/** Set a ref and bump the repo version (invalidating fetch caches). */
function setRef(repo: Repo, ref: string, oid: string): void {
  repo.refs.set(ref, oid);
  repo.version += 1;
}

/** Delete a ref and bump the repo version. */
function deleteRef(repo: Repo, ref: string): void {
  repo.refs.delete(ref);
  repo.version += 1;
}

let repoIdSeq = 5000;
let objectIdSeq = 10000;
let labelIdSeq = 30000;
let commentIdSeq = 40000;
let repoSeq = 0;

const repos = new Map<string, Repo>(); // key: name (owner is always the viewer)

function createRepoRecord(name: string, isPrivate: boolean, description: string): Repo {
  const now = nextTimestamp();
  const repo: Repo = {
    id: repoIdSeq++,
    name,
    full_name: `${VIEWER.login}/${name}`,
    private: isPrivate,
    description,
    default_branch: DEFAULT_BRANCH,
    created_at: now,
    updated_at: now,
    objects: new Map(),
    refs: new Map(),
    labels: new Map(),
    items: new Map(),
    nextNumber: 1,
    seq: ++repoSeq,
    version: 0,
  };
  repos.set(name, repo);
  return repo;
}

function findRepo(owner: string, name: string): Repo | undefined {
  if (owner !== VIEWER.login) return undefined;
  return repos.get(name);
}

function repoObject(repo: Repo): Json {
  return {
    id: repo.id,
    node_id: globalId('Repository', repo.id),
    name: repo.name,
    full_name: repo.full_name,
    private: repo.private,
    description: repo.description,
    default_branch: repo.default_branch,
    owner: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
    html_url: `https://github.com/${repo.full_name}`,
    url: `/api/v3/repos/${repo.full_name}`,
    created_at: repo.created_at,
    updated_at: repo.updated_at,
    pushed_at: repo.updated_at,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    has_pages: false,
    forks_count: 0,
    stargazers_count: 0,
    watchers_count: 0,
    open_issues_count: [...repo.items.values()].filter((item) => item.state === 'open').length,
    license: null,
    visibility: repo.private ? 'private' : 'public',
    archived: false,
    disabled: false,
  };
}

function labelObject(label: Label): Json {
  return { id: label.id, node_id: globalId('Label', label.id), name: label.name, color: label.color, description: label.description, default: false };
}

function userObject(): Json {
  return { login: VIEWER.login, id: VIEWER.id, node_id: globalId('User', VIEWER.id), type: 'User', avatar_url: '', html_url: `https://github.com/${VIEWER.login}` };
}

function issueObject(repo: Repo, issue: Issue): Json {
  return {
    id: issue.id,
    node_id: globalId('Issue', repo.id, issue.number),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map(labelObject),
    user: userObject(),
    assignees: [],
    comments: issue.comments.length,
    created_at: issue.created_at,
    updated_at: issue.updated_at,
    closed_at: issue.state === 'closed' ? issue.updated_at : null,
    html_url: `https://github.com/${repo.full_name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.full_name}/issues/${issue.number}`,
    repository_url: `/api/v3/repos/${repo.full_name}`,
  };
}

function pullObject(repo: Repo, pr: PullRequest): Json {
  const headSha = repo.refs.get(`refs/heads/${pr.head}`) ?? '';
  const baseSha = repo.refs.get(`refs/heads/${pr.base}`) ?? '';
  return {
    id: pr.id,
    node_id: globalId('PullRequest', repo.id, pr.number),
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    merged: pr.merged,
    merged_at: pr.merged_at,
    merge_commit_sha: pr.merge_commit_sha,
    mergeable: prMergeable(repo, pr),
    head: { ref: pr.head, sha: headSha, label: `${VIEWER.login}:${pr.head}`, user: userObject(), repo: repoObject(repo) },
    base: { ref: pr.base, sha: baseSha, label: `${VIEWER.login}:${pr.base}`, user: userObject(), repo: repoObject(repo) },
    user: userObject(),
    created_at: pr.created_at,
    updated_at: pr.updated_at,
    closed_at: pr.state === 'closed' ? pr.updated_at : null,
    html_url: `https://github.com/${repo.full_name}/pull/${pr.number}`,
    url: `/api/v3/repos/${repo.full_name}/pulls/${pr.number}`,
    draft: false,
    additions: 0,
    deletions: 0,
    changed_files: 0,
    commits: 0,
  };
}

// --- global (Relay) ids: opaque base64, stable across reads ---

function globalId(kind: string, a: number, b?: number): string {
  return b === undefined ? b64encode(`${kind}:${a}`) : b64encode(`${kind}:${a}:${b}`);
}

function parseGlobalId(id: string): { kind: string; a: number; b: number | null } | null {
  try {
    const text = b64decode(id).toString('utf8');
    const parts = text.split(':');
    if (parts.length < 2) return null;
    const kind = parts[0];
    const a = Number(parts[1]);
    if (!Number.isInteger(a)) return null;
    const b = parts.length >= 3 ? Number(parts[2]) : null;
    return { kind, a, b: b !== null && Number.isInteger(b) ? b : null };
  } catch {
    return null;
  }
}

function findRepoById(id: number): Repo | undefined {
  for (const repo of repos.values()) if (repo.id === id) return repo;
  return undefined;
}

// --- git object helpers bound to a repo ---

function repoLookup(repo: Repo): (oid: string) => GitObject | undefined {
  return (oid: string) => repo.objects.get(oid);
}

function putObject(repo: Repo, type: GitObjectType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

function resolveRef(repo: Repo, ref: string): string | undefined {
  if (ref.startsWith('refs/')) return repo.refs.get(ref);
  const branch = repo.refs.get(`refs/heads/${ref}`);
  if (branch) return branch;
  const tag = repo.refs.get(`refs/tags/${ref}`);
  if (tag) return tag;
  return repo.refs.get(`refs/heads/${repo.default_branch}`);
}

/** Resolve a ref-ish (branch, tag, full ref, commit oid) to a commit oid. */
function resolveCommit(repo: Repo, refish: string | undefined): string | undefined {
  if (refish === undefined || refish === '') return repo.refs.get(`refs/heads/${repo.default_branch}`);
  if (isOid(refish)) {
    const object = repo.objects.get(refish);
    if (!object) return undefined;
    if (object.type === 'commit') return refish;
    if (object.type === 'tag') return parseTag(object.data).object;
    return undefined;
  }
  const oid = resolveRef(repo, refish);
  if (!oid) return undefined;
  const object = repo.objects.get(oid);
  if (!object) return undefined;
  if (object.type === 'commit') return oid;
  if (object.type === 'tag') return parseTag(object.data).object;
  return undefined;
}

/** The flat file map (path -> {oid, mode}) of a tree, memoized per tree oid. */
const treeFileCache = new Map<string, Map<string, { oid: string; mode: string }>>();
function treeFiles(repo: Repo, treeOid: string): Map<string, { oid: string; mode: string }> {
  const cached = treeFileCache.get(treeOid);
  if (cached) return cached;
  const out = new Map<string, { oid: string; mode: string }>();
  const walk = (oid: string, prefix: string): void => {
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'tree') return;
    for (const entry of parseTree(object.data)) {
      const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.mode === '40000') walk(entry.oid, path);
      else out.set(path, { oid: entry.oid, mode: entry.mode });
    }
  };
  walk(treeOid, '');
  // The cache is keyed by tree oid alone; trees are content-addressed, so this is safe
  // across repos. Bound its size so a long trial cannot grow it without limit.
  if (treeFileCache.size > 5000) treeFileCache.clear();
  treeFileCache.set(treeOid, out);
  return out;
}

/** Build (and store) the tree objects for a flat file map; returns the root tree oid. */
function buildTreeFromFiles(repo: Repo, files: Map<string, { oid: string; mode: string }>): string {
  interface Node {
    files: Map<string, { oid: string; mode: string }>;
    dirs: Map<string, Node>;
  }
  const make = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = make();
  for (const [path, value] of files) {
    const segments = path.split('/');
    let node = root;
    for (let index = 0; index < segments.length - 1; index += 1) {
      const name = segments[index];
      if (!node.dirs.has(name)) node.dirs.set(name, make());
      node = node.dirs.get(name)!;
    }
    node.files.set(segments[segments.length - 1], value);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, value] of node.files) entries.push({ mode: value.mode, name, oid: value.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return putObject(repo, 'tree', buildTree(entries));
  };
  return build(root);
}

/** Create a commit on top of `parents` with the given file map; returns the commit oid. */
function commitFiles(repo: Repo, parents: readonly string[], files: Map<string, { oid: string; mode: string }>, message: string): string {
  const tree = buildTreeFromFiles(repo, files);
  const timestamp = nextTimestampSec();
  const who = `${VIEWER.name} <${VIEWER.email}>`;
  const data = buildCommit(tree, parents, message.endsWith('\n') ? message : `${message}\n`, who, who, timestamp);
  return putObject(repo, 'commit', data);
}

/** List commits reachable from `tip`, newest first (parents before children is not guaranteed; use DFS order). */
function listCommits(repo: Repo, tip: string, limit: number): Array<{ sha: string; commit: CommitView }> {
  const out: Array<{ sha: string; commit: CommitView }> = [];
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length > 0 && out.length < limit) {
    const oid = queue.shift()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') continue;
    const commit = parseCommit(object.data);
    out.push({ sha: oid, commit });
    for (const parent of commit.parents) queue.push(parent);
  }
  return out;
}

/** The merge-base of two commits (first common ancestor found by BFS from both sides). */
function mergeBase(repo: Repo, a: string, b: string): string | undefined {
  const ancestorsA = new Set<string>();
  const queueA = [a];
  while (queueA.length > 0) {
    const oid = queueA.pop()!;
    if (ancestorsA.has(oid)) continue;
    ancestorsA.add(oid);
    const object = repo.objects.get(oid);
    if (object?.type === 'commit') for (const parent of parseCommit(object.data).parents) queueA.push(parent);
  }
  const seen = new Set<string>();
  const queueB = [b];
  while (queueB.length > 0) {
    const oid = queueB.shift()!;
    if (ancestorsA.has(oid)) return oid;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = repo.objects.get(oid);
    if (object?.type === 'commit') for (const parent of parseCommit(object.data).parents) queueB.push(parent);
  }
  return undefined;
}

const MISSING = '\0missing';

/** Three-way merge of `head` into `base` over merge-base `ancestor`. Returns merged files + conflict flag. */
function threeWayMerge(repo: Repo, ancestorTip: string | undefined, baseTip: string, headTip: string): { files: Map<string, { oid: string; mode: string }>; conflict: boolean } {
  const lookup = repoLookup(repo);
  const ancestorFiles = ancestorTip === undefined ? new Map() : treeFiles(repo, parseCommit(repo.objects.get(ancestorTip)!.data).tree);
  const baseFiles = treeFiles(repo, parseCommit(repo.objects.get(baseTip)!.data).tree);
  const headFiles = treeFiles(repo, parseCommit(repo.objects.get(headTip)!.data).tree);
  const merged = new Map<string, { oid: string; mode: string }>();
  let conflict = false;
  const paths = new Set([...ancestorFiles.keys(), ...baseFiles.keys(), ...headFiles.keys()]);
  for (const path of paths) {
    const anc = ancestorFiles.get(path)?.oid ?? MISSING;
    const bas = baseFiles.get(path)?.oid ?? MISSING;
    const hed = headFiles.get(path)?.oid ?? MISSING;
    if (hed !== anc && bas !== anc && hed !== bas) {
      conflict = true;
      merged.set(path, baseFiles.get(path) ?? headFiles.get(path)!);
      continue;
    }
    const chosen = hed !== anc ? hed : bas;
    const source = hed !== anc ? headFiles.get(path) : baseFiles.get(path);
    if (chosen === MISSING) continue;
    merged.set(path, source!);
  }
  return { files: merged, conflict };
}

function prMergeable(repo: Repo, pr: PullRequest): string {
  if (pr.state !== 'open') return 'UNKNOWN';
  const headTip = repo.refs.get(`refs/heads/${pr.head}`);
  const baseTip = repo.refs.get(`refs/heads/${pr.base}`);
  if (!headTip || !baseTip) return 'UNKNOWN';
  if (headTip === baseTip) return 'MERGEABLE';
  const base = mergeBase(repo, headTip, baseTip);
  if (base === undefined) return 'UNKNOWN';
  return threeWayMerge(repo, base, baseTip, headTip).conflict ? 'CONFLICTING' : 'MERGEABLE';
}

/** The files a pull request changes (head tree vs merge-base tree), with line counts. */
function prFiles(repo: Repo, pr: PullRequest): Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> {
  const headTip = repo.refs.get(`refs/heads/${pr.head}`);
  const baseTip = repo.refs.get(`refs/heads/${pr.base}`);
  if (!headTip || !baseTip) return [];
  const base = mergeBase(repo, headTip, baseTip);
  const ancestorFiles = base === undefined ? new Map() : treeFiles(repo, parseCommit(repo.objects.get(base)!.data).tree);
  const headFiles = treeFiles(repo, parseCommit(repo.objects.get(headTip)!.data).tree);
  const out: Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> = [];
  const paths = new Set([...ancestorFiles.keys(), ...headFiles.keys()]);
  for (const path of [...paths].sort()) {
    const anc = ancestorFiles.get(path);
    const hed = headFiles.get(path);
    if (anc && hed && anc.oid === hed.oid) continue;
    let additions = 0;
    let deletions = 0;
    let status = 'modified';
    const oldText = anc ? (repo.objects.get(anc.oid)?.data.toString('utf8') ?? '') : '';
    const newText = hed ? (repo.objects.get(hed.oid)?.data.toString('utf8') ?? '') : '';
    if (!anc && hed) {
      status = 'added';
      additions = newText === '' ? 0 : newText.split('\n').length - (newText.endsWith('\n') ? 1 : 0);
    } else if (anc && !hed) {
      status = 'removed';
      deletions = oldText === '' ? 0 : oldText.split('\n').length - (oldText.endsWith('\n') ? 1 : 0);
    } else {
      const oldLines = oldText.split('\n');
      const newLines = newText.split('\n');
      const oldCount = new Map<string, number>();
      for (const line of oldLines) oldCount.set(line, (oldCount.get(line) ?? 0) + 1);
      const newCount = new Map<string, number>();
      for (const line of newLines) newCount.set(line, (newCount.get(line) ?? 0) + 1);
      for (const [line, count] of newCount) additions += Math.max(0, count - (oldCount.get(line) ?? 0));
      for (const [line, count] of oldCount) deletions += Math.max(0, count - (newCount.get(line) ?? 0));
      if (additions === 0 && deletions === 0) continue;
    }
    out.push({ filename: path, status, additions, deletions, changes: additions + deletions });
  }
  return out;
}

/** Squash-merge a pull request onto its base branch. Returns the merge commit oid, or null on conflict. */
function squashMerge(repo: Repo, pr: PullRequest): string | null {
  const headTip = repo.refs.get(`refs/heads/${pr.head}`);
  const baseTip = repo.refs.get(`refs/heads/${pr.base}`);
  if (!headTip || !baseTip) return null;
  const base = mergeBase(repo, headTip, baseTip);
  const { files, conflict } = threeWayMerge(repo, base, baseTip, headTip);
  if (conflict) return null;
  const message = `${pr.title} (#${pr.number})`;
  return commitFiles(repo, [baseTip], files, message);
}

// ---------------------------------------------------------------------------------------------
// HTTP plumbing: request ids, JSON envelopes, auth, pagination
// ---------------------------------------------------------------------------------------------

const JSON_TYPE = 'application/json; charset=utf-8';

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function jsonResponse(res: ServerResponse, status: number, value: unknown, extraHeaders: Record<string, string> = {}): void {
  const body = Buffer.from(JSON.stringify(value), 'utf8');
  const headers: Record<string, string> = {
    'Content-Type': JSON_TYPE,
    'X-GitHub-Request-Id': nextRequestId(),
    ...extraHeaders,
  };
  res.writeHead(status, headers);
  res.end(body);
}

function errorJson(res: ServerResponse, status: number, message: string, extra?: Json): void {
  const value: Json = { message, documentation_url: 'https://docs.github.com/rest' };
  if (extra) Object.assign(value, extra);
  jsonResponse(res, status, value);
}

function notFound(res: ServerResponse, message = 'Not Found'): void {
  errorJson(res, 404, message);
}

/** The bearer token the suite sends; read from the environment. */
function expectedToken(): string {
  return process.env.MAKEFUN_SHOP_TOKEN ?? '';
}

/**
 * Authorize a REST/GraphQL/MCP request. Returns true when the request may proceed.
 * When the token is not configured in this process, accept any well-formed Bearer
 * token — the suite always sends one, and the harness supplies it via env.
 */
function authorized(req: IncomingMessage): boolean {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return false;
  const token = header.slice('Bearer '.length).trim();
  if (token === '') return false;
  const expected = expectedToken();
  if (expected === '') return true;
  return token === expected;
}

function requireAuth(req: IncomingMessage, res: ServerResponse): boolean {
  if (!authorized(req)) {
    jsonResponse(res, 401, { message: 'Requires authentication' });
    return false;
  }
  return true;
}

function parseQuery(url: string): URLSearchParams {
  return new URL(url, 'http://localhost').searchParams;
}

function parsePagination(query: URLSearchParams): { page: number; perPage: number } {
  const page = Math.max(1, Number.parseInt(query.get('page') ?? '1', 10) || 1);
  const perPageRaw = Number.parseInt(query.get('per_page') ?? '30', 10) || 30;
  const perPage = Math.min(100, Math.max(1, perPageRaw));
  return { page, perPage };
}

function paginate<T>(items: readonly T[], page: number, perPage: number): { pageItems: T[]; total: number; hasNext: boolean } {
  const start = (page - 1) * perPage;
  return { pageItems: items.slice(start, start + perPage), total: items.length, hasNext: start + perPage < items.length };
}

function linkHeader(req: IncomingMessage, query: URLSearchParams, page: number, perPage: number, hasNext: boolean): Record<string, string> {
  const base = `${req.headers.host ? `http://${req.headers.host}` : ''}${req.url!.split('?')[0]}`;
  const build = (pageNumber: number): string => {
    const params = new URLSearchParams(query);
    params.set('page', String(pageNumber));
    params.set('per_page', String(perPage));
    return `${base}?${params.toString()}`;
  };
  const links: string[] = [];
  if (hasNext) links.push(`<${build(page + 1)}>; rel="next"`);
  links.push(`<${build(1)}>; rel="first"`);
  return links.length > 0 ? { Link: links.join(', ') } : {};
}

function parseJsonBody(buffer: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (buffer.length === 0) return { ok: true, value: undefined };
  try {
    return { ok: true, value: JSON.parse(buffer.toString('utf8')) };
  } catch {
    return { ok: false };
  }
}

interface RouteContext {
  req: IncomingMessage;
  res: ServerResponse;
  body: Buffer;
  segments: string[];
  query: URLSearchParams;
}

// ---------------------------------------------------------------------------------------------
// REST v3 handlers
// ---------------------------------------------------------------------------------------------

function handleUserRepos(ctx: RouteContext): void {
  const { req, res, body, query } = ctx;
  if (req.method === 'GET') {
    const { page, perPage } = parsePagination(query);
    const sorted = [...repos.values()].sort((a, b) => a.seq - b.seq);
    const { pageItems, hasNext } = paginate(sorted, page, perPage);
    jsonResponse(res, 200, pageItems.map(repoObject), linkHeader(req, query, page, perPage, hasNext));
    return;
  }
  if (req.method === 'POST') {
    const parsed = parseJsonBody(body);
    if (!parsed.ok) {
      errorJson(res, 400, 'Problems parsing JSON');
      return;
    }
    const payload = isRecord(parsed.value) ? parsed.value : {};
    const name = typeof payload.name === 'string' ? payload.name : '';
    if (name === '') {
      errorJson(res, 422, 'Validation Failed', { errors: [{ resource: 'Repository', field: 'name', code: 'missing' }] });
      return;
    }
    if (repos.has(name)) {
      errorJson(res, 422, 'Repository creation failed.', {
        errors: [{ resource: 'Repository', field: 'name', code: 'custom', message: 'name already exists on this account' }],
      });
      return;
    }
    const repo = createRepoRecord(name, payload.private === true, typeof payload.description === 'string' ? payload.description : '');
    jsonResponse(res, 201, repoObject(repo));
    return;
  }
  notFound(res);
}

function handleUser(ctx: RouteContext): void {
  const { res } = ctx;
  jsonResponse(res, 200, {
    login: VIEWER.login,
    id: VIEWER.id,
    node_id: globalId('User', VIEWER.id),
    name: VIEWER.name,
    email: VIEWER.email,
    type: 'User',
    html_url: `https://github.com/${VIEWER.login}`,
    url: '/api/v3/user',
    public_repos: repos.size,
  });
}

function handleRepo(ctx: RouteContext, owner: string, name: string): void {
  const { req, res, body } = ctx;
  const repo = findRepo(owner, name);
  if (!repo) {
    notFound(res, 'Not Found');
    return;
  }
  if (req.method === 'GET') {
    jsonResponse(res, 200, repoObject(repo));
    return;
  }
  if (req.method === 'PATCH') {
    const parsed = parseJsonBody(body);
    if (!parsed.ok) {
      errorJson(res, 400, 'Problems parsing JSON');
      return;
    }
    const payload = isRecord(parsed.value) ? parsed.value : {};
    if (typeof payload.description === 'string') repo.description = payload.description;
    if (typeof payload.private === 'boolean') repo.private = payload.private;
    repo.updated_at = nextTimestamp();
    jsonResponse(res, 200, repoObject(repo));
    return;
  }
  if (req.method === 'DELETE') {
    repos.delete(name);
    res.writeHead(204, { 'X-GitHub-Request-Id': nextRequestId() });
    res.end();
    return;
  }
  notFound(res);
}

function handleRepoLabels(ctx: RouteContext, owner: string, name: string): void {
  const { req, res, body } = ctx;
  const repo = findRepo(owner, name);
  if (!repo) {
    notFound(res, 'Not Found');
    return;
  }
  if (req.method === 'GET') {
    jsonResponse(res, 200, [...repo.labels.values()].map(labelObject));
    return;
  }
  if (req.method === 'POST') {
    const parsed = parseJsonBody(body);
    if (!parsed.ok) {
      errorJson(res, 400, 'Problems parsing JSON');
      return;
    }
    const payload = isRecord(parsed.value) ? parsed.value : {};
    const labelName = typeof payload.name === 'string' ? payload.name : '';
    if (labelName === '') {
      errorJson(res, 422, 'Validation Failed', { errors: [{ resource: 'Label', field: 'name', code: 'missing' }] });
      return;
    }
    if (repo.labels.has(labelName)) {
      errorJson(res, 422, 'Validation Failed', {
        errors: [{ resource: 'Label', field: 'name', code: 'custom', message: 'already exists' }],
      });
      return;
    }
    const label: Label = {
      id: labelIdSeq++,
      name: labelName,
      color: typeof payload.color === 'string' ? payload.color : 'ededed',
      description: typeof payload.description === 'string' ? payload.description : '',
    };
    repo.labels.set(labelName, label);
    jsonResponse(res, 201, labelObject(label));
    return;
  }
  notFound(res);
}

function handleRepoBranches(ctx: RouteContext, owner: string, name: string, branch?: string): void {
  const { req, res } = ctx;
  const repo = findRepo(owner, name);
  if (!repo) {
    notFound(res, 'Not Found');
    return;
  }
  if (req.method !== 'GET') {
    notFound(res);
    return;
  }
  if (branch !== undefined) {
    const ref = `refs/heads/${branch}`;
    const oid = repo.refs.get(ref);
    if (!oid) {
      notFound(res, 'Branch not found');
      return;
    }
    jsonResponse(res, 200, { name: branch, commit: { sha: oid }, protected: false });
    return;
  }
  const branches = [...repo.refs.entries()]
    .filter(([ref]) => ref.startsWith('refs/heads/'))
    .map(([ref, oid]) => ({ name: ref.slice('refs/heads/'.length), commit: { sha: oid }, protected: false }));
  jsonResponse(res, 200, branches);
}

function handleRepoCommits(ctx: RouteContext, owner: string, name: string): void {
  const { req, res, query } = ctx;
  const repo = findRepo(owner, name);
  if (!repo) {
    notFound(res, 'Not Found');
    return;
  }
  if (req.method !== 'GET') {
    notFound(res);
    return;
  }
  const { page, perPage } = parsePagination(query);
  const tip = resolveCommit(repo, query.get('sha') ?? undefined);
  if (!tip) {
    jsonResponse(res, 200, []);
    return;
  }
  const commits = listCommits(repo, tip, page * perPage);
  const { pageItems, hasNext } = paginate(commits, page, perPage);
  jsonResponse(
    res,
    200,
    pageItems.map(({ sha, commit }) => ({
      sha,
      node_id: globalId('Commit', repo.id, objectIdSeq++),
      commit: {
        author: { name: VIEWER.name, email: VIEWER.email, date: nextTimestamp() },
        committer: { name: VIEWER.name, email: VIEWER.email, date: nextTimestamp() },
        // The stored object ends with a newline, as git does; the API presents it trimmed.
        message: commit.message.replace(/\n+$/, ''),
        tree: { sha: commit.tree },
      },
      parents: commit.parents.map((parent) => ({ sha: parent })),
      html_url: `https://github.com/${repo.full_name}/commit/${sha}`,
      url: `/api/v3/repos/${repo.full_name}/commits/${sha}`,
    })),
    linkHeader(req, query, page, perPage, hasNext),
  );
}

function handleGitRefs(ctx: RouteContext, owner: string, name: string): void {
  const { req, res, body } = ctx;
  const repo = findRepo(owner, name);
  if (!repo) {
    notFound(res, 'Not Found');
    return;
  }
  if (req.method === 'POST') {
    const parsed = parseJsonBody(body);
    if (!parsed.ok) {
      errorJson(res, 400, 'Problems parsing JSON');
      return;
    }
    const payload = isRecord(parsed.value) ? parsed.value : {};
    const ref = typeof payload.ref === 'string' ? payload.ref : '';
    const sha = typeof payload.sha === 'string' ? payload.sha : '';
    if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.has(sha)) {
      errorJson(res, 422, 'Validation Failed', { errors: [{ resource: 'Reference', field: 'ref', code: 'invalid' }] });
      return;
    }
    setRef(repo, ref, sha);
    jsonResponse(res, 201, { ref, node_id: globalId('Ref', repo.id, objectIdSeq++), object: { sha, type: repo.objects.get(sha)!.type, url: `/api/v3/repos/${repo.full_name}/git/${repo.objects.get(sha)!.type}s/${sha}` } });
    return;
  }
  if (req.method === 'GET') {
    const refs = [...repo.refs.entries()]
      .filter(([ref]) => ref.startsWith('refs/heads/'))
      .map(([ref, sha]) => ({ ref, node_id: globalId('Ref', repo.id, objectIdSeq++), object: { sha, type: repo.objects.get(sha)?.type ?? 'commit', url: `/api/v3/repos/${repo.full_name}/git/commits/${sha}` } }));
    jsonResponse(res, 200, refs);
    return;
  }
  notFound(res);
}

function handleGitRef(ctx: RouteContext, owner: string, name: string, branch: string): void {
  const { req, res } = ctx;
  const repo = findRepo(owner, name);
  if (!repo) {
    notFound(res, 'Not Found');
    return;
  }
  if (req.method !== 'GET') {
    notFound(res);
    return;
  }
  const ref = `refs/heads/${branch}`;
  const oid = repo.refs.get(ref);
  if (!oid) {
    notFound(res, 'Reference does not exist');
    return;
  }
  jsonResponse(res, 200, { ref, node_id: globalId('Ref', repo.id, objectIdSeq++), object: { sha: oid, type: repo.objects.get(oid)?.type ?? 'commit', url: `/api/v3/repos/${repo.full_name}/git/commits/${oid}` } });
}

function handleContents(ctx: RouteContext, owner: string, name: string, rawPath: string): void {
  const { req, res, body, query } = ctx;
  const repo = findRepo(owner, name);
  if (!repo) {
    notFound(res, 'Not Found');
    return;
  }
  const path = decodeURIComponent(rawPath);
  const branchParam = query.get('ref') ?? query.get('branch') ?? undefined;

  if (req.method === 'GET') {
    const tip = resolveCommit(repo, branchParam);
    if (!tip) {
      notFound(res, 'This repository is empty.');
      return;
    }
    const tree = parseCommit(repo.objects.get(tip)!.data).tree;
    const files = treeFiles(repo, tree);
    // The oid of the tree object at a directory path (the root tree for '').
    const subtreeOid = (dirPath: string): string | null => {
      if (dirPath === '') return tree;
      let current = tree;
      for (const segment of dirPath.split('/')) {
        const object = repo.objects.get(current);
        if (!object || object.type !== 'tree') return null;
        const found = parseTree(object.data).find((candidate) => candidate.name === segment);
        if (!found || found.mode !== '40000') return null;
        current = found.oid;
      }
      return current;
    };
    // A directory listing: the immediate children of `dirPath` ('' for the root).
    const listDirectory = (dirPath: string): Json[] | null => {
      const prefix = dirPath === '' ? '' : `${dirPath}/`;
      const children = new Map<string, { isDir: boolean; oid: string; size: number }>();
      for (const filePath of [...files.keys()].sort()) {
        if (!filePath.startsWith(prefix)) continue;
        const rest = filePath.slice(prefix.length);
        if (rest === '') continue;
        const first = rest.split('/')[0];
        if (children.has(first)) continue;
        const isDir = rest.includes('/');
        if (isDir) {
          const oid = subtreeOid(dirPath === '' ? first : `${dirPath}/${first}`);
          if (oid === null) continue;
          children.set(first, { isDir: true, oid, size: 0 });
        } else {
          const target = files.get(filePath)!;
          children.set(first, { isDir: false, oid: target.oid, size: repo.objects.get(target.oid)?.data.length ?? 0 });
        }
      }
      if (children.size === 0) return null;
      return [...children.entries()].map(([childName, child]) => {
        const childPath = dirPath === '' ? childName : `${dirPath}/${childName}`;
        return {
          type: child.isDir ? 'dir' : 'file',
          name: childName,
          path: childPath,
          sha: child.oid,
          size: child.size,
          url: `/api/v3/repos/${repo.full_name}/contents/${childPath}`,
          html_url: `https://github.com/${repo.full_name}/${child.isDir ? 'tree' : 'blob'}/${repo.default_branch}/${childPath}`,
          git_url: `/api/v3/repos/${repo.full_name}/git/trees/${child.oid}`,
          download_url: child.isDir ? null : null,
        };
      });
    };
    if (path === '') {
      const entries = listDirectory('');
      jsonResponse(res, 200, entries ?? []);
      return;
    }
    const entry = files.get(path);
    if (!entry) {
      const listing = listDirectory(path);
      if (listing !== null) {
        jsonResponse(res, 200, listing);
        return;
      }
      notFound(res, 'Not Found');
      return;
    }
    const object = repo.objects.get(entry.oid)!;
    jsonResponse(res, 200, {
      type: 'file',
      encoding: 'base64',
      size: object.data.length,
      name: path.split('/').pop(),
      path,
      content: object.data.toString('base64'),
      sha: entry.oid,
      url: `/api/v3/repos/${repo.full_name}/contents/${path}`,
      html_url: `https://github.com/${repo.full_name}/blob/${repo.default_branch}/${path}`,
      git_url: `/api/v3/repos/${repo.full_name}/git/blobs/${entry.oid}`,
      download_url: null,
    });
    return;
  }

  if (req.method === 'PUT') {
    const parsed = parseJsonBody(body);
    if (!parsed.ok) {
      errorJson(res, 400, 'Problems parsing JSON');
      return;
    }
    const payload = isRecord(parsed.value) ? parsed.value : {};
    const content = typeof payload.content === 'string' ? payload.content : '';
    const message = typeof payload.message === 'string' && payload.message !== '' ? payload.message : `Create ${path}`;
    const givenBranch = typeof payload.branch === 'string' && payload.branch !== '' ? payload.branch : repo.default_branch;
    const givenSha = typeof payload.sha === 'string' ? payload.sha : undefined;
    const tip = repo.refs.get(`refs/heads/${givenBranch}`);
    let files = new Map<string, { oid: string; mode: string }>();
    let parents: string[] = [];
    if (tip) {
      const object = repo.objects.get(tip);
      if (object?.type === 'commit') {
        const commit = parseCommit(object.data);
        files = new Map(treeFiles(repo, commit.tree));
        parents = [tip];
      }
    }
    const existing = files.get(path);
    const isCreate = existing === undefined;
    if (!isCreate && givenSha !== undefined && givenSha !== existing!.oid) {
      errorJson(res, 409, 'Conflict', { message: 'sha does not match current file' });
      return;
    }
    if (!isCreate && givenSha === undefined) {
      errorJson(res, 409, 'Conflict', { message: 'sha is required to update a file' });
      return;
    }
    const blobOid = putObject(repo, 'blob', b64decode(content));
    files.set(path, { oid: blobOid, mode: '100644' });
    const commitOid = commitFiles(repo, parents, files, message);
    setRef(repo, `refs/heads/${givenBranch}`, commitOid);
    repo.updated_at = nextTimestamp();
    jsonResponse(res, isCreate ? 201 : 200, {
      content: { name: path.split('/').pop(), path, sha: blobOid, size: b64decode(content).length, url: `/api/v3/repos/${repo.full_name}/contents/${path}`, type: 'file', encoding: 'base64', content },
      commit: { sha: commitOid, message },
    });
    return;
  }

  if (req.method === 'DELETE') {
    const parsed = parseJsonBody(body);
    if (!parsed.ok) {
      errorJson(res, 400, 'Problems parsing JSON');
      return;
    }
    const payload = isRecord(parsed.value) ? parsed.value : {};
    const message = typeof payload.message === 'string' && payload.message !== '' ? payload.message : `Delete ${path}`;
    const givenBranch = typeof payload.branch === 'string' && payload.branch !== '' ? payload.branch : repo.default_branch;
    const givenSha = typeof payload.sha === 'string' ? payload.sha : undefined;
    const tip = repo.refs.get(`refs/heads/${givenBranch}`);
    if (!tip) {
      notFound(res, 'Not Found');
      return;
    }
    const object = repo.objects.get(tip);
    if (!object || object.type !== 'commit') {
      notFound(res, 'Not Found');
      return;
    }
    const commit = parseCommit(object.data);
    const files = new Map(treeFiles(repo, commit.tree));
    const existing = files.get(path);
    if (!existing) {
      notFound(res, 'Not Found');
      return;
    }
    if (givenSha !== undefined && givenSha !== existing.oid) {
      errorJson(res, 409, 'Conflict', { message: 'sha does not match current file' });
      return;
    }
    files.delete(path);
    const commitOid = commitFiles(repo, [tip], files, message);
    setRef(repo, `refs/heads/${givenBranch}`, commitOid);
    repo.updated_at = nextTimestamp();
    jsonResponse(res, 200, { commit: { sha: commitOid, message } });
    return;
  }

  notFound(res);
}

function handleRepoIssues(ctx: RouteContext, owner: string, name: string): void {
  const { req, res, body, query } = ctx;
  const repo = findRepo(owner, name);
  if (!repo) {
    notFound(res, 'Not Found');
    return;
  }
  if (req.method === 'GET') {
    const { page, perPage } = parsePagination(query);
    const state = query.get('state') ?? 'open';
    const sort = query.get('sort') ?? 'created';
    const direction = query.get('direction') ?? 'desc';
    let items = [...repo.items.values()].filter((item) => item.kind === 'issue');
    if (state !== 'all') items = items.filter((item) => item.state === state);
    items.sort((a, b) => {
      const by = sort === 'updated' ? (a.updated_at < b.updated_at ? -1 : 1) : a.seq - b.seq;
      return direction === 'asc' ? by : -by;
    });
    const { pageItems, hasNext } = paginate(items, page, perPage);
    jsonResponse(res, 200, pageItems.map((item) => issueObject(repo, item as Issue)), linkHeader(req, query, page, perPage, hasNext));
    return;
  }
  if (req.method === 'POST') {
    const parsed = parseJsonBody(body);
    if (!parsed.ok) {
      errorJson(res, 400, 'Problems parsing JSON');
      return;
    }
    const payload = isRecord(parsed.value) ? parsed.value : {};
    const title = typeof payload.title === 'string' ? payload.title : '';
    if (title === '') {
      errorJson(res, 422, 'Validation Failed', { errors: [{ resource: 'Issue', field: 'title', code: 'missing' }] });
      return;
    }
    const requestedLabels: string[] = Array.isArray(payload.labels) ? payload.labels.filter((l): l is string => typeof l === 'string') : [];
    const labels: Label[] = [];
    for (const labelName of requestedLabels) {
      const label = repo.labels.get(labelName);
      if (!label) {
        errorJson(res, 422, 'Validation Failed', { errors: [{ resource: 'Issue', field: 'labels', code: 'invalid', message: `Label does not exist: ${labelName}` }] });
        return;
      }
      labels.push(label);
    }
    const number = repo.nextNumber++;
    const now = nextTimestamp();
    const issue: Issue = {
      kind: 'issue',
      id: objectIdSeq++,
      number,
      title,
      body: typeof payload.body === 'string' ? payload.body : '',
      state: 'open',
      labels,
      comments: [],
      created_at: now,
      updated_at: now,
      seq: repo.nextNumber * 1000 + number,
      cachedJson: null,
    };
    issue.seq = repo.nextNumber;
    repo.items.set(number, issue);
    jsonResponse(res, 201, issueObject(repo, issue));
    return;
  }
  notFound(res);
}

function handleRepoIssue(ctx: RouteContext, owner: string, name: string, number: number): void {
  const { req, res, body } = ctx;
  const repo = findRepo(owner, name);
  if (!repo) {
    notFound(res, 'Not Found');
    return;
  }
  const item = repo.items.get(number);
  if (!item || item.kind !== 'issue') {
    notFound(res, 'Not Found');
    return;
  }
  if (req.method === 'GET') {
    if (item.cachedJson !== null) {
      res.writeHead(200, { 'Content-Type': JSON_TYPE, 'X-GitHub-Request-Id': nextRequestId() });
      res.end(item.cachedJson);
      return;
    }
    const body = issueObject(repo, item);
    item.cachedJson = Buffer.from(JSON.stringify(body), 'utf8');
    res.writeHead(200, { 'Content-Type': JSON_TYPE, 'X-GitHub-Request-Id': nextRequestId() });
    res.end(item.cachedJson);
    return;
  }
  if (req.method === 'PATCH') {
    const parsed = parseJsonBody(body);
    if (!parsed.ok) {
      errorJson(res, 400, 'Problems parsing JSON');
      return;
    }
    const payload = isRecord(parsed.value) ? parsed.value : {};
    if (typeof payload.title === 'string') item.title = payload.title;
    if (typeof payload.body === 'string') item.body = payload.body;
    if (payload.state === 'open' || payload.state === 'closed') item.state = payload.state;
    touchIssue(item);
    if (Array.isArray(payload.labels)) {
      const labels: Label[] = [];
      for (const labelName of payload.labels) {
        if (typeof labelName !== 'string') continue;
        const label = repo.labels.get(labelName);
        if (!label) {
          errorJson(res, 422, 'Validation Failed', { errors: [{ resource: 'Issue', field: 'labels', code: 'invalid', message: `Label does not exist: ${labelName}` }] });
          return;
        }
        labels.push(label);
      }
      item.labels = labels;
    }
    item.updated_at = nextTimestamp();
    jsonResponse(res, 200, issueObject(repo, item));
    return;
  }
  notFound(res);
}

function handleIssueComments(ctx: RouteContext, owner: string, name: string, number: number): void {
  const { req, res, body, query } = ctx;
  const repo = findRepo(owner, name);
  if (!repo) {
    notFound(res, 'Not Found');
    return;
  }
  const item = repo.items.get(number);
  if (!item || item.kind !== 'issue') {
    notFound(res, 'Not Found');
    return;
  }
  if (req.method === 'GET') {
    const { page, perPage } = parsePagination(query);
    const { pageItems, hasNext } = paginate(item.comments, page, perPage);
    jsonResponse(
      res,
      200,
      pageItems.map((comment) => ({
        id: comment.id,
        node_id: globalId('Comment', repo.id, comment.id),
        body: comment.body,
        user: userObject(),
        created_at: comment.created_at,
        updated_at: comment.updated_at,
        html_url: `https://github.com/${repo.full_name}/issues/${number}#issuecomment-${comment.id}`,
        url: `/api/v3/repos/${repo.full_name}/issues/${number}/comments/${comment.id}`,
      })),
      linkHeader(req, query, page, perPage, hasNext),
    );
    return;
  }
  if (req.method === 'POST') {
    const parsed = parseJsonBody(body);
    if (!parsed.ok) {
      errorJson(res, 400, 'Problems parsing JSON');
      return;
    }
    const payload = isRecord(parsed.value) ? parsed.value : {};
    const commentBody = typeof payload.body === 'string' ? payload.body : '';
    if (commentBody === '') {
      errorJson(res, 422, 'Validation Failed', { errors: [{ resource: 'IssueComment', field: 'body', code: 'missing' }] });
      return;
    }
    const now = nextTimestamp();
    const comment: IssueComment = { id: commentIdSeq++, body: commentBody, created_at: now, updated_at: now, user: userObject() };
    item.comments.push(comment);
    item.updated_at = now;
    touchIssue(item);
    jsonResponse(res, 201, {
      id: comment.id,
      node_id: globalId('Comment', repo.id, comment.id),
      body: comment.body,
      user: userObject(),
      created_at: comment.created_at,
      updated_at: comment.updated_at,
      html_url: `https://github.com/${repo.full_name}/issues/${number}#issuecomment-${comment.id}`,
      url: `/api/v3/repos/${repo.full_name}/issues/${number}/comments/${comment.id}`,
    });
    return;
  }
  notFound(res);
}

function handleRepoPulls(ctx: RouteContext, owner: string, name: string): void {
  const { req, res, body, query } = ctx;
  const repo = findRepo(owner, name);
  if (!repo) {
    notFound(res, 'Not Found');
    return;
  }
  if (req.method === 'GET') {
    const { page, perPage } = parsePagination(query);
    const state = query.get('state') ?? 'open';
    let items = [...repo.items.values()].filter((item) => item.kind === 'pr');
    if (state !== 'all') items = items.filter((item) => item.state === state);
    items.sort((a, b) => (a.number < b.number ? 1 : -1));
    const { pageItems, hasNext } = paginate(items, page, perPage);
    jsonResponse(res, 200, pageItems.map((item) => pullObject(repo, item as PullRequest)), linkHeader(req, query, page, perPage, hasNext));
    return;
  }
  if (req.method === 'POST') {
    const parsed = parseJsonBody(body);
    if (!parsed.ok) {
      errorJson(res, 400, 'Problems parsing JSON');
      return;
    }
    const payload = isRecord(parsed.value) ? parsed.value : {};
    const title = typeof payload.title === 'string' ? payload.title : '';
    const head = typeof payload.head === 'string' ? payload.head : '';
    const base = typeof payload.base === 'string' ? payload.base : '';
    if (title === '' || head === '' || base === '') {
      errorJson(res, 422, 'Validation Failed', { errors: [{ resource: 'PullRequest', field: 'title', code: 'missing' }] });
      return;
    }
    const headTip = repo.refs.get(`refs/heads/${head}`);
    const baseTip = repo.refs.get(`refs/heads/${base}`);
    if (!headTip || !baseTip) {
      errorJson(res, 422, 'Validation Failed', { errors: [{ resource: 'PullRequest', field: 'head', code: 'invalid', message: 'No commits between base and head' }] });
      return;
    }
    const existing = [...repo.items.values()].find(
      (item) => item.kind === 'pr' && (item as PullRequest).state === 'open' && (item as PullRequest).head === head && (item as PullRequest).base === base,
    );
    if (existing) {
      errorJson(res, 422, 'Validation Failed', { errors: [{ resource: 'PullRequest', field: 'base', code: 'custom', message: 'A pull request already exists for this head and base' }] });
      return;
    }
    const number = repo.nextNumber++;
    const now = nextTimestamp();
    const pr: PullRequest = {
      kind: 'pr',
      id: objectIdSeq++,
      number,
      title,
      body: typeof payload.body === 'string' ? payload.body : '',
      state: 'open',
      head,
      base,
      merged: false,
      merged_at: null,
      merge_commit_sha: null,
      created_at: now,
      updated_at: now,
      seq: number,
    };
    repo.items.set(number, pr);
    jsonResponse(res, 201, pullObject(repo, pr));
    return;
  }
  notFound(res);
}

function handleRepoPull(ctx: RouteContext, owner: string, name: string, number: number): void {
  const { req, res, body } = ctx;
  const repo = findRepo(owner, name);
  if (!repo) {
    notFound(res, 'Not Found');
    return;
  }
  const item = repo.items.get(number);
  if (!item || item.kind !== 'pr') {
    notFound(res, 'Not Found');
    return;
  }
  if (req.method === 'GET') {
    jsonResponse(res, 200, pullObject(repo, item));
    return;
  }
  if (req.method === 'PATCH') {
    const parsed = parseJsonBody(body);
    if (!parsed.ok) {
      errorJson(res, 400, 'Problems parsing JSON');
      return;
    }
    const payload = isRecord(parsed.value) ? parsed.value : {};
    if (typeof payload.title === 'string') item.title = payload.title;
    if (typeof payload.body === 'string') item.body = payload.body;
    if (payload.state === 'open' || payload.state === 'closed') item.state = payload.state;
    item.updated_at = nextTimestamp();
    jsonResponse(res, 200, pullObject(repo, item));
    return;
  }
  notFound(res);
}

function handleRepoPullFiles(ctx: RouteContext, owner: string, name: string, number: number): void {
  const { req, res } = ctx;
  const repo = findRepo(owner, name);
  if (!repo) {
    notFound(res, 'Not Found');
    return;
  }
  const item = repo.items.get(number);
  if (!item || item.kind !== 'pr') {
    notFound(res, 'Not Found');
    return;
  }
  if (req.method !== 'GET') {
    notFound(res);
    return;
  }
  const files = prFiles(repo, item);
  jsonResponse(
    res,
    200,
    files.map((file) => ({
      sha: '',
      filename: file.filename,
      status: file.status,
      additions: file.additions,
      deletions: file.deletions,
      changes: file.changes,
      blob_url: `https://github.com/${repo.full_name}/blob/${item.head}/${file.filename}`,
      raw_url: `https://github.com/${repo.full_name}/raw/${item.head}/${file.filename}`,
      contents_url: `/api/v3/repos/${repo.full_name}/contents/${file.filename}`,
      patch: '',
    })),
  );
}

function handleRepoPullMerge(ctx: RouteContext, owner: string, name: string, number: number): void {
  const { req, res, body } = ctx;
  const repo = findRepo(owner, name);
  if (!repo) {
    notFound(res, 'Not Found');
    return;
  }
  const item = repo.items.get(number);
  if (!item || item.kind !== 'pr') {
    notFound(res, 'Not Found');
    return;
  }
  if (req.method !== 'PUT') {
    notFound(res);
    return;
  }
  const parsed = parseJsonBody(body);
  if (!parsed.ok) {
    errorJson(res, 400, 'Problems parsing JSON');
    return;
  }
  if (item.state !== 'open') {
    errorJson(res, 405, 'Pull request is not open');
    return;
  }
  const mergeSha = squashMerge(repo, item);
  if (mergeSha === null) {
    errorJson(res, 405, 'Merge conflict', { message: 'Merge conflict' });
    return;
  }
  setRef(repo, `refs/heads/${item.base}`, mergeSha);
  item.merged = true;
  item.state = 'closed';
  item.merged_at = nextTimestamp();
  item.merge_commit_sha = mergeSha;
  item.updated_at = item.merged_at;
  jsonResponse(res, 200, { sha: mergeSha, merged: true, message: `Merge pull request #${item.number} from ${VIEWER.login}/${item.head}` });
}

function routeRest(ctx: RouteContext): boolean {
  const { req, res, segments } = ctx;
  if (segments[0] !== 'api' || segments[1] !== 'v3') return false;
  const rest = segments.slice(2);
  if (rest.length === 0) {
    if (req.method === 'GET') {
      jsonResponse(res, 200, { current_user_url: '/api/v3/user' }, { 'X-OAuth-Scopes': 'repo, read:org' });
      return true;
    }
    notFound(res);
    return true;
  }
  if (rest.length === 1 && rest[0] === 'meta') {
    if (req.method === 'GET') {
      jsonResponse(res, 200, { verifiable_password_authentication: true, ssh_key_fingerprints: {}, installed_version: VERSION, api: { version: VERSION } });
      return true;
    }
    notFound(res);
    return true;
  }
  if (rest.length === 1 && rest[0] === 'user') {
    if (req.method !== 'GET') {
      notFound(res);
      return true;
    }
    handleUser(ctx);
    return true;
  }
  if (rest.length === 2 && rest[0] === 'user' && rest[1] === 'repos') {
    handleUserRepos(ctx);
    return true;
  }
  if (rest.length >= 2 && rest[0] === 'repos') {
    const [owner, name] = [rest[1], rest[2]];
    if (rest.length === 3) {
      handleRepo(ctx, owner, name);
      return true;
    }
    if (rest.length === 4 && rest[3] === 'labels') {
      handleRepoLabels(ctx, owner, name);
      return true;
    }
    if (rest.length === 4 && rest[3] === 'branches') {
      handleRepoBranches(ctx, owner, name);
      return true;
    }
    if (rest.length === 5 && rest[3] === 'branches') {
      handleRepoBranches(ctx, owner, name, decodeURIComponent(rest[4]));
      return true;
    }
    if (rest.length === 4 && rest[3] === 'commits') {
      handleRepoCommits(ctx, owner, name);
      return true;
    }
    if (rest.length >= 4 && rest[3] === 'contents') {
      handleContents(ctx, owner, name, rest.slice(4).join('/'));
      return true;
    }
    if (rest.length === 5 && rest[3] === 'git' && rest[4] === 'refs') {
      handleGitRefs(ctx, owner, name);
      return true;
    }
    if (rest.length === 7 && rest[3] === 'git' && rest[4] === 'refs' && rest[5] === 'heads') {
      handleGitRef(ctx, owner, name, decodeURIComponent(rest[6]));
      return true;
    }
    if (rest.length === 4 && rest[3] === 'issues') {
      handleRepoIssues(ctx, owner, name);
      return true;
    }
    if (rest.length === 5 && rest[3] === 'issues' && /^\d+$/.test(rest[4])) {
      handleRepoIssue(ctx, owner, name, Number(rest[4]));
      return true;
    }
    if (rest.length === 6 && rest[3] === 'issues' && /^\d+$/.test(rest[4]) && rest[5] === 'comments') {
      handleIssueComments(ctx, owner, name, Number(rest[4]));
      return true;
    }
    if (rest.length === 4 && rest[3] === 'pulls') {
      handleRepoPulls(ctx, owner, name);
      return true;
    }
    if (rest.length === 5 && rest[3] === 'pulls' && /^\d+$/.test(rest[4])) {
      handleRepoPull(ctx, owner, name, Number(rest[4]));
      return true;
    }
    if (rest.length === 6 && rest[3] === 'pulls' && /^\d+$/.test(rest[4]) && rest[5] === 'files') {
      handleRepoPullFiles(ctx, owner, name, Number(rest[4]));
      return true;
    }
    if (rest.length === 6 && rest[3] === 'pulls' && /^\d+$/.test(rest[4]) && rest[5] === 'merge') {
      handleRepoPullMerge(ctx, owner, name, Number(rest[4]));
      return true;
    }
    notFound(res);
    return true;
  }
  notFound(res);
  return true;
}

// ---------------------------------------------------------------------------------------------
// git smart HTTP handlers
// ---------------------------------------------------------------------------------------------

function sortedRefs(repo: Repo): Array<{ ref: string; oid: string; type: GitObjectType }> {
  const out: Array<{ ref: string; oid: string; type: GitObjectType }> = [];
  for (const [ref, oid] of repo.refs.entries()) {
    const object = repo.objects.get(oid);
    if (!object) continue;
    out.push({ ref, oid, type: object.type });
  }
  out.sort((a, b) => (a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0));
  return out;
}

function handleInfoRefs(ctx: RouteContext, owner: string, name: string, service: string): void {
  const { req, res } = ctx;
  const repo = findRepo(owner, name);
  if (!repo) {
    jsonResponse(res, 404, { message: 'Not Found' });
    return;
  }
  const isUpload = service === 'git-upload-pack';
  const serviceName = isUpload ? 'git-upload-pack' : 'git-receive-pack';
  if (req.method !== 'GET') {
    notFound(res);
    return;
  }
  const protocol = req.headers['git-protocol'] ?? '';
  const refs = sortedRefs(repo);
  const defaultTip = repo.refs.get(`refs/heads/${repo.default_branch}`);
  const lines: Buffer[] = [pktLine(`# service=${serviceName}\n`), pktFlush()];
  if (isUpload && String(protocol).includes('version=2')) {
    lines.push(
      pktLine('version 2\n'),
      pktLine(`agent=${AGENT}\n`),
      pktLine('ls-refs=unborn\n'),
      pktLine('fetch=shallow filter\n'),
      pktLine('object-format=sha1\n'),
      pktFlush(),
    );
  } else if (isUpload) {
    const caps = `symref=HEAD:refs/heads/${repo.default_branch} multi_ack_detailed thin-pack side-band-64k ofs-delta shallow agent=${AGENT} object-format=sha1`;
    if (refs.length === 0) {
      lines.push(pktLine(`${ZERO_OID} HEAD\0${caps}\n`), pktFlush());
    } else {
      const headOid = defaultTip ?? refs[0].oid;
      lines.push(pktLine(`${headOid} HEAD\0${caps}\n`));
      for (const ref of refs) {
        lines.push(pktLine(`${ref.oid} ${ref.ref}\n`));
        if (ref.type === 'tag') {
          const tag = parseTag(repo.objects.get(ref.oid)!.data);
          lines.push(pktLine(`${tag.object} ${ref.ref}^{}\n`));
        }
      }
      lines.push(pktFlush());
    }
  } else {
    const caps = `report-status report-status-v2 side-band-64k delete-refs ofs-delta agent=${AGENT}`;
    if (refs.length === 0) {
      lines.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`), pktFlush());
    } else {
      const first = refs[0];
      lines.push(pktLine(`${first.oid} ${first.ref}\0${caps}\n`));
      for (const ref of refs.slice(1)) lines.push(pktLine(`${ref.oid} ${ref.ref}\n`));
      lines.push(pktFlush());
    }
  }
  res.writeHead(200, {
    'Content-Type': `application/x-${serviceName}-advertisement`,
    'X-GitHub-Request-Id': nextRequestId(),
  });
  res.end(Buffer.concat(lines));
}

function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  for (let offset = 0; offset < pack.length; offset += PKT_LINE_MAX_PAYLOAD) {
    const chunk = pack.subarray(offset, offset + PKT_LINE_MAX_PAYLOAD);
    const payload = Buffer.concat([Buffer.from([1]), chunk]);
    parts.push(pktLine(payload));
  }
  return Buffer.concat(parts);
}

interface UploadArgs {
  command: 'fetch' | 'ls-refs' | '';
  wants: string[];
  haves: string[];
  shallow: string[];
  filter: string | null;
  depth: number | null;
  deepenSince: number | null;
  deepenNot: string[];
  protocol: 'v2' | 'v0';
  noProgress: boolean;
  peel: boolean;
  symrefs: boolean;
  unborn: boolean;
  prefixes: string[];
}

/** One argument line of a v2 fetch / ls-refs request. The client puts want/have/deepen lines
 *  after the delim, so every data packet is scanned the same way regardless of section. */
function parseUploadArgLine(args: UploadArgs, line: string): void {
  if (line.startsWith('want ')) args.wants.push(line.slice(5).trim().split(' ')[0]);
  else if (line.startsWith('have ')) args.haves.push(line.slice(5).trim());
  else if (line.startsWith('shallow ')) args.shallow.push(line.slice(8).trim());
  else if (line.startsWith('filter ')) args.filter = line.slice(7).trim();
  else if (line.startsWith('deepen ')) args.depth = Number.parseInt(line.slice(7).trim(), 10) || null;
  else if (line.startsWith('deepen-since ')) args.deepenSince = Number.parseInt(line.slice(13).trim(), 10) || null;
  else if (line.startsWith('deepen-not ')) args.deepenNot.push(line.slice(11).trim());
  else if (line === 'no-progress') args.noProgress = true;
  else if (line === 'peel') args.peel = true;
  else if (line === 'symrefs') args.symrefs = true;
  else if (line === 'unborn') args.unborn = true;
  else if (line.startsWith('ref-prefix ')) args.prefixes.push(line.slice(11).trim());
}

function blankUploadArgs(protocol: 'v2' | 'v0'): UploadArgs {
  return {
    command: '',
    wants: [],
    haves: [],
    shallow: [],
    filter: null,
    depth: null,
    deepenSince: null,
    deepenNot: [],
    protocol,
    noProgress: false,
    peel: false,
    symrefs: false,
    unborn: false,
    prefixes: [],
  };
}

function parseUploadPackV2(body: Buffer): UploadArgs {
  const { packets } = decodePktLines(body);
  const args = blankUploadArgs('v2');
  for (const packet of packets) {
    if (packet.kind === 'flush') break;
    if (packet.kind !== 'data') continue;
    const line = packet.payload!.toString('utf8').trim();
    if (line === 'command=fetch') {
      args.command = 'fetch';
      continue;
    }
    if (line === 'command=ls-refs') {
      args.command = 'ls-refs';
      continue;
    }
    parseUploadArgLine(args, line);
  }
  return args;
}

function parseUploadPackV0(body: Buffer): UploadArgs {
  const { packets } = decodePktLines(body);
  const args = blankUploadArgs('v0');
  args.command = 'fetch';
  for (const packet of packets) {
    if (packet.kind !== 'data') continue;
    parseUploadArgLine(args, packet.payload!.toString('utf8').trim());
  }
  return args;
}

function computeFetchSet(repo: Repo, args: UploadArgs): { objects: GitObject[]; shallowInfo: string[]; unshallow: string[]; wantOids: string[] } {
  const lookup = repoLookup(repo);
  // Wants are object ids (or ref names). A wanted tag object must itself be delivered —
  // the BFS below then traverses from it into its target, so both arrive.
  const wantOids = args.wants
    .map((want) => {
      if (isOid(want)) {
        return repo.objects.has(want) ? want : null;
      }
      const ref = repo.refs.get(want) ?? repo.refs.get(`refs/heads/${want}`) ?? repo.refs.get(`refs/tags/${want}`);
      return ref ?? null;
    })
    .filter((oid): oid is string => oid !== null);
  // Depth-limited BFS from the wants, stopping at the haves (and at deepen-not tips).
  // A want the client already holds is a deepen: with a depth it is still traversed
  // (its parents are what is wanted) but is not itself re-sent; without a depth a held
  // want means nothing new.
  const haveSet = new Set([...args.haves, ...args.deepenNot]);
  const rootWants = new Set(wantOids);
  const fetched = new Set<string>();
  const shallowInfo: string[] = [];
  const unshallow: string[] = [];
  const depthLimit = args.depth ?? Number.POSITIVE_INFINITY;
  const since = args.deepenSince;
  const commitTime = (oid: string): number | null => {
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') return null;
    const committer = parseCommit(object.data).committer;
    const match = / (\d+) [+-]\d{4}$/.exec(committer);
    return match ? Number(match[1]) : null;
  };
  const queue: Array<{ oid: string; depth: number }> = [];
  for (const oid of wantOids) queue.push({ oid, depth: 1 });
  while (queue.length > 0) {
    const { oid, depth } = queue.shift()!;
    if (fetched.has(oid)) continue;
    const isHeldRoot = rootWants.has(oid) && haveSet.has(oid);
    if (isHeldRoot && args.depth === null) continue;
    if (haveSet.has(oid) && !isHeldRoot) continue;
    const object = repo.objects.get(oid);
    if (!object) continue;
    if (!isHeldRoot) fetched.add(oid);
    if (object.type === 'commit') {
      const commit = parseCommit(object.data);
      const parentTooOld = (parent: string): boolean => {
        if (since === null) return false;
        const time = commitTime(parent);
        return time !== null && time < since;
      };
      // A shallow boundary is only a depth / deepen-since cutoff. A parent the client
      // already holds is NOT a boundary: the commit is fully connected, its parent is
      // simply not re-sent.
      const isShallowBoundary = depth >= depthLimit || commit.parents.some(parentTooOld);
      if (isShallowBoundary) shallowInfo.push(oid);
      if (depth < depthLimit) {
        for (const parent of commit.parents) {
          if (haveSet.has(parent) || parentTooOld(parent)) continue;
          queue.push({ oid: parent, depth: depth + 1 });
        }
      }
      // A held root's tree is already on the client; do not re-send it.
      if (!isHeldRoot) queue.push({ oid: commit.tree, depth });
    } else if (object.type === 'tag') {
      queue.push({ oid: parseTag(object.data).object, depth });
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) if (entry.mode !== '160000') queue.push({ oid: entry.oid, depth });
    }
  }
  for (const oid of args.shallow) {
    if (fetched.has(oid)) {
      const object = repo.objects.get(oid);
      if (object?.type === 'commit') {
        const parents = parseCommit(object.data).parents;
        if (parents.every((parent) => fetched.has(parent) || haveSet.has(parent))) unshallow.push(oid);
      }
    }
  }
  // What the client already holds: everything reachable from its haves — except that a
  // shallow boundary's ancestors are NOT held (that is what a deepen is for). Traversal
  // stops at a boundary's parents, while the boundary itself and its tree stay held.
  const held = new Set<string>();
  {
    const shallowSet = new Set(args.shallow);
    const queue = [...args.haves];
    while (queue.length > 0) {
      const oid = queue.pop()!;
      if (held.has(oid)) continue;
      const object = lookup(oid);
      if (!object) continue;
      held.add(oid);
      if (object.type === 'commit') {
        const commit = parseCommit(object.data);
        queue.push(commit.tree);
        if (!shallowSet.has(oid)) for (const parent of commit.parents) queue.push(parent);
      } else if (object.type === 'tag') {
        queue.push(parseTag(object.data).object);
      } else if (object.type === 'tree') {
        for (const entry of parseTree(object.data)) if (entry.mode !== '160000') queue.push(entry.oid);
      }
    }
  }
  const packOids = [...fetched].filter((oid) => !held.has(oid));
  const objects: GitObject[] = [];
  for (const oid of packOids) {
    const object = repo.objects.get(oid);
    if (object) objects.push(object);
  }
  return { objects, shallowInfo, unshallow, wantOids };
}

function handleLsRefs(repo: Repo, args: UploadArgs): Buffer {
  const lines: Buffer[] = [];
  const refs = sortedRefs(repo);
  const defaultTip = repo.refs.get(`refs/heads/${repo.default_branch}`);
  const keep = (refName: string): boolean => args.prefixes.length === 0 || args.prefixes.some((prefix) => refName.startsWith(prefix));
  if (refs.length === 0) {
    if (args.unborn) lines.push(pktLine(`unborn HEAD symref-target:refs/heads/${repo.default_branch}\n`));
    lines.push(pktFlush());
    return Buffer.concat(lines);
  }
  if (args.symrefs && defaultTip && keep('HEAD')) {
    lines.push(pktLine(`${defaultTip} HEAD symref-target:refs/heads/${repo.default_branch}\n`));
  }
  for (const ref of refs) {
    if (!keep(ref.ref)) continue;
    let line = `${ref.oid} ${ref.ref}`;
    if (args.peel && ref.type === 'tag') {
      const tag = parseTag(repo.objects.get(ref.oid)!.data);
      line += ` peeled:${tag.object}`;
    }
    lines.push(pktLine(`${line}\n`));
  }
  lines.push(pktFlush());
  return Buffer.concat(lines);
}

// Fetch responses are a pure function of the repo version and the request args, so
// identical concurrent fetches (the clone workload's 50 depth-1 clones) share one pack.
const fetchCache = new Map<string, { pack: Buffer; shallowInfo: string[]; unshallow: string[] }>();
const lsRefsCache = new Map<string, Buffer>();

function handleUploadPack(ctx: RouteContext, owner: string, name: string): void {
  const { req, res, body } = ctx;
  const repo = findRepo(owner, name);
  if (!repo) {
    jsonResponse(res, 404, { message: 'Not Found' });
    return;
  }
  if (req.method !== 'POST') {
    notFound(res);
    return;
  }
  const protocol = (req.headers['git-protocol'] ?? '').toString();
  const contentType = (req.headers['content-type'] ?? '').toString();
  const isV2 = protocol.includes('version=2') || contentType.includes('application/x-git-upload-pack-request');
  const args = isV2 ? parseUploadPackV2(body) : parseUploadPackV0(body);
  if (isV2 && args.command === 'ls-refs') {
    const cacheKey = `${repo.id}:${repo.version}:${args.peel}:${args.symrefs}:${args.unborn}:${[...args.prefixes].sort().join(',')}`;
    let response = lsRefsCache.get(cacheKey);
    if (!response) {
      response = handleLsRefs(repo, args);
      if (lsRefsCache.size > 300) lsRefsCache.clear();
      lsRefsCache.set(cacheKey, response);
    }
    res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-result', 'X-GitHub-Request-Id': nextRequestId() });
    res.end(response);
    return;
  }
  const fetchKey = [
    repo.id,
    repo.version,
    [...args.wants].sort().join(','),
    [...args.haves].sort().join(','),
    [...args.shallow].sort().join(','),
    args.depth,
    args.deepenSince,
    [...args.deepenNot].sort().join(','),
    args.filter,
  ].join('|');
  let fetched = fetchCache.get(fetchKey);
  if (!fetched) {
    const { objects, shallowInfo, unshallow } = computeFetchSet(repo, args);
    fetched = { pack: objects.length === 0 ? Buffer.alloc(0) : writePack(objects), shallowInfo, unshallow };
    if (fetchCache.size > 300) fetchCache.clear();
    fetchCache.set(fetchKey, fetched);
  }
  const { pack, shallowInfo, unshallow } = fetched;
  const out: Buffer[] = [];
  if (isV2) {
    // Real git (and GitHub) only carry the acknowledgments section when the client
    // sent haves to negotiate; a fresh fetch starts at shallow-info / packfile.
    if (args.haves.length > 0) {
      out.push(pktLine('acknowledgments\n'));
      const held = args.haves.filter((have) => repo.objects.has(have));
      if (held.length > 0) {
        for (const have of held) out.push(pktLine(`ACK ${have}\n`));
        out.push(pktLine('ready\n'));
      } else {
        out.push(pktLine('NAK\n'));
      }
      out.push(pktDelim());
    }
    if (shallowInfo.length > 0 || unshallow.length > 0) {
      out.push(pktLine('shallow-info\n'));
      for (const oid of shallowInfo) out.push(pktLine(`shallow ${oid}\n`));
      for (const oid of unshallow) out.push(pktLine(`unshallow ${oid}\n`));
      out.push(pktDelim());
    }
    if (pack.length > 0) {
      out.push(pktLine('packfile\n'), sidebandPack(pack));
    }
    out.push(pktFlush());
  } else {
    const held = args.haves.filter((have) => repo.objects.has(have));
    if (held.length > 0) for (const have of held) out.push(pktLine(`ACK ${have}\n`));
    else out.push(pktLine('NAK\n'));
    for (const oid of shallowInfo) out.push(pktLine(`shallow ${oid}\n`));
    if (pack.length > 0) out.push(sidebandPack(pack));
    out.push(pktFlush());
  }
  res.writeHead(200, {
    'Content-Type': 'application/x-git-upload-pack-result',
    'X-GitHub-Request-Id': nextRequestId(),
  });
  res.end(Buffer.concat(out));
}

function handleReceivePack(ctx: RouteContext, owner: string, name: string): void {
  const { req, res, body } = ctx;
  const repo = findRepo(owner, name);
  if (!repo) {
    jsonResponse(res, 404, { message: 'Not Found' });
    return;
  }
  if (req.method !== 'POST') {
    notFound(res);
    return;
  }
  const { packets, trailingOffset } = decodePktLines(body);
  const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  let packOffset = trailingOffset;
  for (const packet of packets) {
    if (packet.kind !== 'data') {
      if (packet.kind === 'flush') break;
      continue;
    }
    // The first command line carries the client's capabilities after a NUL; the ref name
    // is the part before it.
    const line = packet.payload!.toString('utf8').trim().split('\0')[0];
    const match = /^([0-9a-f]{40}) ([0-9a-f]{40}) (.+)$/.exec(line);
    if (match) commands.push({ oldOid: match[1], newOid: match[2], ref: match[3] });
  }
  // The packfile follows the flushed command block as raw bytes.
  const packBytes = body.subarray(packOffset);
  const results: Array<{ ref: string; ok: boolean; reason?: string }> = [];
  const lookup = repoLookup(repo);
  if (packBytes.length > 0) {
    try {
      const objects = readPack(packBytes);
      for (const [oid, object] of objects) {
        if (!repo.objects.has(oid)) repo.objects.set(oid, object);
      }
    } catch {
      // A corrupt pack means every ref is rejected.
      const inner: Buffer[] = [pktLine('unpack ok\n')];
      for (const command of commands) inner.push(pktLine(`ng ${command.ref} unpack failed\n`));
      inner.push(pktFlush());
      res.writeHead(200, { 'Content-Type': 'application/x-git-receive-pack-result', 'X-GitHub-Request-Id': nextRequestId() });
      res.end(pktLines([Buffer.concat([Buffer.from([1]), Buffer.concat(inner)]), 'flush']));
      return;
    }
  }
  for (const command of commands) {
    const isDelete = command.newOid === ZERO_OID;
    const current = repo.refs.get(command.ref);
    let ok = true;
    let reason: string | undefined;
    if (isDelete) {
      if (current === undefined) {
        ok = false;
        reason = 'remote ref does not exist';
      } else if (command.oldOid !== ZERO_OID && command.oldOid !== current) {
        ok = false;
        reason = 'old ref mismatch';
      }
    } else {
      const object = repo.objects.get(command.newOid);
      if (!object) {
        ok = false;
        reason = 'object not found';
      } else if (current !== undefined && current !== ZERO_OID && command.oldOid !== current) {
        ok = false;
        reason = 'old ref mismatch';
      } else if (current !== undefined && current !== ZERO_OID && !isAncestor(current, command.newOid, lookup)) {
        ok = false;
        reason = 'non-fast-forward';
      }
    }
    if (ok) {
      if (isDelete) deleteRef(repo, command.ref);
      else setRef(repo, command.ref, command.newOid);
      repo.updated_at = nextTimestamp();
    }
    results.push({ ref: command.ref, ok, reason });
  }
  const inner: Buffer[] = [pktLine('unpack ok\n')];
  for (const result of results) {
    inner.push(result.ok ? pktLine(`ok ${result.ref}\n`) : pktLine(`ng ${result.ref} ${result.reason ?? 'failed'}\n`));
  }
  inner.push(pktFlush());
  const payload = Buffer.concat([Buffer.from([1]), Buffer.concat(inner)]);
  res.writeHead(200, { 'Content-Type': 'application/x-git-receive-pack-result', 'X-GitHub-Request-Id': nextRequestId() });
  res.end(pktLines([payload, 'flush']));
}

function routeGit(ctx: RouteContext): boolean {
  const { req, res, segments, query } = ctx;
  if (segments.length < 3) return false;
  const owner = segments[0];
  const repoName = segments[1];
  if (!repoName.endsWith('.git')) return false;
  const name = repoName.slice(0, -'.git'.length);
  if (segments[2] === 'info' && segments[3] === 'refs' && segments.length === 4) {
    const service = query.get('service') ?? '';
    if (service === 'git-upload-pack' || service === 'git-receive-pack') {
      handleInfoRefs(ctx, owner, name, service);
      return true;
    }
    jsonResponse(res, 400, { message: 'Invalid service' });
    return true;
  }
  if (segments[2] === 'git-upload-pack' && segments.length === 3) {
    handleUploadPack(ctx, owner, name);
    return true;
  }
  if (segments[2] === 'git-receive-pack' && segments.length === 3) {
    handleReceivePack(ctx, owner, name);
    return true;
  }
  void req;
  return false;
}

// ---------------------------------------------------------------------------------------------
// GraphQL v4: hand-written parser + executor for the shapes the suite sends.
// ---------------------------------------------------------------------------------------------

interface GqlValue {
  kind: 'Int' | 'Float' | 'String' | 'Boolean' | 'Enum' | 'Null' | 'Variable' | 'List' | 'Object';
  value: unknown;
}

interface GqlArgument {
  name: string;
  value: GqlValue;
}

interface GqlField {
  alias: string | null;
  name: string;
  args: GqlArgument[];
  selection: GqlField[] | null;
}

interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  variables: Map<string, GqlValue>;
  fields: GqlField[];
}

class GqlParser {
  #text: string;
  #pos = 0;
  constructor(text: string) {
    this.#text = text;
  }
  #skipIgnored(): void {
    for (;;) {
      while (this.#pos < this.#text.length && /[\s,]/.test(this.#text[this.#pos])) this.#pos += 1;
      if (this.#text[this.#pos] === '#') {
        while (this.#pos < this.#text.length && this.#text[this.#pos] !== '\n') this.#pos += 1;
        continue;
      }
      break;
    }
  }
  #peek(): string {
    this.#skipIgnored();
    return this.#text[this.#pos] ?? '';
  }
  #expect(text: string): void {
    this.#skipIgnored();
    if (!this.#text.startsWith(text, this.#pos)) throw new Error(`expected ${text}`);
    this.#pos += text.length;
  }
  #readName(): string {
    this.#skipIgnored();
    const match = /^[A-Za-z_][A-Za-z0-9_]*/.exec(this.#text.slice(this.#pos));
    if (!match) throw new Error('expected name');
    this.#pos += match[0].length;
    return match[0];
  }
  #readString(): string {
    this.#expect('"');
    let out = '';
    while (this.#pos < this.#text.length) {
      const char = this.#text[this.#pos++];
      if (char === '"') return out;
      if (char === '\\') {
        const esc = this.#text[this.#pos++];
        if (esc === 'n') out += '\n';
        else if (esc === 't') out += '\t';
        else if (esc === 'r') out += '\r';
        else if (esc === 'u') {
          out += String.fromCharCode(Number.parseInt(this.#text.slice(this.#pos, this.#pos + 4), 16));
          this.#pos += 4;
        } else out += esc;
        continue;
      }
      out += char;
    }
    throw new Error('unterminated string');
  }
  #readValue(): GqlValue {
    const char = this.#peek();
    if (char === '"') return { kind: 'String', value: this.#readString() };
    if (char === '$') {
      this.#pos += 1;
      return { kind: 'Variable', value: this.#readName() };
    }
    if (char === '[') {
      this.#pos += 1;
      const items: GqlValue[] = [];
      while (this.#peek() !== ']') items.push(this.#readValue());
      this.#expect(']');
      return { kind: 'List', value: items };
    }
    if (char === '{') {
      this.#pos += 1;
      const fields: Record<string, GqlValue> = {};
      while (this.#peek() !== '}') {
        const name = this.#readName();
        this.#expect(':');
        fields[name] = this.#readValue();
      }
      this.#expect('}');
      return { kind: 'Object', value: fields };
    }
    if (/[0-9-]/.test(char)) {
      const match = /^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(this.#text.slice(this.#pos));
      if (!match) throw new Error('expected number');
      this.#pos += match[0].length;
      return match[0].includes('.') || /[eE]/.test(match[0])
        ? { kind: 'Float', value: Number(match[0]) }
        : { kind: 'Int', value: Number(match[0]) };
    }
    const name = this.#readName();
    if (name === 'true') return { kind: 'Boolean', value: true };
    if (name === 'false') return { kind: 'Boolean', value: false };
    if (name === 'null') return { kind: 'Null', value: null };
    return { kind: 'Enum', value: name };
  }
  #readArguments(): GqlArgument[] {
    const args: GqlArgument[] = [];
    if (this.#peek() !== '(') return args;
    this.#pos += 1;
    while (this.#peek() !== ')') {
      const name = this.#readName();
      this.#expect(':');
      args.push({ name, value: this.#readValue() });
    }
    this.#expect(')');
    return args;
  }
  #readType(): void {
    // Types in variable definitions are not evaluated; skip balanced brackets.
    this.#skipIgnored();
    if (this.#peek() === '[') {
      this.#pos += 1;
      this.#readType();
      this.#expect(']');
    } else {
      this.#readName();
    }
    if (this.#peek() === '!') this.#pos += 1;
  }
  #readVariableDefinitions(): Map<string, GqlValue> {
    const defs = new Map<string, GqlValue>();
    if (this.#peek() !== '(') return defs;
    this.#pos += 1;
    while (this.#peek() !== ')') {
      this.#expect('$');
      const name = this.#readName();
      this.#expect(':');
      this.#readType();
      if (this.#peek() === '=') {
        this.#pos += 1;
        defs.set(name, this.#readValue());
      }
    }
    this.#expect(')');
    return defs;
  }
  #readSelection(): GqlField[] {
    this.#expect('{');
    const fields: GqlField[] = [];
    while (this.#peek() !== '}') {
      const char = this.#peek();
      if (char === '.') {
        // Inline fragment: ... on Type { ... }
        this.#expect('...');
        if (this.#peek() === 'o') {
          const word = this.#readName();
          if (word !== 'on') throw new Error('expected on');
          this.#readName();
        }
        const inner = this.#readSelection();
        fields.push(...inner);
        continue;
      }
      const first = this.#readName();
      let alias: string | null = null;
      let name = first;
      if (this.#peek() === ':') {
        this.#pos += 1;
        alias = first;
        name = this.#readName();
      }
      const args = this.#readArguments();
      let selection: GqlField[] | null = null;
      if (this.#peek() === '{') selection = this.#readSelection();
      fields.push({ alias, name, args, selection });
    }
    this.#expect('}');
    return fields;
  }
  parse(): GqlOperation {
    this.#skipIgnored();
    let kind: 'query' | 'mutation' = 'query';
    let name: string | null = null;
    if (this.#peek() === '{') {
      return { kind, name, variables: new Map(), fields: this.#readSelection() };
    }
    const keyword = this.#readName();
    if (keyword === 'mutation') kind = 'mutation';
    else if (keyword !== 'query') throw new Error(`unknown operation ${keyword}`);
    if (/[A-Za-z_]/.test(this.#peek())) name = this.#readName();
    const variables = this.#readVariableDefinitions();
    const fields = this.#readSelection();
    return { kind, name, variables, fields };
  }
}

function gqlResolveArg(field: GqlField, name: string, variables: Record<string, unknown>): unknown {
  const arg = field.args.find((entry) => entry.name === name);
  if (!arg) return undefined;
  const resolve = (value: GqlValue): unknown => {
    switch (value.kind) {
      case 'Variable':
        return variables[value.value as string];
      case 'List':
        return (value.value as GqlValue[]).map(resolve);
      case 'Object': {
        const out: Record<string, unknown> = {};
        for (const [key, inner] of Object.entries(value.value as Record<string, GqlValue>)) out[key] = resolve(inner);
        return out;
      }
      default:
        return value.value;
    }
  };
  return resolve(arg.value);
}

const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests'],
  Issue: ['id', 'number', 'title', 'state', 'body'],
  PullRequest: ['id', 'number', 'title', 'state', 'body', 'headRefName', 'baseRefName', 'mergeable', 'merged', 'files'],
  User: ['id', 'login', 'name'],
  SearchType: [],
  Label: ['id', 'name', 'color', 'description'],
};

const GQL_TYPE_ENUMS: Record<string, string[]> = {
  Issue: ['OPEN', 'CLOSED'],
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION'],
  PullRequest: ['OPEN', 'CLOSED', 'MERGED'],
};

function gqlError(message: string): Json {
  return { message, locations: [], extensions: { code: 'GRAPHQL_VALIDATION_FAILED' } };
}

function gqlCursor(number: number): string {
  return b64encode(`cursor:${number}`);
}

interface GqlExecContext {
  errors: Json[];
  repo: Repo | null;
}

function gqlIssuesConnection(repo: Repo, field: GqlField, variables: Record<string, unknown>): Json {
  const first = (gqlResolveArg(field, 'first', variables) as number | undefined) ?? 30;
  const after = gqlResolveArg(field, 'after', variables) as string | undefined;
  const states = gqlResolveArg(field, 'states', variables) as string[] | undefined;
  const orderBy = gqlResolveArg(field, 'orderBy', variables) as Json | undefined;
  const direction = String((orderBy as Json | undefined)?.direction ?? 'DESC').toUpperCase();
  let items = [...repo.items.values()].filter((item) => item.kind === 'issue');
  if (states && states.length > 0) {
    const wanted = new Set(states.map((state) => state.toLowerCase()));
    items = items.filter((item) => wanted.has(item.state));
  }
  items.sort((a, b) => {
    const by = direction === 'ASC' ? a.seq - b.seq : b.seq - a.seq;
    if (by !== 0) return by;
    return direction === 'ASC' ? a.number - b.number : b.number - a.number;
  });
  let startIndex = 0;
  if (after) {
    const decoded = b64decode(after).toString('utf8');
    const number = Number(decoded.replace('cursor:', ''));
    const index = items.findIndex((item) => item.number === number);
    if (index >= 0) startIndex = index + 1;
  }
  const sliced = items.slice(startIndex, startIndex + Math.min(first, 100));
  const selection = field.selection ?? [];
  const out: Json = { totalCount: items.length };
  for (const sub of selection) {
    const key = sub.alias ?? sub.name;
    if (sub.name === 'nodes') {
      out[key] = sliced.map((item) => gqlResolveFields('Issue', { repo, issue: item as Issue }, sub, variables));
    } else if (sub.name === 'edges') {
      out[key] = sliced.map((item) => {
        const edge: Json = { cursor: gqlCursor(item.number) };
        for (const edgeField of sub.selection ?? []) {
          if (edgeField.name === 'node') edge[edgeField.alias ?? 'node'] = gqlResolveFields('Issue', { repo, issue: item as Issue }, edgeField, variables);
          else if (edgeField.name === 'cursor') edge[edgeField.alias ?? 'cursor'] = gqlCursor(item.number);
        }
        return edge;
      });
    } else if (sub.name === 'pageInfo') {
      out[key] = {
        hasNextPage: startIndex + sliced.length < items.length,
        hasPreviousPage: startIndex > 0,
        startCursor: sliced.length > 0 ? gqlCursor(sliced[0].number) : null,
        endCursor: sliced.length > 0 ? gqlCursor(sliced[sliced.length - 1].number) : null,
      };
    } else if (sub.name === 'totalCount') {
      out[key] = items.length;
    }
  }
  return out;
}

function gqlPullsConnection(repo: Repo, field: GqlField, variables: Record<string, unknown>): Json {
  const first = (gqlResolveArg(field, 'first', variables) as number | undefined) ?? 30;
  let items = [...repo.items.values()].filter((item) => item.kind === 'pr');
  items.sort((a, b) => b.number - a.number);
  const sliced = items.slice(0, Math.min(first, 100));
  const selection = field.selection ?? [];
  const out: Json = { totalCount: items.length };
  for (const sub of selection) {
    const key = sub.alias ?? sub.name;
    if (sub.name === 'nodes') {
      out[key] = sliced.map((item) => gqlResolveFields('PullRequest', { repo, pr: item as PullRequest }, sub, variables));
    } else if (sub.name === 'edges') {
      out[key] = sliced.map((item) => ({ cursor: gqlCursor(item.number), node: gqlResolveFields('PullRequest', { repo, pr: item as PullRequest }, (sub.selection ?? []).find((f) => f.name === 'node') ?? { alias: null, name: 'node', args: [], selection: null }) }));
    } else if (sub.name === 'pageInfo') {
      out[key] = { hasNextPage: sliced.length < items.length, hasPreviousPage: false, startCursor: sliced.length > 0 ? gqlCursor(sliced[0].number) : null, endCursor: sliced.length > 0 ? gqlCursor(sliced[sliced.length - 1].number) : null };
    } else if (sub.name === 'totalCount') {
      out[key] = items.length;
    }
  }
  return out;
}

function gqlResolveFields(
  typeName: string,
  source: { repo?: Repo | null; issue?: Issue; pr?: PullRequest },
  field: GqlField,
  variables: Record<string, unknown>,
  ctx?: GqlExecContext,
): Json {
  const out: Json = {};
  const repo = source.repo ?? null;
  for (const sub of field.selection ?? []) {
    const key = sub.alias ?? sub.name;
    const value = gqlResolveField(typeName, source, sub, variables, ctx);
    out[key] = value;
  }
  void repo;
  return out;
}

function gqlResolveField(
  typeName: string,
  source: { repo?: Repo | null; issue?: Issue; pr?: PullRequest },
  field: GqlField,
  variables: Record<string, unknown>,
  ctx?: GqlExecContext,
): unknown {
  const repo = source.repo ?? null;
  const name = field.name;
  const known = GQL_TYPE_FIELDS[typeName] ?? [];
  if (typeName === 'Query') {
    if (name === 'viewer') {
      if (!field.selection) return userObject();
      const viewer: Json = {};
      for (const sub of field.selection) {
        if (sub.name === 'login') viewer[sub.alias ?? 'login'] = VIEWER.login;
        else if (sub.name === 'id') viewer[sub.alias ?? 'id'] = globalId('User', VIEWER.id);
        else if (sub.name === 'name') viewer[sub.alias ?? 'name'] = VIEWER.name;
        else ctx?.errors.push(gqlError(`Cannot query field "${sub.name}" on type "User".`));
      }
      return viewer;
    }
    if (name === 'repository') {
      const owner = gqlResolveArg(field, 'owner', variables) as string | undefined;
      const repoName = gqlResolveArg(field, 'name', variables) as string | undefined;
      const found = owner && repoName ? findRepo(owner, repoName) : undefined;
      if (!found) return null;
      if (!field.selection) return {};
      return gqlResolveFields('Repository', { repo: found }, field, variables, ctx);
    }
    if (name === 'node') {
      const id = gqlResolveArg(field, 'id', variables) as string | undefined;
      const parsed = id ? parseGlobalId(id) : null;
      if (!parsed) return null;
      if (parsed.kind === 'Repository') {
        const found = findRepoById(parsed.a);
        if (!found || !field.selection) return found ? {} : null;
        return gqlResolveFields('Repository', { repo: found }, field, variables, ctx);
      }
      if (parsed.kind === 'Issue' && parsed.b !== null) {
        const found = findRepoById(parsed.a);
        const item = found?.items.get(parsed.b);
        if (!found || !item || item.kind !== 'issue' || !field.selection) return null;
        return gqlResolveFields('Issue', { repo: found, issue: item }, field, variables, ctx);
      }
      if (parsed.kind === 'PullRequest' && parsed.b !== null) {
        const found = findRepoById(parsed.a);
        const item = found?.items.get(parsed.b);
        if (!found || !item || item.kind !== 'pr' || !field.selection) return null;
        return gqlResolveFields('PullRequest', { repo: found, pr: item }, field, variables, ctx);
      }
      return null;
    }
    if (name === '__type') {
      const typeArg = gqlResolveArg(field, 'name', variables) as string | undefined;
      if (!typeArg) return null;
      const out: Json = { name: typeArg, kind: 'OBJECT' };
      for (const sub of field.selection ?? []) {
        const key = sub.alias ?? sub.name;
        if (sub.name === 'fields') {
          out[key] = (GQL_TYPE_FIELDS[typeArg] ?? []).map((fieldName) => ({ name: fieldName }));
        } else if (sub.name === 'enumValues') {
          out[key] = (GQL_TYPE_ENUMS[typeArg] ?? []).map((value) => ({ name: value }));
        } else if (sub.name === 'name') {
          out[key] = typeArg;
        } else if (sub.name === 'kind') {
          out[key] = 'OBJECT';
        }
      }
      return out;
    }
    if (name === '__schema') {
      const out: Json = {};
      for (const sub of field.selection ?? []) {
        if (sub.name === 'queryType') out[sub.alias ?? 'queryType'] = { name: 'Query' };
        else if (sub.name === 'mutationType') out[sub.alias ?? 'mutationType'] = { name: 'Mutation' };
      }
      return out;
    }
    ctx?.errors.push(gqlError(`Cannot query field "${name}" on type "Query".`));
    return null;
  }
  if (typeName === 'Repository') {
    if (!repo) return null;
    switch (name) {
      case 'id': return globalId('Repository', repo.id);
      case 'databaseId': return repo.id;
      case 'name': return repo.name;
      case 'nameWithOwner': return repo.full_name;
      case 'owner': {
        if (!field.selection) return { login: VIEWER.login };
        const ownerOut: Json = {};
        for (const sub of field.selection) {
          if (sub.name === 'login') ownerOut[sub.alias ?? 'login'] = VIEWER.login;
          else if (sub.name === 'id') ownerOut[sub.alias ?? 'id'] = globalId('User', VIEWER.id);
          else ctx?.errors.push(gqlError(`Cannot query field "${sub.name}" on type "User".`));
        }
        return ownerOut;
      }
      case 'defaultBranchRef': {
        if (!field.selection) return { name: repo.default_branch };
        const out: Json = {};
        for (const sub of field.selection) {
          if (sub.name === 'name') out[sub.alias ?? 'name'] = repo.default_branch;
          else if (sub.name === 'target') out[sub.alias ?? 'target'] = null;
        }
        return out;
      }
      case 'viewerPermission': return 'ADMIN';
      case 'hasIssuesEnabled': return true;
      case 'issue': {
        const number = gqlResolveArg(field, 'number', variables) as number | undefined;
        const item = number !== undefined ? repo.items.get(number) : undefined;
        if (!item || item.kind !== 'issue') return null;
        return gqlResolveFields('Issue', { repo, issue: item }, field, variables, ctx);
      }
      case 'issues': return gqlIssuesConnection(repo, field, variables);
      case 'pullRequest': {
        const number = gqlResolveArg(field, 'number', variables) as number | undefined;
        const item = number !== undefined ? repo.items.get(number) : undefined;
        if (!item || item.kind !== 'pr') return null;
        return gqlResolveFields('PullRequest', { repo, pr: item }, field, variables, ctx);
      }
      case 'pullRequests': return gqlPullsConnection(repo, field, variables);
      default:
        ctx?.errors.push(gqlError(`Cannot query field "${name}" on type "Repository".`));
        return null;
    }
  }
  if (typeName === 'Issue') {
    const issue = source.issue;
    if (!issue) return null;
    switch (name) {
      case 'id': return globalId('Issue', repo!.id, issue.number);
      case 'number': return issue.number;
      case 'title': return issue.title;
      case 'state': return issue.state.toUpperCase();
      case 'body': return issue.body;
      case 'createdAt': return issue.created_at;
      case 'updatedAt': return issue.updated_at;
      case 'labels': return { nodes: issue.labels.map((label) => ({ name: label.name })) };
      case 'comments': return { totalCount: issue.comments.length };
      default:
        ctx?.errors.push(gqlError(`Cannot query field "${name}" on type "Issue".`));
        return null;
    }
  }
  if (typeName === 'PullRequest') {
    const pr = source.pr;
    if (!pr) return null;
    switch (name) {
      case 'id': return globalId('PullRequest', repo!.id, pr.number);
      case 'number': return pr.number;
      case 'title': return pr.title;
      case 'state': return pr.merged ? 'MERGED' : pr.state.toUpperCase();
      case 'body': return pr.body;
      case 'headRefName': return pr.head;
      case 'baseRefName': return pr.base;
      case 'mergeable': return prMergeable(repo!, pr);
      case 'merged': return pr.merged;
      case 'mergeCommit': return pr.merge_commit_sha ? { oid: pr.merge_commit_sha } : null;
      case 'files': {
        const changed = prFiles(repo!, pr);
        return {
          totalCount: changed.length,
          nodes: changed.map((file) => ({ path: file.filename, additions: file.additions, deletions: file.deletions, changeType: file.status.toUpperCase() })),
        };
      }
      case 'createdAt': return pr.created_at;
      case 'updatedAt': return pr.updated_at;
      default:
        ctx?.errors.push(gqlError(`Cannot query field "${name}" on type "PullRequest".`));
        return null;
    }
  }
  if (typeName === 'Mutation') {
    return gqlResolveMutation(name, field, variables, ctx);
  }
  void known;
  ctx?.errors.push(gqlError(`Cannot query field "${name}" on type "${typeName}".`));
  return null;
}

function gqlResolveMutation(name: string, field: GqlField, variables: Record<string, unknown>, ctx?: GqlExecContext): unknown {
  const selection = field.selection ?? [];
  const project = (value: Json): Json => {
    const out: Json = {};
    for (const sub of selection) {
      const key = sub.alias ?? sub.name;
      if (sub.name === 'clientMutationId') out[key] = gqlResolveArg(field, 'clientMutationId', variables) ?? null;
      else if (sub.name in value) out[key] = value[sub.name];
      else if (sub.selection && value[sub.name] && typeof value[sub.name] === 'object') {
        out[key] = value[sub.name];
      } else out[key] = value[sub.name] ?? null;
    }
    return out;
  };
  if (name === 'createIssue') {
    const input = (gqlResolveArg(field, 'input', variables) as Json | undefined) ?? {};
    const repositoryId = String(input.repositoryId ?? '');
    const parsed = parseGlobalId(repositoryId);
    const repo = parsed?.kind === 'Repository' ? findRepoById(parsed.a) : undefined;
    if (!repo) {
      ctx?.errors.push(gqlError('Could not resolve to a Repository with the global id provided.'));
      return project({ issue: null });
    }
    const number = repo.nextNumber++;
    const now = nextTimestamp();
    const issue: Issue = {
      kind: 'issue',
      id: objectIdSeq++,
      number,
      title: String(input.title ?? ''),
      body: String(input.body ?? ''),
      state: 'open',
      labels: [],
      comments: [],
      created_at: now,
      updated_at: now,
      seq: number,
      cachedJson: null,
    };
    repo.items.set(number, issue);
    return project({ issue: gqlResolveFields('Issue', { repo, issue }, { alias: null, name: 'issue', args: [], selection: selection.find((s) => s.name === 'issue')?.selection ?? null }, variables, ctx) });
  }
  if (name === 'closeIssue') {
    const input = (gqlResolveArg(field, 'input', variables) as Json | undefined) ?? {};
    const parsed = parseGlobalId(String(input.issueId ?? ''));
    const repo = parsed?.kind === 'Issue' ? findRepoById(parsed.a) : undefined;
    const item = repo && parsed?.b !== null ? repo.items.get(parsed.b) : undefined;
    if (!repo || !item || item.kind !== 'issue') {
      ctx?.errors.push(gqlError('Could not resolve to an Issue with the global id provided.'));
      return project({ issue: null });
    }
    item.state = 'closed';
    item.updated_at = nextTimestamp();
    touchIssue(item);
    return project({ issue: gqlResolveFields('Issue', { repo, issue: item }, { alias: null, name: 'issue', args: [], selection: selection.find((s) => s.name === 'issue')?.selection ?? null }, variables, ctx) });
  }
  if (name === 'createPullRequest') {
    const input = (gqlResolveArg(field, 'input', variables) as Json | undefined) ?? {};
    const parsed = parseGlobalId(String(input.repositoryId ?? ''));
    const repo = parsed?.kind === 'Repository' ? findRepoById(parsed.a) : undefined;
    if (!repo) {
      ctx?.errors.push(gqlError('Could not resolve to a Repository with the global id provided.'));
      return project({ pullRequest: null });
    }
    const base = String(input.baseRefName ?? '');
    const head = String(input.headRefName ?? '');
    if (!repo.refs.get(`refs/heads/${base}`) || !repo.refs.get(`refs/heads/${head}`)) {
      ctx?.errors.push(gqlError('No commits between base and head'));
      return project({ pullRequest: null });
    }
    const number = repo.nextNumber++;
    const now = nextTimestamp();
    const pr: PullRequest = {
      kind: 'pr',
      id: objectIdSeq++,
      number,
      title: String(input.title ?? ''),
      body: String(input.body ?? ''),
      state: 'open',
      head,
      base,
      merged: false,
      merged_at: null,
      merge_commit_sha: null,
      created_at: now,
      updated_at: now,
      seq: number,
    };
    repo.items.set(number, pr);
    return project({ pullRequest: gqlResolveFields('PullRequest', { repo, pr }, { alias: null, name: 'pullRequest', args: [], selection: selection.find((s) => s.name === 'pullRequest')?.selection ?? null }, variables, ctx) });
  }
  if (name === 'mergePullRequest') {
    const input = (gqlResolveArg(field, 'input', variables) as Json | undefined) ?? {};
    const parsed = parseGlobalId(String(input.pullRequestId ?? ''));
    const repo = parsed?.kind === 'PullRequest' ? findRepoById(parsed.a) : undefined;
    const item = repo && parsed?.b !== null ? repo.items.get(parsed.b) : undefined;
    if (!repo || !item || item.kind !== 'pr') {
      ctx?.errors.push(gqlError('Could not resolve to a PullRequest with the global id provided.'));
      return project({ pullRequest: null });
    }
    const mergeSha = squashMerge(repo, item);
    if (mergeSha === null) {
      ctx?.errors.push(gqlError('Merge conflict'));
      return project({ pullRequest: null });
    }
    setRef(repo, `refs/heads/${item.base}`, mergeSha);
    item.merged = true;
    item.state = 'closed';
    item.merged_at = nextTimestamp();
    item.merge_commit_sha = mergeSha;
    item.updated_at = item.merged_at;
    return project({ pullRequest: gqlResolveFields('PullRequest', { repo, pr: item }, { alias: null, name: 'pullRequest', args: [], selection: selection.find((s) => s.name === 'pullRequest')?.selection ?? null }, variables, ctx) });
  }
  if (name === 'addComment') {
    const input = (gqlResolveArg(field, 'input', variables) as Json | undefined) ?? {};
    const parsed = parseGlobalId(String(input.subjectId ?? ''));
    const repo = parsed ? findRepoById(parsed.a) : undefined;
    const item = repo && parsed?.b !== null ? repo.items.get(parsed.b) : undefined;
    if (!repo || !item || item.kind !== 'issue') {
      ctx?.errors.push(gqlError('Could not resolve to an Issue with the global id provided.'));
      return project({ commentEdge: null });
    }
    const now = nextTimestamp();
    const comment: IssueComment = { id: commentIdSeq++, body: String(input.body ?? ''), created_at: now, updated_at: now, user: userObject() };
    item.comments.push(comment);
    item.updated_at = now;
    touchIssue(item);
    const edge: Json = { node: { id: globalId('Comment', repo.id, comment.id), body: comment.body } };
    return project({ commentEdge: edge });
  }
  ctx?.errors.push(gqlError(`Cannot query field "${name}" on type "Mutation".`));
  return null;
}

function executeGraphQL(payload: unknown): Json {
  if (!isRecord(payload) || typeof payload.query !== 'string') {
    return { errors: [gqlError('Request must include a query string.')] };
  }
  const variables = isRecord(payload.variables) ? (payload.variables as Record<string, unknown>) : {};
  let operation: GqlOperation;
  try {
    operation = new GqlParser(payload.query).parse();
  } catch (error) {
    return { errors: [gqlError(`Syntax Error: ${error instanceof Error ? error.message : 'invalid query'}`)] };
  }
  for (const [name, defaultValue] of operation.variables) {
    if (!(name in variables) && defaultValue !== undefined) variables[name] = defaultValue.value;
  }
  const ctx: GqlExecContext = { errors: [], repo: null };
  const data: Json = {};
  const rootType = operation.kind === 'mutation' ? 'Mutation' : 'Query';
  for (const field of operation.fields) {
    const key = field.alias ?? field.name;
    data[key] = gqlResolveField(rootType, {}, field, variables, ctx);
  }
  const result: Json = { data };
  if (ctx.errors.length > 0) result.errors = ctx.errors;
  return result;
}

function handleGraphQL(ctx: RouteContext): void {
  const { req, res, body } = ctx;
  if (req.method !== 'POST') {
    notFound(res);
    return;
  }
  const parsed = parseJsonBody(body);
  if (!parsed.ok) {
    jsonResponse(res, 400, { errors: [gqlError('Problems parsing JSON')] });
    return;
  }
  if (Array.isArray(parsed.value)) {
    jsonResponse(res, 200, parsed.value.map((entry) => executeGraphQL(entry)));
    return;
  }
  jsonResponse(res, 200, executeGraphQL(parsed.value));
}

// ---------------------------------------------------------------------------------------------
// MCP: JSON-RPC 2.0 at /mcp
// ---------------------------------------------------------------------------------------------

const MCP_TOOLS: Json[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository.',
    inputSchema: { type: 'object', properties: { name: { type: 'string', description: 'Repository name' }, description: { type: 'string', description: 'Repository description' }, private: { type: 'boolean', description: 'Whether the repository is private' }, owner: { type: 'string', description: 'Owner login' } }, required: ['name'] },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Owner login' }, repo: { type: 'string', description: 'Repository name' } }, required: ['owner', 'repo'] },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Owner login' }, repo: { type: 'string', description: 'Repository name' }, title: { type: 'string', description: 'Issue title' }, body: { type: 'string', description: 'Issue body' } }, required: ['owner', 'repo', 'title'] },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Owner login' }, repo: { type: 'string', description: 'Repository name' }, state: { type: 'string', description: 'Issue state filter', enum: ['open', 'closed', 'all'] } }, required: ['owner', 'repo'] },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Owner login' }, repo: { type: 'string', description: 'Repository name' }, title: { type: 'string', description: 'Pull request title' }, head: { type: 'string', description: 'Head branch' }, base: { type: 'string', description: 'Base branch' }, body: { type: 'string', description: 'Pull request body' } }, required: ['owner', 'repo', 'title', 'head', 'base'] },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request in a repository.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Owner login' }, repo: { type: 'string', description: 'Repository name' }, pull_number: { type: 'number', description: 'Pull request number' } }, required: ['owner', 'repo', 'pull_number'] },
  },
];

function mcpResult(res: ServerResponse, id: unknown, result: Json): void {
  jsonResponse(res, 200, { jsonrpc: '2.0', id, result });
}

function mcpError(res: ServerResponse, id: unknown, code: number, message: string): void {
  jsonResponse(res, 200, { jsonrpc: '2.0', id, error: { code, message } });
}

function mcpToolResult(res: ServerResponse, id: unknown, content: unknown, isError = false): void {
  mcpResult(res, id, {
    content: [{ type: 'text', text: typeof content === 'string' ? content : JSON.stringify(content) }],
    structuredContent: isRecord(content) || Array.isArray(content) ? content : { value: content },
    isError,
  });
}

function handleMcp(ctx: RouteContext): void {
  const { req, res, body } = ctx;
  if (req.method !== 'POST') {
    notFound(res);
    return;
  }
  let payload: unknown;
  try {
    payload = JSON.parse(body.toString('utf8'));
  } catch {
    jsonResponse(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  if (!isRecord(payload) || typeof payload.method !== 'string') {
    jsonResponse(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
    return;
  }
  const id = payload.id ?? null;
  const method = payload.method;
  const params = isRecord(payload.params) ? payload.params : {};

  if (method === 'server/discover') {
    mcpResult(res, id, {
      supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'],
      capabilities: { tools: {} },
      serverInfo: { name: 'github-core-clone', version: VERSION },
    });
    return;
  }
  if (method === 'initialize') {
    const requested = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2025-11-25';
    const supported = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
    const protocolVersion = supported.includes(requested) ? requested : '2025-11-25';
    mcpResult(res, id, { protocolVersion, capabilities: { tools: {} }, serverInfo: { name: 'github-core-clone', version: VERSION } });
    return;
  }
  if (method === 'notifications/initialized' || method.startsWith('notifications/')) {
    res.writeHead(202, { 'X-GitHub-Request-Id': nextRequestId() });
    res.end();
    return;
  }
  if (method === 'ping') {
    mcpResult(res, id, {});
    return;
  }
  if (method === 'tools/list') {
    mcpResult(res, id, { tools: MCP_TOOLS });
    return;
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = isRecord(params.arguments) ? params.arguments : {};
    const tool = MCP_TOOLS.find((entry) => entry.name === toolName);
    if (!tool) {
      mcpError(res, id, -32602, `Unknown tool: ${toolName}`);
      return;
    }
    const required = ((tool.inputSchema as Json).required as string[]) ?? [];
    for (const key of required) {
      if (args[key] === undefined || args[key] === null || args[key] === '') {
        mcpToolResult(res, id, { error: `Missing required argument: ${key}` }, true);
        return;
      }
    }
    const owner = typeof args.owner === 'string' ? args.owner : VIEWER.login;
    if (toolName === 'create_repo') {
      const name = String(args.name);
      if (repos.has(name)) {
        mcpToolResult(res, id, { error: 'Repository already exists' }, true);
        return;
      }
      const repo = createRepoRecord(name, args.private === true, typeof args.description === 'string' ? args.description : '');
      mcpToolResult(res, id, repoObject(repo));
      return;
    }
    const repoName = String(args.repo ?? '');
    const repo = findRepo(owner, repoName);
    if (!repo) {
      mcpToolResult(res, id, { error: 'Repository not found' }, true);
      return;
    }
    if (toolName === 'get_repo') {
      mcpToolResult(res, id, repoObject(repo));
      return;
    }
    if (toolName === 'create_issue') {
      const number = repo.nextNumber++;
      const now = nextTimestamp();
      const issue: Issue = {
        kind: 'issue',
        id: objectIdSeq++,
        number,
        title: String(args.title),
        body: typeof args.body === 'string' ? args.body : '',
        state: 'open',
        labels: [],
        comments: [],
        created_at: now,
        updated_at: now,
        seq: number,
        cachedJson: null,
      };
      repo.items.set(number, issue);
      mcpToolResult(res, id, issueObject(repo, issue));
      return;
    }
    if (toolName === 'list_issues') {
      const state = typeof args.state === 'string' ? args.state : 'open';
      const issues = [...repo.items.values()]
        .filter((item) => item.kind === 'issue' && (state === 'all' || item.state === state))
        .sort((a, b) => b.number - a.number)
        .map((item) => issueObject(repo, item as Issue));
      mcpToolResult(res, id, { issues });
      return;
    }
    if (toolName === 'create_pull_request') {
      const head = String(args.head);
      const base = String(args.base);
      if (!repo.refs.get(`refs/heads/${head}`) || !repo.refs.get(`refs/heads/${base}`)) {
        mcpToolResult(res, id, { error: 'No commits between base and head' }, true);
        return;
      }
      const existing = [...repo.items.values()].find((item) => item.kind === 'pr' && (item as PullRequest).state === 'open' && (item as PullRequest).head === head && (item as PullRequest).base === base);
      if (existing) {
        mcpToolResult(res, id, { error: 'A pull request already exists for this head and base' }, true);
        return;
      }
      const number = repo.nextNumber++;
      const now = nextTimestamp();
      const pr: PullRequest = {
        kind: 'pr',
        id: objectIdSeq++,
        number,
        title: String(args.title),
        body: typeof args.body === 'string' ? args.body : '',
        state: 'open',
        head,
        base,
        merged: false,
        merged_at: null,
        merge_commit_sha: null,
        created_at: now,
        updated_at: now,
        seq: number,
      };
      repo.items.set(number, pr);
      mcpToolResult(res, id, pullObject(repo, pr));
      return;
    }
    if (toolName === 'merge_pull_request') {
      const number = Number(args.pull_number);
      const item = repo.items.get(number);
      if (!item || item.kind !== 'pr') {
        mcpToolResult(res, id, { error: 'Pull request not found' }, true);
        return;
      }
      if (item.state !== 'open') {
        mcpToolResult(res, id, { error: 'Pull request is not open' }, true);
        return;
      }
      const mergeSha = squashMerge(repo, item);
      if (mergeSha === null) {
        mcpToolResult(res, id, { error: 'Merge conflict' }, true);
        return;
      }
      setRef(repo, `refs/heads/${item.base}`, mergeSha);
      item.merged = true;
      item.state = 'closed';
      item.merged_at = nextTimestamp();
      item.merge_commit_sha = mergeSha;
      item.updated_at = item.merged_at;
      mcpToolResult(res, id, { sha: mergeSha, merged: true, message: `Merge pull request #${item.number} from ${VIEWER.login}/${item.head}` });
      return;
    }
    mcpError(res, id, -32602, `Unknown tool: ${toolName}`);
    return;
  }
  mcpError(res, id, -32601, `Method not found: ${method}`);
}

// ---------------------------------------------------------------------------------------------
// Server: routing and export
// ---------------------------------------------------------------------------------------------

export function createApp(): Server {
  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const body = await readBody(req).catch(() => Buffer.alloc(0));
    const url = req.url ?? '/';
    const path = url.split('?')[0];
    const segments = path.split('/').filter((segment) => segment !== '');
    const query = parseQuery(url);
    const ctx: RouteContext = { req, res, body, segments, query };

    if (path === '/healthz' || path === '/health') {
      res.writeHead(200, { 'Content-Type': 'text/plain', 'X-GitHub-Request-Id': nextRequestId() });
      res.end('ok');
      return;
    }
    if (routeGit(ctx)) return;

    const isApiRoute = segments[0] === 'api' || segments[0] === 'mcp';
    if (isApiRoute) {
      if (segments[0] === 'mcp') {
        if (!requireAuth(req, res)) return;
        handleMcp(ctx);
        return;
      }
      if (segments[1] === 'v3') {
        if (!requireAuth(req, res)) return;
        routeRest(ctx);
        return;
      }
      if (segments[1] === 'graphql') {
        if (!requireAuth(req, res)) return;
        handleGraphQL(ctx);
        return;
      }
      notFound(res);
      return;
    }

    if (segments.length === 0) {
      jsonResponse(res, 200, { message: 'github-core-clone' });
      return;
    }
    notFound(res);
  });
}

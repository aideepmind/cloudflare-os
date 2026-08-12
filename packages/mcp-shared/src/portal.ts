// Recovers the upstream servers behind an aggregator endpoint, such as a Cloudflare MCP server
// portal, which flattens every upstream server's tools into one `tools/list`.
//
// Two facts from the portal's documented contract carry this. Every tool is named
// `{server_id}_{original_name}`, split on the FIRST underscore only, and an alias replaces the tool
// name but never the prefix; so membership is a string test that cannot fail open on a network
// error. And portals expose their own `portal_*` tools, one of which identifies the endpoint as a
// portal. See the MCP Server Portals connector's README.

import type { McpTool } from "./client.js";
import { MAX_TOOLS_PER_SERVER } from "./tools.js";

// The portal's built-in server-listing tool. Its presence in `tools/list` is what identifies an
// endpoint as a portal.
//
// Calling it yields display names, ordering and enabled state, but not authority: membership is
// decided by the `{server_id}_` prefix on each tool name, which is what `scopeAllows` enforces. A
// server the listing omits still owns its prefixed tools, and one it invents owns nothing. See
// `reconcilePortalServers`.
export const PORTAL_LIST_SERVERS_TOOL = "portal_list_servers";

// Prefix the portal reserves for its own session-management tools.
const PORTAL_NATIVE_PREFIX = "portal_";

// One upstream server behind a portal, as the portal itself reports it.
export type PortalServer = {
  // The server id that prefixes every one of its tool names.
  id: string;
  // Display name, falling back to the id.
  name: string;
  // Whether the server is currently enabled in this portal session.
  enabled: boolean;
};

// True for the portal's own tools, which are excluded from every grant: `portal_toggle_servers` and
// friends change which upstream servers the session can reach, so granting one would let a Gadget
// widen its own authority.
export function isPortalNativeTool(name: string): boolean {
  return name.startsWith(PORTAL_NATIVE_PREFIX);
}

// True when this tool list came from a portal.
//
// A truncated listing counts as a portal regardless of what is in it: `tools/list` is unordered, so
// answering "not a portal" because the evidence fell past the cut would fail open on the `portal_*`
// exclusion above -- a real portal would be granted at its bare endpoint, and a Gadget holding that
// grant could call `portal_toggle_servers` to widen its own reach.
//
// The explicit bounds form avoids guessing. `truncated` covers the byte budget, which stops a
// listing without leaving a short array behind, and `cap` is the tool count the caller fetched with,
// so that reaching it can be read as evidence of a cut here too. Callers fetch with several
// different caps -- a scoped catalog and a wide index are not the same size -- and a cap guessed
// wrong on the low side reports portals that are not, while one guessed high misses the cut that
// the first paragraph exists to catch. The boolean overload preserves callers using the ordinary
// catalog cap while portal-specific wide indexes migrate to explicit bounds.
export function looksLikePortal(
  tools: readonly Pick<McpTool, "name">[],
): boolean;
export function looksLikePortal(
  tools: readonly Pick<McpTool, "name">[],
  truncated: boolean,
): boolean;
export function looksLikePortal(
  tools: readonly Pick<McpTool, "name">[],
  bounds: { truncated: boolean; cap: number },
): boolean;
export function looksLikePortal(
  tools: readonly Pick<McpTool, "name">[],
  bounds: boolean | { truncated: boolean; cap: number } = false,
): boolean {
  const normalized = typeof bounds === "boolean"
    ? { truncated: bounds, cap: MAX_TOOLS_PER_SERVER }
    : bounds;
  if (normalized.truncated || tools.length >= normalized.cap) return true;
  return tools.some(tool => tool.name === PORTAL_LIST_SERVERS_TOOL);
}

// The upstream server id a portal tool name belongs to, or null if it carries no prefix. Split on
// the first underscore only, so an upstream tool name may itself contain underscores.
function serverIdOfTool(name: string): string | null {
  const separator = name.indexOf("_");
  if (separator <= 0 || separator === name.length - 1) return null;
  return name.slice(0, separator);
}

// Whether `toolName` belongs to upstream server `serverId`. Syntactic, so enforcing a server scope
// never depends on reaching the portal.
export function toolBelongsToServer(toolName: string, serverId: string): boolean {
  return serverIdOfTool(toolName) === serverId;
}

// Groups a portal's tools by upstream server id, dropping the portal's own tools.
export function groupToolsByServer<T extends Pick<McpTool, "name">>(
  tools: T[],
): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const tool of tools) {
    if (isPortalNativeTool(tool.name)) continue;
    const serverId = serverIdOfTool(tool.name);
    if (!serverId) continue;
    const existing = groups.get(serverId);
    if (existing) existing.push(tool);
    else groups.set(serverId, [tool]);
  }
  return groups;
}

// `portal_list_servers` answers in prose, not JSON. A Cloudflare portal replies with bullet lines of
// the form `- {display name} ({server id}): {status}`:
//
//   Available MCP Servers:
//
//   - Cloudflare documentation (test): \u2713 enabled
//   - Linear (linear): \u2713 enabled
//
// Display metadata only, so an unrecognized line is skipped rather than raised, but the enclosing
// listing is marked incomplete so a truncated tool index cannot mistake the partial result for all
// servers. A complete index can still recover the skipped id from tool-name prefixes.
function parseServerLine(line: string): PortalServer | null {
  const bulletLine = line.trimStart();
  if (bulletLine[0] !== "-" && bulletLine[0] !== "*" && bulletLine[0] !== "\u2022") return null;

  const content = bulletLine.slice(1);
  let nameStart = 0;
  while (nameStart < content.length && content[nameStart].trim().length === 0) ++nameStart;

  let open = -1;
  let closedOpen = -1;
  let close = -1;
  for (let index = nameStart; index < content.length; ++index) {
    const character = content[index];
    if (close >= 0) {
      if (character === ":") {
        const name = content.slice(nameStart, closedOpen).trimEnd();
        if (!name && nameStart === 0) return null;
        const id = content.slice(closedOpen + 1, close);
        return {
          id,
          name: name || id,
          enabled: !/disabled|\u2717|\u2718/i.test(content.slice(index + 1)),
        };
      }
      if (character.trim().length === 0) continue;
      close = -1;
      closedOpen = -1;
    }

    if (character === "(") {
      open = index;
    } else if (open >= 0 && character === ")") {
      if (index > open + 1) {
        closedOpen = open;
        close = index;
      }
      open = -1;
    } else if (open >= 0 && character.trim().length === 0) {
      open = -1;
    }
  }
  return null;
}

function parseServerLines(text: string): {
  servers: PortalServer[];
  complete: boolean;
  recognized: boolean;
} {
  const servers: PortalServer[] = [];
  const seen = new Set<string>();
  let recognized = /available mcp servers\s*:/i.test(text);
  let complete = true;
  for (const line of text.split(/\r?\n/)) {
    const first = line.trimStart()[0];
    const bullet = first === "-" || first === "*" || first === "\u2022";
    const server = parseServerLine(line);
    if (!server) {
      if (bullet) complete = false;
      continue;
    }
    recognized = true;
    if (seen.has(server.id)) continue;
    seen.add(server.id);
    servers.push(server);
  }
  return { servers, complete: recognized && complete, recognized };
}

// A `structuredContent` payload, if a future portal version supplies one. Read literally as an array
// of `{ id, name, enabled }`, with no guessing at alternative spellings.
function parseStructured(value: unknown): { servers: PortalServer[]; complete: boolean } | null {
  if (value === undefined) return null;
  if (!Array.isArray(value)) return { servers: [], complete: false };
  const servers: PortalServer[] = [];
  let complete = true;
  for (const entry of value) {
    if (typeof entry !== "object" || entry === null) {
      complete = false;
      continue;
    }
    const record = entry as Record<string, unknown>;
    const id = typeof record.id === "string" ? record.id.trim() : "";
    if (!id) {
      complete = false;
      continue;
    }
    servers.push({
      id,
      name: typeof record.name === "string" && record.name.trim() ? record.name.trim() : id,
      enabled: record.enabled !== false,
    });
  }
  return { servers, complete };
}

/** A parsed portal server list and whether every advertised entry was understood. */
export type PortalServerListing = { servers: PortalServer[]; complete: boolean };

// Parses the upstream server list out of a `portal_list_servers` result. `complete` is false when
// the response was absent, unrecognized, or only partly understood; a truncated tool index cannot
// safely use such a response as its authoritative list.
// Typed by what it reads rather than as `McpToolCallResult`, which a result satisfies: this is an
// untrusted reply and every field is re-checked here, so the loose type is the honest one.
export function parsePortalServers(
  result: { structuredContent?: unknown; content?: unknown },
): PortalServerListing {
  const structured = parseStructured(result.structuredContent);
  if (structured) return structured;

  for (const block of Array.isArray(result.content) ? result.content : []) {
    const { type, text } = (block ?? {}) as { type?: unknown; text?: unknown };
    if (type !== "text" || typeof text !== "string") continue;
    const listing = parseServerLines(text);
    if (listing.recognized) return { servers: listing.servers, complete: listing.complete };
  }
  return { servers: [], complete: false };
}

// Merges the portal's reported servers with the ids present in the tool list. With a complete
// catalog, tool names are the authority and reported empty servers are dropped. With a truncated
// catalog, absence is not evidence, so reported servers are retained for server-wide grants.
export function reconcilePortalServers(
  reported: PortalServer[], tools: Pick<McpTool, "name">[], truncated = false,
): PortalServer[] {
  const grouped = groupToolsByServer(tools);
  const byId = new Map(reported.map(server => [server.id, server]));
  const servers: PortalServer[] = [];
  const ids = truncated
    ? new Set([...reported.map(server => server.id), ...grouped.keys()])
    : grouped.keys();
  for (const id of ids) {
    servers.push(byId.get(id) ?? { id, name: id, enabled: true });
  }
  return servers.toSorted((a, b) => a.name.localeCompare(b.name));
}

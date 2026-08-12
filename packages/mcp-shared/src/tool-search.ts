// Matching a text query against a tool, shared by every catalog search.
//
// One implementation on purpose. Two connectors search the same way over different sources -- one
// filters definitions already in hand, while endpoint discovery applies it as each page is parsed --
// and a query answered differently depending on the path would be a difference nobody asked for and
// nobody could see.

import type { McpTool } from "./client.js";

// Longest query accepted. A query is agent-supplied text that ends up in an observation record, and
// every term is tested against every tool, so its length bounds work as well as display.
export const MAX_QUERY_CHARS = 200;

// Most matches any search returns. A search is a discovery aid: an agent that wants the whole list
// should read the catalog, and a result set large enough to fill the agent's context is not a search.
export const MAX_SEARCH_RESULTS = 20;

// Longest run of one server-supplied field considered when matching.
//
// The bound is load-bearing on the path that matches tools as they arrive from the endpoint, before
// per-field clamping: a description there is whatever the server sent, and every term is tested
// against it. Applied unconditionally rather than only on that path, so no caller has to know which
// of its inputs were already clamped in order to be safe.
const MAX_SEARCHABLE_FIELD_CHARS = 4000;

// Normalizes text for matching. Word separators become spaces so that a query typed as
// `list issues`, `list_issues`, or `listIssues` reaches a tool named `github_list_issues`: MCP tool
// names are overwhelmingly snake_case or camelCase, and a portal prefixes each with `{server_id}_`,
// so leaving word boundaries in place would make the obvious query miss the obvious tool.
function normalize(text: string): string {
  return text.slice(0, MAX_SEARCHABLE_FIELD_CHARS)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .replace(/[_\-\s]+/g, " ");
}

// Splits a query into the terms a tool must match all of. Normalized the same way as the text it is
// matched against, so the two cannot disagree about what a separator is.
export function toolQueryTerms(query: string): string[] {
  return normalize(query).split(" ").filter(Boolean);
}

// Whether a tool matches every term, by name, title, and description.
export function matchesToolQuery(
  tool: Pick<McpTool, "name" | "title" | "description">,
  terms: readonly string[],
): boolean {
  if (terms.length === 0) return false;
  const text = [tool.name, tool.title, tool.description]
    .filter((value): value is string => typeof value === "string")
    .map(normalize)
    .join(" ");
  return terms.every(term => text.includes(term));
}

// The trust boundary: what an MCP server says about its own tools becomes what a Gadget may do.
// Nothing outside this file reads a tool's `annotations`.

import type { ActionKind } from "@gadgets/workshop-shared/gatekeeper";
import {
  clampToolSummary,
  type McpContentBlock,
  type McpTool,
  type McpToolAnnotations,
  type McpToolCallResult,
} from "./client.js";
import type { McpCallResult, McpToolInfo, McpToolSummary } from "./types";
import { hexEncode } from "./util.js";

// How far an endpoint's self-description is trusted.
//
// MCP's own guidance is that a client must treat tool annotations as untrusted unless they come from
// a trusted server. This type is that distinction, made explicit and decided by the deployment
// rather than by the server describing itself:
//
// vetted   an administrator asserted this endpoint's annotations are reliable; they may drive
//          auto-approval.
// byo      a user typed the URL in. `readOnlyHint` still classifies reads; nothing it says can
//          auto-apply a write.
//
// Honouring `readOnlyHint` on `byo` is a knowing departure from treating annotations as wholly
// untrusted, argued in `classifyTool` below and stated on the connect form the user types the URL
// into. Every other annotation is inert until a deployment vouches for the endpoint.
//
// This governs trust in annotations only. Neither tier can be shared (see `sharing-policy.ts`). It
// is deployment configuration rather than account state, so read it afresh wherever it is used and
// withdrawing it takes effect without a reconnect.
export type ServerTrust = "vetted" | "byo";

// Which side decided a tool's read/action classification.
export type ClassificationSource = "server-annotation" | "default";

// Upper bound on tools taken from one endpoint, to keep generated types and catalogs bounded.
export const MAX_TOOLS_PER_SERVER = 200;

// The decisions this gatekeeper has made about one tool, independent of the tool itself.
export type ToolClassification = {
  // `read` runs immediately and is recorded as an observation; `action` goes to the queue.
  mode: "read" | "action";
  // Whether the deployment may let this action through without a prompt.
  autoApprovable: boolean;
  // Whose word `mode` rests on. Recorded rather than re-derived, so no consumer can answer it
  // differently from the classifier that did.
  classifiedBy: ClassificationSource;
};

// A tool plus the decisions this gatekeeper has made about it.
export type ClassifiedTool = ToolClassification & {
  tool: McpTool;
};

// Whether the server declares this tool read-only. Strictly `=== true`, matching the spec's own
// default of `false`, so an absent annotation is not a read.
function isDeclaredReadOnly(annotations: McpToolAnnotations | undefined): boolean {
  return annotations?.readOnlyHint === true;
}

// The single place a server's self-description becomes a policy decision.
//
// `readOnlyHint` is honoured on both tiers. That is a tradeoff, not a free win: a tool the server
// mislabels runs with no approval, where an unlabelled one would have been queued. Auto-applying a
// write is not accepted on the same terms, and additionally requires a vetted endpoint, so the
// deployment rather than the server casts the deciding vote. See the README.
//
// Every test is `=== true` or `=== false` rather than a truthiness check, so an unannotated tool
// fails all of them and comes out as an action that can never auto-apply.
export function classifyAnnotations(
  annotations: McpToolAnnotations | undefined,
  trust: ServerTrust,
): ToolClassification {
  const claims = annotations ?? {};
  const readOnly = isDeclaredReadOnly(annotations);

  const autoApprovable = !readOnly
    && trust === "vetted"
    && claims.destructiveHint === false
    && claims.idempotentHint === true;

  return {
    mode: readOnly ? "read" : "action",
    autoApprovable,
    classifiedBy: readOnly ? "server-annotation" : "default",
  };
}

// Classifies a full tool definition. Annotations are the only input, so an `IndexedTool` can be
// classified identically through `classifyAnnotations` -- but only a real definition can become a
// `ClassifiedTool`, which is what gets rendered into approval prompts and generated types.
export function classifyTool(tool: McpTool, trust: ServerTrust): ClassifiedTool {
  return { tool, ...classifyAnnotations(tool.annotations, trust) };
}

// The tool as a Gadget sees it. `classifiedBy` is carried through so an audit can find every call
// that was trusted on the server's word.
export function toolInfo(entry: ClassifiedTool): McpToolInfo {
  return {
    name: entry.tool.name,
    title: entry.tool.title,
    description: entry.tool.description,
    mode: entry.mode,
    classifiedBy: entry.classifiedBy,
    inputSchema: entry.tool.inputSchema,
  };
}

/** The bounded, schema-free form returned by catalog search. */
export function toolSummary(entry: ClassifiedTool): McpToolSummary {
  const tool = clampToolSummary(entry.tool);
  return {
    name: tool.name,
    title: tool.title,
    description: tool.description,
    mode: entry.mode,
    classifiedBy: entry.classifiedBy,
  };
}

// The approval-policy identity of one tool on one binding. `scopeTag` is caller-supplied so that two
// connectors using the same binding id cannot share pre-approvals.
export function actionKindFor(scopeTag: string, toolName: string): ActionKind {
  return { tag: `${encodeURIComponent(scopeTag)}:${encodeURIComponent(toolName)}`, label: toolName };
}

// One annotation as a fingerprint character. Tri-state, so that a server starting or stopping making
// a claim is visible even where both lead to the same decision today.
function claimChar(value: boolean | undefined): string {
  return value === true ? "1" : value === false ? "0" : "-";
}

// Every annotation that feeds a policy decision, in a fixed order.
function policyClaims(tool: McpTool): string {
  return [
    isDeclaredReadOnly(tool.annotations) ? "r" : "w",
    claimChar(tool.annotations?.destructiveHint),
    claimChar(tool.annotations?.idempotentHint),
  ].join("");
}

/** Stable snapshot of every mutable input that controls one tool's dispatch policy. */
export function toolPolicyFingerprint(tool: McpTool, trust: ServerTrust): string {
  return `${trust}:${policyClaims(tool)}`;
}

// Stable fingerprint of a tool catalog, for detecting that an endpoint changed under us.
//
// Covers each tool's name and every claim a grant was decided against, including `destructiveHint`
// and `idempotentHint`, which move a tool into `getAutoApprovableActions()` on a vetted endpoint.
// Descriptions are excluded so that copy edits do not fire the signal.
export async function catalogRevision(tools: McpTool[]): Promise<string> {
  const canonical = tools
    .map(tool => `${tool.name}\u0000${policyClaims(tool)}`)
    .toSorted()
    .join("\u0001");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return hexEncode(new Uint8Array(digest)).slice(0, 16);
}

// Flattens tool content into the shape a Gadget sees.
export function toCallResult(
  result: McpToolCallResult,
): Extract<McpCallResult, { status: "ok" }> {
  const content = (result.content ?? []) as McpContentBlock[];
  const text = content
    .filter((block): block is { type: "text"; text: string } => block.type === "text")
    .map(block => block.text)
    .join("\n");
  return {
    status: "ok",
    content: content as Extract<McpCallResult, { status: "ok" }>["content"],
    text,
    structuredContent: result.structuredContent,
    isError: result.isError,
  };
}

// Longest server-supplied tool description reproduced in an approval prompt.
const MAX_DESCRIPTION = 600;

// Longest rendering of a tool call's arguments reproduced in an approval prompt.
const MAX_ARGUMENTS = 4000;

// Neutralizes Markdown fences in text about to be placed inside one. Without it a value can close
// the fence and continue in the prompt's own voice.
function defuseFences(text: string): string {
  return text.replace(/`{3,}/g, "'''");
}

// Renders untrusted server text safely inside the approval prompt. Left alone, a tool description
// can write its own "Endpoint:" line and argue the server's case in the prompt's voice, so fences
// and headings are neutralized, the text is capped, and the rest is block-quoted.
function quoteUntrusted(text: string, max: number): string {
  const cleaned = defuseFences(text)
    // Repeated, since one strip leaves `##` as `#` -- still a heading, at heading weight, in the
    // prompt the approver reads.
    .replace(/^[ \t]*[#>]+[ \t]*/gm, "")
    .trim();
  const clipped = cleaned.length > max ? `${cleaned.slice(0, max)}\u2026` : cleaned;
  return clipped.split("\n").map(line => `> ${line}`).join("\n");
}

/**
 * Renders server-chosen text inside a bounded Markdown code span.
 *
 * Backticks are dropped and whitespace is flattened so the value cannot escape into prompt prose.
 */
export function codeSpan(text: string, max = MAX_INLINE_TEXT): string {
  const cleaned = text.replace(/`/g, "").replace(/\s+/g, " ").trim();
  const clipped = cleaned.length > max ? `${cleaned.slice(0, max)}\u2026` : cleaned;
  return `\`${clipped || "(unnamed)"}\``;
}

// Longest server-chosen name or endpoint shown inline in a prompt.
const MAX_INLINE_TEXT = 120;

// Renders untrusted text as inline prose, with the characters that would let it forge structure
// removed. `account.ts` already does this to a server's reported name before storing it; this is the
// same guard at the point of use, for the callers that pass a name from somewhere else.
//
// Exported for the observation records that quote text the agent chose, such as a search query,
// which is untrusted for the same reason a server's tool name is.
export function plainInline(text: string, max = MAX_INLINE_TEXT): string {
  const cleaned = text.replace(/[`*_[\]()#>|]/g, "").replace(/\s+/g, " ").trim();
  const clipped = cleaned.length > max ? `${cleaned.slice(0, max)}\u2026` : cleaned;
  return clipped || "(unnamed)";
}

// Renders a tool call as the Markdown an approver reads before deciding.
export function describeCall(args: {
  serverName: string;
  endpoint: string;
  tool: McpTool;
  toolArgs: Record<string, unknown>;
  mode: "read" | "action";
  classifiedBy: ClassificationSource;
}): { title: string; description: string } {
  // The arguments are the agent's text, and the agent is who this prompt protects the user from, so
  // they get the same treatment as the server's description. `JSON.stringify` escapes quotes and
  // backslashes but not backticks.
  let rendered: string;
  try {
    rendered = defuseFences(JSON.stringify(args.toolArgs, null, 2));
  } catch {
    rendered = "(arguments could not be displayed)";
  }
  if (rendered.length > MAX_ARGUMENTS) {
    rendered = `${rendered.slice(0, MAX_ARGUMENTS)}\n... (truncated)`;
  }

  const provenance = args.mode === "read"
    ? args.classifiedBy === "server-annotation"
      ? "The server declares this tool read-only, so it runs without approval. That claim comes " +
        "from the server itself."
      : "Treated as read-only by this deployment."
    : "Treated as an action because the server did not declare it read-only. Nothing has been " +
      "sent yet.";

  const description = [
    `**${plainInline(args.serverName)}** \u2192 ${codeSpan(args.tool.name)}`,
    "",
    args.tool.description
      ? quoteUntrusted(args.tool.description, MAX_DESCRIPTION)
      : "_The server provided no description for this tool._",
    "",
    "Arguments:",
    "```json",
    rendered,
    "```",
    "",
    `Endpoint: ${codeSpan(args.endpoint)}`,
    "",
    provenance,
  ].join("\n");

  // The title is plain text rather than Markdown, but it is server-chosen and appears in the
  // approval list, so it gets the same flattening and cap.
  return {
    title: `${plainInline(args.serverName)}: ${plainInline(args.tool.name)}`,
    description,
  };
}

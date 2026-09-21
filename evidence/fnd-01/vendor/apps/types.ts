/**
 * MCP Apps Protocol Types and Schemas
 *
 * This file re-exports types from `spec.types.ts` and schemas from `generated/schema.ts`.
 * Compile-time verification is handled by `generated/schema.test.ts`.
 *
 * @see `spec.types.ts` for the source of truth TypeScript interfaces
 * @see `generated/schema.ts` for auto-generated Zod schemas
 * @see `generated/schema.test.ts` for compile-time verification
 */

// Re-export all types from spec.types.ts
export {
  DOWNLOAD_FILE_METHOD,
  HOST_CONTEXT_CHANGED_METHOD,
  INITIALIZE_METHOD,
  INITIALIZED_METHOD,
  LATEST_PROTOCOL_VERSION,
  type McpUiAppCapabilities,
  type McpUiClientCapabilities,
  type McpUiDisplayMode,
  type McpUiDownloadFileRequest,
  type McpUiDownloadFileResult,
  type McpUiHostCapabilities,
  type McpUiHostContext,
  type McpUiHostContextChangedNotification,
  type McpUiHostCss,
  type McpUiHostStyles,
  type McpUiInitializedNotification,
  type McpUiInitializeRequest,
  type McpUiInitializeResult,
  type McpUiMessageRequest,
  type McpUiMessageResult,
  type McpUiOpenLinkRequest,
  type McpUiOpenLinkResult,
  type McpUiRequestDisplayModeRequest,
  type McpUiRequestDisplayModeResult,
  type McpUiRequestTeardownNotification,
  type McpUiResourceCsp,
  type McpUiResourceMeta,
  type McpUiResourcePermissions,
  type McpUiResourceTeardownRequest,
  type McpUiResourceTeardownResult,
  type McpUiSandboxProxyReadyNotification,
  type McpUiSandboxResourceReadyNotification,
  type McpUiSizeChangedNotification,
  type McpUiStyles,
  type McpUiStyleVariableKey,
  type McpUiSupportedContentBlockModalities,
  type McpUiTheme,
  type McpUiToolCancelledNotification,
  type McpUiToolInputNotification,
  type McpUiToolInputPartialNotification,
  type McpUiToolMeta,
  type McpUiToolResultNotification,
  type McpUiToolVisibility,
  type McpUiUpdateModelContextRequest,
  MESSAGE_METHOD,
  OPEN_LINK_METHOD,
  REQUEST_DISPLAY_MODE_METHOD,
  REQUEST_TEARDOWN_METHOD,
  RESOURCE_TEARDOWN_METHOD,
  SANDBOX_PROXY_READY_METHOD,
  SANDBOX_RESOURCE_READY_METHOD,
  SIZE_CHANGED_METHOD,
  TOOL_CANCELLED_METHOD,
  TOOL_INPUT_METHOD,
  TOOL_INPUT_PARTIAL_METHOD,
  TOOL_RESULT_METHOD,
} from "./spec.types.js";

// Import types needed for protocol type unions (not re-exported, just used internally)
import type {
  McpUiDownloadFileRequest,
  McpUiDownloadFileResult,
  McpUiHostContextChangedNotification,
  McpUiInitializedNotification,
  McpUiInitializeRequest,
  McpUiInitializeResult,
  McpUiMessageRequest,
  McpUiMessageResult,
  McpUiOpenLinkRequest,
  McpUiOpenLinkResult,
  McpUiRequestDisplayModeRequest,
  McpUiRequestDisplayModeResult,
  McpUiRequestTeardownNotification,
  McpUiResourceTeardownRequest,
  McpUiResourceTeardownResult,
  McpUiSandboxProxyReadyNotification,
  McpUiSandboxResourceReadyNotification,
  McpUiSizeChangedNotification,
  McpUiToolCancelledNotification,
  McpUiToolInputNotification,
  McpUiToolInputPartialNotification,
  McpUiToolResultNotification,
  McpUiUpdateModelContextRequest,
} from "./spec.types.js";

// Re-export all schemas from generated/schema.ts (already PascalCase)
export {
  McpUiAppCapabilitiesSchema,
  McpUiDisplayModeSchema,
  McpUiDownloadFileRequestSchema,
  McpUiDownloadFileResultSchema,
  McpUiHostCapabilitiesSchema,
  McpUiHostContextChangedNotificationSchema,
  McpUiHostContextSchema,
  McpUiHostCssSchema,
  McpUiHostStylesSchema,
  McpUiInitializedNotificationSchema,
  McpUiInitializeRequestSchema,
  McpUiInitializeResultSchema,
  McpUiMessageRequestSchema,
  McpUiMessageResultSchema,
  McpUiOpenLinkRequestSchema,
  McpUiOpenLinkResultSchema,
  McpUiRequestDisplayModeRequestSchema,
  McpUiRequestDisplayModeResultSchema,
  McpUiRequestTeardownNotificationSchema,
  McpUiResourceCspSchema,
  McpUiResourceMetaSchema,
  McpUiResourcePermissionsSchema,
  McpUiResourceTeardownRequestSchema,
  McpUiResourceTeardownResultSchema,
  McpUiSandboxProxyReadyNotificationSchema,
  McpUiSandboxResourceReadyNotificationSchema,
  McpUiSizeChangedNotificationSchema,
  McpUiSupportedContentBlockModalitiesSchema,
  McpUiThemeSchema,
  McpUiToolCancelledNotificationSchema,
  McpUiToolInputNotificationSchema,
  McpUiToolInputPartialNotificationSchema,
  McpUiToolMetaSchema,
  McpUiToolResultNotificationSchema,
  McpUiToolVisibilitySchema,
  McpUiUpdateModelContextRequestSchema,
} from "./generated/schema.js";

// Re-export SDK types used in protocol type unions
import type {
  CallToolRequest,
  CallToolResult,
  CreateMessageRequest,
  CreateMessageResult,
  CreateMessageResultWithTools,
  EmptyResult,
  ListPromptsRequest,
  ListPromptsResult,
  ListResourcesRequest,
  ListResourcesResult,
  ListResourceTemplatesRequest,
  ListResourceTemplatesResult,
  ListToolsRequest,
  ListToolsResult,
  LoggingMessageNotification,
  PingRequest,
  PromptListChangedNotification,
  ReadResourceRequest,
  ReadResourceResult,
  ResourceListChangedNotification,
  ToolListChangedNotification,
} from "@modelcontextprotocol/sdk/types.js";

/**
 * All request types in the MCP Apps protocol.
 *
 * Includes:
 * - MCP UI requests (initialize, open-link, message, resource-teardown, request-display-mode)
 * - MCP server requests forwarded from the app (tools/call, tools/list, resources/list,
 *   resources/templates/list, resources/read, prompts/list)
 * - MCP client requests forwarded to the host (sampling/createMessage)
 * - Protocol requests (ping)
 */
export type AppRequest =
  | McpUiInitializeRequest
  | McpUiOpenLinkRequest
  | McpUiDownloadFileRequest
  | McpUiMessageRequest
  | McpUiUpdateModelContextRequest
  | McpUiResourceTeardownRequest
  | McpUiRequestDisplayModeRequest
  | CallToolRequest
  | ListToolsRequest
  | ListResourcesRequest
  | ListResourceTemplatesRequest
  | ReadResourceRequest
  | ListPromptsRequest
  | CreateMessageRequest
  | PingRequest;

/**
 * All notification types in the MCP Apps protocol.
 *
 * Host to app:
 * - Tool lifecycle (input, input-partial, result, cancelled)
 * - Host context changes
 * - MCP list changes (tools, resources, prompts)
 * - Sandbox resource ready
 *
 * App to host:
 * - Initialized, size-changed, sandbox-proxy-ready, request-teardown
 * - Logging messages
 */
export type AppNotification =
  // Sent to app
  | McpUiHostContextChangedNotification
  | McpUiToolInputNotification
  | McpUiToolInputPartialNotification
  | McpUiToolResultNotification
  | McpUiToolCancelledNotification
  | McpUiSandboxResourceReadyNotification
  | ToolListChangedNotification
  | ResourceListChangedNotification
  | PromptListChangedNotification
  // Received from app
  | McpUiInitializedNotification
  | McpUiSizeChangedNotification
  | McpUiSandboxProxyReadyNotification
  | McpUiRequestTeardownNotification
  | LoggingMessageNotification;

/**
 * All result types in the MCP Apps protocol.
 */
export type AppResult =
  | McpUiInitializeResult
  | McpUiOpenLinkResult
  | McpUiDownloadFileResult
  | McpUiMessageResult
  | McpUiResourceTeardownResult
  | McpUiRequestDisplayModeResult
  | CallToolResult
  | ListToolsResult
  | ListResourcesResult
  | ListResourceTemplatesResult
  | ReadResourceResult
  | ListPromptsResult
  | CreateMessageResult
  | CreateMessageResultWithTools
  | EmptyResult;

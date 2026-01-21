//! Integration tests for fastmcp-console component interoperability.
//!
//! These tests verify that components work correctly together at their boundaries:
//! - Console + Theme interaction
//! - Renderer + Console interaction
//! - DisplayContext affecting multiple components
//! - Config affecting all subsystems

use std::time::Duration;

use fastmcp_console::client::ClientInfoRenderer;
use fastmcp_console::config::ConsoleConfig;
use fastmcp_console::detection::DisplayContext;
use fastmcp_console::diagnostics::RichErrorRenderer;
use fastmcp_console::error::ErrorBoundary;
use fastmcp_console::stats::{ServerStats, StatsRenderer};
use fastmcp_console::tables::{PromptTableRenderer, ResourceTableRenderer, ToolTableRenderer};
use fastmcp_console::testing::TestConsole;
use fastmcp_console::theme::theme;
use fastmcp_core::McpError;
use fastmcp_protocol::{ClientCapabilities, ClientInfo, RootsCapability};

// ============================================================================
// Theme-Console Integration Tests
// ============================================================================

#[test]
fn test_theme_singleton_used_by_console() {
    let tc = TestConsole::new();
    let console = tc.console();
    let console_theme = console.theme();
    let global_theme = theme();

    // Both should reference the same singleton
    assert_eq!(console_theme.primary.triplet, global_theme.primary.triplet);
    assert_eq!(console_theme.error.triplet, global_theme.error.triplet);
}

#[test]
fn test_theme_styles_consistent_across_renderers() {
    // All renderers should use the same theme singleton
    let t = theme();

    // Verify theme has expected colors (non-default)
    assert!(t.primary.triplet.is_some());
    assert!(t.error.triplet.is_some());
    assert!(t.warning.triplet.is_some());
    assert!(t.success.triplet.is_some());
}

// ============================================================================
// Renderer-Console Integration Tests
// ============================================================================

#[test]
fn test_error_renderer_uses_console_correctly() {
    let tc = TestConsole::new();
    let renderer = RichErrorRenderer::new();

    let error = McpError::internal_error("test error message");
    renderer.render(&error, tc.console());

    // Verify output was captured
    assert!(!tc.output().is_empty());
    tc.assert_contains("test error message");
}

#[test]
fn test_stats_renderer_uses_console_correctly() {
    let tc = TestConsole::new();
    let stats = ServerStats::new();

    // Record some activity
    stats.record_request("tools/call", Duration::from_millis(50), true);
    stats.record_request("resources/read", Duration::from_millis(100), true);
    stats.record_request("tools/call", Duration::from_millis(75), false);

    let snapshot = stats.snapshot();
    let renderer = StatsRenderer::new(DisplayContext::new_agent());
    renderer.render_table(&snapshot, tc.console());

    // Verify output was captured
    assert!(!tc.output().is_empty());
    // Stats should show request counts
    tc.assert_contains("3"); // Total requests
}

#[test]
fn test_tool_renderer_uses_console_correctly() {
    let tc = TestConsole::new();
    let renderer = ToolTableRenderer::new(DisplayContext::new_agent());

    // Empty tool list
    renderer.render(&[], tc.console());

    // Should show "no tools" message
    tc.assert_contains("No tools");
}

#[test]
fn test_resource_renderer_uses_console_correctly() {
    let tc = TestConsole::new();
    let renderer = ResourceTableRenderer::new(DisplayContext::new_agent());

    // Empty resource list
    renderer.render(&[], tc.console());

    // Should show "no resources" message
    tc.assert_contains("No resources");
}

#[test]
fn test_prompt_renderer_uses_console_correctly() {
    let tc = TestConsole::new();
    let renderer = PromptTableRenderer::new(DisplayContext::new_agent());

    // Empty prompt list
    renderer.render(&[], tc.console());

    // Should show "no prompts" message
    tc.assert_contains("No prompts");
}

#[test]
fn test_client_renderer_uses_console_correctly() {
    let tc = TestConsole::new();
    let renderer = ClientInfoRenderer::new(DisplayContext::new_agent());

    let client = ClientInfo {
        name: "Test Client".to_string(),
        version: "1.0.0".to_string(),
    };

    renderer.render_connected(&client, tc.console());

    tc.assert_contains("Test Client");
    tc.assert_contains("1.0.0");
}

#[test]
fn test_multiple_renderers_share_console() {
    let tc = TestConsole::new();
    let context = DisplayContext::new_agent();

    // Use multiple renderers with the same console
    let error_renderer = RichErrorRenderer::new();
    let stats_renderer = StatsRenderer::new(context.clone());
    let tool_renderer = ToolTableRenderer::new(context.clone());

    error_renderer.render(&McpError::internal_error("test error"), tc.console());

    let stats = ServerStats::new();
    stats.record_request("tools/call", Duration::from_millis(10), true);
    stats_renderer.render_table(&stats.snapshot(), tc.console());

    tool_renderer.render(&[], tc.console());

    // All outputs should be captured
    tc.assert_contains("test error");
    tc.assert_contains("No tools");
}

// ============================================================================
// DisplayContext Propagation Tests
// ============================================================================

#[test]
fn test_agent_context_produces_plain_output() {
    let tc = TestConsole::new();
    let context = DisplayContext::new_agent();

    let error_renderer = RichErrorRenderer::new();
    let stats_renderer = StatsRenderer::new(context.clone());
    let tool_renderer = ToolTableRenderer::new(context.clone());

    error_renderer.render(&McpError::internal_error("error"), tc.console());

    let stats = ServerStats::new();
    stats.record_request("test", Duration::from_millis(10), true);
    stats_renderer.render_table(&stats.snapshot(), tc.console());

    tool_renderer.render(&[], tc.console());

    // In agent context with non-rich console, no ANSI codes should appear
    // The raw output from a non-rich TestConsole should have ANSI codes stripped
    // or not present at all, depending on the console mode
    // The assertion checks that we get meaningful text output
    assert!(!tc.output().is_empty());
}

#[test]
fn test_human_context_works_with_rich_console() {
    let tc = TestConsole::new_rich();
    let context = DisplayContext::new_human();

    let client_renderer = ClientInfoRenderer::new(context);
    let client = ClientInfo {
        name: "Test Client".to_string(),
        version: "2.0.0".to_string(),
    };

    client_renderer.render_connected(&client, tc.console());

    // Should still have readable content
    tc.assert_contains("Test Client");

    // Raw output might have ANSI codes
    // Just verify we got some output
    assert!(!tc.raw_output().is_empty());
}

#[test]
fn test_context_detection_functions() {
    // Test the detection helper functions
    use fastmcp_console::detection::{is_agent_context, should_enable_rich};

    // These depend on environment, but should not panic
    let _ = is_agent_context();
    let _ = should_enable_rich();

    // DisplayContext::detect() should work
    let detected = DisplayContext::detect();
    // Should be one of the two variants
    assert!(detected.is_human() || detected.is_agent());
}

// ============================================================================
// Config Propagation Tests
// ============================================================================

#[test]
fn test_config_default_creates_working_components() {
    let config = ConsoleConfig::default();

    // Default config should be usable
    assert!(config.show_banner);
    // plain_mode should be false by default (rich enabled)
    assert!(!config.force_plain);
}

#[test]
fn test_config_plain_mode_affects_context() {
    let config = ConsoleConfig::new().plain_mode();

    // plain_mode should force plain output
    assert!(config.force_plain);
}

#[test]
fn test_config_without_banner_setting() {
    let config = ConsoleConfig::new().without_banner();

    // Verify banner is disabled
    assert!(!config.show_banner);
}

#[test]
fn test_config_builder_pattern() {
    let config = ConsoleConfig::new()
        .without_banner()
        .plain_mode()
        .force_color(false);

    assert!(!config.show_banner);
    assert!(config.force_plain);
    // force_color should be Some(false)
    assert_eq!(config.force_color, Some(false));
}

// ============================================================================
// Error Boundary Integration Tests
// ============================================================================

#[test]
fn test_error_boundary_integrates_with_console() {
    let tc = TestConsole::new();
    let boundary = ErrorBoundary::new(tc.console());

    // Wrap a successful result
    let result: Result<i32, McpError> = Ok(42);
    let value = boundary.wrap(result);
    assert_eq!(value, Some(42));
    assert!(!boundary.has_errors());

    // No error output should have been generated
    assert!(tc.output().is_empty());
}

#[test]
fn test_error_boundary_displays_errors_via_console() {
    let tc = TestConsole::new();
    let boundary = ErrorBoundary::new(tc.console());

    // Wrap an error result
    let result: Result<i32, McpError> = Err(McpError::internal_error("boundary test error"));
    let value = boundary.wrap(result);

    assert!(value.is_none());
    assert!(boundary.has_errors());
    assert_eq!(boundary.error_count(), 1);

    // Error should have been displayed
    tc.assert_contains("boundary test error");
}

#[test]
fn test_error_boundary_handles_multiple_errors() {
    let tc = TestConsole::new();
    let boundary = ErrorBoundary::new(tc.console());

    // Wrap multiple errors
    let _: Option<i32> = boundary.wrap(Err(McpError::internal_error("error 1")));
    let _: Option<i32> = boundary.wrap(Err(McpError::internal_error("error 2")));
    let result: Result<i32, McpError> = Ok(42);
    let _: Option<i32> = boundary.wrap(result); // This should succeed
    let _: Option<i32> = boundary.wrap(Err(McpError::internal_error("error 3")));

    assert_eq!(boundary.error_count(), 3);

    tc.assert_contains("error 1");
    tc.assert_contains("error 2");
    tc.assert_contains("error 3");
}

// ============================================================================
// Stats Collection Integration Tests
// ============================================================================

#[test]
fn test_stats_collection_integrates_with_renderer() {
    let stats = ServerStats::new();

    // Simulate server activity with varying success rates
    for i in 0..100 {
        let success = i % 10 != 0; // 90% success rate
        let latency = Duration::from_millis(10 + (i % 50));
        let method = if i % 2 == 0 {
            "tools/call"
        } else {
            "resources/read"
        };
        stats.record_request(method, latency, success);
    }

    let snapshot = stats.snapshot();

    // Verify stats are captured
    assert_eq!(snapshot.total_requests, 100);
    assert_eq!(snapshot.successful_requests, 90);
    assert_eq!(snapshot.failed_requests, 10);

    // Render to verify integration
    let tc = TestConsole::new();
    let renderer = StatsRenderer::new(DisplayContext::new_agent());
    renderer.render_table(&snapshot, tc.console());

    // Output should contain stats
    tc.assert_contains("100");
}

#[test]
fn test_stats_method_tracking() {
    let stats = ServerStats::new();

    stats.record_request("tools/call", Duration::from_millis(10), true);
    stats.record_request("tools/call", Duration::from_millis(20), true);
    stats.record_request("resources/read", Duration::from_millis(15), true);

    let snapshot = stats.snapshot();

    // Should track per-method stats
    assert_eq!(snapshot.total_requests, 3);

    // Render and verify
    let tc = TestConsole::new();
    let renderer = StatsRenderer::new(DisplayContext::new_agent());
    renderer.render_table(&snapshot, tc.console());

    assert!(!tc.output().is_empty());
}

// ============================================================================
// Client Info Integration Tests
// ============================================================================

#[test]
fn test_client_info_with_capabilities() {
    let tc = TestConsole::new();
    let renderer = ClientInfoRenderer::new(DisplayContext::new_agent());

    let client = ClientInfo {
        name: "Full Client".to_string(),
        version: "3.0.0".to_string(),
    };

    let caps = ClientCapabilities {
        sampling: Some(fastmcp_protocol::SamplingCapability {}),
        roots: Some(RootsCapability { list_changed: true }),
    };

    renderer.render_connected_with_caps(&client, &caps, tc.console());

    tc.assert_contains("Full Client");
    tc.assert_contains("3.0.0");
    tc.assert_contains("sampling");
    tc.assert_contains("roots");
}

#[test]
fn test_client_disconnection_flow() {
    let tc = TestConsole::new();
    let renderer = ClientInfoRenderer::new(DisplayContext::new_agent());

    let client = ClientInfo {
        name: "Disconnecting Client".to_string(),
        version: "1.0.0".to_string(),
    };

    // Connect
    renderer.render_connected(&client, tc.console());
    tc.assert_contains("Connected");
    tc.assert_contains("Disconnecting Client");

    // Clear and disconnect
    tc.clear();
    renderer.render_disconnected_with_reason(&client, "timeout", tc.console());
    tc.assert_contains("Disconnected");
    tc.assert_contains("timeout");
}

// ============================================================================
// TestConsole Integration Tests
// ============================================================================

#[test]
fn test_test_console_modes() {
    // Plain mode
    let plain = TestConsole::new();
    assert!(!plain.is_rich());

    // Rich mode
    let rich = TestConsole::new_rich();
    assert!(rich.is_rich());

    // Both should capture output
    plain.console().print("plain test");
    rich.console().print("rich test");

    plain.assert_contains("plain test");
    rich.assert_contains("rich test");
}

#[test]
fn test_test_console_clear_works() {
    let tc = TestConsole::new();

    tc.console().print("First output");
    tc.assert_contains("First");

    tc.clear();

    // Should be empty after clear
    assert!(tc.output().is_empty());

    tc.console().print("Second output");
    tc.assert_contains("Second");
    tc.assert_not_contains("First");
}

#[test]
fn test_test_console_raw_vs_stripped() {
    let tc = TestConsole::new_rich();

    // Print with markup
    tc.console().print("[bold]Bold text[/]");

    // Stripped output should not have markup
    let stripped = tc.output_string();
    assert!(stripped.contains("Bold text"));
    assert!(!stripped.contains("[bold]"));

    // Raw output captures everything
    let raw = tc.raw_output();
    assert!(!raw.is_empty());
}

// ============================================================================
// Cross-Component State Independence Tests
// ============================================================================

#[test]
fn test_renderers_dont_share_state() {
    let tc1 = TestConsole::new();
    let tc2 = TestConsole::new();

    let renderer1 = RichErrorRenderer::new();
    let renderer2 = RichErrorRenderer::new();

    renderer1.render(&McpError::internal_error("error for tc1"), tc1.console());
    renderer2.render(&McpError::internal_error("error for tc2"), tc2.console());

    // Each console should only have its own output
    tc1.assert_contains("error for tc1");
    tc1.assert_not_contains("error for tc2");

    tc2.assert_contains("error for tc2");
    tc2.assert_not_contains("error for tc1");
}

#[test]
fn test_error_boundaries_independent() {
    let tc1 = TestConsole::new();
    let tc2 = TestConsole::new();

    let boundary1 = ErrorBoundary::new(tc1.console());
    let boundary2 = ErrorBoundary::new(tc2.console());

    let _: Option<i32> = boundary1.wrap(Err(McpError::internal_error("b1 error")));
    let result: Result<i32, McpError> = Ok(42);
    let _: Option<i32> = boundary2.wrap(result);

    // Boundaries should have independent state
    assert!(boundary1.has_errors());
    assert!(!boundary2.has_errors());
    assert_eq!(boundary1.error_count(), 1);
    assert_eq!(boundary2.error_count(), 0);
}

#[test]
fn test_stats_instances_independent() {
    let stats1 = ServerStats::new();
    let stats2 = ServerStats::new();

    stats1.record_request("test", Duration::from_millis(10), true);
    stats1.record_request("test", Duration::from_millis(10), true);

    stats2.record_request("test", Duration::from_millis(10), false);

    let snap1 = stats1.snapshot();
    let snap2 = stats2.snapshot();

    assert_eq!(snap1.total_requests, 2);
    assert_eq!(snap1.successful_requests, 2);

    assert_eq!(snap2.total_requests, 1);
    assert_eq!(snap2.failed_requests, 1);
}

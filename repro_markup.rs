#[cfg(test)]
mod tests {
    use fastmcp_console::console::strip_markup;

    #[test]
    fn test_strip_markup_backslash_escape() {
        // This mirrors what FastMcpConsole::print_plain emits for literal brackets: "\\[OK\\]"
        let input = r"tools/list \[OK\] 12ms";
        let output = strip_markup(input);

        // Backslash-escaped brackets should be preserved as literal brackets.
        assert_eq!(output, "tools/list [OK] 12ms");
    }

    #[test]
    fn test_strip_markup_double_bracket_escape() {
        // Double-bracket escape uses Rich's "[[" -> "[" behavior.
        let input = "tools/list [[OK]] 12ms";
        let output = strip_markup(input);

        assert_eq!(output, "tools/list [OK]] 12ms");
    }
}

#[cfg(test)]
mod tests {
    use fastmcp_console::console::strip_markup;

    #[test]
    fn test_strip_markup_backslash_escape() {
        // This mirrors what render_pair_plain does: "\\[OK\\]"
        let input = r"tools/list \[OK\] 12ms";
        let output = strip_markup(input);
        
        // If my analysis is correct, output will be "tools/list \ 12ms"
        // If it handled backslash escapes (which it doesn't seem to), it would be "tools/list [OK] 12ms"
        println!("Input: '{}'", input);
        println!("Output: '{}'", output);
        
        // Asserting the CURRENT BROKEN behavior to confirm understanding
        // If this passes, the code is indeed doing what I think (stripping [OK])
        assert_eq!(output, r"tools/list \ 12ms");
    }

    #[test]
    fn test_strip_markup_double_bracket_escape() {
        // This is what it SHOULD probably use: "[[OK]]" (if it wants [OK] in output)
        // But strip_markup replaces [[ with [
        // So "[[OK]]" -> "[OK]]" because it replaces [[ with [ and leaves ]] as ]]
        // Wait, strip_markup only handles [[ -> [. It doesn't seem to handle ]] -> ]?
        // Let's check logic:
        // match ch {
        // '[' => check peek '[' ... 
        // }
        // It doesn't check ']'
        
        let input = "tools/list [[OK]] 12ms";
        let output = strip_markup(input);
        println!("Input: '{}'", input);
        println!("Output: '{}'", output);
        
        // [[ -> [
        // OK
        // ]] -> ]]
        // So expected: "tools/list [OK]] 12ms"
        // This implies plain text rendering of brackets is tricky with this stripper.
        // It consumes ']' inside the tag skipping loop. It doesn't treat ']' specially outside.
        assert_eq!(output, "tools/list [OK]] 12ms");
    }
}

//! FastMCP color theme

use rich_rust::prelude::*;

/// FastMCP color palette
pub struct FastMcpTheme {
    // Primary colors
    pub primary: Color,   // Vibrant cyan (#00d4ff)
    pub secondary: Color, // Soft purple (#a855f7)
    pub accent: Color,    // Electric green (#22c55e)

    // Semantic colors
    pub success: Color, // Green (#22c55e)
    pub warning: Color, // Amber (#f59e0b)
    pub error: Color,   // Red (#ef4444)
    pub info: Color,    // Blue (#3b82f6)

    // Neutral palette
    pub text: Color,       // Light gray (#e5e7eb)
    pub text_muted: Color, // Medium gray (#9ca3af)
    pub text_dim: Color,   // Dark gray (#6b7280)
    pub border: Color,     // Border gray (#374151)
    pub background: Color, // Dark background (#1f2937)

    // Styles
    pub header_style: Style,
    pub subheader_style: Style,
    pub label_style: Style,
    pub value_style: Style,
    pub key_style: Style,
    pub muted_style: Style,
    pub success_style: Style,
    pub warning_style: Style,
    pub error_style: Style,
    pub info_style: Style,
    pub border_style: Style,
}

impl Default for FastMcpTheme {
    fn default() -> Self {
        Self {
            // Colors
            primary: Color::from_rgb(0, 212, 255),
            secondary: Color::from_rgb(168, 85, 247),
            accent: Color::from_rgb(34, 197, 94),
            success: Color::from_rgb(34, 197, 94),
            warning: Color::from_rgb(245, 158, 11),
            error: Color::from_rgb(239, 68, 68),
            info: Color::from_rgb(59, 130, 246),
            text: Color::from_rgb(229, 231, 235),
            text_muted: Color::from_rgb(156, 163, 175),
            text_dim: Color::from_rgb(107, 114, 128),
            border: Color::from_rgb(55, 65, 81),
            background: Color::from_rgb(31, 41, 55),

            // Styles
            header_style: Style::new().bold().color(Color::from_rgb(0, 212, 255)),
            subheader_style: Style::new().color(Color::from_rgb(156, 163, 175)),
            label_style: Style::new().color(Color::from_rgb(107, 114, 128)),
            value_style: Style::new().color(Color::from_rgb(229, 231, 235)),
            key_style: Style::new().bold().color(Color::from_rgb(168, 85, 247)),
            muted_style: Style::new().dim().color(Color::from_rgb(107, 114, 128)),
            success_style: Style::new().bold().color(Color::from_rgb(34, 197, 94)),
            warning_style: Style::new().bold().color(Color::from_rgb(245, 158, 11)),
            error_style: Style::new().bold().color(Color::from_rgb(239, 68, 68)),
            info_style: Style::new().color(Color::from_rgb(59, 130, 246)),
            border_style: Style::new().color(Color::from_rgb(55, 65, 81)),
        }
    }
}

/// Global theme access
pub fn theme() -> &'static FastMcpTheme {
    static THEME: std::sync::OnceLock<FastMcpTheme> = std::sync::OnceLock::new();
    THEME.get_or_init(FastMcpTheme::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_theme_default_colors() {
        let t = FastMcpTheme::default();
        // Verify primary cyan color
        assert_eq!(t.primary.triplet.map(|tr| tr.red), Some(0));
        assert_eq!(t.primary.triplet.map(|tr| tr.green), Some(212));
        assert_eq!(t.primary.triplet.map(|tr| tr.blue), Some(255));
    }

    #[test]
    fn test_theme_semantic_colors() {
        let t = FastMcpTheme::default();
        // Success should be green
        assert_eq!(t.success.triplet.map(|tr| tr.green), Some(197));
        // Error should be red
        assert_eq!(t.error.triplet.map(|tr| tr.red), Some(239));
        // Warning should be amber
        assert_eq!(t.warning.triplet.map(|tr| tr.red), Some(245));
    }

    #[test]
    fn test_theme_global_singleton() {
        let t1 = theme();
        let t2 = theme();
        // Should return the same static reference
        assert!(std::ptr::eq(t1, t2));
    }

    #[test]
    fn test_theme_styles_exist() {
        let t = FastMcpTheme::default();
        // Just verify styles are accessible without panicking
        let _ = t.header_style.clone();
        let _ = t.error_style.clone();
        let _ = t.success_style.clone();
        let _ = t.warning_style.clone();
    }
}

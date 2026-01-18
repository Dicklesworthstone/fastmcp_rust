//! Example: Calculator Server
//!
//! A mathematical calculator MCP server demonstrating various tool patterns:
//! - Multiple parameter types (integers, floats, strings)
//! - Error handling and validation
//! - Progress reporting for long operations
//! - Complex computations
//!
//! Run with:
//! ```bash
//! cargo run --example calculator_server
//! ```
//!
//! Test with MCP Inspector:
//! ```bash
//! npx @anthropic-ai/mcp-inspector cargo run --example calculator_server
//! ```

#![allow(clippy::needless_pass_by_value)]
#![allow(
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation
)]

use fastmcp::prelude::*;

// ============================================================================
// Basic Arithmetic Tools
// ============================================================================

/// Add two numbers.
#[tool(description = "Add two numbers together")]
fn add(_ctx: &McpContext, a: f64, b: f64) -> String {
    format!("{}", a + b)
}

/// Subtract the second number from the first.
#[tool(description = "Subtract b from a")]
fn subtract(_ctx: &McpContext, a: f64, b: f64) -> String {
    format!("{}", a - b)
}

/// Multiply two numbers.
#[tool(description = "Multiply two numbers")]
fn multiply(_ctx: &McpContext, a: f64, b: f64) -> String {
    format!("{}", a * b)
}

/// Divide the first number by the second.
#[tool(description = "Divide a by b. Returns error if b is zero.")]
fn divide(_ctx: &McpContext, a: f64, b: f64) -> String {
    if b == 0.0 {
        "Error: Division by zero".to_string()
    } else {
        format!("{}", a / b)
    }
}

// ============================================================================
// Advanced Math Tools
// ============================================================================

/// Calculate the power of a number.
#[tool(
    name = "power",
    description = "Calculate base raised to the exponent power"
)]
fn power_fn(_ctx: &McpContext, base: f64, exponent: f64) -> String {
    format!("{}", base.powf(exponent))
}

/// Calculate the square root.
#[tool(description = "Calculate the square root of a number")]
fn sqrt(_ctx: &McpContext, number: f64) -> String {
    if number < 0.0 {
        "Error: Cannot calculate square root of negative number".to_string()
    } else {
        format!("{}", number.sqrt())
    }
}

/// Calculate the absolute value.
#[tool(description = "Calculate the absolute value of a number")]
fn abs(_ctx: &McpContext, number: f64) -> String {
    format!("{}", number.abs())
}

/// Calculate the factorial of a non-negative integer.
#[tool(description = "Calculate factorial (n!). Only works for non-negative integers up to 20.")]
fn factorial(ctx: &McpContext, n: i64) -> String {
    if n < 0 {
        return "Error: Factorial is not defined for negative numbers".to_string();
    }
    if n > 20 {
        return "Error: Factorial overflow for n > 20".to_string();
    }

    let mut result: u64 = 1;
    for i in 2..=n as u64 {
        // Check for cancellation periodically
        if ctx.is_cancelled() {
            return "Cancelled".to_string();
        }
        result = result.saturating_mul(i);
    }
    format!("{result}")
}

/// Calculate the nth Fibonacci number.
#[tool(description = "Calculate the nth Fibonacci number (0-indexed). Max n is 92.")]
fn fibonacci(ctx: &McpContext, n: i64) -> String {
    if n < 0 {
        return "Error: Fibonacci is not defined for negative indices".to_string();
    }
    if n > 92 {
        return "Error: Fibonacci overflow for n > 92".to_string();
    }

    if n == 0 {
        return "0".to_string();
    }
    if n == 1 {
        return "1".to_string();
    }

    let mut a: u64 = 0;
    let mut b: u64 = 1;
    for _ in 2..=n {
        if ctx.is_cancelled() {
            return "Cancelled".to_string();
        }
        let next = a.saturating_add(b);
        a = b;
        b = next;
    }
    format!("{b}")
}

/// Check if a number is prime.
#[tool(description = "Check if a number is prime")]
fn is_prime(ctx: &McpContext, n: i64) -> String {
    if n < 2 {
        return "false".to_string();
    }

    let n_unsigned = n as u64;
    let sqrt_n = (n_unsigned as f64).sqrt() as u64;

    for i in 2..=sqrt_n {
        if ctx.is_cancelled() {
            return "Cancelled".to_string();
        }
        if n_unsigned % i == 0 {
            return "false".to_string();
        }
    }
    "true".to_string()
}

/// Calculate the greatest common divisor (GCD) of two numbers.
#[tool(description = "Calculate the greatest common divisor using Euclidean algorithm")]
fn gcd(ctx: &McpContext, a: i64, b: i64) -> String {
    let mut a = a.unsigned_abs();
    let mut b = b.unsigned_abs();

    while b != 0 {
        if ctx.is_cancelled() {
            return "Cancelled".to_string();
        }
        let temp = b;
        b = a % b;
        a = temp;
    }
    format!("{a}")
}

/// Calculate the least common multiple (LCM) of two numbers.
#[tool(description = "Calculate the least common multiple")]
fn lcm(_ctx: &McpContext, a: i64, b: i64) -> String {
    if a == 0 || b == 0 {
        return "0".to_string();
    }

    let a_abs = a.unsigned_abs();
    let b_abs = b.unsigned_abs();

    // Calculate GCD first
    let mut x = a_abs;
    let mut y = b_abs;
    while y != 0 {
        let temp = y;
        y = x % y;
        x = temp;
    }
    let gcd = x;

    format!("{}", (a_abs / gcd) * b_abs)
}

// ============================================================================
// Statistical Tools
// ============================================================================

/// Calculate the average of a comma-separated list of numbers.
#[tool(description = "Calculate the arithmetic mean of numbers (comma-separated)")]
fn average(_ctx: &McpContext, numbers: String) -> String {
    let nums: Vec<f64> = numbers
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    if nums.is_empty() {
        return "Error: No valid numbers provided".to_string();
    }

    let sum: f64 = nums.iter().sum();
    format!("{}", sum / nums.len() as f64)
}

/// Calculate the standard deviation of a comma-separated list of numbers.
#[tool(description = "Calculate the standard deviation of numbers (comma-separated)")]
fn std_dev(_ctx: &McpContext, numbers: String) -> String {
    let nums: Vec<f64> = numbers
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    if nums.len() < 2 {
        return "Error: Need at least 2 numbers for standard deviation".to_string();
    }

    let mean: f64 = nums.iter().sum::<f64>() / nums.len() as f64;
    let variance: f64 =
        nums.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (nums.len() - 1) as f64;
    format!("{}", variance.sqrt())
}

// ============================================================================
// Resources
// ============================================================================

/// Returns mathematical constants.
#[resource(
    uri = "math://constants",
    name = "Mathematical Constants",
    description = "Common mathematical constants"
)]
fn math_constants(_ctx: &McpContext) -> String {
    r#"{
    "pi": 3.141592653589793,
    "e": 2.718281828459045,
    "phi": 1.618033988749895,
    "sqrt2": 1.4142135623730951,
    "ln2": 0.6931471805599453,
    "ln10": 2.302585092994046
}"#
    .to_string()
}

/// Returns a list of prime numbers up to 100.
#[resource(
    uri = "math://primes",
    name = "Prime Numbers",
    description = "List of prime numbers up to 100"
)]
fn prime_numbers(_ctx: &McpContext) -> String {
    "[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]".to_string()
}

// ============================================================================
// Prompts
// ============================================================================

/// A prompt for explaining a mathematical concept.
#[prompt(description = "Generate a prompt to explain a mathematical concept")]
fn explain_math(_ctx: &McpContext, concept: String, level: String) -> Vec<PromptMessage> {
    let level_desc = match level.to_lowercase().as_str() {
        "beginner" => "a beginner with no prior math knowledge",
        "intermediate" => "someone with high school math knowledge",
        "advanced" => "someone with university-level math knowledge",
        _ => "a general audience",
    };

    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!(
                "Please explain the mathematical concept of '{concept}' to {level_desc}. \
                 Include practical examples and applications where relevant."
            ),
        },
    }]
}

/// A prompt for solving a word problem.
#[prompt(description = "Generate a prompt to solve a mathematical word problem")]
fn solve_problem(_ctx: &McpContext, problem: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!(
                "Please solve the following mathematical problem step by step, \
                 showing all work and explaining each step:\n\n{problem}"
            ),
        },
    }]
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    Server::new("calculator-server", "1.0.0")
        // Basic arithmetic
        .tool(Add)
        .tool(Subtract)
        .tool(Multiply)
        .tool(Divide)
        // Advanced math
        .tool(PowerFn)
        .tool(Sqrt)
        .tool(Abs)
        .tool(Factorial)
        .tool(Fibonacci)
        .tool(IsPrime)
        .tool(Gcd)
        .tool(Lcm)
        // Statistics
        .tool(Average)
        .tool(StdDev)
        // Resources
        .resource(MathConstantsResource)
        .resource(PrimeNumbersResource)
        // Prompts
        .prompt(ExplainMathPrompt)
        .prompt(SolveProblemPrompt)
        // Config
        .request_timeout(30)
        .instructions(
            "A mathematical calculator server. Use 'add', 'subtract', 'multiply', 'divide' \
             for basic operations. Use 'factorial', 'fibonacci', 'is_prime', 'gcd', 'lcm' \
             for number theory. Use 'average', 'std_dev' for statistics. \
             Access 'math://constants' for mathematical constants.",
        )
        .build()
        .run_stdio();
}

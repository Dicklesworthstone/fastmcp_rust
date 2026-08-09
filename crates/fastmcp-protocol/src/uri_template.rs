//! Bounded RFC 6570 Level 4 URI-template parsing and expansion.
//!
//! A URI template is deliberately distinct from [`crate::AbsoluteUri`]: a
//! template describes a set of references and must be expanded before it can
//! be used where an ordinary URI is required.  This module owns the
//! syntax-preserving representation and forward expansion only.  Reverse
//! routing is a separate, stricter admission concern because many valid RFC
//! 6570 templates are not invertible.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

/// Maximum UTF-8 bytes accepted in a single URI template source string.
pub const MAX_URI_TEMPLATE_BYTES: usize = 16 * 1024;
/// Maximum literal/expression parts retained in one parsed template.
pub const MAX_URI_TEMPLATE_PARTS: usize = 256;
/// Maximum expressions retained in one parsed template.
pub const MAX_URI_TEMPLATE_EXPRESSIONS: usize = 128;
/// Maximum variable specifications allowed in one expression.
pub const MAX_URI_TEMPLATE_VARIABLES_PER_EXPRESSION: usize = 64;
/// Maximum UTF-8 bytes in one RFC 6570 variable name.
pub const MAX_URI_TEMPLATE_VARIABLE_NAME_BYTES: usize = 512;
/// Maximum RFC 6570 prefix modifier, which is strictly less than 10000.
pub const MAX_URI_TEMPLATE_PREFIX_LENGTH: usize = 9_999;
/// Maximum individual UTF-8 value/key bytes admitted by the bounded expander.
pub const MAX_URI_TEMPLATE_VALUE_BYTES: usize = 16 * 1024;
/// Maximum composite members inspected by one expansion.
pub const MAX_URI_TEMPLATE_COMPOSITE_ITEMS: usize = 1_024;
/// Maximum UTF-8 output bytes emitted by one expansion.
pub const MAX_URI_TEMPLATE_EXPANSION_OUTPUT_BYTES: usize = 64 * 1024;

/// Values supplied to a [`UriTemplate`] expansion.
pub type TemplateValues = BTreeMap<String, TemplateValue>;

/// One defined RFC 6570 variable value.
///
/// An absent map entry denotes RFC 6570's undefined value. Empty list and map
/// values are likewise treated as undefined, while an empty scalar is defined.
/// Associative values retain their pair order so expansions reproduce the
/// order supplied by an RFC 6570 data model rather than silently sorting keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TemplateValue {
    /// A single scalar string value.
    Scalar(String),
    /// An ordered composite list value.
    List(Vec<Option<String>>),
    /// A composite associative value.
    Associative(Vec<(String, Option<String>)>),
}

impl TemplateValue {
    /// Constructs a scalar value.
    #[must_use]
    pub fn scalar(value: impl Into<String>) -> Self {
        Self::Scalar(value.into())
    }

    /// Constructs a list value.
    #[must_use]
    pub fn list(values: Vec<String>) -> Self {
        Self::List(values.into_iter().map(Some).collect())
    }

    /// Constructs a list that can retain undefined members.
    #[must_use]
    pub fn list_with_undefined(values: Vec<Option<String>>) -> Self {
        Self::List(values)
    }

    /// Constructs an associative value.
    #[must_use]
    pub fn associative(values: Vec<(String, String)>) -> Self {
        Self::Associative(
            values
                .into_iter()
                .map(|(key, value)| (key, Some(value)))
                .collect(),
        )
    }

    /// Constructs an associative value that can retain undefined members.
    #[must_use]
    pub fn associative_with_undefined(values: Vec<(String, Option<String>)>) -> Self {
        Self::Associative(values)
    }
}

impl From<String> for TemplateValue {
    fn from(value: String) -> Self {
        Self::Scalar(value)
    }
}

impl From<&str> for TemplateValue {
    fn from(value: &str) -> Self {
        Self::Scalar(value.to_owned())
    }
}

/// Hard-bounded limits used by [`UriTemplate::expand_with_limits`].
///
/// Callers can tighten the defaults for a particular boundary but cannot
/// configure away the crate-level safety caps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UriTemplateExpansionLimits {
    max_output_bytes: usize,
    max_composite_items: usize,
    max_value_bytes: usize,
}

impl UriTemplateExpansionLimits {
    /// Creates a bounded expansion configuration.
    pub fn new(
        max_output_bytes: usize,
        max_composite_items: usize,
        max_value_bytes: usize,
    ) -> Result<Self, UriTemplateError> {
        if max_output_bytes == 0 || max_output_bytes > MAX_URI_TEMPLATE_EXPANSION_OUTPUT_BYTES {
            return Err(UriTemplateError::InvalidExpansionLimit {
                field: "max_output_bytes",
                actual: max_output_bytes,
                maximum: MAX_URI_TEMPLATE_EXPANSION_OUTPUT_BYTES,
            });
        }
        if max_composite_items == 0 || max_composite_items > MAX_URI_TEMPLATE_COMPOSITE_ITEMS {
            return Err(UriTemplateError::InvalidExpansionLimit {
                field: "max_composite_items",
                actual: max_composite_items,
                maximum: MAX_URI_TEMPLATE_COMPOSITE_ITEMS,
            });
        }
        if max_value_bytes == 0 || max_value_bytes > MAX_URI_TEMPLATE_VALUE_BYTES {
            return Err(UriTemplateError::InvalidExpansionLimit {
                field: "max_value_bytes",
                actual: max_value_bytes,
                maximum: MAX_URI_TEMPLATE_VALUE_BYTES,
            });
        }
        Ok(Self {
            max_output_bytes,
            max_composite_items,
            max_value_bytes,
        })
    }

    /// Returns the maximum output bytes permitted by this configuration.
    #[must_use]
    pub const fn max_output_bytes(self) -> usize {
        self.max_output_bytes
    }

    /// Returns the maximum composite members inspected by this configuration.
    #[must_use]
    pub const fn max_composite_items(self) -> usize {
        self.max_composite_items
    }

    /// Returns the maximum bytes permitted in one key or value.
    #[must_use]
    pub const fn max_value_bytes(self) -> usize {
        self.max_value_bytes
    }
}

impl Default for UriTemplateExpansionLimits {
    fn default() -> Self {
        Self {
            max_output_bytes: MAX_URI_TEMPLATE_EXPANSION_OUTPUT_BYTES,
            max_composite_items: MAX_URI_TEMPLATE_COMPOSITE_ITEMS,
            max_value_bytes: MAX_URI_TEMPLATE_VALUE_BYTES,
        }
    }
}

/// An immutable, source-preserving RFC 6570 Level 4 template AST.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UriTemplate {
    source: String,
    parts: Vec<UriTemplatePart>,
}

impl UriTemplate {
    /// Parses a complete RFC 6570 Level 4 URI template.
    pub fn parse(source: impl AsRef<str>) -> Result<Self, UriTemplateError> {
        let source = source.as_ref();
        if source.len() > MAX_URI_TEMPLATE_BYTES {
            return Err(UriTemplateError::SourceTooLong {
                actual: source.len(),
                maximum: MAX_URI_TEMPLATE_BYTES,
            });
        }

        let bytes = source.as_bytes();
        let mut index = 0;
        let mut literal_start = 0;
        let mut expressions = 0;
        let mut parts = Vec::new();

        while index < bytes.len() {
            match bytes[index] {
                b'{' => {
                    push_literal(&mut parts, &source[literal_start..index], literal_start)?;
                    let expression_start = index + 1;
                    let Some(relative_end) = bytes[expression_start..]
                        .iter()
                        .position(|byte| *byte == b'}')
                    else {
                        return Err(UriTemplateError::UnclosedExpression { offset: index });
                    };
                    let expression_end = expression_start + relative_end;
                    if let Some(relative_nested) = bytes[expression_start..expression_end]
                        .iter()
                        .position(|byte| *byte == b'{')
                    {
                        return Err(UriTemplateError::NestedExpression {
                            offset: expression_start + relative_nested,
                        });
                    }
                    if expressions == MAX_URI_TEMPLATE_EXPRESSIONS {
                        return Err(UriTemplateError::TooManyExpressions {
                            maximum: MAX_URI_TEMPLATE_EXPRESSIONS,
                        });
                    }
                    push_part(
                        &mut parts,
                        UriTemplatePart::Expression(parse_expression(
                            &source[expression_start..expression_end],
                            expression_start,
                        )?),
                    )?;
                    expressions += 1;
                    index = expression_end + 1;
                    literal_start = index;
                }
                b'}' => return Err(UriTemplateError::UnexpectedCloseBrace { offset: index }),
                _ => index += 1,
            }
        }
        push_literal(&mut parts, &source[literal_start..], literal_start)?;

        Ok(Self {
            source: source.to_owned(),
            parts,
        })
    }

    /// Returns the exact source text used to construct this template.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the source-preserving AST parts in expansion order.
    #[must_use]
    pub fn parts(&self) -> &[UriTemplatePart] {
        &self.parts
    }

    /// Expands the template using the default hard-bounded limits.
    pub fn expand(&self, values: &TemplateValues) -> Result<String, UriTemplateError> {
        self.expand_with_limits(values, UriTemplateExpansionLimits::default())
    }

    /// Expands the template using caller-tightened, hard-bounded limits.
    pub fn expand_with_limits(
        &self,
        values: &TemplateValues,
        limits: UriTemplateExpansionLimits,
    ) -> Result<String, UriTemplateError> {
        let mut output = String::new();
        let mut state = ExpansionState::default();
        for part in &self.parts {
            match part {
                UriTemplatePart::Literal(literal) => {
                    append_encoded_literal(&mut output, literal, limits)?;
                }
                UriTemplatePart::Expression(expression) => {
                    expand_expression(&mut output, expression, values, limits, &mut state)?;
                }
            }
        }
        Ok(output)
    }
}

impl AsRef<str> for UriTemplate {
    fn as_ref(&self) -> &str {
        self.source()
    }
}

impl fmt::Display for UriTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.source())
    }
}

impl FromStr for UriTemplate {
    type Err = UriTemplateError;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        Self::parse(source)
    }
}

/// One ordered segment in a [`UriTemplate`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UriTemplatePart {
    /// Literal source text outside a template expression.
    Literal(String),
    /// A parsed expression.
    Expression(UriTemplateExpression),
}

/// One parsed RFC 6570 expression.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UriTemplateExpression {
    operator: UriTemplateOperator,
    variables: Vec<UriTemplateVariable>,
}

impl UriTemplateExpression {
    /// Returns the expression operator.
    #[must_use]
    pub const fn operator(&self) -> UriTemplateOperator {
        self.operator
    }

    /// Returns the variable specifications in source order.
    #[must_use]
    pub fn variables(&self) -> &[UriTemplateVariable] {
        &self.variables
    }
}

/// The Level 4 expression operator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UriTemplateOperator {
    /// `{var}` simple string expansion.
    Simple,
    /// `{+var}` reserved string expansion.
    Reserved,
    /// `{#var}` fragment expansion.
    Fragment,
    /// `{.var}` label expansion.
    Label,
    /// `{/var}` path-segment expansion.
    Path,
    /// `{;var}` matrix/path-parameter expansion.
    PathParameter,
    /// `{?var}` form-style query expansion.
    Query,
    /// `{&var}` form-style query continuation.
    QueryContinuation,
}

impl UriTemplateOperator {
    /// Returns the operator character, or `None` for simple expansion.
    #[must_use]
    pub const fn character(self) -> Option<char> {
        match self {
            Self::Simple => None,
            Self::Reserved => Some('+'),
            Self::Fragment => Some('#'),
            Self::Label => Some('.'),
            Self::Path => Some('/'),
            Self::PathParameter => Some(';'),
            Self::Query => Some('?'),
            Self::QueryContinuation => Some('&'),
        }
    }

    const fn properties(self) -> OperatorProperties {
        match self {
            Self::Simple => OperatorProperties::new("", ",", false, "", false),
            Self::Reserved => OperatorProperties::new("", ",", false, "", true),
            Self::Fragment => OperatorProperties::new("#", ",", false, "", true),
            Self::Label => OperatorProperties::new(".", ".", false, "", false),
            Self::Path => OperatorProperties::new("/", "/", false, "", false),
            Self::PathParameter => OperatorProperties::new(";", ";", true, "", false),
            Self::Query => OperatorProperties::new("?", "&", true, "=", false),
            Self::QueryContinuation => OperatorProperties::new("&", "&", true, "=", false),
        }
    }
}

/// One named variable and optional Level 4 modifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UriTemplateVariable {
    name: String,
    modifier: Option<UriTemplateModifier>,
}

impl UriTemplateVariable {
    /// Returns the exact, case-sensitive RFC 6570 variable name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the optional Level 4 modifier.
    #[must_use]
    pub const fn modifier(&self) -> Option<UriTemplateModifier> {
        self.modifier
    }
}

/// One RFC 6570 Level 4 variable modifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UriTemplateModifier {
    /// Restrict a scalar variable to this many Unicode code points.
    Prefix(usize),
    /// Expand every list member or associative pair independently.
    Explode,
}

/// One typed reason template parsing or expansion failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UriTemplateError {
    /// Source text exceeded the fixed parser bound.
    SourceTooLong {
        /// Observed UTF-8 bytes.
        actual: usize,
        /// Maximum UTF-8 bytes.
        maximum: usize,
    },
    /// Parsing would retain too many parts.
    TooManyParts {
        /// Maximum part count.
        maximum: usize,
    },
    /// Parsing would retain too many expressions.
    TooManyExpressions {
        /// Maximum expression count.
        maximum: usize,
    },
    /// An expression exceeded its variable-specification bound.
    TooManyVariables {
        /// Maximum variable specifications.
        maximum: usize,
    },
    /// A variable name exceeded its byte bound.
    VariableNameTooLong {
        /// Observed UTF-8 bytes.
        actual: usize,
        /// Maximum UTF-8 bytes.
        maximum: usize,
    },
    /// A literal used a character outside RFC 6570's literal grammar.
    InvalidLiteral {
        /// Byte offset in the source text.
        offset: usize,
    },
    /// An expression opened without a matching closing brace.
    UnclosedExpression {
        /// Byte offset of the opening brace.
        offset: usize,
    },
    /// An expression attempted to nest another expression.
    NestedExpression {
        /// Byte offset of the nested opening brace.
        offset: usize,
    },
    /// A closing brace appeared outside an expression.
    UnexpectedCloseBrace {
        /// Byte offset of the closing brace.
        offset: usize,
    },
    /// An expression did not contain a variable specification.
    EmptyExpression {
        /// Byte offset immediately after the opening brace.
        offset: usize,
    },
    /// An expression used an RFC-reserved, unsupported operator.
    UnsupportedOperator {
        /// The reserved operator character.
        operator: char,
        /// Byte offset of the operator.
        offset: usize,
    },
    /// A variable specification did not match the RFC 6570 grammar.
    InvalidVariable {
        /// Byte offset of the variable specification.
        offset: usize,
    },
    /// A prefix modifier did not match the RFC's positive four-digit grammar.
    InvalidPrefix {
        /// Byte offset of the prefix modifier.
        offset: usize,
    },
    /// A caller tried to relax a fixed expansion limit or selected zero.
    InvalidExpansionLimit {
        /// The invalid configuration field.
        field: &'static str,
        /// Requested value.
        actual: usize,
        /// Fixed ceiling.
        maximum: usize,
    },
    /// A supplied scalar, list member, map key, or map value was too large.
    ValueTooLong {
        /// Observed UTF-8 bytes.
        actual: usize,
        /// Configured maximum UTF-8 bytes.
        maximum: usize,
    },
    /// Expansion would inspect too many composite members.
    TooManyCompositeItems {
        /// Observed total members.
        actual: usize,
        /// Configured maximum members.
        maximum: usize,
    },
    /// Expansion output would exceed the configured byte bound.
    ExpansionTooLarge {
        /// Bytes that would be present after the append.
        actual: usize,
        /// Configured maximum output bytes.
        maximum: usize,
    },
    /// A prefix modifier was applied to a non-scalar value.
    PrefixAppliedToComposite {
        /// The affected variable name.
        variable: String,
    },
    /// An associative value supplied the same key more than once.
    DuplicateAssociativeKey {
        /// The repeated key.
        key: String,
    },
}

impl fmt::Display for UriTemplateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceTooLong { actual, maximum } => {
                write!(
                    formatter,
                    "URI template is {actual} bytes; maximum is {maximum}"
                )
            }
            Self::TooManyParts { maximum } => {
                write!(formatter, "URI template exceeds {maximum} parsed parts")
            }
            Self::TooManyExpressions { maximum } => {
                write!(formatter, "URI template exceeds {maximum} expressions")
            }
            Self::TooManyVariables { maximum } => {
                write!(
                    formatter,
                    "URI template expression exceeds {maximum} variables"
                )
            }
            Self::VariableNameTooLong { actual, maximum } => {
                write!(
                    formatter,
                    "URI template variable is {actual} bytes; maximum is {maximum}"
                )
            }
            Self::InvalidLiteral { offset } => {
                write!(formatter, "invalid URI template literal at byte {offset}")
            }
            Self::UnclosedExpression { offset } => {
                write!(
                    formatter,
                    "unclosed URI template expression at byte {offset}"
                )
            }
            Self::NestedExpression { offset } => {
                write!(formatter, "nested URI template expression at byte {offset}")
            }
            Self::UnexpectedCloseBrace { offset } => {
                write!(
                    formatter,
                    "unexpected URI template closing brace at byte {offset}"
                )
            }
            Self::EmptyExpression { offset } => {
                write!(formatter, "empty URI template expression at byte {offset}")
            }
            Self::UnsupportedOperator { operator, offset } => write!(
                formatter,
                "unsupported URI template operator {operator:?} at byte {offset}"
            ),
            Self::InvalidVariable { offset } => {
                write!(formatter, "invalid URI template variable at byte {offset}")
            }
            Self::InvalidPrefix { offset } => {
                write!(
                    formatter,
                    "invalid URI template prefix modifier at byte {offset}"
                )
            }
            Self::InvalidExpansionLimit {
                field,
                actual,
                maximum,
            } => write!(formatter, "{field} is {actual}; maximum is {maximum}"),
            Self::ValueTooLong { actual, maximum } => {
                write!(
                    formatter,
                    "URI template value is {actual} bytes; maximum is {maximum}"
                )
            }
            Self::TooManyCompositeItems { actual, maximum } => write!(
                formatter,
                "URI template expansion has {actual} composite members; maximum is {maximum}"
            ),
            Self::ExpansionTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "URI template expansion is {actual} bytes; maximum is {maximum}"
                )
            }
            Self::PrefixAppliedToComposite { variable } => write!(
                formatter,
                "URI template prefix modifier cannot be applied to composite variable {variable:?}"
            ),
            Self::DuplicateAssociativeKey { key } => {
                write!(
                    formatter,
                    "URI template associative key {key:?} is duplicated"
                )
            }
        }
    }
}

impl std::error::Error for UriTemplateError {}

#[derive(Clone, Copy)]
struct OperatorProperties {
    first: &'static str,
    separator: &'static str,
    named: bool,
    if_empty: &'static str,
    allow_reserved: bool,
}

impl OperatorProperties {
    const fn new(
        first: &'static str,
        separator: &'static str,
        named: bool,
        if_empty: &'static str,
        allow_reserved: bool,
    ) -> Self {
        Self {
            first,
            separator,
            named,
            if_empty,
            allow_reserved,
        }
    }

    const fn is_form_style(self) -> bool {
        matches!(self.first, "?" | "&")
    }
}

#[derive(Default)]
struct ExpansionState {
    composite_items: usize,
}

impl ExpansionState {
    fn inspect_composite(
        &mut self,
        count: usize,
        limits: UriTemplateExpansionLimits,
    ) -> Result<(), UriTemplateError> {
        let actual = self.composite_items.saturating_add(count);
        if actual > limits.max_composite_items() {
            return Err(UriTemplateError::TooManyCompositeItems {
                actual,
                maximum: limits.max_composite_items(),
            });
        }
        self.composite_items = actual;
        Ok(())
    }
}

struct ExpressionWriter<'a> {
    output: &'a mut String,
    properties: OperatorProperties,
    wrote_value: bool,
    limits: UriTemplateExpansionLimits,
}

impl<'a> ExpressionWriter<'a> {
    fn new(
        output: &'a mut String,
        properties: OperatorProperties,
        limits: UriTemplateExpansionLimits,
    ) -> Self {
        Self {
            output,
            properties,
            wrote_value: false,
            limits,
        }
    }

    fn begin_value(&mut self) -> Result<(), UriTemplateError> {
        let delimiter = if self.wrote_value {
            self.properties.separator
        } else {
            self.properties.first
        };
        append_output(self.output, delimiter, self.limits)?;
        self.wrote_value = true;
        Ok(())
    }

    fn write_value(
        &mut self,
        name: &str,
        value: &str,
        logically_empty: bool,
    ) -> Result<(), UriTemplateError> {
        self.begin_value()?;
        if self.properties.named {
            append_variable_name(self.output, name, self.limits)?;
            append_output(
                self.output,
                if logically_empty {
                    self.properties.if_empty
                } else {
                    "="
                },
                self.limits,
            )?;
        }
        append_encoded_value(
            self.output,
            value,
            self.properties.allow_reserved,
            self.limits,
        )
    }

    fn write_associative_pair(&mut self, key: &str, value: &str) -> Result<(), UriTemplateError> {
        self.begin_value()?;
        if self.properties.named {
            append_encoded_value(
                self.output,
                key,
                self.properties.allow_reserved,
                self.limits,
            )?;
            append_output(
                self.output,
                if value.is_empty() {
                    self.properties.if_empty
                } else {
                    "="
                },
                self.limits,
            )?;
            return append_encoded_value(
                self.output,
                value,
                self.properties.allow_reserved,
                self.limits,
            );
        }

        append_encoded_value(
            self.output,
            key,
            self.properties.allow_reserved,
            self.limits,
        )?;
        if !value.is_empty() || self.properties.is_form_style() {
            append_output(self.output, "=", self.limits)?;
        }
        append_encoded_value(
            self.output,
            value,
            self.properties.allow_reserved,
            self.limits,
        )
    }
}

fn push_part(
    parts: &mut Vec<UriTemplatePart>,
    part: UriTemplatePart,
) -> Result<(), UriTemplateError> {
    if parts.len() == MAX_URI_TEMPLATE_PARTS {
        return Err(UriTemplateError::TooManyParts {
            maximum: MAX_URI_TEMPLATE_PARTS,
        });
    }
    parts.push(part);
    Ok(())
}

fn push_literal(
    parts: &mut Vec<UriTemplatePart>,
    literal: &str,
    offset: usize,
) -> Result<(), UriTemplateError> {
    if literal.is_empty() {
        return Ok(());
    }
    if let Some(relative_offset) = invalid_literal_offset(literal) {
        return Err(UriTemplateError::InvalidLiteral {
            offset: offset + relative_offset,
        });
    }
    push_part(parts, UriTemplatePart::Literal(literal.to_owned()))
}

fn parse_expression(
    source: &str,
    source_offset: usize,
) -> Result<UriTemplateExpression, UriTemplateError> {
    let bytes = source.as_bytes();
    let Some(&first) = bytes.first() else {
        return Err(UriTemplateError::EmptyExpression {
            offset: source_offset,
        });
    };
    let (operator, variable_start) = match first {
        b'+' => (UriTemplateOperator::Reserved, 1),
        b'#' => (UriTemplateOperator::Fragment, 1),
        b'.' => (UriTemplateOperator::Label, 1),
        b'/' => (UriTemplateOperator::Path, 1),
        b';' => (UriTemplateOperator::PathParameter, 1),
        b'?' => (UriTemplateOperator::Query, 1),
        b'&' => (UriTemplateOperator::QueryContinuation, 1),
        b'=' | b',' | b'!' | b'@' | b'|' => {
            return Err(UriTemplateError::UnsupportedOperator {
                operator: char::from(first),
                offset: source_offset,
            });
        }
        _ => (UriTemplateOperator::Simple, 0),
    };
    let variables_source = &source[variable_start..];
    if variables_source.is_empty() {
        return Err(UriTemplateError::EmptyExpression {
            offset: source_offset + variable_start,
        });
    }

    let mut variables = Vec::new();
    let mut variable_offset = source_offset + variable_start;
    for variable_source in variables_source.split(',') {
        if variables.len() == MAX_URI_TEMPLATE_VARIABLES_PER_EXPRESSION {
            return Err(UriTemplateError::TooManyVariables {
                maximum: MAX_URI_TEMPLATE_VARIABLES_PER_EXPRESSION,
            });
        }
        variables.push(parse_variable(variable_source, variable_offset)?);
        variable_offset += variable_source.len() + 1;
    }
    Ok(UriTemplateExpression {
        operator,
        variables,
    })
}

fn parse_variable(
    source: &str,
    source_offset: usize,
) -> Result<UriTemplateVariable, UriTemplateError> {
    if source.is_empty() {
        return Err(UriTemplateError::InvalidVariable {
            offset: source_offset,
        });
    }

    let (name, modifier) = if let Some(name) = source.strip_suffix('*') {
        if name.is_empty() || name.contains(':') {
            return Err(UriTemplateError::InvalidVariable {
                offset: source_offset,
            });
        }
        (name, Some(UriTemplateModifier::Explode))
    } else if let Some((name, prefix)) = source.split_once(':') {
        let prefix_offset = source_offset + name.len();
        if !is_valid_prefix(prefix) {
            return Err(UriTemplateError::InvalidPrefix {
                offset: prefix_offset,
            });
        }
        let length = prefix
            .parse::<usize>()
            .map_err(|_| UriTemplateError::InvalidPrefix {
                offset: prefix_offset,
            })?;
        (name, Some(UriTemplateModifier::Prefix(length)))
    } else {
        (source, None)
    };

    if name.len() > MAX_URI_TEMPLATE_VARIABLE_NAME_BYTES {
        return Err(UriTemplateError::VariableNameTooLong {
            actual: name.len(),
            maximum: MAX_URI_TEMPLATE_VARIABLE_NAME_BYTES,
        });
    }
    if !is_valid_variable_name(name) {
        return Err(UriTemplateError::InvalidVariable {
            offset: source_offset,
        });
    }

    Ok(UriTemplateVariable {
        name: name.to_owned(),
        modifier,
    })
}

fn is_valid_prefix(prefix: &str) -> bool {
    let bytes = prefix.as_bytes();
    bytes.len() <= 4
        && bytes
            .first()
            .is_some_and(|byte| matches!(*byte, b'1'..=b'9'))
        && bytes.iter().all(u8::is_ascii_digit)
        && prefix
            .parse::<usize>()
            .is_ok_and(|length| length <= MAX_URI_TEMPLATE_PREFIX_LENGTH)
}

fn is_valid_variable_name(name: &str) -> bool {
    !name.is_empty() && name.split('.').all(is_valid_variable_name_segment)
}

fn is_valid_variable_name_segment(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    let bytes = segment.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_' {
            index += 1;
        } else if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            index += 3;
        } else {
            return false;
        }
    }
    true
}

fn invalid_literal_offset(literal: &str) -> Option<usize> {
    let bytes = literal.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii() {
            if byte == b'%' {
                if index + 2 >= bytes.len()
                    || !bytes[index + 1].is_ascii_hexdigit()
                    || !bytes[index + 2].is_ascii_hexdigit()
                {
                    return Some(index);
                }
                index += 3;
            } else if is_valid_literal_byte(byte) {
                index += 1;
            } else {
                return Some(index);
            }
        } else {
            let Some(character) = literal[index..].chars().next() else {
                return Some(index);
            };
            if !is_valid_literal_character(character) {
                return Some(index);
            }
            index += character.len_utf8();
        }
    }
    None
}

fn is_valid_literal_character(character: char) -> bool {
    matches!(
        u32::from(character),
        0x00A0..=0xD7FF
            | 0xE000..=0xF8FF
            | 0xF900..=0xFDCF
            | 0xFDF0..=0xFFEF
            | 0x10000..=0x1FFFD
            | 0x20000..=0x2FFFD
            | 0x30000..=0x3FFFD
            | 0x40000..=0x4FFFD
            | 0x50000..=0x5FFFD
            | 0x60000..=0x6FFFD
            | 0x70000..=0x7FFFD
            | 0x80000..=0x8FFFD
            | 0x90000..=0x9FFFD
            | 0xA0000..=0xAFFFD
            | 0xB0000..=0xBFFFD
            | 0xC0000..=0xCFFFD
            | 0xD0000..=0xDFFFD
            | 0xE1000..=0xEFFFD
    )
}

fn is_valid_literal_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!'
            | b'#'..=b'$'
            | b'&'
            | b'('..=b';'
            | b'='
            | b'?'..=b'['
            | b']'
            | b'_'
            | b'a'..=b'z'
            | b'~'
    )
}

fn expand_expression(
    output: &mut String,
    expression: &UriTemplateExpression,
    values: &TemplateValues,
    limits: UriTemplateExpansionLimits,
    state: &mut ExpansionState,
) -> Result<(), UriTemplateError> {
    let properties = expression.operator.properties();
    let mut writer = ExpressionWriter::new(output, properties, limits);
    for variable in &expression.variables {
        let Some(value) = values.get(variable.name()) else {
            continue;
        };
        expand_variable(&mut writer, variable, value, state)?;
    }
    Ok(())
}

fn expand_variable(
    writer: &mut ExpressionWriter<'_>,
    variable: &UriTemplateVariable,
    value: &TemplateValue,
    state: &mut ExpansionState,
) -> Result<(), UriTemplateError> {
    match value {
        TemplateValue::Scalar(value) => {
            let value = scalar_prefix(value, variable, writer.limits)?;
            writer.write_value(variable.name(), value, value.is_empty())
        }
        TemplateValue::List(values) => {
            if values.is_empty() {
                return Ok(());
            }
            state.inspect_composite(values.len(), writer.limits)?;
            for value in values.iter().flatten() {
                check_value_bound(value, writer.limits)?;
            }
            if !values.iter().any(Option::is_some) {
                return Ok(());
            }
            reject_prefix_on_composite(variable)?;
            if variable.modifier() == Some(UriTemplateModifier::Explode) {
                for value in values.iter().flatten() {
                    writer.write_value(variable.name(), value, value.is_empty())?;
                }
                return Ok(());
            }

            writer.begin_value()?;
            if writer.properties.named {
                append_variable_name(writer.output, variable.name(), writer.limits)?;
                append_output(writer.output, "=", writer.limits)?;
            }
            let mut first = true;
            for value in values.iter().flatten() {
                if !first {
                    append_output(writer.output, ",", writer.limits)?;
                }
                append_encoded_value(
                    writer.output,
                    value,
                    writer.properties.allow_reserved,
                    writer.limits,
                )?;
                first = false;
            }
            Ok(())
        }
        TemplateValue::Associative(values) => {
            if values.is_empty() {
                return Ok(());
            }
            state.inspect_composite(values.len(), writer.limits)?;
            let mut unique_keys = BTreeSet::new();
            for (key, value) in values {
                if !unique_keys.insert(key.as_str()) {
                    return Err(UriTemplateError::DuplicateAssociativeKey { key: key.clone() });
                }
                check_value_bound(key, writer.limits)?;
                if let Some(value) = value {
                    check_value_bound(value, writer.limits)?;
                }
            }
            if !values.iter().any(|(_, value)| value.is_some()) {
                return Ok(());
            }
            reject_prefix_on_composite(variable)?;
            if variable.modifier() == Some(UriTemplateModifier::Explode) {
                for (key, value) in values {
                    let Some(value) = value else {
                        continue;
                    };
                    writer.write_associative_pair(key, value)?;
                }
                return Ok(());
            }

            writer.begin_value()?;
            if writer.properties.named {
                append_variable_name(writer.output, variable.name(), writer.limits)?;
                append_output(writer.output, "=", writer.limits)?;
            }
            let mut first = true;
            for (key, value) in values {
                let Some(value) = value else {
                    continue;
                };
                if !first {
                    append_output(writer.output, ",", writer.limits)?;
                }
                append_encoded_value(
                    writer.output,
                    key,
                    writer.properties.allow_reserved,
                    writer.limits,
                )?;
                append_output(writer.output, ",", writer.limits)?;
                append_encoded_value(
                    writer.output,
                    value,
                    writer.properties.allow_reserved,
                    writer.limits,
                )?;
                first = false;
            }
            Ok(())
        }
    }
}

fn scalar_prefix<'a>(
    value: &'a str,
    variable: &UriTemplateVariable,
    limits: UriTemplateExpansionLimits,
) -> Result<&'a str, UriTemplateError> {
    check_value_bound(value, limits)?;
    let value = match variable.modifier() {
        Some(UriTemplateModifier::Prefix(length)) => &value[..prefix_end(value, length)],
        Some(UriTemplateModifier::Explode) | None => value,
    };
    Ok(value)
}

fn reject_prefix_on_composite(variable: &UriTemplateVariable) -> Result<(), UriTemplateError> {
    if matches!(variable.modifier(), Some(UriTemplateModifier::Prefix(_))) {
        return Err(UriTemplateError::PrefixAppliedToComposite {
            variable: variable.name().to_owned(),
        });
    }
    Ok(())
}

fn prefix_end(value: &str, maximum_characters: usize) -> usize {
    let bytes = value.as_bytes();
    let mut index = 0;
    let mut characters = 0;
    while index < bytes.len() && characters < maximum_characters {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            index += pct_encoded_character_width(&bytes[index..]);
        } else {
            let Some(character) = value[index..].chars().next() else {
                break;
            };
            index += character.len_utf8();
        }
        characters += 1;
    }
    index
}

fn pct_encoded_character_width(source: &[u8]) -> usize {
    let first = decode_pct_encoded_octet(source);
    let utf8_octets = first.map_or(1, utf8_sequence_width);
    if !(2..=4).contains(&utf8_octets) || source.len() < utf8_octets * 3 {
        return 3;
    }

    let mut decoded = [0_u8; 4];
    for (index, slot) in decoded.iter_mut().take(utf8_octets).enumerate() {
        let offset = index * 3;
        let Some(octet) = decode_pct_encoded_octet(&source[offset..]) else {
            return 3;
        };
        *slot = octet;
    }
    if std::str::from_utf8(&decoded[..utf8_octets])
        .is_ok_and(|decoded| decoded.chars().count() == 1)
    {
        utf8_octets * 3
    } else {
        3
    }
}

fn decode_pct_encoded_octet(source: &[u8]) -> Option<u8> {
    if source.len() < 3 || source[0] != b'%' {
        return None;
    }
    Some((hex_value(source[1])? << 4) | hex_value(source[2])?)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

const fn utf8_sequence_width(first: u8) -> usize {
    match first {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => 1,
    }
}

fn check_value_bound(
    value: &str,
    limits: UriTemplateExpansionLimits,
) -> Result<(), UriTemplateError> {
    if value.len() > limits.max_value_bytes() {
        return Err(UriTemplateError::ValueTooLong {
            actual: value.len(),
            maximum: limits.max_value_bytes(),
        });
    }
    Ok(())
}

fn append_encoded_literal(
    output: &mut String,
    literal: &str,
    limits: UriTemplateExpansionLimits,
) -> Result<(), UriTemplateError> {
    append_percent_encoded(output, literal, true, true, limits)
}

fn append_variable_name(
    output: &mut String,
    name: &str,
    limits: UriTemplateExpansionLimits,
) -> Result<(), UriTemplateError> {
    append_percent_encoded(output, name, false, true, limits)
}

fn append_encoded_value(
    output: &mut String,
    value: &str,
    allow_reserved: bool,
    limits: UriTemplateExpansionLimits,
) -> Result<(), UriTemplateError> {
    append_percent_encoded(output, value, allow_reserved, allow_reserved, limits)
}

fn append_percent_encoded(
    output: &mut String,
    source: &str,
    allow_reserved: bool,
    preserve_pct_encoded: bool,
    limits: UriTemplateExpansionLimits,
) -> Result<(), UriTemplateError> {
    let bytes = source.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if preserve_pct_encoded
            && byte == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            append_output(output, &source[index..index + 3], limits)?;
            index += 3;
        } else if is_unreserved(byte) || (allow_reserved && is_reserved(byte)) {
            append_byte(output, byte, limits)?;
            index += 1;
        } else {
            append_percent_triplet(output, byte, limits)?;
            index += 1;
        }
    }
    Ok(())
}

fn append_output(
    output: &mut String,
    fragment: &str,
    limits: UriTemplateExpansionLimits,
) -> Result<(), UriTemplateError> {
    let actual = output.len().saturating_add(fragment.len());
    if actual > limits.max_output_bytes() {
        return Err(UriTemplateError::ExpansionTooLarge {
            actual,
            maximum: limits.max_output_bytes(),
        });
    }
    output.push_str(fragment);
    Ok(())
}

fn append_byte(
    output: &mut String,
    byte: u8,
    limits: UriTemplateExpansionLimits,
) -> Result<(), UriTemplateError> {
    let actual = output.len().saturating_add(1);
    if actual > limits.max_output_bytes() {
        return Err(UriTemplateError::ExpansionTooLarge {
            actual,
            maximum: limits.max_output_bytes(),
        });
    }
    output.push(char::from(byte));
    Ok(())
}

fn append_percent_triplet(
    output: &mut String,
    byte: u8,
    limits: UriTemplateExpansionLimits,
) -> Result<(), UriTemplateError> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let actual = output.len().saturating_add(3);
    if actual > limits.max_output_bytes() {
        return Err(UriTemplateError::ExpansionTooLarge {
            actual,
            maximum: limits.max_output_bytes(),
        });
    }
    output.push('%');
    output.push(char::from(HEX[usize::from(byte >> 4)]));
    output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    Ok(())
}

const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

const fn is_reserved(byte: u8) -> bool {
    matches!(
        byte,
        b':' | b'/'
            | b'?'
            | b'#'
            | b'['
            | b']'
            | b'@'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values() -> TemplateValues {
        let mut values = TemplateValues::new();
        values.insert("var".to_owned(), TemplateValue::scalar("value"));
        values.insert("hello".to_owned(), TemplateValue::scalar("Hello World!"));
        values.insert("path".to_owned(), TemplateValue::scalar("/foo/bar"));
        values.insert(
            "list".to_owned(),
            TemplateValue::list(vec![
                "red".to_owned(),
                "green".to_owned(),
                "blue".to_owned(),
            ]),
        );
        values.insert(
            "keys".to_owned(),
            TemplateValue::associative(vec![
                ("semi".to_owned(), ";".to_owned()),
                ("dot".to_owned(), ".".to_owned()),
                ("comma".to_owned(), ",".to_owned()),
            ]),
        );
        values
    }

    #[test]
    fn rfc6570_level_four_expansion_positive() {
        let values = values();
        let examples = [
            ("{var:3}", "val"),
            ("{+path}", "/foo/bar"),
            ("{#hello}", "#Hello%20World!"),
            ("X{.list*}", "X.red.green.blue"),
            ("{/list*,path:4}", "/red/green/blue/%2Ffoo"),
            ("{;keys*}", ";semi=%3B;dot=.;comma=%2C"),
            ("{?keys*}", "?semi=%3B&dot=.&comma=%2C"),
            (
                "?fixed=yes{&list*}",
                "?fixed=yes&list=red&list=green&list=blue",
            ),
            ("{keys}", "semi,%3B,dot,.,comma,%2C"),
            ("{+keys*}", "semi=;,dot=.,comma=,"),
            ("{hello}", "Hello%20World%21"),
        ];

        for (template, expected) in examples {
            let parsed = UriTemplate::parse(template).expect("RFC 6570 example parses");
            assert_eq!(parsed.source(), template);
            assert_eq!(
                parsed.expand(&values).expect("RFC example expands"),
                expected
            );
        }
    }

    #[test]
    fn rfc6570_unicode_and_existing_percent_triplets_positive() {
        let template = UriTemplate::parse("https://example.test/é%27s/{term}/{+encoded}")
            .expect("printable Unicode literal and RFC expressions parse");
        let mut values = TemplateValues::new();
        values.insert("term".to_owned(), TemplateValue::scalar("café"));
        values.insert("encoded".to_owned(), TemplateValue::scalar("50%25"));

        assert_eq!(
            template
                .expand(&values)
                .expect("Unicode expands as UTF-8 percent triplets"),
            "https://example.test/%C3%A9%27s/caf%C3%A9/50%25"
        );
        assert_eq!(
            UriTemplate::parse("{encoded}")
                .expect("simple expansion parses")
                .expand(&values)
                .expect("simple expansion percent-encodes a supplied triplet once"),
            "50%2525"
        );
    }

    #[test]
    fn rfc6570_literal_grammar_accepts_final_ucschar_and_rejects_nearby_exclusions() {
        let admitted = format!(
            "mcp://resource/{}",
            char::from_u32(0xE1000).expect("E1000 is a Unicode scalar")
        );
        UriTemplate::parse(&admitted).expect("the first scalar in RFC 6570's final ucschar range");

        let excluded_ucschar = format!(
            "mcp://resource/{}",
            char::from_u32(0xE0FFF).expect("E0FFF is a Unicode scalar")
        );
        assert!(matches!(
            UriTemplate::parse(&excluded_ucschar),
            Err(UriTemplateError::InvalidLiteral { .. })
        ));
        assert!(matches!(
            UriTemplate::parse("mcp://resource/raw'apostrophe"),
            Err(UriTemplateError::InvalidLiteral { .. })
        ));
        UriTemplate::parse("mcp://resource/encoded%27apostrophe")
            .expect("pct-encoded apostrophe remains a valid literal");
    }

    #[test]
    fn rfc6570_bounds_apply_before_ownership_and_prefix_projection() {
        let oversized_source = "x".repeat(MAX_URI_TEMPLATE_BYTES + 1);
        assert_eq!(
            UriTemplate::parse(&oversized_source),
            Err(UriTemplateError::SourceTooLong {
                actual: MAX_URI_TEMPLATE_BYTES + 1,
                maximum: MAX_URI_TEMPLATE_BYTES,
            })
        );

        let template = UriTemplate::parse("{value:1}").expect("prefix expression parses");
        let mut values = TemplateValues::new();
        values.insert("value".to_owned(), TemplateValue::scalar("ab"));
        let limits =
            UriTemplateExpansionLimits::new(16, 1, 1).expect("one-byte scalar limit is valid");
        assert_eq!(
            template.expand_with_limits(&values, limits),
            Err(UriTemplateError::ValueTooLong {
                actual: 2,
                maximum: 1,
            })
        );
    }

    #[test]
    fn rfc6570_prefix_counts_percent_encoded_utf8_as_one_unicode_scalar() {
        let template = UriTemplate::parse("{+value:1}").expect("prefix expression parses");
        let mut values = TemplateValues::new();
        values.insert("value".to_owned(), TemplateValue::scalar("%C3%A9clair"));

        assert_eq!(
            template
                .expand(&values)
                .expect("encoded Unicode scalar is not split between octets"),
            "%C3%A9"
        );
    }

    #[test]
    fn rfc6570_undefined_composite_members_are_ignored_without_losing_empty_values() {
        let template = UriTemplate::parse("{?list*,keys*}").expect("composite expression parses");
        let mut values = TemplateValues::new();
        values.insert(
            "list".to_owned(),
            TemplateValue::list_with_undefined(vec![
                None,
                Some("one".to_owned()),
                Some(String::new()),
                None,
            ]),
        );
        values.insert(
            "keys".to_owned(),
            TemplateValue::associative_with_undefined(vec![
                ("ignored".to_owned(), None),
                ("second".to_owned(), Some("2".to_owned())),
            ]),
        );

        assert_eq!(
            template
                .expand(&values)
                .expect("only defined composite members expand"),
            "?list=one&list=&second=2"
        );

        values.insert(
            "list".to_owned(),
            TemplateValue::list_with_undefined(vec![None]),
        );
        values.insert(
            "keys".to_owned(),
            TemplateValue::associative_with_undefined(vec![("ignored".to_owned(), None)]),
        );
        assert_eq!(
            template
                .expand(&values)
                .expect("all-undefined composites are undefined variables"),
            ""
        );
        assert_eq!(
            UriTemplate::parse("{list:1}{keys:1}")
                .expect("prefix modifiers parse independently of runtime value types")
                .expand(&values)
                .expect("an undefined composite is ignored before modifier semantics"),
            ""
        );
    }

    #[test]
    fn rfc6570_associative_order_is_lossless_and_duplicates_fail_closed() {
        let template = UriTemplate::parse("{keys}").expect("associative expression parses");
        let mut values = TemplateValues::new();
        values.insert(
            "keys".to_owned(),
            TemplateValue::associative(vec![
                ("second".to_owned(), "2".to_owned()),
                ("first".to_owned(), "1".to_owned()),
            ]),
        );
        assert_eq!(
            template.expand(&values).expect("ordered pairs expand"),
            "second,2,first,1"
        );

        let before = values.clone();
        values.insert(
            "keys".to_owned(),
            TemplateValue::associative(vec![
                ("same".to_owned(), "1".to_owned()),
                ("same".to_owned(), "2".to_owned()),
            ]),
        );
        let planted_before = values.clone();
        assert_eq!(
            template.expand(&values),
            Err(UriTemplateError::DuplicateAssociativeKey {
                key: "same".to_owned(),
            })
        );
        assert_ne!(
            planted_before, before,
            "negative changes only the associative input"
        );
        assert_eq!(
            values, planted_before,
            "rejected expansion leaves caller values unchanged"
        );
    }

    #[test]
    fn rfc6570_level_four_near_negative_rejects_invalid_prefix_without_mutation() {
        let accepted = "mcp://resources/{term:3}{?cursor}";
        let planted = "mcp://resources/{term:0}{?cursor}";
        let parsed = UriTemplate::parse(accepted).expect("positive control parses");
        let before = parsed.clone();

        let error = UriTemplate::parse(planted)
            .expect_err("changing only the positive prefix length to zero must reject");
        assert!(matches!(error, UriTemplateError::InvalidPrefix { .. }));
        assert_eq!(
            parsed, before,
            "rejected input cannot mutate an admitted AST"
        );
        assert_eq!(parsed.source(), accepted);
    }

    #[test]
    fn rfc6570_level_four_near_negative_rejects_composite_overflow_without_mutation() {
        let template = UriTemplate::parse("{?items*}").expect("positive control parses");
        let mut values = TemplateValues::new();
        values.insert(
            "items".to_owned(),
            TemplateValue::list(vec!["one".to_owned(), "two".to_owned()]),
        );
        let before = values.clone();
        let limits = UriTemplateExpansionLimits::new(128, 1, 16)
            .expect("the stricter configured limits are valid");

        let error = template
            .expand_with_limits(&values, limits)
            .expect_err("changing only the allowed member count must reject the same input");
        assert_eq!(
            error,
            UriTemplateError::TooManyCompositeItems {
                actual: 2,
                maximum: 1,
            }
        );
        assert_eq!(
            values, before,
            "rejected expansion leaves caller values unchanged"
        );
    }
}

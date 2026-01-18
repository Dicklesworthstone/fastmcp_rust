//! Example: Notes Server
//!
//! An in-memory note-taking MCP server demonstrating:
//! - CRUD operations (Create, Read, Update, Delete)
//! - State management with thread-safe collections
//! - Complex data structures
//! - Dynamic resource URIs
//! - Search and filtering
//!
//! Run with:
//! ```bash
//! cargo run --example notes_server
//! ```
//!
//! Test with MCP Inspector:
//! ```bash
//! npx @anthropic-ai/mcp-inspector cargo run --example notes_server
//! ```

#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::cast_sign_loss)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use fastmcp::prelude::*;

// ============================================================================
// Data Structures
// ============================================================================

/// A single note.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Note {
    id: u64,
    title: String,
    content: String,
    tags: Vec<String>,
    created_at: u64,
    updated_at: u64,
}

/// Global note storage.
static NOTE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
static NOTES: Mutex<Option<HashMap<u64, Note>>> = Mutex::new(None);

fn get_notes() -> std::sync::MutexGuard<'static, Option<HashMap<u64, Note>>> {
    let mut guard = NOTES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// CRUD Tools
// ============================================================================

/// Create a new note.
#[tool(description = "Create a new note with title, content, and optional tags (comma-separated)")]
fn create_note(_ctx: &McpContext, title: String, content: String, tags: String) -> String {
    let id = NOTE_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    let timestamp = current_timestamp();

    let tag_list: Vec<String> = if tags.is_empty() {
        vec![]
    } else {
        tags.split(',').map(|s| s.trim().to_string()).collect()
    };

    let note = Note {
        id,
        title,
        content,
        tags: tag_list,
        created_at: timestamp,
        updated_at: timestamp,
    };

    let mut notes = get_notes();
    notes.as_mut().unwrap().insert(id, note.clone());

    serde_json::to_string_pretty(&note).unwrap_or_else(|_| format!("Created note with ID: {id}"))
}

/// Get a note by ID.
#[tool(description = "Retrieve a note by its ID")]
fn get_note(_ctx: &McpContext, id: i64) -> String {
    if id < 0 {
        return "Error: ID must be non-negative".to_string();
    }

    let notes = get_notes();
    match notes.as_ref().unwrap().get(&(id as u64)) {
        Some(note) => {
            serde_json::to_string_pretty(note).unwrap_or_else(|_| "Error serializing note".into())
        }
        None => format!("Error: Note with ID {id} not found"),
    }
}

/// Update an existing note.
#[tool(description = "Update a note's title, content, or tags. Empty values keep existing data.")]
fn update_note(_ctx: &McpContext, id: i64, title: String, content: String, tags: String) -> String {
    if id < 0 {
        return "Error: ID must be non-negative".to_string();
    }

    let mut notes = get_notes();
    let notes_map = notes.as_mut().unwrap();

    match notes_map.get_mut(&(id as u64)) {
        Some(note) => {
            if !title.is_empty() {
                note.title = title;
            }
            if !content.is_empty() {
                note.content = content;
            }
            if !tags.is_empty() {
                note.tags = tags.split(',').map(|s| s.trim().to_string()).collect();
            }
            note.updated_at = current_timestamp();

            serde_json::to_string_pretty(note).unwrap_or_else(|_| format!("Updated note {id}"))
        }
        None => format!("Error: Note with ID {id} not found"),
    }
}

/// Delete a note by ID.
#[tool(description = "Delete a note by its ID")]
fn delete_note(_ctx: &McpContext, id: i64) -> String {
    if id < 0 {
        return "Error: ID must be non-negative".to_string();
    }

    let mut notes = get_notes();
    match notes.as_mut().unwrap().remove(&(id as u64)) {
        Some(_) => format!("Successfully deleted note {id}"),
        None => format!("Error: Note with ID {id} not found"),
    }
}

// ============================================================================
// Query Tools
// ============================================================================

/// List all notes.
#[tool(description = "List all notes (returns ID, title, and tags for each)")]
fn list_notes(_ctx: &McpContext) -> String {
    let notes = get_notes();
    let notes_map = notes.as_ref().unwrap();

    if notes_map.is_empty() {
        return "No notes found".to_string();
    }

    let summaries: Vec<serde_json::Value> = notes_map
        .values()
        .map(|note| {
            serde_json::json!({
                "id": note.id,
                "title": note.title,
                "tags": note.tags,
                "updated_at": note.updated_at
            })
        })
        .collect();

    serde_json::to_string_pretty(&summaries).unwrap_or_else(|_| "Error listing notes".into())
}

/// Search notes by keyword.
#[tool(description = "Search notes by keyword in title or content")]
fn search_notes(_ctx: &McpContext, query: String) -> String {
    let query_lower = query.to_lowercase();
    let notes = get_notes();
    let notes_map = notes.as_ref().unwrap();

    let matches: Vec<&Note> = notes_map
        .values()
        .filter(|note| {
            note.title.to_lowercase().contains(&query_lower)
                || note.content.to_lowercase().contains(&query_lower)
        })
        .collect();

    if matches.is_empty() {
        return format!("No notes found matching '{query}'");
    }

    serde_json::to_string_pretty(&matches).unwrap_or_else(|_| "Error searching notes".into())
}

/// Find notes by tag.
#[tool(description = "Find all notes with a specific tag")]
fn notes_by_tag(_ctx: &McpContext, tag: String) -> String {
    let tag_lower = tag.to_lowercase();
    let notes = get_notes();
    let notes_map = notes.as_ref().unwrap();

    let matches: Vec<&Note> = notes_map
        .values()
        .filter(|note| note.tags.iter().any(|t| t.to_lowercase() == tag_lower))
        .collect();

    if matches.is_empty() {
        return format!("No notes found with tag '{tag}'");
    }

    serde_json::to_string_pretty(&matches).unwrap_or_else(|_| "Error finding notes by tag".into())
}

/// Get all unique tags.
#[tool(description = "List all unique tags across all notes")]
fn list_tags(_ctx: &McpContext) -> String {
    let notes = get_notes();
    let notes_map = notes.as_ref().unwrap();

    let mut all_tags: Vec<String> = notes_map
        .values()
        .flat_map(|note| note.tags.iter().cloned())
        .collect();

    all_tags.sort();
    all_tags.dedup();

    if all_tags.is_empty() {
        return "No tags found".to_string();
    }

    serde_json::to_string_pretty(&all_tags).unwrap_or_else(|_| "Error listing tags".into())
}

/// Get statistics about the notes collection.
#[tool(description = "Get statistics about the notes collection")]
fn notes_stats(_ctx: &McpContext) -> String {
    let notes = get_notes();
    let notes_map = notes.as_ref().unwrap();

    let total_notes = notes_map.len();
    let total_content_length: usize = notes_map.values().map(|n| n.content.len()).sum();

    let mut tag_counts: HashMap<String, usize> = HashMap::new();
    for note in notes_map.values() {
        for tag in &note.tags {
            *tag_counts.entry(tag.clone()).or_insert(0) += 1;
        }
    }

    let stats = serde_json::json!({
        "total_notes": total_notes,
        "total_content_length": total_content_length,
        "average_content_length": if total_notes > 0 { total_content_length / total_notes } else { 0 },
        "unique_tags": tag_counts.len(),
        "tag_counts": tag_counts
    });

    serde_json::to_string_pretty(&stats).unwrap_or_else(|_| "Error computing stats".into())
}

// ============================================================================
// Resources
// ============================================================================

/// Returns help documentation.
#[resource(
    uri = "notes://help",
    name = "Notes Help",
    description = "Documentation for the notes server"
)]
fn notes_help(_ctx: &McpContext) -> String {
    r#"{
    "description": "An in-memory note-taking server",
    "tools": {
        "create_note": "Create a new note with title, content, and optional tags",
        "get_note": "Retrieve a specific note by ID",
        "update_note": "Update an existing note (empty fields preserve existing values)",
        "delete_note": "Delete a note by ID",
        "list_notes": "List all notes with summaries",
        "search_notes": "Search notes by keyword in title or content",
        "notes_by_tag": "Find notes with a specific tag",
        "list_tags": "List all unique tags",
        "notes_stats": "Get collection statistics"
    },
    "example_workflow": [
        "1. Create a note: create_note('Shopping List', 'Milk, Eggs, Bread', 'shopping,household')",
        "2. List all notes: list_notes()",
        "3. Search: search_notes('milk')",
        "4. Filter by tag: notes_by_tag('shopping')",
        "5. Update: update_note(1, '', 'Milk, Eggs, Bread, Butter', '')",
        "6. Delete: delete_note(1)"
    ]
}"#
    .to_string()
}

/// Returns sample data for demo purposes.
#[resource(
    uri = "notes://samples",
    name = "Sample Notes",
    description = "Pre-populated sample notes for demonstration"
)]
fn sample_notes(_ctx: &McpContext) -> String {
    r#"[
    {
        "title": "Meeting Notes",
        "content": "Discussed Q1 roadmap. Key decisions: prioritize mobile app.",
        "tags": ["work", "meetings"]
    },
    {
        "title": "Book Recommendations",
        "content": "1. The Pragmatic Programmer\n2. Clean Code\n3. Design Patterns",
        "tags": ["books", "learning"]
    },
    {
        "title": "Recipe: Pasta",
        "content": "Ingredients: pasta, olive oil, garlic, parmesan.\nBoil pasta, sauté garlic in oil, combine with cheese.",
        "tags": ["recipes", "cooking"]
    }
]"#
    .to_string()
}

// ============================================================================
// Prompts
// ============================================================================

/// A prompt for organizing notes.
#[prompt(description = "Generate suggestions for organizing notes")]
fn organize_notes(_ctx: &McpContext, current_tags: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!(
                "I have a note-taking system with the following tags: {current_tags}\n\n\
                 Please suggest:\n\
                 1. A better tag taxonomy or hierarchy\n\
                 2. Tags that could be merged or split\n\
                 3. New tags that might be useful\n\
                 4. Tips for maintaining note organization"
            ),
        },
    }]
}

/// A prompt for summarizing notes.
#[prompt(description = "Generate a summary of note contents")]
fn summarize_notes(_ctx: &McpContext, notes_content: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!(
                "Please summarize the following notes into key points and action items:\n\n{notes_content}"
            ),
        },
    }]
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    Server::new("notes-server", "1.0.0")
        // CRUD operations
        .tool(CreateNote)
        .tool(GetNote)
        .tool(UpdateNote)
        .tool(DeleteNote)
        // Query operations
        .tool(ListNotes)
        .tool(SearchNotes)
        .tool(NotesByTag)
        .tool(ListTags)
        .tool(NotesStats)
        // Resources
        .resource(NotesHelpResource)
        .resource(SampleNotesResource)
        // Prompts
        .prompt(OrganizeNotesPrompt)
        .prompt(SummarizeNotesPrompt)
        // Config
        .request_timeout(30)
        .instructions(
            "A note-taking server with full CRUD support. Start with 'create_note' to add notes, \
             use 'list_notes' to see all, 'search_notes' to find specific content, and \
             'notes_by_tag' to filter by tag. Check 'notes://help' resource for full documentation.",
        )
        .build()
        .run_stdio();
}

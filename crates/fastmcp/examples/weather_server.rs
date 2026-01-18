//! Example: Weather Server
//!
//! A mock weather service MCP server demonstrating:
//! - Multiple related tools working together
//! - Resource templates and dynamic URIs
//! - Real-world data patterns (JSON responses)
//! - Progress reporting for "slow" operations
//! - Error handling for invalid inputs
//!
//! Run with:
//! ```bash
//! cargo run --example weather_server
//! ```
//!
//! Test with MCP Inspector:
//! ```bash
//! npx @anthropic-ai/mcp-inspector cargo run --example weather_server
//! ```
//!
//! Note: This is a mock server - all weather data is simulated.

#![allow(clippy::needless_pass_by_value)]
#![allow(
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::map_unwrap_or
)]

use std::collections::HashMap;

use fastmcp::prelude::*;

// ============================================================================
// Mock Data
// ============================================================================

/// Mock weather data for cities.
fn get_mock_weather(city: &str) -> Option<serde_json::Value> {
    let city_lower = city.to_lowercase();
    let data: HashMap<&str, serde_json::Value> = HashMap::from([
        (
            "new york",
            serde_json::json!({
                "city": "New York",
                "country": "US",
                "temperature_c": 18,
                "temperature_f": 64,
                "condition": "Partly Cloudy",
                "humidity": 65,
                "wind_speed_kmh": 15,
                "wind_direction": "NW",
                "uv_index": 4,
                "visibility_km": 10
            }),
        ),
        (
            "london",
            serde_json::json!({
                "city": "London",
                "country": "UK",
                "temperature_c": 12,
                "temperature_f": 54,
                "condition": "Rainy",
                "humidity": 85,
                "wind_speed_kmh": 20,
                "wind_direction": "SW",
                "uv_index": 2,
                "visibility_km": 5
            }),
        ),
        (
            "tokyo",
            serde_json::json!({
                "city": "Tokyo",
                "country": "JP",
                "temperature_c": 22,
                "temperature_f": 72,
                "condition": "Sunny",
                "humidity": 55,
                "wind_speed_kmh": 10,
                "wind_direction": "E",
                "uv_index": 6,
                "visibility_km": 15
            }),
        ),
        (
            "sydney",
            serde_json::json!({
                "city": "Sydney",
                "country": "AU",
                "temperature_c": 25,
                "temperature_f": 77,
                "condition": "Clear",
                "humidity": 50,
                "wind_speed_kmh": 18,
                "wind_direction": "NE",
                "uv_index": 8,
                "visibility_km": 20
            }),
        ),
        (
            "paris",
            serde_json::json!({
                "city": "Paris",
                "country": "FR",
                "temperature_c": 15,
                "temperature_f": 59,
                "condition": "Overcast",
                "humidity": 70,
                "wind_speed_kmh": 12,
                "wind_direction": "W",
                "uv_index": 3,
                "visibility_km": 8
            }),
        ),
    ]);

    data.get(city_lower.as_str()).cloned()
}

/// Mock forecast data.
fn get_mock_forecast(city: &str, days: i64) -> Option<serde_json::Value> {
    get_mock_weather(city).map(|current| {
        let base_temp = current["temperature_c"].as_i64().unwrap_or(20);
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let forecasts: Vec<serde_json::Value> = (1..=days)
            .map(|day| {
                // Vary temperature slightly each day
                let temp_variation = (day * 2) % 5 - 2;
                let temp_c = base_temp + temp_variation;
                let conditions = ["Sunny", "Partly Cloudy", "Cloudy", "Rainy", "Clear"];
                let condition = conditions[(day as usize) % conditions.len()];

                serde_json::json!({
                    "day": day,
                    "high_c": temp_c + 5,
                    "low_c": temp_c - 3,
                    "condition": condition,
                    "precipitation_chance": (day as u64 * 15) % 100
                })
            })
            .collect();

        serde_json::json!({
            "city": current["city"],
            "country": current["country"],
            "forecast": forecasts
        })
    })
}

// ============================================================================
// Weather Tools
// ============================================================================

/// Get current weather for a city.
#[tool(description = "Get current weather conditions for a city")]
fn get_weather(_ctx: &McpContext, city: String) -> String {
    match get_mock_weather(&city) {
        Some(weather) => serde_json::to_string_pretty(&weather)
            .unwrap_or_else(|_| format!("Error formatting weather data for {city}")),
        None => format!(
            "Error: City '{city}' not found. Available cities: New York, London, Tokyo, Sydney, Paris"
        ),
    }
}

/// Get weather forecast for multiple days.
#[tool(description = "Get weather forecast for a city (1-7 days)")]
fn get_forecast(ctx: &McpContext, city: String, days: i64) -> String {
    if !(1..=7).contains(&days) {
        return "Error: Days must be between 1 and 7".to_string();
    }

    // Simulate a slow operation with progress
    #[allow(clippy::cast_precision_loss)]
    for i in 1..=days {
        if ctx.is_cancelled() {
            return "Cancelled".to_string();
        }
        // Report progress
        ctx.report_progress_with_total(i as f64, days as f64, None);
    }

    match get_mock_forecast(&city, days) {
        Some(forecast) => serde_json::to_string_pretty(&forecast)
            .unwrap_or_else(|_| format!("Error formatting forecast for {city}")),
        None => format!(
            "Error: City '{city}' not found. Available cities: New York, London, Tokyo, Sydney, Paris"
        ),
    }
}

/// Compare weather between two cities.
#[tool(description = "Compare current weather between two cities")]
fn compare_weather(_ctx: &McpContext, city1: String, city2: String) -> String {
    let weather1 = get_mock_weather(&city1);
    let weather2 = get_mock_weather(&city2);

    match (weather1, weather2) {
        (Some(w1), Some(w2)) => {
            let temp_diff = w1["temperature_c"].as_i64().unwrap_or(0)
                - w2["temperature_c"].as_i64().unwrap_or(0);
            let humidity_diff =
                w1["humidity"].as_i64().unwrap_or(0) - w2["humidity"].as_i64().unwrap_or(0);

            serde_json::to_string_pretty(&serde_json::json!({
                "cities": [w1["city"], w2["city"]],
                "comparison": {
                    "temperature_diff_c": temp_diff,
                    "warmer_city": if temp_diff > 0 { &w1["city"] } else { &w2["city"] },
                    "humidity_diff": humidity_diff,
                    "more_humid_city": if humidity_diff > 0 { &w1["city"] } else { &w2["city"] }
                },
                "city1_weather": w1,
                "city2_weather": w2
            }))
            .unwrap_or_else(|_| "Error formatting comparison".into())
        }
        (None, _) => format!("Error: City '{city1}' not found"),
        (_, None) => format!("Error: City '{city2}' not found"),
    }
}

/// Convert temperature between Celsius and Fahrenheit.
#[tool(
    description = "Convert temperature between Celsius and Fahrenheit. Use 'c' or 'f' for unit."
)]
fn convert_temp(_ctx: &McpContext, value: f64, from_unit: String) -> String {
    match from_unit.to_lowercase().as_str() {
        "c" | "celsius" => {
            let fahrenheit = (value * 9.0 / 5.0) + 32.0;
            format!("{value}°C = {fahrenheit:.1}°F")
        }
        "f" | "fahrenheit" => {
            let celsius = (value - 32.0) * 5.0 / 9.0;
            format!("{value}°F = {celsius:.1}°C")
        }
        _ => "Error: Unit must be 'c' (Celsius) or 'f' (Fahrenheit)".to_string(),
    }
}

/// Get weather alerts for a city.
#[tool(description = "Check for weather alerts and warnings for a city")]
fn weather_alerts(_ctx: &McpContext, city: String) -> String {
    match get_mock_weather(&city) {
        Some(weather) => {
            let mut alerts = vec![];

            // Generate mock alerts based on conditions
            let temp = weather["temperature_c"].as_i64().unwrap_or(20);
            let humidity = weather["humidity"].as_i64().unwrap_or(50);
            let uv = weather["uv_index"].as_i64().unwrap_or(5);
            let wind = weather["wind_speed_kmh"].as_i64().unwrap_or(10);

            if temp > 35 {
                alerts.push(serde_json::json!({
                    "type": "Heat Warning",
                    "severity": "high",
                    "message": "Extreme heat expected. Stay hydrated and avoid outdoor activities."
                }));
            } else if temp < 0 {
                alerts.push(serde_json::json!({
                    "type": "Freeze Warning",
                    "severity": "medium",
                    "message": "Freezing temperatures expected. Protect pipes and plants."
                }));
            }

            if humidity > 80 {
                alerts.push(serde_json::json!({
                    "type": "Humidity Advisory",
                    "severity": "low",
                    "message": "High humidity may cause discomfort."
                }));
            }

            if uv > 7 {
                alerts.push(serde_json::json!({
                    "type": "UV Warning",
                    "severity": "medium",
                    "message": "High UV index. Use sunscreen and protective clothing."
                }));
            }

            if wind > 50 {
                alerts.push(serde_json::json!({
                    "type": "Wind Advisory",
                    "severity": "high",
                    "message": "Strong winds expected. Secure loose objects."
                }));
            }

            let response = serde_json::json!({
                "city": weather["city"],
                "alerts_count": alerts.len(),
                "alerts": if alerts.is_empty() {
                    vec![serde_json::json!({"type": "None", "message": "No active weather alerts"})]
                } else {
                    alerts
                }
            });

            serde_json::to_string_pretty(&response)
                .unwrap_or_else(|_| "Error formatting alerts".into())
        }
        None => format!(
            "Error: City '{city}' not found. Available cities: New York, London, Tokyo, Sydney, Paris"
        ),
    }
}

/// List all available cities.
#[tool(description = "List all cities with available weather data")]
fn list_cities(_ctx: &McpContext) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "available_cities": [
            {"name": "New York", "country": "US", "timezone": "EST"},
            {"name": "London", "country": "UK", "timezone": "GMT"},
            {"name": "Tokyo", "country": "JP", "timezone": "JST"},
            {"name": "Sydney", "country": "AU", "timezone": "AEST"},
            {"name": "Paris", "country": "FR", "timezone": "CET"}
        ]
    }))
    .unwrap_or_else(|_| "Error listing cities".into())
}

// ============================================================================
// Resources
// ============================================================================

/// Returns API documentation.
#[resource(
    uri = "weather://docs",
    name = "Weather API Docs",
    description = "Documentation for the weather server API"
)]
fn weather_docs(_ctx: &McpContext) -> String {
    r#"{
    "description": "Mock weather data server for demonstration",
    "available_cities": ["New York", "London", "Tokyo", "Sydney", "Paris"],
    "tools": {
        "get_weather": "Get current conditions (temp, humidity, wind, etc.)",
        "get_forecast": "Get 1-7 day forecast with daily highs/lows",
        "compare_weather": "Compare conditions between two cities",
        "convert_temp": "Convert between Celsius and Fahrenheit",
        "weather_alerts": "Check for weather warnings and advisories",
        "list_cities": "List all available cities with metadata"
    },
    "data_fields": {
        "temperature_c": "Temperature in Celsius",
        "temperature_f": "Temperature in Fahrenheit",
        "condition": "Weather condition (Sunny, Cloudy, Rainy, etc.)",
        "humidity": "Relative humidity percentage",
        "wind_speed_kmh": "Wind speed in km/h",
        "wind_direction": "Cardinal wind direction",
        "uv_index": "UV index (1-11+)",
        "visibility_km": "Visibility in kilometers"
    },
    "note": "This is a mock server. All data is simulated for demonstration purposes."
}"#
    .to_string()
}

/// Returns weather condition icons mapping.
#[resource(
    uri = "weather://icons",
    name = "Weather Icons",
    description = "Mapping of weather conditions to emoji icons"
)]
fn weather_icons(_ctx: &McpContext) -> String {
    r#"{
    "conditions": {
        "Sunny": "☀️",
        "Clear": "🌙",
        "Partly Cloudy": "⛅",
        "Cloudy": "☁️",
        "Overcast": "🌥️",
        "Rainy": "🌧️",
        "Stormy": "⛈️",
        "Snowy": "❄️",
        "Foggy": "🌫️",
        "Windy": "💨"
    }
}"#
    .to_string()
}

// ============================================================================
// Prompts
// ============================================================================

/// A prompt for weather-based activity suggestions.
#[prompt(description = "Get activity suggestions based on weather conditions")]
fn suggest_activities(
    _ctx: &McpContext,
    city: String,
    activity_type: String,
) -> Vec<PromptMessage> {
    let weather_info = get_mock_weather(&city)
        .map(|w| serde_json::to_string_pretty(&w).unwrap_or_default())
        .unwrap_or_else(|| "Weather data not available".to_string());

    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!(
                "Based on the following weather conditions in {city}:\n\n{weather_info}\n\n\
                 Please suggest appropriate {activity_type} activities. Consider:\n\
                 - Temperature and how to dress\n\
                 - Any weather-related precautions\n\
                 - Best times of day for the activities\n\
                 - Indoor alternatives if weather is unfavorable"
            ),
        },
    }]
}

/// A prompt for packing suggestions.
#[prompt(description = "Get packing suggestions for a trip based on weather")]
fn packing_list(
    _ctx: &McpContext,
    destination: String,
    duration_days: String,
) -> Vec<PromptMessage> {
    let weather_info = get_mock_weather(&destination)
        .map(|w| serde_json::to_string_pretty(&w).unwrap_or_default())
        .unwrap_or_else(|| "Weather data not available".to_string());

    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!(
                "I'm traveling to {destination} for {duration_days} days. \
                 The current weather conditions are:\n\n{weather_info}\n\n\
                 Please create a comprehensive packing list that includes:\n\
                 - Appropriate clothing for the weather\n\
                 - Weather-specific items (umbrella, sunscreen, etc.)\n\
                 - Travel essentials\n\
                 - Quantities based on the trip duration"
            ),
        },
    }]
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    Server::new("weather-server", "1.0.0")
        // Weather tools
        .tool(GetWeather)
        .tool(GetForecast)
        .tool(CompareWeather)
        .tool(ConvertTemp)
        .tool(WeatherAlerts)
        .tool(ListCities)
        // Resources
        .resource(WeatherDocsResource)
        .resource(WeatherIconsResource)
        // Prompts
        .prompt(SuggestActivitiesPrompt)
        .prompt(PackingListPrompt)
        // Config
        .request_timeout(60)
        .instructions(
            "A mock weather server for demonstration. Get current weather with 'get_weather', \
             forecasts with 'get_forecast', or compare cities with 'compare_weather'. \
             Available cities: New York, London, Tokyo, Sydney, Paris. \
             Check 'weather://docs' for full API documentation.",
        )
        .build()
        .run_stdio();
}

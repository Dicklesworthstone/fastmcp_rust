//! Literal frozen LEG-02 A runner entries.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use fastmcp_protocol::methods::{
    Legacy2024ListChangedCapability, Legacy2024ResourcesCapability, Legacy2024ServerCapabilities,
    COMPLETION_COMPLETE, NOTIFICATIONS_CANCELLED, NOTIFICATIONS_MESSAGE, NOTIFICATIONS_PROGRESS,
    NOTIFICATIONS_ROOTS_LIST_CHANGED, ROOTS_LIST, SAMPLING_CREATE_MESSAGE,
};
use fastmcp_server::legacy_2024::{
    Legacy2024Handler, Legacy2024HandlerError, Legacy2024Lifecycle, Legacy2024Outbound,
    Legacy2024ServerAdapter, Legacy2024ServerConfig, Legacy2024ServerInfo, LegacyPeerBinding,
};
use serde_json::{json, Value};

#[derive(Clone)]
struct RecordingHandler {
    methods: Rc<RefCell<Vec<&'static str>>>,
}

impl Legacy2024Handler for RecordingHandler {
    fn handle_legacy_2024(
        &mut self,
        method: &'static str,
        _params: Option<&Value>,
    ) -> Result<Value, Legacy2024HandlerError> {
        self.methods.borrow_mut().push(method);
        Ok(json!({"handled": method}))
    }
}

fn adapter(methods: Rc<RefCell<Vec<&'static str>>>) -> Legacy2024ServerAdapter<RecordingHandler> {
    Legacy2024ServerAdapter::install(
        LegacyPeerBinding::new(20241105),
        Legacy2024ServerConfig {
            capabilities: Legacy2024ServerCapabilities {
                logging: Some(BTreeMap::default()),
                tools: Some(Legacy2024ListChangedCapability::default()),
                resources: Some(Legacy2024ResourcesCapability {
                    subscribe: true,
                    ..Legacy2024ResourcesCapability::default()
                }),
                prompts: Some(Legacy2024ListChangedCapability::default()),
                ..Legacy2024ServerCapabilities::default()
            },
            server_info: Legacy2024ServerInfo {
                name: "public-legacy-server".to_owned(),
                version: "1.0.0".to_owned(),
            },
            instructions: Some("exact 2024 server surface".to_owned()),
        },
        RecordingHandler { methods },
    )
    .expect("exact public server configuration must install")
}

fn initialize() -> Value {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"sampling": {}, "roots": {"listChanged": true}},
            "clientInfo": {"name": "public-legacy-client", "version": "1.0.0"},
        },
    })
}

fn operating_adapter(
    methods: Rc<RefCell<Vec<&'static str>>>,
) -> Legacy2024ServerAdapter<RecordingHandler> {
    let binding = LegacyPeerBinding::new(20241105);
    let mut adapter = adapter(methods);
    assert!(matches!(
        adapter
            .receive(binding, initialize())
            .expect("initialize response"),
        Legacy2024Outbound::Response(_)
    ));
    assert_eq!(
        adapter
            .receive(
                binding,
                json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            )
            .expect("initialized notification"),
        Legacy2024Outbound::NoResponse
    );
    adapter
}

#[test]
fn leg_02_a_positive() {
    let binding = LegacyPeerBinding::new(20241105);
    let methods = Rc::new(RefCell::new(Vec::new()));
    let mut adapter = operating_adapter(methods.clone());
    assert_eq!(adapter.installed_receipt().protocol_version(), "2024-11-05");
    assert!(adapter
        .installed_receipt()
        .canonical_bytes()
        .starts_with(b"fastmcp-legacy-server-install-v1\0"));
    let rows = [
        adapter.receive(
            binding,
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        ),
        adapter.receive(
            binding,
            json!({"jsonrpc": "2.0", "id": 3, "method": "resources/list"}),
        ),
        adapter.receive(
            binding,
            json!({"jsonrpc": "2.0", "id": 4, "method": "prompts/list"}),
        ),
        adapter.receive(
            binding,
            json!({
                "jsonrpc": "2.0", "id": 5, "method": COMPLETION_COMPLETE,
                "params": {
                    "ref": {"type": "ref/prompt", "name": "legacy-prompt"},
                    "argument": {"name": "topic", "value": "legacy"},
                },
            }),
        ),
        adapter.receive(
            binding,
            json!({
                "jsonrpc": "2.0", "id": 6, "method": "resources/subscribe",
                "params": {"uri": "file:///workspace"},
            }),
        ),
    ];
    assert!(rows
        .into_iter()
        .all(|row| matches!(row, Ok(Legacy2024Outbound::Response(_)))));
    assert!(matches!(
        adapter
            .make_reverse_request(binding, ROOTS_LIST, json!({}))
            .expect("roots request"),
        Legacy2024Outbound::ReverseRequest(request) if request["method"] == ROOTS_LIST
    ));
    assert!(matches!(
        adapter
            .make_reverse_request(
                binding,
                SAMPLING_CREATE_MESSAGE,
                json!({"messages": [], "maxTokens": 16}),
            )
            .expect("sampling request"),
        Legacy2024Outbound::ReverseRequest(request) if request["method"] == SAMPLING_CREATE_MESSAGE
    ));
    assert!(matches!(
        adapter
            .receive(
                binding,
                json!({
                    "jsonrpc": "2.0", "id": 7, "method": "logging/setLevel",
                    "params": {"level": "info"},
                })
            )
            .expect("logging response"),
        Legacy2024Outbound::Response(_)
    ));
    assert_eq!(
        adapter
            .receive(
                binding,
                json!({
                    "jsonrpc": "2.0", "method": NOTIFICATIONS_CANCELLED,
                    "params": {"requestId": 6},
                })
            )
            .expect("cancellation notification"),
        Legacy2024Outbound::NoResponse
    );
    assert_eq!(
        adapter
            .receive(
                binding,
                json!({
                    "jsonrpc": "2.0", "method": NOTIFICATIONS_PROGRESS,
                    "params": {"progressToken": 1, "progress": 1},
                })
            )
            .expect("progress notification"),
        Legacy2024Outbound::NoResponse
    );
    let state = adapter.snapshot();
    assert_eq!(adapter.lifecycle(), Legacy2024Lifecycle::Operating);
    assert_eq!(state.operating_transition_count, 1);
    assert_eq!(state.subscription_count, 1);
    assert_eq!(state.control_notification_count, 2);
    assert_eq!(
        methods.borrow().as_slice(),
        [
            "tools/list",
            "resources/list",
            "prompts/list",
            COMPLETION_COMPLETE
        ]
    );
}

#[test]
fn leg_02_a_planted_negative() {
    let binding = LegacyPeerBinding::new(20241105);
    let methods = Rc::new(RefCell::new(Vec::new()));
    let mut adapter = adapter(methods.clone());
    let before = adapter.snapshot();
    let mut wrong_era = initialize();
    wrong_era["params"]["protocolVersion"] = json!("2025-11-25");
    let mut modern_shape = initialize();
    modern_shape["params"]["capabilities"]["elicitation"] = json!({"form": {}});
    for planted in [wrong_era, modern_shape] {
        let response = adapter
            .receive(binding, planted)
            .expect("valid request id receives error");
        assert!(matches!(
            response,
            Legacy2024Outbound::Response(response) if response["error"]["code"] == -32600
        ));
        assert_eq!(adapter.snapshot(), before);
    }
    assert!(methods.borrow().is_empty());
}

#[test]
fn legacy_2024_notification_surface_positive() {
    let binding = LegacyPeerBinding::new(20241105);
    let methods = Rc::new(RefCell::new(Vec::new()));
    let mut adapter = operating_adapter(methods);
    assert!(matches!(
        adapter
            .make_notification(
                binding,
                NOTIFICATIONS_MESSAGE,
                Some(json!({"level": "info", "data": "exact"})),
            )
            .expect("advertised logging capability permits exact notification"),
        Legacy2024Outbound::ReverseNotification(notification)
            if notification["method"] == NOTIFICATIONS_MESSAGE
    ));
    assert_eq!(
        adapter
            .receive(
                binding,
                json!({
                    "jsonrpc": "2.0", "method": NOTIFICATIONS_ROOTS_LIST_CHANGED,
                    "params": {},
                }),
            )
            .expect("negotiated roots list-change notification"),
        Legacy2024Outbound::NoResponse
    );
    assert_eq!(adapter.snapshot().roots_list_changed_count, 1);
}

#[test]
fn legacy_2024_notification_surface_planted_negative() {
    let binding = LegacyPeerBinding::new(20241105);
    let methods = Rc::new(RefCell::new(Vec::new()));
    let adapter = operating_adapter(methods);
    let before = adapter.snapshot();
    assert!(adapter
        .make_notification(binding, NOTIFICATIONS_ROOTS_LIST_CHANGED, Some(json!({})))
        .is_err());
    assert_eq!(adapter.snapshot(), before);
}

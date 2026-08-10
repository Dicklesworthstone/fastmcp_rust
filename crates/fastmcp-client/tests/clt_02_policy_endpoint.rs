use asupersync::Cx;
use fastmcp_client::{
    CanonicalHttpUrl, ClientBuilder, ClientHttpConnectionError, ClientHttpNegotiationError,
    ClientProtocolPlan, ClientSession, ModernHttpClientError, ProtocolEra, ProtocolPolicy,
};
use fastmcp_core::McpErrorCode;
use fastmcp_protocol::{ClientInfo, ServerCapabilities, ServerInfo};

const ABSENT_STDIO_COMMAND: &str = "./clt-02-intentionally-absent-server";

fn url(value: &str) -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse(value).expect("test endpoint must be canonical")
}

fn auto_http_plan() -> ClientProtocolPlan {
    ClientProtocolPlan::http(
        ProtocolPolicy::Auto,
        Some(url("http://127.0.0.1:9/mcp")),
        Some(url("http://127.0.0.1:9/sse")),
        Some(url("http://127.0.0.1:9/messages")),
        "credential-partition-a".to_owned(),
        "security-partition-a".to_owned(),
        "streamable-http-v1".to_owned(),
        8,
        4,
        0,
    )
    .expect("test HTTP plan must be accepted")
}

#[test]
fn clt_02_a_positive() {
    let http_plan = ClientProtocolPlan::http(
        ProtocolPolicy::ModernOnly,
        Some(url("https://client.example.test/mcp?tenant=alpha")),
        None,
        None,
        "credential-partition-a".to_owned(),
        "security-partition-a".to_owned(),
        "streamable-http-v1".to_owned(),
        8,
        4,
        0,
    )
    .expect("modern-only plan needs one configured modern endpoint");
    let default_builder = ClientBuilder::new();
    let plan = ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly);
    let builder = default_builder.clone().protocol_plan(plan.clone());
    let state_before_connect = builder.selected_protocol_plan().clone();
    let error =
        match builder
            .clone()
            .connect_stdio_with_cx(ABSENT_STDIO_COMMAND, &[], &Cx::for_request())
        {
            Ok(_) => panic!("accepted modern policy must reach command admission"),
            Err(error) => error,
        };

    assert_eq!(builder.selected_protocol_plan(), &plan);
    assert_eq!(plan.policy(), ProtocolPolicy::ModernOnly);
    assert_eq!(
        default_builder.selected_protocol_plan().policy(),
        ProtocolPolicy::Auto
    );
    assert!(http_plan.http_endpoints().is_some());
    assert_eq!(error.code, McpErrorCode::InternalError);
    assert_eq!(builder.selected_protocol_plan(), &state_before_connect);

    let session = ClientSession::try_new(
        ClientInfo {
            name: "test-client".to_owned(),
            version: "1.0.0".to_owned(),
        },
        Default::default(),
        ServerInfo {
            name: "test-server".to_owned(),
            version: "1.0.0".to_owned(),
        },
        ServerCapabilities::default(),
        "2024-11-05".to_owned(),
    )
    .expect("exact supported protocol version")
    .with_protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::Auto));
    assert_eq!(session.selected_era(), Some(ProtocolEra::Legacy2024));
}

#[test]
fn clt_02_a_planted_negative() {
    let baseline = ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly);
    let accepted_builder = ClientBuilder::new().protocol_plan(baseline.clone());
    let accepted_state = accepted_builder.selected_protocol_plan().clone();

    // Only the policy differs from the accepted baseline. Auto requires the
    // unavailable exact legacy adapter and must refuse before command spawn.
    let refusal = ClientProtocolPlan::stdio(ProtocolPolicy::Auto);
    let refusal_builder = ClientBuilder::new().protocol_plan(refusal.clone());
    let refusal_state = refusal_builder.selected_protocol_plan().clone();
    let error = match refusal_builder.clone().connect_stdio_with_cx(
        ABSENT_STDIO_COMMAND,
        &[],
        &Cx::for_request(),
    ) {
        Ok(_) => {
            panic!("auto policy without the legacy adapter must be refused before spawn")
        }
        Err(error) => error,
    };

    assert_eq!(baseline.policy(), ProtocolPolicy::ModernOnly);
    assert_eq!(refusal.policy(), ProtocolPolicy::Auto);
    assert_eq!(error.code, McpErrorCode::InvalidParams);
    assert_eq!(accepted_builder.selected_protocol_plan(), &baseline);
    assert_eq!(accepted_builder.selected_protocol_plan(), &accepted_state);
    assert_eq!(refusal_builder.selected_protocol_plan(), &refusal_state);

    let http_refusal = ClientBuilder::new().protocol_plan(auto_http_plan());
    let http_error = fastmcp_core::block_on(async {
        match http_refusal.connect_http_with_cx(&Cx::for_request()).await {
            Ok(_) => {
                panic!("auto HTTP policy without the legacy adapter must be refused before contact")
            }
            Err(error) => error,
        }
    });
    assert!(matches!(
        http_error,
        ClientHttpConnectionError::Modern(ModernHttpClientError::Negotiation(
            ClientHttpNegotiationError::ModernProbeForbiddenForLegacyOnly
        ))
    ));
}

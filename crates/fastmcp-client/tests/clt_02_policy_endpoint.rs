use fastmcp_client::{
    CanonicalHttpUrl, ClientBuilder, ClientProtocolPlan, HttpEndpointBundleError, ProtocolPolicy,
};

fn url(value: &str) -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse(value).expect("test endpoint must be canonical")
}

#[test]
fn clt_02_a_positive() {
    let plan = ClientProtocolPlan::http(
        ProtocolPolicy::ModernOnly,
        Some(url("https://client.example.test/mcp?tenant=alpha")),
        None,
        None,
        "credential-partition-a".to_owned(),
        "streamable-http-v1".to_owned(),
        4,
        0,
    )
    .expect("modern-only plan needs one configured modern endpoint");
    let builder = ClientBuilder::new().protocol_plan(plan.clone());

    assert_eq!(builder.selected_protocol_plan(), &plan);
    assert_eq!(plan.policy(), ProtocolPolicy::ModernOnly);
    assert!(plan.http_endpoints().is_some());
}

#[test]
fn clt_02_a_planted_negative() {
    let baseline_policy = ProtocolPolicy::ModernOnly;
    let baseline = ClientProtocolPlan::http(
        baseline_policy,
        Some(url("https://client.example.test/mcp?tenant=alpha")),
        None,
        None,
        "credential-partition-a".to_owned(),
        "streamable-http-v1".to_owned(),
        4,
        0,
    )
    .expect("baseline is accepted");
    let accepted_builder = ClientBuilder::new().protocol_plan(baseline.clone());

    // Only the required modern POST endpoint changes from the accepted plan.
    let refusal = ClientProtocolPlan::http(
        baseline_policy,
        None,
        None,
        None,
        "credential-partition-a".to_owned(),
        "streamable-http-v1".to_owned(),
        4,
        0,
    );

    assert_eq!(
        refusal,
        Err(HttpEndpointBundleError::MissingModernPostTarget {
            policy: ProtocolPolicy::ModernOnly,
        })
    );
    assert_eq!(accepted_builder.selected_protocol_plan(), &baseline);
}

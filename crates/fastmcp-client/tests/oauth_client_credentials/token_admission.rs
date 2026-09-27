//! Successful machine grants must remain in the explicitly selected bearer
//! profile. These tests use public discovery/acquisition/MCP APIs and native
//! TLS with the parent's explicit trust configuration. The peer scripts issuer
//! responses; this is not external-provider or durable-custody qualification.

use super::*;

fn run_admission<F, Fut>(scenario: F)
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = ()>,
{
    RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .build().unwrap().block_on(async move {
            let cx = Cx::current().unwrap();
            let deadline = cx.now().saturating_add_nanos(30_000_000_000);
            asupersync::time::timeout_at(deadline, Box::pin(scenario(cx)))
                .await.expect("machine token admission fixture must settle");
        });
}

async fn discover(peer: &Peer, cx: &Cx, post: bool) -> ClientCredentialsClient {
    let mut plan = peer.plan(Duration::from_secs(10));
    if post {
        plan = plan.with_secret_authentication(ClientSecretAuthenticationMethod::Post).unwrap();
        let ((), client) = pair(post_metadata(peer, PostCase::Lifecycle), plan.discover(cx)).await;
        client.unwrap()
    } else {
        let ((), client) = pair(peer.metadata(Case::Complete), plan.discover(cx)).await;
        client.unwrap()
    }
}

async fn reply(peer: &Peer, post: bool, body: &str) {
    let mut socket = if post {
        post_token_request(peer, "service-client", "service-secret").await
    } else {
        peer.token_request().await
    };
    json_reply(&mut socket, body).await;
}

fn ordinary_token() -> Value {
    json!({"access_token":"admitted-access", "token_type":"Bearer",
        "expires_in":300, "scope":"read"})
}

async fn core_succeeds(peer: &Peer, cx: &Cx, client: &ClientCredentialsClient, token: &str) {
    let ((), response) = pair(peer.operation(41, "tools/call", token, CALL),
        client.execute_core(cx, core("tools/call"), RequestId::Number(41), RequestId::Number(42))).await;
    let result = response.unwrap().read_json_result(cx, 4096).await.unwrap();
    assert!(matches!(result, CoreResult::Final(FinalCoreResult::ToolsCall { .. })));
    peer.quiet();
}

#[test]
fn incompatible_machine_grants_stop_dispatch_without_installing_a_generation() {
    for post in [false, true] {
        run_admission(|cx| async move {
            let peer = Peer::new().await;
            let client = discover(&peer, &cx, post).await;
            for (index, (key, value)) in [
                ("refresh_token", json!("private-refresh-canary")),
                ("id_token", json!("private-identity-canary")),
                ("cnf", json!({"jkt":"private-proof-canary"})),
                ("issued_token_type", json!("urn:ietf:params:oauth:token-type:access_token")),
                ("error_description", json!("private-error-canary")),
                ("error_uri", json!("https://untrusted.example/error")),
            ].into_iter().enumerate() {
                let mut document = ordinary_token();
                document[key] = value;
                let body = document.to_string();
                let ((), result) = pair(reply(&peer, post, &body), client.execute_core(
                    &cx, core("tools/call"), RequestId::Number(1), RequestId::Number(2),
                )).await;
                let error = result.err().expect("incompatible success must not reach MCP dispatch");
                assert!(matches!(error, Error::InvalidToken));
                let diagnostic = format!("{error:?} {error}");
                assert!(!diagnostic.contains("private-") && !diagnostic.contains("admitted-access"));
                assert_eq!(peer.grants.load(Ordering::SeqCst), index + 1);
                assert_eq!(peer.rpcs.load(Ordering::SeqCst), 0);
                peer.quiet();
            }
            // This is an explicit new acquisition after rejection, not an
            // automatic retry. Every failed candidate left generation zero.
            let body = ordinary_token().to_string();
            let ((), admitted) = pair(reply(&peer, post, &body), client.credential(&cx)).await;
            let admitted = admitted.unwrap();
            assert_eq!(admitted.generation(), 1);
            assert_eq!(admitted.scopes(), ["read"]);
            core_succeeds(&peer, &cx, &client, "admitted-access").await;
            assert_eq!(peer.grants.load(Ordering::SeqCst), 7);
            assert_eq!(peer.rpcs.load(Ordering::SeqCst), 2);
            assert_eq!(peer.gets.load(Ordering::SeqCst), 2);
            assert!(cx.checkpoint().is_ok());
            client.close();
        });
    }
}

#[test]
fn ignored_machine_metadata_is_not_mistaken_for_top_level_token_authority() {
    for post in [false, true] {
        run_admission(|cx| async move {
            let peer = Peer::new().await;
            let client = discover(&peer, &cx, post).await;
            let mut document = ordinary_token();
            document["token_type"] = json!("bEaReR");
            document["x-extension"] = json!({"refresh_token":null, "id_token":"nested",
                "cnf":{"jkt":"nested"}, "error_description":"nested", "scope":"admin"});
            document["token_endpoint"] = json!("https://untrusted.example/alternate");
            document["registration_client_uri"] = json!("https://untrusted.example/registration");
            let body = document.to_string();
            let ((), admitted) = pair(reply(&peer, post, &body), client.credential(&cx)).await;
            let admitted = admitted.unwrap();
            assert_eq!(admitted.generation(), 1);
            assert_eq!(admitted.scopes(), ["read"]);
            assert_eq!(admitted.credential().resource(), client.resource());
            assert!(admitted.credential().authorization_for_target(&url("https://untrusted.example/alternate")).is_none());
            core_succeeds(&peer, &cx, &client, "admitted-access").await;
            assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
            assert_eq!(peer.rpcs.load(Ordering::SeqCst), 2);
            assert_eq!(peer.gets.load(Ordering::SeqCst), 2);
            assert!(cx.checkpoint().is_ok());
            client.close();
        });
    }
}

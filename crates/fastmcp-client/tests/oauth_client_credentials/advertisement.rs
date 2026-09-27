//! Optional machine-auth advertisements through the public TLS client.
//!
//! The parent supplies real issuer/resource discovery, Basic/Post grants and
//! explicitly scoped CA trust. No credentials or response owners are injected.
//! Peers script protocol replies: this is not native-server or issuer qualification.

use super::*;

const TOKEN: &str = "optional-advertisement-access";

fn run_machine<F, Fut>(post: bool, scenario: F)
where
    F: FnOnce(Cx, Peer, ClientCredentialsClient) -> Fut,
    Fut: Future<Output = ()>,
{
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap())
        .build().unwrap().block_on(async move {
            let cx = Cx::current().unwrap();
            let deadline = cx.now().saturating_add_nanos(30_000_000_000);
            asupersync::time::timeout_at(deadline, Box::pin(async {
                let peer = Peer::new().await;
                let mut plan = peer.plan(Duration::from_secs(10));
                let client = if post {
                    plan = plan.with_secret_authentication(ClientSecretAuthenticationMethod::Post).unwrap();
                    let ((), client) = pair(post_metadata(&peer, PostCase::Lifecycle), plan.discover(&cx)).await;
                    let client = client.unwrap();
                    let ((), token) = pair(post_grant(&peer, "service-client", "service-secret", TOKEN, 300),
                        client.credential(&cx)).await;
                    assert_eq!(token.unwrap().generation(), 1);
                    client
                } else {
                    let ((), client) = pair(peer.metadata(Case::Complete), plan.discover(&cx)).await;
                    let client = client.unwrap();
                    acquire(&peer, &cx, &client, TOKEN, 300).await;
                    client
                };
                scenario(cx, peer, client).await;
            })).await.expect("optional-advertisement TLS case must settle");
        });
}

fn discovery_document(capabilities: Value) -> String {
    json!({"resultType":"complete","supportedVersions":["2026-07-28"],
        "capabilities":capabilities,"ttlMs":0,"cacheScope":"private"}).to_string()
}

async fn operation(peer: &Peer, id: i64, capabilities: Value, method: &str, result: &str) {
    peer.discovery(id, TOKEN, &discovery_document(capabilities)).await;
    json_reply(&mut peer.rpc(id + 1, method, TOKEN).await, &terminal(id + 1, result)).await;
}

#[test]
fn absent_and_exact_machine_advertisements_both_allow_authenticated_core_calls() {
    for post in [false, true] {
        run_machine(post, |cx, peer, client| async move {
            for (index, capabilities) in [json!({}), json!({"extensions":{}}),
                json!({"extensions":{CLIENT_CREDENTIALS_EXTENSION:{}}}),
                json!({"extensions":{"com.example/independent":{}}})].into_iter().enumerate()
            {
                let id = 1 + 2 * index as i64;
                let request = core("tools/call");
                let before = request.encode_params().unwrap();
                let ((), response) = pair(operation(&peer, id, capabilities, "tools/call", CALL),
                    client.execute_core(&cx, request.clone(), RequestId::Number(id), RequestId::Number(id + 1))).await;
                let response = response.unwrap();
                assert_eq!(response.credential_generation(), 1);
                let result = response.read_json_result(&cx, 4096).await.unwrap();
                assert!(matches!(&result, CoreResult::Final(FinalCoreResult::ToolsCall { .. })));
                assert!(result.encode().unwrap().contains("1.20e+4"));
                assert_eq!(request.encode_params().unwrap(), before);
                peer.quiet();
            }
            assert_eq!(peer.gets.load(Ordering::SeqCst), 2);
            assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
            assert_eq!(peer.rpcs.load(Ordering::SeqCst), 8);
            assert!(cx.checkpoint().is_ok());
            client.close();
        });
    }
}

#[test]
fn earlier_machine_admission_cannot_hide_a_later_malformed_advertisement() {
    for post in [false, true] {
        run_machine(post, |cx, peer, client| async move {
            let ((), admitted) = pair(operation(&peer, 1, json!({}), "tools/call", CALL),
                client.execute_core(&cx, core("tools/call"), RequestId::Number(1), RequestId::Number(2))).await;
            assert!(admitted.unwrap().read_json_result(&cx, 4096).await.is_ok());
            let bad = [json!({"extensions":null}), json!({"extensions":[]}),
                json!({"extensions":{CLIENT_CREDENTIALS_EXTENSION:null}}),
                json!({"extensions":{CLIENT_CREDENTIALS_EXTENSION:{"enabled":true}}})];
            for (index, capabilities) in bad.into_iter().enumerate() {
                let id = 3 + 2 * index as i64;
                let document = discovery_document(capabilities);
                let ((), refused) = pair(peer.discovery(id, TOKEN, &document), client.execute_core(
                    &cx, core("tools/call"), RequestId::Number(id), RequestId::Number(id + 1),
                )).await;
                assert!(matches!(refused, Err(Error::Negotiation)));
                assert_eq!(peer.rpcs.load(Ordering::SeqCst), 3 + index,
                    "malformed current discovery must not dispatch the operation");
                peer.quiet();
            }
            let ((), admitted) = pair(operation(&peer, 11, json!({"extensions":{}}), "tools/call", CALL),
                client.execute_core(&cx, core("tools/call"), RequestId::Number(11), RequestId::Number(12))).await;
            assert!(admitted.unwrap().read_json_result(&cx, 4096).await.is_ok());
            assert_eq!(peer.rpcs.load(Ordering::SeqCst), 8);
            assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
            assert_eq!(client.credential(&cx).await.unwrap().generation(), 1);
            peer.quiet();
            client.close();
        });
    }
}

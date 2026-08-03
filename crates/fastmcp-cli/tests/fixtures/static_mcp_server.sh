#!/bin/sh

# Deterministic stdio MCP peer for CLI integration tests. Keeping this fixture
# independent of Cargo makes targeted `fastmcp-cli` tests hermetic on a cold
# build worker while still exercising the real subprocess and JSON-RPC paths.

respond() {
    printf '{"jsonrpc":"2.0","id":%s,"result":%s}\n' "$request_id" "$1"
}

respond_method_not_found() {
    printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"Method not found"}}\n' "$request_id"
}

while IFS= read -r request; do
    case "$request" in
        *'"id":'*)
            # JsonRpcRequest serializes its envelope ID last. Use the final
            # occurrence, then require the exact final unsigned-numeric shape
            # emitted by this client. A notification containing a nested
            # params.id must not be mistaken for a request.
            request_id=${request##*'"id":'}
            request_id=${request_id%\}}
            case "$request_id" in
                '' | *[!0-9]*) continue ;;
            esac
            ;;
        *)
            # JSON-RPC notifications never receive a response.
            continue
            ;;
    esac

    case "$request" in
        *'"method":"initialize"'*)
            respond '{"protocolVersion":"2024-11-05","capabilities":{"tools":{},"resources":{},"prompts":{}},"serverInfo":{"name":"echo-server","version":"1.0.0"}}'
            ;;
        *'"method":"ping"'*)
            respond '{}'
            ;;
        *'"method":"tools/list"'*)
            respond '{"tools":[{"name":"echo","description":"Echo the input message back.","inputSchema":{"type":"object"}},{"name":"add","description":"Calculate the sum of two numbers","inputSchema":{"type":"object"}},{"name":"reverse","description":"Reverse a string.","inputSchema":{"type":"object"}},{"name":"word_count","description":"Count the number of words in text","inputSchema":{"type":"object"}}]}'
            ;;
        *'"method":"resources/list"'*)
            respond '{"resources":[{"uri":"info://server","name":"server_info"},{"uri":"info://time","name":"Current Time"}]}'
            ;;
        *'"method":"resources/templates/list"'*)
            respond '{"resourceTemplates":[]}'
            ;;
        *'"method":"prompts/list"'*)
            respond '{"prompts":[{"name":"greeting","description":"Generate a friendly greeting"},{"name":"review_code","description":"A code review prompt."}]}'
            ;;
        *)
            respond_method_not_found
            ;;
    esac
done

use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, shell::ShellTask, tng::TngInstance, NodeType, Task as _},
};

/// End-to-end test for the Python SDK (sync `tng.Transport` and async `tng.AsyncTransport`).
///
/// The Python SDK acts as the ingress — it calls `OHttpSecurityLayer::forward_http_request()`
/// directly, encrypts via OHTTP, and sends to the TNG egress which decrypts and forwards
/// to the backend.
///
/// Topology:
///   Python (client netns) --OHTTP--> TNG Egress (server netns :20001) --> Backend (server netns :30001)
///
/// Prerequisites (run from the repo root before `cargo test`):
///   ```sh
///   python3 -m venv .venv
///   .venv/bin/pip install maturin httpx
///   cd tng-python && ../.venv/bin/maturin develop
///   ```
///
/// Run with: `cargo test -p tng-testsuite --features python-sdk --test python_sdk`
#[cfg(feature = "python-sdk")]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
#[serial]
async fn test_python_sdk() -> Result<()> {
    run_test(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "mapping": {
                            "in": {
                                "host": "0.0.0.0",
                                "port": 20001
                            },
                            "out": {
                                "host": "127.0.0.1",
                                "port": 30001
                            }
                        },
                        "ohttp": {},
                        "no_ra": true
                    }
                ]
            }
            "#,
        )
        .boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "192.168.1.1:20001",
            expected_path_and_query: "/test?q=1",
        }
        .boxed(),
        ShellTask {
            name: "python_sdk_test".to_owned(),
            node_type: NodeType::Client,
            script: concat!(env!("CARGO_MANIFEST_DIR"), r#"/../.venv/bin/python3 -c '
import asyncio
import cohere_tng as tng
import httpx

URL = "http://192.168.1.1:20001/test?q=1"
BIG = b"x" * 200_000

# --- Sync Transport ---

transport = tng.Transport(verify=None)
with httpx.Client(transport=transport) as client:
    resp = client.get(URL)
    assert resp.status_code == 200
    assert resp.read() == b"Hello World HTTP!"
    resp.close()
    print("PASS: sync buffered GET")

    with client.stream("GET", URL) as resp:
        assert resp.status_code == 200
        body = b"".join(resp.iter_bytes())
        assert body == b"Hello World HTTP!"
    print("PASS: sync response streaming GET")

    resp = client.post(URL, content=b"echo me")
    assert resp.read() == b"echo me"
    resp.close()
    print("PASS: sync POST echo")

    resp = client.post(URL, content=(c for c in [b"chunk1", b"chunk2", b"chunk3"]))
    assert resp.read() == b"chunk1chunk2chunk3"
    resp.close()
    print("PASS: sync streaming POST echo")

    with client.stream("POST", URL, content=(BIG[i:i+1000] for i in range(0, len(BIG), 1000))) as resp:
        chunks = list(resp.iter_bytes())
        assert len(chunks) > 1, f"expected chunked response, got {len(chunks)} chunk(s)"
        assert b"".join(chunks) == BIG
    print(f"PASS: sync large streaming POST echo (200KB, {len(chunks)} chunks)")

# --- Async Transport ---

async def async_tests():
    transport = tng.AsyncTransport(verify=None)
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await client.get(URL)
        assert resp.status_code == 200
        assert resp.text == "Hello World HTTP!"
        print("PASS: async buffered GET")

        async with client.stream("GET", URL) as resp:
            assert resp.status_code == 200
            body = b"".join([c async for c in resp.aiter_bytes()])
            assert body == b"Hello World HTTP!"
        print("PASS: async response streaming GET")

        resp = await client.post(URL, content=b"echo me")
        assert resp.read() == b"echo me"
        print("PASS: async POST echo")

        async def chunks():
            for c in [b"chunk1", b"chunk2", b"chunk3"]:
                yield c
        resp = await client.post(URL, content=chunks())
        assert resp.read() == b"chunk1chunk2chunk3"
        print("PASS: async streaming POST echo")

        big = BIG
        async def big_chunks():
            for i in range(0, len(big), 1000):
                yield big[i:i+1000]
        async with client.stream("POST", URL, content=big_chunks()) as resp:
            chunks = [c async for c in resp.aiter_bytes()]
            assert len(chunks) > 1, f"expected chunked response, got {len(chunks)} chunk(s)"
            assert b"".join(chunks) == big
        print(f"PASS: async large streaming POST echo (200KB, {len(chunks)} chunks)")

asyncio.run(async_tests())

print("SUCCESS: all Python SDK tests passed")
'
            "#)
            .to_owned(),
            stop_test_on_finish: true,
            run_in_foreground: false,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

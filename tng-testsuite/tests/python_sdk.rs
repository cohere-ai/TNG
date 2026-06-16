use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, shell::ShellTask, tng::TngInstance, NodeType, Task as _},
};

/// End-to-end test for the Python SDK (`tng.Transport`).
///
/// The Python SDK acts as the ingress — it calls `OHttpSecurityLayer::forward_http_request()`
/// directly, encrypts via OHTTP, and sends to the TNG egress which decrypts and forwards
/// to the backend.
///
/// Topology:
///   Python (client netns) --OHTTP--> TNG Egress (server netns :20001) --> Backend (server netns :30001)
///
/// Prerequisites (run before `cargo test`):
///   ```sh
///   cd tng-python
///   python3 -m venv .venv
///   .venv/bin/pip install maturin httpx
///   .venv/bin/maturin develop
///   ```
///
/// Run with: `cargo test -p tng-testsuite --features python-sdk --test python_sdk`
#[cfg(feature = "python-sdk")]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
#[serial]
async fn test_python_sdk_sync() -> Result<()> {
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
            name: "python_sdk_sync_test".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                cd ../tng-python
                .venv/bin/python3 -c '
import tng
import httpx
import sys

url = "http://192.168.1.1:20001/test?q=1"
transport = tng.Transport(verify=None)
with httpx.Client(transport=transport) as client:
    resp = client.get(url)
    assert resp.status_code == 200
    assert resp.read() == b"Hello World HTTP!"
    resp.close()
    print("PASS: buffered GET")

    with client.stream("GET", url) as resp:
        assert resp.status_code == 200
        body = b"".join(resp.iter_bytes())
        assert body == b"Hello World HTTP!"
    print("PASS: response streaming GET")

    resp = client.post(url, content=b"hello from python")
    assert resp.read() == b"hello from python"
    resp.close()
    print("PASS: POST with body echo")

    resp = client.post(url, content=(c for c in [b"chunk1", b"chunk2", b"chunk3"]))
    assert resp.read() == b"chunk1chunk2chunk3"
    resp.close()
    print("PASS: request streaming POST echo")

    big = b"x" * 200_000
    resp = client.post(url, content=(big[i:i+1000] for i in range(0, len(big), 1000)))
    assert resp.read() == big
    resp.close()
    print("PASS: large streaming POST echo (200KB)")

print("SUCCESS: all sync Python SDK tests passed")
'
            "#
            .to_owned(),
            stop_test_on_finish: true,
            run_in_foreground: false,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Async transport test using `tng.AsyncTransport` with `httpx.AsyncClient`.
#[cfg(feature = "python-sdk")]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
#[serial]
async fn test_python_sdk_async() -> Result<()> {
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
            name: "python_sdk_async_test".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                cd ../tng-python
                .venv/bin/python3 -c '
import asyncio
import tng
import httpx

async def main():
    url = "http://192.168.1.1:20001/test?q=1"
    transport = tng.AsyncTransport(verify=None)
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await client.get(url)
        assert resp.status_code == 200
        assert resp.text == "Hello World HTTP!"
        print("PASS: async buffered GET")

        async with client.stream("GET", url) as resp:
            assert resp.status_code == 200
            body = b"".join([c async for c in resp.aiter_bytes()])
            assert body == b"Hello World HTTP!"
        print("PASS: async response streaming GET")

        resp = await client.post(url, content=b"hello from python")
        assert resp.read() == b"hello from python"
        print("PASS: async POST with body echo")

        async def chunks():
            for c in [b"chunk1", b"chunk2", b"chunk3"]:
                yield c
        resp = await client.post(url, content=chunks())
        assert resp.read() == b"chunk1chunk2chunk3"
        print("PASS: async request streaming POST echo")

        big = b"x" * 200_000
        async def big_chunks():
            for i in range(0, len(big), 1000):
                yield big[i:i+1000]
        resp = await client.post(url, content=big_chunks())
        assert resp.read() == big
        print("PASS: async large streaming POST echo (200KB)")

    print("SUCCESS: all async Python SDK tests passed")

asyncio.run(main())
'
            "#
            .to_owned(),
            stop_test_on_finish: true,
            run_in_foreground: false,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

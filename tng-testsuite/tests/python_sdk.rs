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

transport = tng.Transport(verify=None)
with httpx.Client(transport=transport) as client:
    for i in range(3):
        try:
            resp = client.get("http://192.168.1.1:20001/test?q=1")
            body = resp.read()
            resp.close()
            print(f"Request {i}: status={resp.status_code} body={body}", flush=True)
            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        except Exception as e:
            print(f"Request {i}: FAILED with {e}", file=sys.stderr, flush=True)
            raise

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
    transport = tng.AsyncTransport(verify=None)
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await client.get("http://192.168.1.1:20001/test?q=1")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert resp.text == "Hello World HTTP!", f"Unexpected body: {resp.text}"
        print("PASS: async GET")

        async with client.stream("GET", "http://192.168.1.1:20001/test?q=1") as resp:
            assert resp.status_code == 200, f"Stream expected 200, got {resp.status_code}"
            chunks = []
            async for chunk in resp.aiter_bytes():
                chunks.append(chunk)
            assert len(chunks) > 0, "No chunks received"
            full_body = b"".join(chunks).decode()
            assert full_body == "Hello World HTTP!", f"Unexpected stream body: {full_body}"
            print("PASS: async streaming GET")

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

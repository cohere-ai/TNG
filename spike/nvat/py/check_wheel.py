"""Run both verifications from the installed nvat-spike wheel and compare them with what the
nvat-spike-verify binary produced for the same library (out/<mode>.json, from check.sh)."""

import json
import os
import pathlib
import sys

import nvat_spike

spike = pathlib.Path(__file__).resolve().parent.parent
out = spike / "out"
nonce = "87d8e24ab336adafe228d49e83d745f6dba4ae505372b6a5704820856b343fec"
print("module:", nvat_spike.__file__)
# Name the system CA bundle the same way check.sh had to for this build.
if (out / "ca").read_text().strip() != "default":
    os.environ["NVAT_SPIKE_TLS_CA_CERT"] = "auto"

status = 0
for mode in ("remote", "local"):
    got = json.loads(
        nvat_spike.verify(mode, str(out / "report.txt"), str(spike / "testdata/hopper_coco_certs1.txt"), nonce)
    )
    want = json.loads((out / f"{mode}.json").read_text())
    if got == want:
        print(f"ok   {mode} from the wheel: success={got['success']}, same claims as the binary")
    else:
        print(f"FAIL {mode} from the wheel differs from the binary:")
        print(json.dumps(got, indent=2, sort_keys=True))
        status = 1
sys.exit(status)

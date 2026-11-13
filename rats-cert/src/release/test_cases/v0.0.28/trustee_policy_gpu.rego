# Trustee GPU appraisal policy.
#
# Written for the REMOTE verifier (NRAS).
#
# The local verifier emits a much thinner claim set (arch, uuid,
# measurements, config) and compares nothing against NVIDIA's reference
# integrity manifests, which would leave the RIM values to be transcribed
# into Rego/RVPS and re-transcribed on every driver and VBIOS update. NRAS
# does that comparison against NVIDIA's signed RIMs and reports the verdict, 
# so the claims below are appraisals rather than raw measurements.
#
# Claims are NVIDIA's EAT payload passed through verbatim (nras_response.rs),
# one device per appraisal, plus x-nvidia-overall-att-result lifted from the
# JWT. The same claims (claims 3.0 on /v4) are featured in ITA policy but in
# a different envelope: flat under input.nvidia rather than nested per
# device under input.nvgpu.claim_details.
#
# Flat because Trustee sends one device per NRAS request and rejects a
# response carrying more than one detached EAT. A multi-GPU node is handled
# a layer up instead, where the broker raises one appraisal per device and
# runs this same file against each, so nothing here needs to iterate.


package policy

import rego.v1

# AR4SI defaults. rats-cert treats 2..=31 as affirming, so these deny.
# 33: "Runtime memory includes executables ... which are not recognized."
default executables := 33

# 97: "A Verifier does not recognize an Attester's hardware or firmware."
default hardware := 97

# 36: "Elements of the configuration relevant to security are unavailable."
default configuration := 36

# 0 is "no assertion" for the dimensions this policy does not speak to.
default file_system := 0

default instance_identity := 0

default runtime_opaque := 0

default storage_opaque := 0

default sourced_data := 0

trust_claims := {
	"executables": executables,
	"hardware": hardware,
	"configuration": configuration,
	"file-system": file_system,
	"instance-identity": instance_identity,
	"runtime-opaque": runtime_opaque,
	"storage-opaque": storage_opaque,
	"sourced-data": sourced_data,
}

extensions := [
	{
		"name": "cohere.policy-version",
		"key": -72000,
		"value": "v0.0.28",
	},
]

gpu := input.nvidia

# One entry per distinct driver version across the manifest's PodVM images.
# An empty set denies, since indexing it is undefined.
accepted_gpu_driver_versions := {
	"580.178.04",
}

# 2: "An Attester has passed its hardware and/or firmware verifications
#     needed to demonstrate that these are genuine/supported."
hardware := 2 if {
	gpu

	# The report parsed, is signed by the device, and the signature verifies.
	gpu["x-nvidia-gpu-attestation-report-parsed"] == true
	gpu["x-nvidia-gpu-attestation-report-signature-verified"] == true

	# The signing certificate chains to NVIDIA's root and is not revoked.
	gpu["x-nvidia-gpu-attestation-report-cert-chain"]["x-nvidia-cert-status"] == "valid"
	gpu["x-nvidia-gpu-attestation-report-cert-chain"]["x-nvidia-cert-ocsp-status"] == "good"

	# The certificate's fwid matches the one in the report, binding the
	# certificate to this specific device in this specific firmware state.
	gpu["x-nvidia-gpu-attestation-report-cert-chain-fwid-match"] == true

	# Freshness: the report answers the nonce from this handshake, so a
	# captured report cannot be replayed.
	gpu["x-nvidia-gpu-attestation-report-nonce-match"] == true

	# The device really is the architecture it claims. Remote NRAS reports
	# the model as "GH100".
	gpu["x-nvidia-gpu-arch-check"] == true
	gpu.hwmodel == "GH100"
}

# 3: "Only a recognized genuine set of approved executables have been
#     loaded."
executables := 3 if {
	rims_verified

	# The comparison itself came out clean.
	gpu.measres == "success"
	gpu["x-nvidia-overall-att-result"] == true
}

executables := 3 if {
	rims_verified
	firmware_mismatch_waived
}

# NRAS compared the device's measurements against the driver and VBIOS
# RIMs. Each RIM has to have been fetched, schema checked, signed by a
# chain that is neither invalid nor revoked, matched to the running
# version, and actually carry measurements, otherwise the verdict on the
# comparison would be vacuous.
rims_verified if {
	gpu

	gpu["x-nvidia-gpu-driver-rim-fetched"] == true
	gpu["x-nvidia-gpu-driver-rim-measurements-available"] == true
	gpu["x-nvidia-gpu-driver-rim-schema-validated"] == true
	gpu["x-nvidia-gpu-driver-rim-signature-verified"] == true
	gpu["x-nvidia-gpu-driver-rim-version-match"] == true
	gpu["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-status"] == "valid"
	gpu["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-ocsp-status"] == "good"

	gpu["x-nvidia-gpu-vbios-rim-fetched"] == true
	gpu["x-nvidia-gpu-vbios-rim-measurements-available"] == true
	gpu["x-nvidia-gpu-vbios-rim-schema-validated"] == true
	gpu["x-nvidia-gpu-vbios-rim-signature-verified"] == true
	gpu["x-nvidia-gpu-vbios-rim-version-match"] == true
	gpu["x-nvidia-gpu-vbios-rim-cert-chain"]["x-nvidia-cert-status"] == "valid"
	gpu["x-nvidia-gpu-vbios-rim-cert-chain"]["x-nvidia-cert-ocsp-status"] == "good"
}

# 2: "The configuration is a known and approved config."
#
# No fallback tier: a driver version outside the set denies.
#
# The VBIOS version is neither pinned nor floored. The vbios-rim checks above
# prove the running VBIOS matches NVIDIA's signed RIM for whatever version it
# is, and NVIDIA retires a version found vulnerable by revoking that RIM's
# signing certificate, which the OCSP check already catches. A floor would add
# little beyond that and could not be maintained anyway as NRAS claims identify 
# no VM SKU or cloud to scope one by.
configuration := 2 if {
	gpu
	device_locked_down

	# NRAS reports the upstream driver version, without the Ubuntu packaging
	# suffix that measurements.json records.
	gpu["x-nvidia-gpu-driver-version"] in accepted_gpu_driver_versions
}

# Secure boot on and debug off: without both, the measurements above say
# nothing about what the device will do next.
device_locked_down if {
	gpu.secboot == true
	gpu.dbgstat == "disabled"
}

# NVIDIA's verifiers do not read these from the device: they emit both only
# when measres is "success" and omit them otherwise. Under the waiver their
# absence is accepted, but never a reported bad value.
device_locked_down if {
	firmware_mismatch_waived
	not "secboot" in object.keys(gpu)
	not "dbgstat" in object.keys(gpu)
}

# Narrow workaround for a deterministic firmware mismatch on Azure H100
# peer pods, the same index ITA policy waives on GCP with differing values:
# https://github.com/NVIDIA/nvtrust/issues/132
firmware_mismatch_waived if {
	gpu["x-nvidia-overall-att-result"] == false
	{"fail", "comparison-fail"}[gpu.measres]

	records := gpu["x-nvidia-mismatch-measurement-records"]
	count(records) == 1
	record := records[0]
	record.index == 9
	record.measurementSource == "Firmware"
	record.goldenSize == 48
	record.goldenValue == "059b32e712a153f490dbfb7976a9e275d789e28bd4803c357def2b6123327c430526bfaecc200f496d4e149fc5eade03"
	record.runtimeSize == 48
	record.runtimeValue == "a88ad47656c234338b2bc2055d04d61e07f08f2deecab303f2f7309fdeae239728d4ec1fa0279eb36c6ab782a289bdbd"
}

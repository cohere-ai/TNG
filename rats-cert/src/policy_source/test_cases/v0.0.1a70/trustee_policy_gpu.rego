# WARNING: this policy pins no NVIDIA driver version, because no manifest target
# reached it. Every generated section is empty, so it admits nothing.

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

gpu := input.nvidia

# One entry per distinct driver version across the manifest's PodVM images.
# An empty set denies, since indexing it is undefined.
accepted_gpu_driver_versions := {

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
	gpu

	# NRAS compared the device's measurements against the driver and VBIOS
	# RIMs. Each RIM has to have been fetched, schema checked, signed by a
	# chain that is neither invalid nor revoked, matched to the running
	# version, and actually carry measurements, otherwise "success" below
	# would be vacuous.
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

	# The comparison itself came out clean.
	gpu.measres == "success"
	gpu["x-nvidia-overall-att-result"] == true
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

	# Secure boot on and debug off: without both, the measurements above say
	# nothing about what the device will do next.
	gpu.secboot == true
	gpu.dbgstat == "disabled"

	# NRAS reports the upstream driver version, without the Ubuntu packaging
	# suffix that measurements.json records.
	gpu["x-nvidia-gpu-driver-version"] in accepted_gpu_driver_versions
}

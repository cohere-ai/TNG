package policy

import rego.v1

# TNG appraisal policy for NVIDIA GPUs verified by the in-process local verifier.
#
# This policy exists because the upstream default GPU policy cannot be used here. That policy
# reads `x-nvidia-*` verdict claims, which are produced by NVIDIA's remote attestation service
# (NRAS). The local verifier does not call NRAS and never emits them, so under the default policy
# a perfectly good GPU is always contraindicated. The claims available locally are the parsed
# attestation report itself -- architecture, configuration and the raw measurement slots -- so the
# RIM comparison NRAS would have done has to happen here instead.
#
# The local verifier only produces claims at all once it has checked the SPDM report signature,
# the device certificate chain up to NVIDIA's root, and that the report is bound to our nonce.
# Those properties are therefore preconditions of this policy rather than things it re-checks.
#
# Claim values follow AR4SI, where 2..31 is affirming, 32..95 is warning and 96..127 is
# contraindicated. Every claim must be affirming for the submodule to be accepted.

default hardware := 97

default executables := 33

default configuration := 36

default file_system := 0

default instance_identity := 0

default runtime_opaque := 0

default storage_opaque := 0

default sourced_data := 0

# The golden maps are keyed by version, and each version maps a measurement index to the values
# the RIM permits at that index. An index legitimately has several acceptable values, so each
# entry is a list rather than a single digest.
#
# Fail-closed follows from the shape: an unknown driver or VBIOS version makes the lookup
# undefined and the rule fails, so there is no allowlist to forget to prune when a version is
# withdrawn. An empty map rejects everything.
#
# The generator must wrap these maps across lines. Regorus refuses to parse a source line longer
# than 1024 characters, and a single version's measurements serialized onto one line exceeds that
# on its own.

# BEGIN GENERATED driver_golden
driver_golden := {}

# END GENERATED driver_golden

# BEGIN GENERATED vbios_golden
vbios_golden := {}

# END GENERATED vbios_golden

# An index present in the RIM but absent or zeroed in the report must not pass. Comparing in this
# direction -- over the golden indices rather than the reported ones -- means an unmeasured slot
# fails the membership test instead of being skipped.
measurements_match(expected) if {
	count(expected) > 0
	every index, allowed in expected {
		input.nvidia.measurements[index] in allowed
	}
}

# Hopper is the only architecture whose golden values are currently published. Adding Blackwell
# is a matter of generating its maps, but it should not pass silently before then.
hardware := 2 if {
	input.nvidia

	input.nvidia.arch == "Hopper"
}

executables := 3 if {
	input.nvidia

	measurements_match(driver_golden[input.nvidia.config.driver_version])
	measurements_match(vbios_golden[input.nvidia.config.vbios_version])
}

# Secure boot and debug status are NRAS verdict claims and are not available locally, so the
# configuration assertion is narrower than the upstream policy's: it states that the driver and
# VBIOS versions in the report are ones we publish golden values for. That is a real statement
# about the configuration, and it is the strongest one the local claims support.
configuration := 2 if {
	input.nvidia

	driver_golden[input.nvidia.config.driver_version]
	vbios_golden[input.nvidia.config.vbios_version]
}

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

package policy

import rego.v1

# TNG appraisal policy for Azure SEV-SNP confidential VMs.
#
# Golden values are inlined instead of being resolved with `query_reference_value`. TNG runs the
# attestation service in-process with an empty RVPS, so every reference-value lookup returns an
# empty set and every rule built on one fails. The block between the GENERATED markers is
# rewritten by CI from the measurement manifest; the rules below it are hand-maintained.
#
# Claim values follow AR4SI, where 2..31 is affirming, 32..95 is warning and 96..127 is
# contraindicated. A submodule is only accepted when every claim is affirming, so each claim this
# policy asserts has to be raised out of its default. Leaving one at its default is not a neutral
# "no opinion" -- it fails the appraisal.

default hardware := 97

default executables := 33

default configuration := 36

default file_system := 0

default instance_identity := 0

default runtime_opaque := 0

default storage_opaque := 0

default sourced_data := 0

# BEGIN GENERATED golden
# Every entry is an allowlist. An empty list matches nothing, so an ungenerated copy of this
# policy rejects all evidence rather than admitting it. The generator must wrap long lists across
# lines: regorus refuses to parse a source line longer than 1024 characters.
golden := {
	"measurement": [],
	"pcr11": [],
	"tcb_bootloader": [],
	"tcb_microcode": [],
	"tcb_snp": [],
	"tcb_tee": [],
	"smt_enabled": [],
	"tsme_enabled": [],
	"abi_major": [],
	"abi_minor": [],
	"single_socket": [],
	"smt_allowed": [],
}

# END GENERATED golden

# The launch measurement covers the guest image, and PCR11 binds the vTPM-recorded boot chain
# that continues past launch. Both are needed: the measurement alone says nothing about what the
# guest booted afterwards.
executables := 3 if {
	input["az-snp-vtpm"]

	input["az-snp-vtpm"].measurement in golden.measurement
	input["az-snp-vtpm"].tpm.pcr11 in golden.pcr11
}

# The reported TCB pins the AMD security processor firmware the report was produced under, which
# is what ties the launch measurement to a platform that has not been rolled back to a version
# with known escapes.
hardware := 2 if {
	input["az-snp-vtpm"]

	input["az-snp-vtpm"].reported_tcb_bootloader in golden.tcb_bootloader
	input["az-snp-vtpm"].reported_tcb_microcode in golden.tcb_microcode
	input["az-snp-vtpm"].reported_tcb_snp in golden.tcb_snp
	input["az-snp-vtpm"].reported_tcb_tee in golden.tcb_tee
}

# Guest policy and platform settings are generated rather than fixed here because they are
# deployment choices, not properties of a build.
configuration := 2 if {
	input["az-snp-vtpm"]

	input["az-snp-vtpm"].platform_smt_enabled in golden.smt_enabled
	input["az-snp-vtpm"].platform_tsme_enabled in golden.tsme_enabled
	input["az-snp-vtpm"].policy_abi_major in golden.abi_major
	input["az-snp-vtpm"].policy_abi_minor in golden.abi_minor
	input["az-snp-vtpm"].policy_single_socket in golden.single_socket
	input["az-snp-vtpm"].policy_smt_allowed in golden.smt_allowed
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

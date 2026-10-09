# WARNING: this policy pins no pod VM image, because no manifest target
# reached it. Every generated section is empty, so it admits nothing.

# Trustee CPU appraisal policy.
#

package policy

import rego.v1

# AR4SI defaults. rats-cert treats 2..=31 as affirming, so these deny.
# 33: "Runtime memory includes executables ... which are not recognized."
default executables := 33

# 97: "A Verifier does not recognize an Attester's hardware or firmware."
default hardware := 97

# 36: "Elements of the configuration relevant to security are unavailable."
default configuration := 36

# 0 is "no assertion" for the dimensions this policy does not speak to. For
# example, with Azure SEV-SNP, the dm-verity roothash claim reaches
# executables through PCR 9, so file-system stays silent.
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

##### Azure SEV-SNP (az-snp-vtpm)
#
# Every rule in this section is guarded on the attester key (azsnp), so a
# section for another attester can be appended without two of them assigning
# one dimension different values. Helpers are prefixed with the attester for
# the same reason.
#
# Claim shapes (deps/verifier/src/az_snp_vtpm/mod.rs). Getting one wrong fails
# open into a default:
#
#   - PCR keys are zero padded: pcr04, not pcr4.
#   - Booleans and integers alike arrive as STRINGS.
#   - measurement is STANDARD base64 of 48 bytes, not hex.
#   - report_data is the TPM quote's extraData rather than the SNP report
#     field of that name, and is nothing to pin: the AS has already checked it
#     against the runtime data its caller supplied.
#
azsnp := input["az-snp-vtpm"]

# Microsoft's paravisor as featured in the SNP launch measurement (base64
# of 48 bytes). The vTPM emulating the PCRs below runs inside that paravisor at
# VMPL 0, so without this pin anyone with SEV-SNP hardware could run their own
# VMPL 0 code and quote PCRs however they like.
#
# A set, so a firmware roll can be ridden out by adding the new value beside
# the old.
azsnp_paravisor_measurements := {
	"qnydpVwThuWxZTsSWXi+2ns/laha6w+d2723g84FaijJ0CHaI5w0pYw6ZXZUJw7v",
}

# Minimum AMD secure processor TCB. Greater or equal rather than exact, so a
# platform TCB roll forward is accepted while rollback is refused.
azsnp_min_tcb := {
	"bootloader": 10,
	"tee": 0,
	"snp": 23,
	"microcode": 84,
}

# When no match blocks are present, we default to a valid deny-only policy.
#
# The static rules below need no default. They always have a definition and
# merely evaluate to undefined when they do not match, which fails the
# enclosing body exactly as false would.
default azsnp_image_ok := false

default azsnp_initdata_ok := false

# Every claim arrives as a string, and Rego orders numbers before strings, so
# a bare `azsnp.reported_tcb_snp >= 23` is true for any string at all and
# fails open. to_number() required for correct interpretation.
azsnp_tcb_ok if {
	to_number(azsnp.reported_tcb_bootloader) >= azsnp_min_tcb.bootloader
	to_number(azsnp.reported_tcb_tee) >= azsnp_min_tcb.tee
	to_number(azsnp.reported_tcb_snp) >= azsnp_min_tcb.snp
	to_number(azsnp.reported_tcb_microcode) >= azsnp_min_tcb.microcode
}

# Guest policy bits set at SNP_LAUNCH_START.
#
# policy_smt_allowed only permits SMT and is true on our nodes today. What
# matters is whether the platform enables it, which azsnp_platform_ok pins.
azsnp_launch_policy_ok if {
	azsnp.policy_debug_allowed == "false"
	azsnp.policy_migrate_ma == "false"
}

# PLATFORM_INFO.
azsnp_platform_ok if {
	azsnp.platform_smt_enabled == "false"
}

# 3: "Only a recognized genuine set of approved executables have been loaded
#     during the boot process."
executables := 3 if {
	azsnp
	azsnp.measurement in azsnp_paravisor_measurements
	azsnp_image_ok
}

# 2: "An Attester has passed its hardware and/or firmware verifications
#     needed to demonstrate that these are genuine/supported."
hardware := 2 if {
	azsnp
	azsnp_tcb_ok
}

# 2: "The configuration is a known and approved config."
configuration := 2 if {
	azsnp
	azsnp_launch_policy_ok
	azsnp_platform_ok
	azsnp_initdata_ok
}

# One block per pod VM image, asserting all four registers together. They are
# all measured from the same image, so splitting them into separate rules
# would admit image A's UKI beside image B's partition table.
#
#   PCR 4   The firmware's boot chain: EV_EFI_ACTION, a separator, then
#           Authenticode over the whole UKI and over its .linux section
#           loaded as its own PE. The only measurement of systemd-stub
#           itself.
#   PCR 5   The GPT partition table.
#   PCR 9   The kernel command line the EFI stub passed as LoadOptions and
#           the .ucode||.initrd blob it handed the kernel. The dm-verity
#           roothash= lives on that command line, so this transitively pins
#           the whole root filesystem.
#   PCR 11  systemd-stub's measurement of every UKI section it recognises,
#           name then content. The OS image identity.


# One block per deployment initdata, which carries the configuration for guest
# components such as Kata agent and the KBS. Read through input.init_data
# rather than tpm.pcr08: the two are byte-identical here, since extend_claim
# overwrites init_data with hex of PCR 8, but the named claim reads as an
# initdata binding instead of an opaque register compare.
#
# The value is sha256(0x00 * 32 || initdata_digest[:32]). A digest wider than
# the register is truncated to fit rather than re-hashed, so the usual sha384
# initdata gives sha256(0 || sha384(toml)[:32]) and not sha256(0 ||
# sha256(toml)).
#
# Kept separate from the image blocks, so any approved image pairs with any
# approved initdata.


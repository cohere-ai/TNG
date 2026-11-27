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

extensions := [
	{
		"name": "cohere.policy-version",
		"key": -72000,
		"value": "v0.0.27",
	},
]

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
#   - report_data is the TPM quote's extraData rather than the SNP report
#     field of that name, and is nothing to pin: the AS has already checked it
#     against the runtime data its caller supplied.
#
azsnp := input["az-snp-vtpm"]

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
# PodVM image: podvm-ubuntu-release-0-3-1-cohere-2
azsnp_image_ok if {
	azsnp.tpm.pcr04 == "c81e723165b9348294745f055fb847c593426fbea1a6a4a838d8af9467e735e7"
	azsnp.tpm.pcr05 == "a760f18e9d7212274e2c79c2fad269e7612f5e4dcb3350e25401bc5059400f6a"
	azsnp.tpm.pcr09 == "fefebec2c4cab703e65f7f4573fa770d253a9c037cb6dfbf0a69dfa2d7b59239"
	azsnp.tpm.pcr11 == "6ba4e8eb0c0a9149f3f2b290cce3966e8aea60885dd7d687a6fae4acd99c427c"
}

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
# Model: e4-l-azure (Initdata: 82effb84018e)
azsnp_initdata_ok if {
	input.init_data == "19fd771993d91dfceec91e0ad4c15dbc2bde979b06f3b006ffb61dad03eca474"
}

# Model: e5f-l-azure (Initdata: 95f5af0c6d74)
azsnp_initdata_ok if {
	input.init_data == "ec5eaa2574f2f2c4da5776f255f7f51de913b28328bdee2c3e01fc701d5d5899"
}

# Model: e5p-l-azure (Initdata: 118b83fb2908)
azsnp_initdata_ok if {
	input.init_data == "b5c12bd9b4d66038e1e2ca0561ad1f378a405d8ab397d0e42261a859495b25c5"
}

# Model: r4f-l-azure (Initdata: 47d35967f401)
azsnp_initdata_ok if {
	input.init_data == "bd2a4d2b2bac64f68caf26014505b9b3a305a595fb505b0a145c68f2afb833f2"
}

# Model: r4p-l-azure (Initdata: 293d60834772)
azsnp_initdata_ok if {
	input.init_data == "8328a785aa7def2807fe6e8dfe19596da7339176d874f2dd966fe4430e848bbe"
}

# Model: r5f-l-azure (Initdata: 21d0a18fc6f9)
azsnp_initdata_ok if {
	input.init_data == "ece7c7275d4d76ba80571d0d7a7134882738cdf61274ea600bd8c0184cf6d15e"
}

# Model: r5p-l-azure (Initdata: 56af2db99c6b)
azsnp_initdata_ok if {
	input.init_data == "0a5cbba7230c9d491d1ddbdf1849c43f73cde297d790b5b2594f39f9a382ba59"
}

# Model: cvp4-l-azure (Initdata: c0a709aafeba)
azsnp_initdata_ok if {
	input.init_data == "26060df85533130d1e26e085977526474dd32093d88ac2b5627dd6bdbd372d37"
}

# Model: cat2508rws-l-azure (Initdata: 47b0d05f6b71)
azsnp_initdata_ok if {
	input.init_data == "8384342bfedd851fe49d8e631761875069bb7f8f844ff445c618e92c0b77eb36"
}

# Model: cmp-l-azure (Initdata: 7192ca681cb4)
azsnp_initdata_ok if {
	input.init_data == "d4c3168f86ea7e749c9a2d85278999e411f4b566c9127d60bae8de09a4190efe"
}

# Model: nmc2606-l-azure (Initdata: e16afc3ad480)
azsnp_initdata_ok if {
	input.init_data == "cd213a64a4b8ba75383dfe6a32d685162cb59f3ed5edaafc0cb43c63a14199d7"
}

# Model: qw3-4b-l-azure (Initdata: 0ab55b51ef42)
azsnp_initdata_ok if {
	input.init_data == "f77c8b274d4e376ded47b73e7141ec1556676c421109984e0ef9e733b51f8002"
}

# Model: qw3-5-4b-l-azure (Initdata: 78b2ccd6f3e6)
azsnp_initdata_ok if {
	input.init_data == "deecfdfc54ba661a08d0036860e683a5aeca689c149aef91967c8d20aa7b61bf"
}

# Model: qw3-5-35b-a3b-l-azure (Initdata: ba16776520e2)
azsnp_initdata_ok if {
	input.init_data == "614cfab34c6a040933c69ff826bc66a8aaf411f0766ab14f345ce40898f6c557"
}

# Model: qw36-27b-l-azure (Initdata: 7b3d5acb4be2)
azsnp_initdata_ok if {
	input.init_data == "610687ef0db7593d382e31bf562d4808af266e321f7b5df59829461157a1a81f"
}

# Model: qw38-27b-l-azure (Initdata: 7bb8b81c1521)
azsnp_initdata_ok if {
	input.init_data == "8824cba70259d8d93f33a0a0a1d2918e9ed40912a0e859b76d1a9228b27350dd"
}

# Model: mstr3-3b-r-l-azure (Initdata: cfc28a76aa6a)
azsnp_initdata_ok if {
	input.init_data == "c43db16b4518886512859e52ee92403adaa4e734ccff5a35f4f5474358724915"
}

# Model: dvs2-24b-l-azure (Initdata: ba6bf4ae6bbc)
azsnp_initdata_ok if {
	input.init_data == "4383443823be4defb07f506b3dacc1fb7dce3d463c35150d94b4149c13fd21cc"
}

# Model: phi4m-l-azure (Initdata: da84ede12496)
azsnp_initdata_ok if {
	input.init_data == "44a023a53c714d7332a3241f3feb108fa67c9f880fc82a4b41061cee608e79ac"
}

# Model: gm4-26b-a4b-l-azure (Initdata: d369cdca251d)
azsnp_initdata_ok if {
	input.init_data == "b38d13606cde1250aac55956d6d2004bf4f8501279c3876cf041bfc77592aefa"
}

# Model: gptoss20b-l-azure (Initdata: 2a87a2b2b307)
azsnp_initdata_ok if {
	input.init_data == "f0631db84e5073638aa5c0b796d5c628839e241e26f8c0f29df90c8d6a46a4b3"
}

# Model: ct2603-l-azure (Initdata: 2c83c717e191)
azsnp_initdata_ok if {
	input.init_data == "9103710a341bb13f3b337b23d415edb98f8f09d5243a258167e62a1d2a980390"
}

# Model: cta2605-l-azure (Initdata: 086573aebe5a)
azsnp_initdata_ok if {
	input.init_data == "44396ec5a43262995c0dcbd4792da41505e9046278f6d806d6ff738cf4728cbf"
}

# Model: diarization-l-azure (Initdata: 64ffe1c4ec2a)
azsnp_initdata_ok if {
	input.init_data == "38d4c9e0e94f1d9bfbbccf5ac17d7cc79ee60be70548487128fab26f720b2ebe"
}

# Model: e4-l-azure (Initdata: fee21d630bd4)
azsnp_initdata_ok if {
	input.init_data == "365fcbaa60d599e16258519ba6b24fd9d08f13f3a8c238ed39e3300a82aeae5e"
}

# Model: e5f-l-azure (Initdata: 7df883250e22)
azsnp_initdata_ok if {
	input.init_data == "b360a646ed792f57e9587405cdb17aa2c31f1e266f1789d4e57824ce80a9b7ea"
}

# Model: e5p-l-azure (Initdata: a647bc68f2e4)
azsnp_initdata_ok if {
	input.init_data == "46fc58ae8d2dcb50496301b445d1318c55ecebcddd7bbcf659bbc70627d8b895"
}

# Model: r4f-l-azure (Initdata: a9f576d1af47)
azsnp_initdata_ok if {
	input.init_data == "2dbd78c44a027a07edf89acc1cf1f07654b52f0413d8f7fa934752e221887f4d"
}

# Model: r4p-l-azure (Initdata: e2be3a369b8f)
azsnp_initdata_ok if {
	input.init_data == "2fe160f7c8df1765124e7087b3c98c1f8b36329c795e8c590b9bb97d66a8745b"
}

# Model: r5f-l-azure (Initdata: 4f30c2a9a395)
azsnp_initdata_ok if {
	input.init_data == "b46c919b9b0988885a5f35cee6b3eca00e18fbb04e905499aed5f3c9b026a1f4"
}

# Model: r5p-l-azure (Initdata: 6679d1a9978c)
azsnp_initdata_ok if {
	input.init_data == "55ce9911b7e5d4e9caa244267bc56c31dce723e36a7784df7dcd46a472a5f80f"
}

# Model: cvp4-l-azure (Initdata: 10e215a9fe1e)
azsnp_initdata_ok if {
	input.init_data == "d61f50e5f150dc65e5b6edc763ef2521fef2d680add27969049126f398c20257"
}

# Model: cat2508rws-l-azure (Initdata: 7f4ef56db4fe)
azsnp_initdata_ok if {
	input.init_data == "de5afb2c4d324c46d97a0e6a303749e0ef088e366ddda1a2e9df9f284b6e6be6"
}

# Model: cmp-l-azure (Initdata: 193e7116f0da)
azsnp_initdata_ok if {
	input.init_data == "c3b128263db3c340a887ece8d5fe9f28cea80395552073b99d4037d8fcf38600"
}

# Model: nmc2606-l-azure (Initdata: 3e8ae47ae01c)
azsnp_initdata_ok if {
	input.init_data == "cab2d8f85fb0cea256c2fd5cb7b28eaa20aaa29bce76f6f6f4174faf78a0afda"
}

# Model: qw3-4b-l-azure (Initdata: a3a0d9d5cca1)
azsnp_initdata_ok if {
	input.init_data == "4a7b2b2fa43f0c3fe7da9179777b8175d0ef7b8f5b26e2195ec6624110e78174"
}

# Model: qw3-5-4b-l-azure (Initdata: 46bab0809611)
azsnp_initdata_ok if {
	input.init_data == "0fe4a77e0d726d99650cfb3f8f4d52e45dc74df98924cbd00bff8b7800a86c42"
}

# Model: qw3-5-35b-a3b-l-azure (Initdata: f529ac3152f9)
azsnp_initdata_ok if {
	input.init_data == "97ec39e05fb2a924995ba149e07e228b5495a42bb1f7f68d9856e7c0644c25b8"
}

# Model: qw36-27b-l-azure (Initdata: 6a819a88140b)
azsnp_initdata_ok if {
	input.init_data == "384993522bda468539dc759dd052102957b398faca70c75bf845740b44edbbcf"
}

# Model: qw38-27b-l-azure (Initdata: 01389c02db02)
azsnp_initdata_ok if {
	input.init_data == "344bafee9656852063b903293dc97c2136238f7b2da16beadc320f31bc0de7ac"
}

# Model: mstr3-3b-r-l-azure (Initdata: 4972a7e0fce3)
azsnp_initdata_ok if {
	input.init_data == "ae08b5a188c18b7e55a9e307edcd184abd79e9b7f43c8794aae2e92972ce5cf7"
}

# Model: dvs2-24b-l-azure (Initdata: 31c3a95afb8e)
azsnp_initdata_ok if {
	input.init_data == "0241d7c1fa9b9dc1626ba8040a850ae7a2af8cf52ddb8bbe381a9a2184e77f77"
}

# Model: phi4m-l-azure (Initdata: 61b043a4d238)
azsnp_initdata_ok if {
	input.init_data == "54d651b17fb6262bd2591e19542dbf7e5cf05537b7b87b92c907e08408a98faa"
}

# Model: gm4-26b-a4b-l-azure (Initdata: a24e84fcdc74)
azsnp_initdata_ok if {
	input.init_data == "5e71a7774ba5e086d67fc6dff77022872444f576958df2788b043ebb4f800fb7"
}

# Model: gptoss20b-l-azure (Initdata: e8a872442eda)
azsnp_initdata_ok if {
	input.init_data == "14e1da4c08fb48ef262aae859ec3f6895f39dc70cdf8526c9cf7401c4746f16a"
}

# Model: ct2603-l-azure (Initdata: b303c4f12263)
azsnp_initdata_ok if {
	input.init_data == "8bcfe479acd5cb798f158aa5ec504495b45c9f8a3283a432154bf2c0ac400dd1"
}

# Model: cta2605-l-azure (Initdata: 7eac21ec9b74)
azsnp_initdata_ok if {
	input.init_data == "20bdad0c549f78e5ba792ebe1fa232aab7d2a62f7b0069a23942a99f71b59f86"
}

# Model: diarization-l-azure (Initdata: 67afb86bba32)
azsnp_initdata_ok if {
	input.init_data == "8c346a620c75ea5aa84552b4a357d626273f298b7c8970fa164f2d9d08e53e95"
}

# Model: mstr3-3b-r-l-azure (Initdata: 57d15616a5f3)
azsnp_initdata_ok if {
	input.init_data == "9ca796361819f911eb35b14d30734017255ecd656d7827f2b6ab8887a95230e4"
}

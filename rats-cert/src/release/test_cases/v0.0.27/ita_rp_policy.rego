# ITA relying-party policy, evaluated by the relying party against the claims
# of an ITA token, with this release's ita_rims.json loaded as data.
#
# Besides checking that ITA appraised the token with this release's policy, it
# pins the measurements ITA accepted to this release's RIM values. ITA reads
# RIMs at appraisal time and the token does not record their content, so the
# policy match alone does not show which values were accepted.

package ita_rp

import rego.v1
import data.public.cohere.v1.rtmr3 as rtmr3_rims
import data.public.cohere.v1.platform as platform_rim

default allow := false

allow if {
    ita_policy_matched
    platform_matched
    workload_matched
    gpu_drivers_matched
}

ita_policy_matched if {
    some policy in input.policy_ids_matched
    policy.id == "dddaaee6-7456-42c9-8727-d2f1929144dc"
    policy.hash == "NEJrRkJvTGJmRWpKQS9UUjl3bDZCK2JwSDJvZjVKTmlEM3o2Tkdaam90d3gvd2lLV3g4VEhYb1VvZDF6TFFCNg=="
}

platform_matched if {
    some pair in platform_rim.rtmr1_rtmr2
    pair.rtmr1 == input.tdx.tdx_rtmr1
    pair.rtmr2 == input.tdx.tdx_rtmr2
}

workload_matched if {
    rtmr3_rim_names := {
        "s000"
    }
    some name in rtmr3_rim_names
    input.tdx.tdx_rtmr3 in rtmr3_rims[name].rtmr3
}

gpu_drivers_matched if {
    count(input.nvgpu.claim_details) > 0
    every gpu in input.nvgpu.claim_details {
        driver := gpu["x-nvidia-gpu-driver-version"]
        driver in platform_rim.nvidia_driver_versions
    }
}

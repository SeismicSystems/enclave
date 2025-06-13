/// This file defines const Strings for the policies
/// They are defined this way as opposed to being read in from a file
/// so that
/// 1) They impact the fingerprint for the TEE Service binary
/// 2) They cannot be easily modified (unlike system files, which are designed and have more complex permissioning systems)

pub const ALLOW_POLICY: &str = r#"
package policy

default allow = true
"#;

pub const DENY_POLICY: &str = r#"
package policy

default allow = false
"#;

pub const YOCTO_POLICY: &str = r#"
package policy

import rego.v1

default allow = false

allow if {
	input["aztdxvtpm.quote.body.mr_td"] == "bb379f8e734a755832509f61403f99db2258a70a01e1172a499d6d364101b0675455b4e372a35c1f006541f2de0d7154"
	input["aztdxvtpm.quote.body.mr_seam"] == "9790d89a10210ec6968a773cee2ca05b5aa97309f36727a968527be4606fc19e6f73acce350946c9d46a9bf7a63f8430"
	input["aztdxvtpm.tpm.pcr04"] == "fc846c8703feffa34e7c70cc62701f534abd3a59942a04a20081f0bff7cf182d"
}
"#;

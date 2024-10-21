# Attestion Agent

The Attestation Agent package provides handlers for interacting with the [CoCo Attestation Agent](https://github.com/confidential-containers/guest-components/tree/main/attestation-agent). The attestation agent privides APIs to interact with the secure hardware features of the enclave. 

Below is a quick explainer of the features offered by the attestation agent, and how they are relevant to Seismic.

## Features we use
### Get Evidence
Attestation evidence is: 
1) The current state of the TEE, such as its RTMR measurements, if it's in debug mode, etc
2) The runtime data that is included in the request. This can be up to 64 bytes, usually acting as a nonce to prevent replay or the hash of some other data
3) A signature of 1) and 2) above, which needs to be checked against a registry of enclave public keys. Intel maintains a PCCS (Provisioning Certificate Caching Service), and you can configure which service to use by modifying /etc/sgx_default_qcnl.conf

See [Intel Docs](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf) Section 2.3.2 for more details



## Features we don't use
### Get Type
This feature returns the type of enclave hardware being used. 

It's not relevant to Seismic at the moment because we want to abstract this information away from other services we currently use (namely reth).

### Extend Runtime Measurement
Extending runtime measurements sets the values of RTMR registers. By convention for TDX, RTMR registers 0-2 are used to measure the kernal and OS, and register 3 is used to measure the guest workload.

Because Seismic is building our application into a yocto image, our measurements will included in [INSERT CORRECT FACT HERE WHEN WE HAVE SUCCESS WITH YOCTO]. We currently have no plans to expose this feature to other services, like RETH.

### Check Init Data
For Intel TDX, the init_data are the 48 bytes in MRCONFIGID. MRCONFIGID is a fingerprint of software that is setup by the host (i.e. the person or platform providing the hardware), such as the OS that the guest application runs on.

The init_data feature is not supported for AzTdxVtpm because their secure boot works differently than default TDX

### Get token
The CoCo library is built as a series of services that communicate with each other. Get token has the AA generate an attestation, and then send it to the AS to have the attestation verified. The AS then returns a token, which can be used to request resources. 

This feature is not relevant to Seimic because we do not have this architecture. 
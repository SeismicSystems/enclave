# Seismic enclave

**Current state**

This is a **mock** server designed to handle cryptographic requests. It is intended to be run within a Trusted Execution Environment (TEE). It is a work-in-progress, and shouldn't be used in production in its current form as your secrets will be exposed.

## Running the Server

You can only run the server on a machine where various Intel SGX & TDX libraries are installed. See [tss-esapi-sys](https://crates.io/crates/tss-esapi-sys) for information on this.

The command to run the server is:

`cargo build && sudo target/debug/seismic-enclave-server`

You should see something like `Listening on http://127.0.0.1:7878`

## Example Request

curl http://127.0.0.1:7878/genesis/data

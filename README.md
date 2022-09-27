# DCAP PoC

## Build


Generation (Require HW SGX & HW)

```
cd SGXDataCenterAttestationPrimitives/QuoteVerification/dcap_quoteverify/linux
make
cd ../../../../gramine-build
make run
```

Verification
```
cargo run
```

## References

- https://download.01.org/intel-sgx/sgx-dcap/1.14/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf

## Sample

[Sample output](doc/output.sample)

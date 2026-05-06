# libcvc

`libcvc` is a compact C library for parsing, building and signing CVC (Card Verifiable Certificate) structures used in TR-03110 / ISO 7816 ecosystems.

The library is designed for embedded targets:
- deterministic memory usage
- no dynamic allocations in core paths
- minimal copies where possible
- direct TLV write paths

## Status

Current implementation is production-oriented but still evolving.

What is implemented:
- DER TLV helpers (tag/length/value parsing and writing)
- CVC field extraction (`CAR`, `CHR`, `body`, `signature`, `extensions`, `pubkey template`)
- Public key template build:
  - RSA (TR-03110 D.3.1)
  - EC Weierstrass (TR-03110 D.3.3)
  - DH-style encoding for Montgomery/Edwards keys (TR-03110 D.3.2 mapping)
- Certificate body / certificate / request wrapper build
- Inner/outer signature request handling
- Signing via mbedTLS PK API (RSA, ECDSA raw `r||s`, EdDSA when enabled)
- Optional strict profile checks in writer mode

What is intentionally out of scope (for now):
- full chain validation / PKI policy engine
- role hierarchy evaluation from CHAT
- PRKD-specific routines

## Project layout

- `include/cvc.h`: public API
- `include/cvc_tags.h`: CVC tags/constants
- `src/cvc_tlv.c`: TLV primitives
- `src/cvc_parse.c`: extract/parse helpers
- `src/cvc_build.c`: low-level builders
- `src/cvc_sign.c`: signing and high-level build+sign helpers
- `src/cvc_write.c`: stateful writer API and profile validation

## Build

### Standalone build

```bash
cmake -S ../libcvc -B ../libcvc/build
cmake --build ../libcvc/build
```

This builds target `cvc` and static library `libcvc.a` (toolchain-dependent naming).

### As a dependency from another project

```cmake
add_subdirectory(path/to/libcvc path/to/build/libcvc)
target_link_libraries(your_target PRIVATE cvc)
```

## Dependencies

- C11 compiler
- mbedTLS (required)

`libcvc` links `mbedtls` target:
- `target_link_libraries(cvc PUBLIC mbedtls)`

Note: current `CMakeLists.txt` also includes a private include path to mbedTLS as used in this workspace layout. If you use a different layout, adapt that include path or provide your own mbedTLS target/include wiring.

## API overview

### 1) Parse/extract layer

Use these for zero-copy access to fields inside existing encoded blobs:
- `cvc_get_field`
- `cvc_get_body`
- `cvc_get_sig`
- `cvc_get_car`
- `cvc_get_chr`
- `cvc_get_pub`
- `cvc_get_ext`

Public key parsing helpers:
- `cvc_parse_pubkey_template`
- `cvc_extract_pubkey`
- `cvc_extract_ec_point`

### 2) Builder layer (stateless)

Use when you already have all pieces and want TLV encoding only:
- `cvc_build_pubkey_template_ex`
- `cvc_build_cert_body`
- `cvc_build_cert`
- `cvc_build_request`

### 3) Writer layer (stateful)

Use when you want a structured flow with validation and convenience setters:
- `cvc_write_cert_init`, `cvc_write_req_init`
- `cvc_write_set_*` setters
- `cvc_write_cert_der`, `cvc_write_req_der`

Profile knobs:
- `cvc_write_set_strict_profile`
- `cvc_write_set_domain_params_policy`

### 4) Build+sign convenience

- `cvc_build_and_sign_cert`
- `cvc_build_and_sign_request`

## Minimal example

```c
cvc_write_cert w;
uint8_t out[2048];
uint16_t out_len = 0;

cvc_write_cert_init(&w);
cvc_write_set_subject_key(&w, subject_pk);
cvc_write_set_issuer_key(&w, issuer_pk);
cvc_write_set_algorithm_oid(&w, alg_oid, alg_oid_len);
cvc_write_set_car(&w, car, car_len);
cvc_write_set_chr(&w, chr, chr_len);
cvc_write_set_validity(&w, valid_from_yyMMdd, 6, valid_to_yyMMdd, 6);

/* Optional strict checks */
cvc_write_set_strict_profile(&w, true);

if (cvc_write_cert_der(&w, out, sizeof(out), &out_len, f_rng, p_rng) != 0) {
    /* handle error */
}
```

## TR-03110 conformance notes

### C (profiles)

Implemented:
- certificate body signed over encoded `0x7F4E` body
- request inner signature over encoded body
- optional outer signature over concatenation:
  - encoded CV certificate
  - encoded CAR

Strict profile mode checks currently include:
- presence and format of dates (`YYMMDD`, 6 unpacked BCD digits)
- `valid_from <= valid_to`
- configurable domain-parameter policy

### D (DER/TLV)

Implemented:
- one/two-byte tag support
- short and long-form lengths up to 65535
- minimal length encoding in writer helpers

## Embedded characteristics

- no heap allocation in core `build/parse/sign/write` paths
- bounded stack buffers
- direct writes into caller-provided output buffers
- explicit output capacity checks

## Return/error model

Most encode helpers return:
- `0` on error
- encoded length on success

Most writer/sign/parse helpers return symbolic status codes:
- `LIBCVC_OK`
- `LIBCVC_ERR_INVALID_ARG`
- `LIBCVC_ERR_FORMAT`
- `LIBCVC_ERR_UNSUPPORTED`
- `LIBCVC_ERR_NO_SPACE`
- `LIBCVC_ERR_CRYPTO`
- `LIBCVC_ERR_POLICY`

## Known limitations

- no certificate chain/path validation
- no authoritative OID policy engine (caller controls OIDs)
- role-specific CVCA/DV/Terminal policy is not yet inferred automatically from CHAT
- no time source abstraction yet for forcing “effective date == generation date”

## Roadmap

- configurable time callback for issuance-time checks
- optional role-policy module for CVCA/DV/Terminal constraints
- extended test vectors for all key families and profile combinations
- decouple workspace-specific mbedTLS include path in CMake

## License

GNU Affero General Public License v3.0.

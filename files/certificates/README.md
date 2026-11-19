Public certificate provenance (validated 2026-11-19)

The four self-signed roots are DER exports of ../sssd_dod_roots.pem, with no changes to their encoded certificate bytes. All four match certificates in the official DoD PKCS7 bundle byte for byte:
https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip
Published SHA1 identities: https://usgovpki.apps.deas.ecs.mil/dod/cas-root/index.html

The supplied PEM contains no cross-certificates. The two DoD Root CA 3/6 cross-certificates for each interoperability authority were extracted from these official DISA PKCS7 bundles over authenticated HTTPS:
https://crl.disa.mil/issuedby/DODINTEROPERABILITYROOTCA2_IB.p7c
https://crl.disa.mil/issuedby/USDODCCEBINTEROPERABILITYROOTCA2_IB.p7c

Their signatures were verified using the matching issuer certificates from:
https://crl.disa.mil/issuedto/DODINTEROPERABILITYROOTCA2_IT.p7c
https://crl.disa.mil/issuedto/USDODCCEBINTEROPERABILITYROOTCA2_IT.p7c
OpenSSL verify -partial_chain -purpose any -trusted <issuer> <cross> succeeded for all four. Their subject public keys also match the supplied self-signed DoD Root CA 3/6 keys. Issuer certificates are verification material only and are not shipped or imported as trusted roots.

vars/certificates.yml pins the SHA256, SHA1, subject and issuer for every payload. All eight are CA certificates, currently valid, with certificate-signing usage and no private keys. Root self-signatures were verified with OpenSSL verify -check_ss_sig. Runtime checks fail closed on altered, expired, wrongly classified or private-key-bearing payloads.

V-278192 imports the self-signed roots into LocalMachine Root. V-278193/194 remove only the exact managed cross-certificate thumbprints from Root/CertificateAuthority and install them into Disallowed, in both LocalMachine and the connecting user's CurrentUser stores. This is scoped store remediation; no unrelated certificates are deleted. No signer or cross-certificate is made trusted. These controls are gated by win25_stig_unclassified; classified systems require site-approved NSS anchors instead.

Check mode stages public payloads to permit the native certificate-store module to inspect them. Certificate-store changes honor check mode. Review and renew pinned payloads before expiry; imports do not download certificates at runtime.

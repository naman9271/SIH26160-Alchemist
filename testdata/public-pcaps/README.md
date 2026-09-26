# Public IPsec PCAP test set

These captures come from the official Wireshark project and were verified with
this repository's upload and analysis APIs on 2026-09-26. They contain no
traffic collected by this project team.

## Recommended order

1. `ikev2_s2s_aes256gcm_dh19_esp_icmp.pcapng`
   - Best end-to-end demonstration capture.
   - Complete IKEv2 site-to-site establishment followed by ESP-encapsulated
     ICMP traffic.
   - Wireshark describes the configuration as AES-256-GCM with DH group 19.
   - Project verification: 12 packets, 4 IKE, 8 ESP; numeric provisional score
     available (100), 23.08% evidence coverage.

2. `ikev2_natt_gcm_ctr_cbc_esp_icmp.pcapng`
   - Best NAT-T and multi-SA parser test.
   - Three IKEv2 sessions over UDP/4500 using AES-GCM, AES-CTR, and AES-CBC;
     each session carries ESP-protected ICMP traffic.
   - Project verification: 54 packets, 30 IKE, 24 ESP, 54 NAT-T; numeric
     provisional score available (100), 23.08% evidence coverage.
   - The upstream description is preserved in
     `WIRESHARK_MULTI_CIPHER_README.txt`.

3. `ikev1_certificates.pcap`
   - IKEv1 compatibility and certificate-payload parser test.
   - Contains negotiation only, with no ESP data.
   - Project verification: 10 packets, all IKE; numeric provisional score 0
     with one IKEv1 baseline finding and 11.54% evidence coverage.

4. `ikev2_aes256gcm16.pcap`
   - Focused IKEv2 AES-256-GCM-16 negotiation/decryption regression capture.
   - Contains negotiation only, with no ESP data.
   - Project verification: 6 packets, all IKE; numeric provisional score 100,
     23.08% evidence coverage.

5. `ikev2_aes256cbc_sha256.pcapng`
   - Focused IKEv2 AES-256-CBC/SHA-256 negotiation/decryption regression
     capture.
   - Contains negotiation only, with no ESP data.
   - Project verification: 4 packets, all IKE; numeric provisional score 100,
     23.08% evidence coverage.

The score is intentionally provisional. A passive capture can establish the
visible IKE proposal and protocol version, but encrypted IKE_AUTH messages and
ESP headers do not prove every CHILD-SA, authentication, replay, lifetime, or
gateway runtime setting. Use Deep Assessment for those controls.

## Sources

- Wireshark SampleCaptures IPsec section:
  <https://gitlab.com/wireshark/wireshark/-/wikis/SampleCaptures#ipsec>
- Site-to-site IKEv2 capture:
  <https://gitlab.com/wireshark/wireshark/-/wikis/uploads/c45aa4606b860d707db92e180c147001/ikev2_s2s_ipsec_vpn_aes_gcm.pcapng>
- NAT-T multi-cipher archive:
  <https://gitlab.com/wireshark/wireshark/-/wikis/uploads/dc5b30a117424e6ed21c726771a4006b/ipsec_ikev2+esp_aes-gcm_aes-ctr_aes-cbc.tgz>
- Wireshark regression captures:
  <https://gitlab.com/wireshark/wireshark/-/tree/master/test/captures>

## SHA-256

```text
903a9868d58554031c40f7eee921e24e725bd8bd2bb8fc8ba36c49f6436f2edd  ikev1_certificates.pcap
86505314cc2cbe68b1c4af270d099cab234e64595277bb572f18dfaab2654179  ikev2_aes256gcm16.pcap
1a033591e44f3570fe99b36af0a0727e01b3076589611d2218f264caac326f40  ikev2_aes256cbc_sha256.pcapng
58c748c33388614a767d90345b38b827098d4d3f9609f7075e3ff58a4f49b6ad  ikev2_natt_gcm_ctr_cbc_esp_icmp.pcapng
7802a8edc23470f698094263479d6f2cd1672ce71a404a604ca741a8a9994615  ikev2_s2s_aes256gcm_dh19_esp_icmp.pcapng
```

## Testing

Upload one file at a time in the workspace. Start with either of the first two
files when testing the full workflow because they include both negotiation and
encrypted data traffic. The final score card should be numeric and marked
provisional. Confirm the displayed IKE/ESP/NAT-T counters against the values
above, then inspect VPN Sessions, Evidence, Security Findings, Risk & Fixes, and
the executive and technical reports.

Do not use the three negotiation-only captures to evaluate traffic
classification; they are parser and security-rule fixtures.

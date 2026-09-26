
CONTENTS OF THIS DIRECTORY
==========================

 Author: Matthias St. Pierre (matthias.st.pierre@ncp-e.com)

 Date : June 2021


* Dissection of encrypted (and UDP-encapsulated) IKEv2 and ESP messages
-----------------------------------------------------------------------

A VPN client (192.168.245.131) behind a NAT device connects three times
to the VPN gateway (172.16.15.92) using IKEv2, sends some pings through
the VPN tunnel (192.168.225.0/24) to the gateway (192.168.225.1), which
are returned successfully, and disconnects.

The three connections differ by the AES operation mode used for the
encrypted payloads of the IKE_AUTH and ESP messages:

    Encryption                            Authentication

 1  AES-GCM with 16 octet ICV [RFC4106]   NULL
 2  AES-CTR [RFC3686]                     HMAC-SHA-256-128 [RFC4868]
 3  AES-CBC [RFC3602]                     HMAC-SHA-256-128 [RFC4868]

The entire conversation (IKE+ESP) is sent UDP-encapsulated on port 4500.

The directory contains :

- capture.pcap:              packet capture file
- esp_sa:                    decryption table for the ESP SAs
                             (requires [MR !3444])
- esp_sa.no_icv:             decryption table for the ESP SAs
                             (without AES-GCM ICV length)
- ikev2_decryption_table:    decryption table for the IKEv2 SAs


[MR !3444]: https://gitlab.com/wireshark/wireshark/-/merge_requests/3444

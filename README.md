# AKE-over-CoAP
## Introduction
This is the self-documenting python implementation for the paper **LAKE: A Lightweight Authenticated Key Exchange Protocol for Power Constrained Devices**. The client and the server perform a LAKE handshake and establish a short-term key with **Elliptic-curve Diffie–Hellman (ECDH)**. The developers are aware that this is not the most efficient way to implement the protocol. The code serves as a practical guideline for the protocol and helps to estimate its overhead.
## Getting Started
Install the required python packagses.
```
pip install -r requirements.txt
```
Make sure to install the latest available version of **pycryptodome**. Otherwise, the package may not include the `ed448` curve. Run the server and the client in order. 
```
python server.py 
python client.py
```
The running code logs the important information during the handshake. 
## Future Work
1. Implementing the IP-range blocking mechanism in which an IP-range with 3 or more failed attempts gets blocked by the server. 
2. Implementing the protocol in lower layers. 
3. Transferring the control and the session key to `DTLS` after the handshake.
4. Implementing in `c++` for faster handshakes. 

## Citation
```yaml
cff-version: 1.2.0
message: "If you use this software, please cite it as below."
authors:
  - family-names: Nabavirazavi
    given-names: Seyedsina
    orcid: https://orcid.org/0000-0002-9186-4386
title: "LAKE Over aiocoap"
version: 1
date-released: 2022-06-03
```

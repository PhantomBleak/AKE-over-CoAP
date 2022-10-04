# AKE-over-CoAP
## Introduction
This is the self-documenting python implementation for the paper **LAKEE: A Lightweight Authenticated Key Exchange Protocol for Power Constrained Devices**. The client and the server perform a LAKEE handshake and establish a short-term key with **Elliptic-curve Diffie–Hellman (ECDH)**. The developers are aware that this is not the most efficient way to implement the protocol. The code serves as a practical guideline for the protocol and helps to estimate its overhead.
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

%%%
    Title = "Hidden Encrypted SNI in TLS 1.3 (HESNI)"
    abbrev = "HESNI"
    category = "experimental"
    docName= "draft-huitema-tls-hesni-latest"
    ipr = "trust200902"
    area = "Network"
    date = 2019-02-24T00:00:00Z
    [pi]
    toc = "yes"
    compact = "yes"
    symrefs = "yes"
    sortrefs = "yes"
    subcompact = "no"
    [[author]]
    initials="C."
    surname="Huitema"
    fullname="Christian Huitema"
    organization = "Private Octopus Inc."
      [author.address]
      email = "huitema@huitema.net"
      [author.address.postal]
      city = "Friday Harbor"
      code = "WA  98250"
      country = "U.S.A"
%%%

.# Abstract

Hidden Encrypted SNI (HESNI) specifies how to exchange the TLS SNI between client and
server in a hidden manner, so that usage of Encrypted SNI does not stick out. The
goal is to evade censorship that could be triggred by the detection
of an Encrypted SNI extension.

Achieving the goal to not stick out requires tradeoffs, in particular the use of trial
decryption by servers. This may restrict the deployment of this specification to
especially motivated servers, hence the experimental nature of this draft.

{mainmatter}

# Introduction

A procedure to encrypt the TLS Service Name Indication is described in [@!ietf-tls-esni].
This procedure is sound, but it relies on adding an ESNI extension to the Client Hello.
This extension is transmitted in clear text. Its presence can be noticed by inspecting the traffic.
There is a risk that censors will program firewalls to block all connections using that extension.
We develop here the Hidden ESNI (HESNI) alternative, in which the encrypted SNI is hidden in the
Client Hello, in an attempt to evade detection by censors and firewalls.

This draft isn't meant to replace the ESNI draft, but only to experiment with a stealthier 
alternative. HESNI choses different design tradeoffs than the ESNI draft. With the draft ESNI,
the server can find in the ESNI extension all information needed to retrieve the original SNI.
In contrast, the server participating in the HESNI experiment has to perform "trial decryption"
on the incoming connection attempts to find out whether HESNI is present.

The clients using HESNI hide the value of the key shares and the encrypted text in a small set of
standard fields in the Client Hello and its extensions. These fields have a relatively small size,
which limits the amount of data that can be conveyed, and also limits the number of algorithms
used to encrypt the SNI in HESNI. For example, HESNI requires that the keys used to establish
the SNI encryption secret are picked in the x25519 group [@?RFC7748]. Using different groups
may become required over time, but would have to be defined in a different experiment.

HESNI requires TLS 1.3 [@!RFC8446], in part because TLS 1.3 encrypts most of the server messages
and thus provides an easier starting point than TLS 1.2. Defining an SNI encryption procedure for
TLS 1.2 [@?RFC5246] would require further work, such as identifying suitable fields in TLS 1.2
messages or finding a way to not send the private server's certificate in clear text. This would
have to be explored in a separate experiment.


# Conventions and Definitions

The key words “MUST”, “MUST NOT”, “REQUIRED”, “SHALL”, “SHALL NOT”, “SHOULD”, “SHOULD NOT”, “RECOMMENDED”,
“NOT RECOMMENDED”, “MAY”, and “OPTIONAL” in this document are to be interpreted as described in BCP 14
[@!RFC2119] [@!RFC8174] when, and only when, they appear in all capitals, as shown here.

# Overview

This document is designed to support the
“Shared Mode” and “Split Mode” defined in section 3 of [@!ietf-tls-esni].

First, the client facing server publishes at least one public key share, which we refer to as
the "HESNI server key share".
It will be used for SNI encryption for all the domains that the server
serves directly or indirectly (via Split mode).

This draft does not require that the HESNI server key share be kept secret from observers.
The HESNI server key share MAY be published in the
DNS as defined in section 4 of [@!ietf-tls-esni]. 
The HESNI server key share MAY also be provisioned in the client
through other mechanisms, such as for example software update of applications.
Servers MAY attempt to hide their participation in the HESNI experiment 
by restricting the publication of their HESNI key share to trusted clients.

Clients encode HESNI parameters in two selected fields
of the ClientHello: the "Client random" parameter, and the
"legacy session ID" parameter. 

The client facing server that receives the ClientHello will check whether the Encrypted
SNI (ESNI) extension is present. If it is not, the server tries
to decrypt the value from the selected fields. If decryption is succesful, the server can either
terminate the connection (in Shared Mode) or forward it to the backend server (in Split Mode).
If the decryption fails, the server proceeds with the connection as specified in TLS 1.3 
[@!RFC8446].

# HESNI procedures

The HESNI procedures use a single set of algorithms:

* The HESNI server key share and client key share belong to the group x25519 [@?RFC7748].

* The select hash function is SHA256

* The SNI will be encrypted using the AEAD algorithm AEAD_CHACHA20_POLY1305 [@?RFC8439].




## Client Behavior

The client who wants to joint a private server in the HESNI experiment MUST first
select the corresponding client facing server, and obtain the HESNI server key share
of the client facing server -- or select one of the available key shares if the
server published several of them.

* The client MAY obtain these key shares by looking for _esni TXT records
  in the DNS entry of the server (per section  4 of [@!ietf-tls-esni]).

* The client MUST only select key shares drawn from the x25519 group.

The client then generate its own x25519 key share. The client MUST pick a new
key share for each connection, using a CSRNG complaint with the requirements
of [@!RFC8446]. The client derives the associated 32 bytes public key (section
6.1 of [@?RFC7748]. The client then sets the value of the ClientHello.Random
field to the 32 byte public key share value.

* TODO: some bits in the x25519 public key share have fixed values. Should
  we specify a masking process?

The client will derive a shared secret by combining its own key share and 
the selected HESNI server key share. It will then derive an AEAD key, an
AEAD IV and HESNI nonce from this secret:

```
Zx = HKDF-Extract(0, Z)
key = HKDF-Expand-Label(Zx, "hesni key", NULL, key_length)
iv = HKDF-Expand-Label(Zx, "hesni iv", NULL, iv_length)
nonce = HKDF-Expand-Label(Zx, "hesni nonce", NULL, 16)
```
Where:

 * HKDF is the HMAC-based Extract-and-Expand Key Derivation Function
   [@!RFC5869] derived from HMAC/SHA256.
 * key_length is 32 bytes (256 bits) and IV length is 14 bytes (96 bits)
   per definition of ChaCha20 & Poly1305 [@?RFC8439]

To compute the encrypted SNI value, the client will proceed as follow:
```
paddedSNI = original SNI, padded with zeroes to a length of 16 bytes
encrypted_sni = AEAD-Encrypt(key, iv, 
                             ClientHello.KeyShareClientHello, paddedSNI)
```
The AEAD encrypt is applied as in TLS 1.3, using ChaCha20 & Poly1305.
Encryption of the 16 bytes padded SNI results in a 32 bytes encrypted
SNI, which is copied to the legacySessionID field of the client
Hello.

The client MUST ensure that the modified ClientRandom and legacySessionID
values are used when computing the handshake context and PSK binder per TLS 1.3.

If the server does not negotiate TLS 1.3 or above, then the client
MUST abort the connection with an "unsupported_version" alert.  If
the server supports TLS 1.3, the client MUST check that the first 16 bytes
of the ServerHello "ServerLegacySessionId" parameter match the
value of the HESNI nonce. If it doesn't, the client SHOULD
abort the session.

## Client Facing Server Behavior

The client facing server that receives a client's first flight has to decide whether to
attempt decryption of the HESNI, and what key to use. For the purpose of the
HESNI experiment, the client facing server will check whether the ESNI extension is
present. If it is, the message will be processed per ESNI [@!ietf-tls-esni]. In
the other cases, the server attempts to decrypt the SNI according to HESNI.

The server will try HESNI decryption using each of the published HESNI server key
shares, until either one of the decryption succeeds, or all fail.

* TODO: are we concerned about constant time decryption?

If no trial decryption is successful, the server processes the message as if HESNI
was not in use.

To perform trial decryption, the server effectively reverses the process used by the
client to compute the encrypted SNI. The trial decryption fails if the AEAD
decryption of the encrypted_sni fails. An error is detected if the AEAD decryption
succeeds, but the padded length does not match the server specified value.

Upon determining the true SNI, the client-facing server then either
serves the connection directly (if in Shared Mode), in which case it
executes the steps in the following section, or forwards the TLS
connection to the backend server (if in Split Mode).  In the latter
case, it does not make any changes to the TLS messages, but just
blindly forwards them.

## Shared Mode Server Behavior

A server operating in Shared Mode uses the decrypted SNI as if
it were the "server_name" extension to finish the handshake.  It
SHOULD pad the Certificate message, via padding at the record layer,
such that its length equals the size of the largest possible
Certificate (message) covered by the same HESNI key.  Moreover, the
server MUST set the first 16 bytes of the "ServerLegacySessionId"
to the value of HESNI nonce derived from the shared HESNI secret.

## Split Mode Server Behavior

In Split Mode, the backend server must know the value of
HESNI nonce to echo it back in the first 16 bytes
of the "ServerLegacySessionId". Appendix B of [@!ietf-tls-esni]
describes one mechanism to do so.

# Compatibility Issues

HESNI suffers from the same potential issues as explained in section 6 of
[@!ietf-tls-esni]. 

# Security considerations

The security properties of HESNI are similar to those of ESNI, as listed
in the Security Consideration section of [@!ietf-tls-esni], with one major
difference: HESNI is designed to not "stick out", and thus might succeed
even in the absence of large scale deployment of ESNI. There are however some
specific issues.

## Drawbacks of using fixed algorithms

The HESNI specification uses a fixed set of algorithms: x25519, chacha20,
poly1035 and SHA256. This results in a simple specification and in a tight
usage of available fields in the ClientHello and ServerHello. If any of
these algorithm becomes unsuitable, due for example to progress in cryptoanalysis,
the HESNI experiment described in this specification SHOULD be terminated,
and a new specification SHOULD be developed.

## Drawbacks of Repurposing the Client Random

The ClientHello.Random field is used in TLS as a source of randomness when generating
key material. According to annex C.1. of [@!RFC8446], this field should be filled with
the output of a godd quality CSPRG, such as provided by the operating system. HESNI
deviates from that recommendation, as it fills the ClientHello.Random field with
the x25519 public key share of the client. (TODO: obfuscation of fixed parts?)

# IANA Considerations

This draft does not require any IANA action.

# Acknowledgements

TBD

{backmatter}
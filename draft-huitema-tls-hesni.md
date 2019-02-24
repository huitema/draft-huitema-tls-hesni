%%%
    Title = "Hidden Encrypted SNI (HESNI)"
    abbrev = "HESNI"
    category = "experimental"
    docName= "draft-huitema-tls-hesni-latest"
    ipr = "trust200902"
    area = "Network"
    date = 2019-02-23T00:00:00Z
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

HESNI choses different design tradeoffs than the ESNI draft. With the draft ESNI,
the server can find in the ESNI extension all information needed to retrieve the original SNI.
In contrast, the server supporting HESNI has to perform "trial decryption" on the incoming connection
attempts to find out whether HESNI is present.

The clients using HESNI hide the value of the key shares and the encrypted text in a small set of
standard fields in the Client Hello and its extensions. These fields have a relatively small size,
which limits the amount of data that can be conveyed. Given this small size, HESNI supports fewer
options than ESNI.

# Conventions and Definitions

The key words “MUST”, “MUST NOT”, “REQUIRED”, “SHALL”, “SHALL NOT”, “SHOULD”, “SHOULD NOT”, “RECOMMENDED”,
“NOT RECOMMENDED”, “MAY”, and “OPTIONAL” in this document are to be interpreted as described in BCP 14
[@!RFC2119] [@!RFC8174] when, and only when, they appear in all capitals, as shown here.

# Overview

This document is designed to support the
“Shared Mode” and “Split Mode” defined in section 3 of [@!ietf-tls-esni].

First, the provider publishes a public key which is used for SNI encryption for all the domains
for which it serves directly or indirectly (via Split mode). The key MAY be published in the
DNS as defined in section 4 of [@!ietf-tls-esni]. The key MAY also be provisioned in the client
through other mechanisms, such as for example software update of applications.

Instead of relying on a TLS extension, HESNI encodes its parameters in two selected fields
of the ClientHello: 32 bytes of data are carried in the "Client random" parameter, and up to
32 bytes are carried in the "legacy session ID" parameter. 

When a client wants to form a TLS connection to any of the domains served by an HESNI-supporting
provider, it sets the “server_name” extension in the ClientHello to a cover value designating the
client facing server, it encrypts the true extension using the provider’s public key, and it
hides the encrypted value in the selected fields.

The client facing server that receives the ClientHello will check whether the regular Encrypted
Extension is present. If it is not, it checks whether the “server_name” extension matches one
of the cover values specific to this client facing server. If that's the case, the server tries
to decrypt the value from the selected fields. If decryption is succesful, the server can either
terminate the connection (in Shared Mode) or forward it to the backend server (in Split Mode).
If the decryption fails, the server proceeds with the connection as specified TLS 1.3 [@?RFC8446].

# HESNI procedures

The ESNI extension defined in [@!ietf-tls-esni] uses four parameters:

* The cipher suite used to encrypt the SNI.

* The KeyShareEntry carrying the client's public ephemeral key shared used to derive the ESNI key.

* The record digest, which is a cryptographic hash of the ESNIKeys structure from which the ESNI
  key was obtained.

* The encrypted SNI.

The HESNI procedure will not transmit the cipher suite or the record digest, in part
to preserve the small amount of hiding spaceavailable in the ClientHello, and also because
any "clear text" parameter could tip observers about the use of ESNI. Instead, clients
will pick one of the ESNI keys advertise by the server. The server will use heuristics to try
decryption with a first key, and if that fails try the other published keys in turn.

The syntax and the size of the KeyShareEntry depends on the selected group. For X25519 the
key size is 32 bytes, but for other groups it can be significantly larger: 56 bytes for
X448, 64 bytes for secp256r1, and even more for other groups. That means the encoding of
both the KeyShareEntry and the encrypted SNI would only fit in the 64 available bytes
if we constrained HESNI to only use X25519. To avoid that, we decide that the KeyShareEntry
selected for HESNI will always be the first KeyShareEntry listed by the client.

For the purpose of the experiment, the ciphersuite will be
a direct function of the group of the selected Key Share. The following table provides a list of
the groups supported in the HESNI experiment, and the corresponding ciphersuite:
```
+-----------+------------------------------+
| Group     | HESNI ciphersuite            |
+-----------+------------------------------+
| secp256r1 | TLS_AES_128_GCM_SHA256       |
| secp384r1 | TLS_AES_256_GCM_SHA384       |
| secp521r1 | TLS_AES_256_GCM_SHA384       |
| x25519    | TLS_CHACHA20_POLY1305_SHA256 |
| x448      | TLS_CHACHA20_POLY1305_SHA256 |
| ffdhe2048 | TLS_AES_128_GCM_SHA384       |
| ffdhe3072 | TLS_AES_256_GCM_SHA384       |
| ffdhe4096 | TLS_AES_256_GCM_SHA384       |
| ffdhe6144 | TLS_AES_256_GCM_SHA384       |
| ffdhe8192 | TLS_AES_256_GCM_SHA384       |
+-----------+------------------------------+
```


## Client Behavior

As specified in ection 5.1 of [@!ietf-tls-esni] the client MUST first select one
of the server ESNIKeyShareEntry values and generate an (EC)DHE share
in the matching group. That key share MUST be documented as the first entry
in the KeyShare ClientHello extension. The client will then derive a shared
secret from the selected ESNIKeyShareEntry of the server and the client generated
KeyShare, and then derive an AEAD key and an AEAD IV from this
shared secret using the process specified in section 5.1 of [@!ietf-tls-esni].

To compute the Hidden ESNI value, the client will compose the ClientESNIInner
structure as specified in section 5.1 of [@!ietf-tls-esni], and then encrypt
it using the usual TLS 1.3 AEAD:
```
   encrypted_sni = AEAD-Encrypt(key, iv, 
                                ClientHello.KeyShareClientHello, ClientESNIInner)
```
The length of the encrypted_sni value will be the sum of:

* ClientESNIInner.nonce: 16 bytes

* ClientESNIInner.PaddedServerNameList: padded length specified with ESNI key

* AEAD tag: depend on AEAD algorithm, usually 16 bytes

In order to ensure that the encrypted_sni fits in the 64 bytes available in the
selected fields of the ClientHello, the server MUST specify a padded length
of at most 32 bytes long. To simplify processing, the server SHOULD specify a
padded length of exactly 32 bytes.

Once the encrypted_sni is computed, the client resets the ClientRandom and
legacySessionID fields of the message as follow:

* ClientRandom value is set to the first 32 bytes of the encrypted SNI

* legacySessionID is set to the remaining bytes of the encrypted SNI.

In addition, the client MUST add to the ClientHello an SNI extension set to
the "cover SNI" chosen by the server.

The client MUST ensure that the modified ClientRandom and legacySessionID
values are used in the PSK Binder, per section 4.2.11.2 of [@!RFC8446].


If the server does not negotiate TLS 1.3 or above, then the client
MUST abort the connection with an "unsupported_version" alert.  If
the server supports TLS 1.3, the client MUST check that the first 16 bytes
of the ServerHello "ServerLegacySessionId" parameter match the
value of the ClientESNIInner.nonce. If it doesn't, the client SHOULD
abort the session.

## Client Facing Server Behavior

The client facing server that receives a client's first flight has to decide whether to
attempt decryption of the HESNI, and what key to use. For the purpose of the
HESNI experiment, the client facing server will:

1) Check that the ESNI extension is not present. 

2) Check that the SNI extension is present, and is set to one of the cover
values supported by the server.

3) Check that the KeyShare extension is present and that
the group selected for the first KeyShareEntry matches at least one of the groups
for which the server has published an ESNI key.

If any of these tests fails, the server MUST NOT attempt HESNI decryption. If the tests
succeed, the server has identified the client key share and the selected group.
The server will try HESNI decryption using each of the published ESNI keys that
matches the selected group, until either one of the decryption succeeds, or all fail.
If no trial decryption is successful, the server processes the message as if HESNI
was not in use.

To perform trial decryption, the server effectively reverses the process used by the
client to compute the encrypted ESNI. The trial decryption fails if the AEAD
decryption of the encrypted_sni fails. An error is detected if the AEAD decryption
succeeds, but the padded length does not match the server specified value.

As specified in section 5.2. of [@!ietf-tls-esni],
upon determining the true SNI, the client-facing server then either
serves the connection directly (if in Shared Mode), in which case it
executes the steps in the following section, or forwards the TLS
connection to the backend server (if in Split Mode).  In the latter
case, it does not make any changes to the TLS messages, but just
blindly forwards them.

## Shared Mode Server Behavior

A server operating in Shared Mode uses PaddedServerNameList.sni as if
it were the "server_name" extension to finish the handshake.  It
SHOULD pad the Certificate message, via padding at the record layer,
such that its length equals the size of the largest possible
Certificate (message) covered by the same ESNI key.  Moreover, the
server MUST set the first 16 bytes of the "ServerLegacySessionId"
to the value of ClientESNIInner.nonce.

## Split Mode Server Behavior

In Split Mode, the backend server must know the value of
ClientESNIInner.nonce to echo it back in the first 16 bytes
of the "ServerLegacySessionId". Appendix B of [@!ietf-tls-esni]
describes one mechanism to do so.

# Compatibility Issues

HESNI suffers from the same potential issues as explained in section 6 of
[@!ietf-tls-esni]. 

<TBD>
<Something about NAT?>

# Security considerations

The security properties of HESNI are similar to those of ESNI, as listed
in the Security Consideration section of [@!ietf-tls-esni], with one major
difference: HESNI is designed to not "stick out", and thus might succeed
even in the absence of large scale deployment of ESNI. There are however some
specific issues.

## Drawbacks of Conflating Session KeyShare and HESNI KeyShare

We understand the drawbacks of conflating the selection of key share for HESNI and for the
session. Among the known drawbacks:

* There is a potential downgrade attack, in which the attacker provides the client with
  a spoofed DNS record documenting ESNI encryption with a weaker group than preferred by
  the server. The client would be tricked into selecting that group for both the HESNI key
  and the session key.

* Many clients document just one key share. If they want to use HESNI, they are constrained
  to propose the same group for HESNI and for the session. This pushes all the private
  servers to allow negotiation of the same group chosen by the client facing server.

For the HESNI experiment, we intend to mitigate the first attack by server-side enforcement
of acceptable groups. The server knows what groups were genuinely published in the DNS, or
otherwise provisioned. It SHOULD refuse to accept attempts to use any other groups. We
do not intend to mitigate the second issue, and will just accept the contraint that
private servers cannot negotiate stronger encryption than accepted by the client facing
server.

## Drawbacks of Repurposing the Client Random

The ClientHello.Random field is used in TLS as a source of randomness when generating
key material. According to annex C.1. of [@!RFC8446], this field should be filled with
the output of a godd quality CSPRG, such as provided by the operating system. HESNI
deviates from that recommendation, as it fills the ClientHello.Random field with
the result of SNI encryption. However, this process probably meets the requirements
of [@?RFC4086], since the encryption includes multiple sources of randomness, including
the choice of the key shares and the value of the ClientESNIInner.nonce.

# IANA Considerations

This draft does not require any IANA action.

# Acknowledgements

TBD

{backmatter}
# draft-huitema-tls-hesni
Hidden variation of the ESNI draft

A procedure to encrypt the TLS Service Name Indication is described in https://github.com/tlswg/draft-ietf-tls-esni.
This procedure is sound, but it relies on adding an ESNI extension to the Client Hello. This extension is transmitted
in clear text. Its presence can be noticed by inspecting the traffic. There is a risk that censors will program
firewalls to block all connections using that extension. We develop here the Hidden ESNI (HESNI) alternative,
in which the encrypted SNI is hidden in the Client Hello, in an attempt to evade detection by censors and firewalls.

HESNI choses different design tradeoffs than the ESNI draft. With the draft
ESNI, the server can find in the ESNI extension all information needed to retrieve the original SNI. In contrast,
the server supporting HESNI  has to perform "trial decryption" on the incoming connection attempts to
find out whether HESNI is present.

The clients using HESNI hide the value of the key shares and the encrypted text in a small set of standard
fields in the Client Hello and its extensions. These fields have a relatively small size, which limits
the amount of data that can be conveyed. Given this small size, HESNI supports fewer options than ESNI.

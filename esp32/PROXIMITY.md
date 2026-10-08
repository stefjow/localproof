# Proximity tokens

A validation normally proves that a live browser at a plausible location
answered a fresh challenge. It cannot rule out an accomplice at the device
streaming the QR to someone elsewhere. Proximity tokens close the cheap
version of that gap: the person proving presence carries a small ESP32
token, and the station checks over ESP-NOW that the token answers its
challenges faster than a relay could.

## What a proximity-verified validation shows

That a token registered to the scanning account answered 24 timed
challenges from this station, with a median round trip under the limit,
within the QR's freshness window. The station signs this into the QR
payload (`ts|lat|lng|tokenId|medianRttUs`), so only the station can have
added it.

**It stops**

- Streaming the QR to a remote person (video call, photo, screen share):
  the remote token never hears the station.
- Bridging the station's radio traffic to a remote token over the
  internet: every round picks up tens of milliseconds and fails the limit.
- Replaying a recorded exchange, pre-asking the token with fake challenges,
  or claiming someone else's token key (see `tests/lpx_host_test.cpp`).
- Someone else scanning a QR that attests your token: they get an ordinary
  validation, never your proximity.

**It does not stop**

- Handing the token itself to the accomplice. Proximity proves the token
  was there, not the person.
- A cheater who reflashes their own token to leak its per-session secret
  to a device next to the station. Issue tokens with ESP32 Secure Boot and
  flash encryption enabled so holders can't run custom firmware.
- A radio relay that forwards the signal itself rather than packets, which
  adds microseconds. Only nanosecond time-of-flight (UWB secure ranging,
  802.15.4z) catches that.

## Proof without scanning

A token with Wi-Fi uploads the proof itself. After a passed exchange the
station sends the token the same signed code its QR shows (`LPX_ATTEST`),
and the token posts it to `/api/token-proof`. The station's signature names
the token, so the code can only ever credit that token's owner; the
endpoint needs no login, and anyone who gets hold of the code (a photo of
the QR, a sniffed frame) can at most credit the owner.

- **Late uploads count.** The timestamp comes from the station's GPS-set
  clock and is signed, so the server accepts codes up to 7 days old
  (`TOKEN_PROOF_MAX_AGE_SECONDS`). A token that saw no known network keeps
  up to 16 codes in NVS and uploads them the next time it is on near one.
  The validation is logged at the station's time, not the upload's; one
  that arrives more than 5 min late says "uploaded 3 h later" in its reason.
- **Counts once.** An upload and the owner's QR scan of the same code are
  one validation, whichever comes first. A token upload counts toward the
  station's `max_validations` like a scan.
- **One code per power-on.** The token is meant to be switched on next to a
  station and off again. After one code it stops answering stations, so a
  token left on doesn't log a validation every 30 s.
- **Failures aren't logged** (anyone can post to the endpoint); the token
  prints the server's status on serial and shows it on its LED.
- **Wi-Fi** is set in the Tokens panel, which writes up to 3 networks to the
  token over USB (`wifi-add`, `wifi-clear`, `status` on serial). They never
  reach the server. A phone hotspot lets the token upload at the station.
  The networks sit in NVS in plain text, like the software key.

The upload uses HTTPS validated against ISRG Root X1/X2
(`token/letsencrypt_roots.h`). The code needs no protection in transit;
validation only stops a fake server from telling the token to drop it.

## How the exchange works

Defined in `lpx_protocol.h`; the diagram at the top of that file is the
reference. In short: the token commits to 24 random bytes `m`, answers each
challenge byte `c` with `c XOR m[i]` (microseconds, no crypto), then
reveals `m` and signs the whole transcript. The station times each round
itself, so nothing the token says about time is trusted. The signature is
not timed because an ATECC608B takes tens of milliseconds to sign.

## Setting up

1. **Token hardware**: any ESP32 with an ATECC608B, provisioned like a
   station (locked, key in slot 0). Set `TOKEN_SDA`/`TOKEN_SCL` in
   `token/token.ino`. Without an ATECC the token makes a software key in
   NVS. That is fine for bench tests but can be cloned from flash.
2. **Install, register, Wi-Fi**: in the site's Tokens panel (Chrome or
   Edge on a desktop, token on USB): install the token firmware, Read from
   token, Register Token, and optionally add Wi-Fi networks. The panel
   also lists and revokes your tokens. By hand: flash `token/token.ino`,
   turn the `Pubkey:` line into a PEM with
   `python python_generator_v2.py pem <xy-hex>` and post it to `/add-token`.
3. **Flash** the station with the updated `esp32_code.ino`. Each 30 s
   cycle it now advertises for `LPX_WINDOW_MS` (3 s) before drawing the QR.
   Switch the token on near the station; the next QR carries the
   attestation, and the token uploads its copy if it has Wi-Fi.

## Calibrating the limit

The default limit is 3 ms. It comes from two classic ESP32s with the token
next to the station, where every session's median fell between 2050 and
2070 us (single rounds occasionally reach 5-7 ms; the median ignores them).
For other hardware, hold a token next to the station and watch serial for
lines like

```
LPX rtt us: 1830 1795 1902 ...
LPX PASS: token in range (token 38345a73, median 1850 us, max 2410 us)
```

over a few dozen sessions. Set `LPX_MAX_MEDIAN_RTT_US` (station) to about
the worst honest median plus 1 ms, and `MAX_TOKEN_RTT_US` (server
environment) to the same or lower. The server limit can be tightened
without reflashing stations.

## Costs and side effects

- **Battery**: the radio draws roughly 100 mA during the 3 s window, every
  cycle. Shorten `LPX_WINDOW_MS`, or wake on a button instead.
- **Flash**: the Wi-Fi stack grows the station image from about 360 KB to
  970 KB (73% of the default partition). The token, with HTTPS, is about
  1080 KB (82%).
- **QR size**: an attested URL can reach about 195 characters, past QR
  version 8's 192 bytes, so `drawQRCode` switches to version 9 (3 px
  modules) when needed. Check that phones still scan it on your display.
- Station and token must use the same `LPX_CHANNEL`, and
  `token/lpx_protocol.h` must stay identical to `lpx_protocol.h` (a test
  checks this).

## Status

Hardware-tested on 2026-10-08 with two classic ESP32s (station with
ATECC608B, token with a software key): sessions pass every cycle at a
median of about 2050 us, and QR version 9 scans fine on the e-paper. The
token upload (`LPX_ATTEST`, `/api/token-proof`) passed end to end against
the live server the same day. The LED states are untested: the bench
token's only LED shows serial activity, so `TOKEN_LED` drives nothing
there.

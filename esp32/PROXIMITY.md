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
2. **Flash** `token/token.ino` and copy the `Pubkey:` line from serial.
3. **Register** it to your account:
   ```bash
   python python_generator_v2.py pem <xy-hex>
   ```
   then, logged in on the site, run in the browser console:
   ```js
   fetch('/add-token', {method: 'POST', headers: {'Content-Type': 'application/json'},
     body: JSON.stringify({pubkey: `<paste PEM>`})}).then(r => r.json()).then(console.log)
   ```
   `GET /api/my-tokens` lists your tokens; `DELETE /delete-token/<id>`
   revokes a lost one.
4. **Flash** the station with the updated `esp32_code.ino`. Each 30 s
   cycle it now advertises for `LPX_WINDOW_MS` (3 s) before drawing the QR.
   Hold the token near the station; the next QR carries the attestation.

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
  970 KB (73% of the default partition).
- **QR size**: an attested URL can reach about 195 characters, past QR
  version 8's 192 bytes, so `drawQRCode` switches to version 9 (3 px
  modules) when needed. Check that phones still scan it on your display.
- Station and token must use the same `LPX_CHANNEL`, and
  `token/lpx_protocol.h` must stay identical to `lpx_protocol.h` (a test
  checks this).

## Status

Both sketches compile on Arduino-ESP32 core 3.3.12 for the classic ESP32,
and the protocol checks pass the host tests. Nothing has been run on
hardware yet, so radio timing, the default limit and QR scannability at
version 9 still need to be verified on real devices.

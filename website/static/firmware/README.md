# Web-flashable firmware

Files served to the ESP Web Tools install buttons: `manifest.json` (station,
Add Device panel) and `token-manifest.json` (proximity token, Tokens
panel). Both share the bootloader, partition table and `boot_app0.bin`,
which are identical for the two sketches. The `version` field in each
manifest is the git short SHA the binaries were built from.

## Rebuild

From the repo root. arduino-cli wants the main file named after its folder,
so the station sketch is built from a copy:

```bash
rm -rf /tmp/esp32_code && mkdir /tmp/esp32_code
cp esp32/esp32_code.ino esp32/lpx_*.h esp32/qrcodegen.[ch] /tmp/esp32_code/
arduino-cli compile --fqbn esp32:esp32:esp32 --output-dir build/station /tmp/esp32_code
arduino-cli compile --fqbn esp32:esp32:esp32 --output-dir build/token esp32/token
cp build/station/esp32_code.ino.bootloader.bin website/static/firmware/bootloader.bin
cp build/station/esp32_code.ino.partitions.bin website/static/firmware/partitions.bin
cp build/station/esp32_code.ino.bin            website/static/firmware/localproof.bin
cp build/token/token.ino.bin                   website/static/firmware/token.bin
```

`boot_app0.bin` comes from the ESP32 Arduino core
(`~/.arduino15/packages/esp32/hardware/esp32/<ver>/tools/partitions/boot_app0.bin`)
and does not change between builds.

Bump the `version` in both manifests to the new git SHA and commit.

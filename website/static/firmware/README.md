# Web-flashable firmware

Files served to the ESP Web Tools install button in the register popup.
The `version` field in `manifest.json` is the git short SHA the binaries
were built from.

## Rebuild

From the repo root:

```bash
arduino-cli compile --fqbn esp32:esp32:esp32 \
    --output-dir build esp32
cp build/esp32_code.ino.bootloader.bin website/static/firmware/bootloader.bin
cp build/esp32_code.ino.partitions.bin website/static/firmware/partitions.bin
cp build/esp32_code.ino.bin            website/static/firmware/localproof.bin
```

`boot_app0.bin` comes from the ESP32 Arduino core
(`~/.arduino15/packages/esp32/hardware/esp32/<ver>/tools/partitions/boot_app0.bin`)
and does not change between builds.

Bump the `version` in `manifest.json` to the new git SHA and commit.

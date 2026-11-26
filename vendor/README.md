# vendor/ — third-party files shipped with NetWatch

NetWatch used to load these from a CDN on every start. They now ship with the app, so the map works
with no Internet and nothing is requested from outside when you open NetWatch.

| File | Package | Version | SHA-256 (base64) |
|---|---|---|---|
| `d3.min.js` | [d3](https://github.com/d3/d3) | 7.9.0 | `8glLv2FBs1lyLE/kVOtsSw8OQswQzHr5IfwVj864ZTk=` |
| `topojson-client.min.js` | [topojson-client](https://github.com/topojson/topojson-client) | 3.1.0 | `Jc0CrkhsxQY+AhWk5M+xXeg3AMh6xIusTVfcaq8+u4k=` |
| `countries-110m.json` | [world-atlas](https://github.com/topojson/world-atlas) | 2.0.2 | `JRbJFYZ8e68Y3exyeuxGwxVUGgfPs9eaZVmwXV6U7ug=` |
| `countries-50m.json` | [world-atlas](https://github.com/topojson/world-atlas) | 2.0.2 | `BDQs3B4wFrzX2xYw3pVoTWe3n+PIxGAyHoeu9GlQI5Q=` |

The hashes are the ones published for these exact versions; `tests/test_vendor.py` fails if a file changes.
Files are unmodified. Licences: see `LICENSES.txt`.

To update a library: download the new version, replace the file, update the version and hash here and in the test.

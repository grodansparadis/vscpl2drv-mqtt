# Changes in vscpl2drv-mqtt

Every change that goes into a release is listed here, newest release first.
Add each change under **Unreleased** when it is made. When a release is
tagged, rename **Unreleased** to the version and date, and start a new
**Unreleased** section above it.

## Unreleased

- Add scripts/download-artifacts.sh to download and verify the newest CI build artifacts
- CI writes a SHA256SUMS-<artifact> checksum file into every uploaded build artifact
- Added CI artifact creation (556be94)
- Initial plan (591a508)
- Fix macOS build: replace sem_timedwait with portable sem_trywait fallback (4c070d7)
- Initial plan (132bcae)
- Added CI workflows (8d66bf3)
- Updated to work with latest vscp base code (5dcc046)
- Now using cmake (49e782a)
- Added checkout info (7fd5a09)
- Paths now realtive to submodule (ca9f121)
- Updated build instructions (67fb44d)
- Cleaned up (94f59d6)
- Ignoring config and make file (bd48f4f)
- Ignoring build files (f1739a7)
- Fixed type (5ddc279)
- Added build info (57e4f88)
- Updated fundings (2bb483b)
- Changed copyright year (d7571cf)
- Reading encryption key (3c7ad3a)
- Rearranged (e613d41)
- submodule update (b22483c)
- simple subscribe is now in place (cf3e1d0)
- pub/sub works (2ffd917)
- Adopted helper changes (d1fc127)
- publish functionality in place (0f618d2)
- mongoose removed (5374323)
- Removed mongoose submodule (8931450)
- Driver builds again (5b61921)
- Adopting submodules instead of copies (4e90518)
- using  submodules instead of copies (748dd22)
- Added submosule (fff8758)
- Reverting to /srv folder (e825a32)
- cleared rules (573276f)
- override dh_build (03fbea1)
- Adding buildflags to rules (6595174)
- Set verbose flag i rules (30a220d)
- Changed mean build tool from 11 to 10.2 (c240d63)
- Added confiog.log to gitignore (689b430)
- Fixed misspelled static file (8ba473f)
- Removed some junk (287f9ca)
- static now builds with dl (0679743)
- Remove all tag from toop make (3bcbbfa)
- Added static to install (5ed64d7)
- Removed default destdir setting from config (120c37e)
- removed override of auto install (94a32cf)
- changed install folder (5690b7e)
- Removed implicit autoreconf (9cd650a)
- Now removing static lib in 'clean' (5785c52)
- Added  readme for man page generation (a4dbd59)
- Removed some junk (4673042)
- deb file in sync with make (bffffba)
- ...and 9 earlier commits (see `git log`)

No release has been tagged yet.

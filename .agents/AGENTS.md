# Project Guidelines & Rules for console-web (NetWatch)

## Synchronous Versioning Rule (版本同步更新规范)

Whenever modifying, enhancing, or bumping project versions:
1. **Semantic Versioning (`MAJOR.MINOR.PATCH`)**:
   Always bump the version number according to [SemVer 2.0.0](https://semver.org/).

2. **Synchronous File Updates**:
   Must update the version string synchronously in all 3 authoritative locations:
   - [`app/config.py`](file:///c:/Users/Flanker/console-web/app/config.py): `__version__ = "X.Y.Z"`
   - [`setup.cfg`](file:///c:/Users/Flanker/console-web/setup.cfg): `version = X.Y.Z`
   - [`README.md`](file:///c:/Users/Flanker/console-web/README.md): Version badge URL & Changelog section entry.

3. **Validation**:
   Always run endpoint assertions on `/api/version/check` to ensure `parse_semver()` evaluates version comparison correctly before committing.

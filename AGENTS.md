# CleveresTricky Versioning Rules

When bumping versions for the CleveresTricky module, do NOT touch `update.json`. You must leave `update.json` completely unmodified.
Only update `build.gradle.kts` (e.g., `val verName by extra(...)`) and any other necessary files, but explicitly skip `update.json`.

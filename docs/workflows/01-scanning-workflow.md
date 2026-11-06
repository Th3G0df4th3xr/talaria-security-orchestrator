# Scanning Workflow

## 1. Purpose

Run a bounded, repeatable pattern-based scan against a registered/authorized local Git repository and persist its results.

## 2. Current flow

```text
Operator
  -> CLI/API scan request
  -> RepositoryService validates/registers path
  -> create scan record
  -> load Hunter Profile
  -> traverse eligible files
  -> apply enabled regex checks
  -> normalize/fingerprint matches
  -> deterministic investigation + remediation advice
  -> persist findings
  -> complete scan and write audit event
  -> return scan summary
```

## 3. Preconditions

- The operator is authorized to scan the repository.
- The path resolves to an existing Git working tree.
- The baseline profile exists and is valid.
- The database is writable and has passed integrity checks.
- The target repository is not modified by TALARIA.

## 4. File selection

The current scanner excludes common generated directories such as `.git`, virtual environments, `node_modules`, and Python caches. Rules specify file extensions and regex patterns. A per-file size limit is applied.

The current implementation still needs comprehensive limits for file count, aggregate bytes, wall-clock duration, symlink handling, regex complexity, and cancellation. Do not run it against untrusted massive repositories as a production service.

## 5. Finding creation

A match captures rule ID, title, severity, relative path, line number, and a bounded snippet. The normalizer computes a fingerprint. Investigation is deterministic and explicitly does not prove exploitability. The remediation advisor supplies guidance, not a patch.

## 6. Persistence and consistency

The scan record, findings, completion state, and audit event should be committed consistently. If any stage fails, the scan must be marked failed and partial results handled according to a documented transaction policy. Foreign-key enforcement must be enabled on every connection.

## 7. Operator verification

After a scan:
- Confirm scan ID and completion timestamp.
- Compare finding count with returned results.
- Inspect representative findings and source locations.
- Check audit event details.
- Run SQLite foreign-key and integrity checks during diagnostics.
- Confirm source repository status is unchanged.

## 8. Interpretation

A regex match is a candidate signal. Validate context manually before treating it as a vulnerability. Absence of a match does not prove that the repository is secure.

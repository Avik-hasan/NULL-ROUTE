## Description
Please include a summary of the change and which issue (if any) is fixed. Please also include relevant motivation and context.

Fixes #(issue)

## Type of change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Security & Fail-Safety Checklist
- [ ] This change maintains zeroization of sensitive cryptographic key material in memory (`Zeroize`).
- [ ] System network state (routing, DNS, WFP filters) is properly protected by RAII guards or registered in `CleanupRegistry` for crash/panic restoration.
- [ ] The Windows named pipe DACL continues to restrict access exclusively to `SYSTEM` and the interactive session user.
- [ ] `cargo check --workspace` and `cargo test --workspace` pass locally without warnings.

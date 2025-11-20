# Release Process

> - **Development:** `x.y.z-dev`  
> - **Release Candidate:** `x.y.z-rc`  
> - **Final Release:** `x.y.z`  
> - **After RC creation:** Increment the minor version for further development (`x.(y+1).0-dev`)

---

## Introduction

This release flow provides a clear, predictable, and stable progression from development builds to final releases.

Releases always fall into one of three categories:
- **Development** – ongoing work, unstable features.
- **Release Candidate** – validation phase, used for QA, privacy, and security audits.  
- **Final Release** – production-ready version, approved after the checklist is complete.  

By following this naming scheme, the release phase is always explicit.  
A release candidate represents the version being validated, while a final release confirms that it has successfully passed all checks.

In the diagram below an example is drawn out where features are merged to the main branch.
At a certain point the decision is made to create a final release. At that moment `v4.1.0-rc` tag is created.
If additional work is required by QA, privacy or security on the RC a release branch will be created.
Work done on the release branch always needs to be merged back to the main branch. Even if the feature is not in main 
anymore. In the merge to the main branch this conflict can be resolved. This will make sure that this conflict does
not come up later when a new hotfix is applied that should be merged back.

```mermaid
---
config:
  logLevel: 'debug'
  theme: 'base'
  gitGraph:
    rotateTagLabel: true
    diagramPadding: 32
    showCommitLabel: false
---
gitGraph:
    commit id:"" tag: "v4.1.0-dev.143"
    branch feature/long
    checkout feature/long
    commit
    checkout main
    branch feature/new
    checkout main
    branch feature/another
    commit
    checkout feature/new
    commit
    checkout feature/another
    commit
    checkout main
    merge feature/new tag: "v4.1.0-dev.144"
    branch feature/awesome
    checkout feature/awesome
    commit
    checkout main
    merge feature/another tag: "v4.1.0-dev.145" tag: "v4.1.0-rc"
    branch release/4.1
    checkout feature/awesome
    commit
    checkout main
    merge feature/long tag: "v4.2.0-dev"
    checkout release/4.1
    checkout feature/awesome
    commit
    checkout release/4.1
    branch rc-fix/4.1-fix
    commit
    checkout release/4.1
    merge rc-fix/4.1-fix tag: "v4.1.0-rc.1"
    checkout main
    merge release/4.1 tag: "v4.2.0-dev.1"
    checkout rc-fix/4.1-fix
    commit
    checkout release/4.1
    merge rc-fix/4.1-fix tag: "v4.1.0-rc.2" tag: "v4.1.0"
    checkout main
    merge release/4.1 tag: "v4.2.0-dev.2"
    checkout feature/awesome
    commit
    checkout main
    merge feature/awesome tag: "v4.2.0-dev.3"
    checkout release/4.1
    branch hotfix/something-broken
    commit
    checkout release/4.1
    merge hotfix/something-broken tag: "v4.1.1-rc"
    checkout main
    merge release/4.1 tag: "v4.2.0-dev.4"
    checkout hotfix/something-broken
    commit
    checkout release/4.1
    merge hotfix/something-broken tag: "v4.1.1-rc.1" tag: "v4.1.1"
    checkout main
    merge release/4.1 tag: "v4.2.0-dev.5"
    checkout hotfix/something-broken
    commit
    checkout release/4.1
    merge hotfix/something-broken tag: "v4.1.2-rc" tag: "v4.1.2"
    checkout main
    merge release/4.1 tag: "v4.2.0-dev.6"
```

---

### Release reliability

> [!IMPORTANT]  
> Use only **Final releases** on production environments. 

Do not make any assumptions on non **Final releases**. During the development phase pre-releases are created to test and
validate the software. Only when the software is **Final** you can assume that the checks are performed and approved
by QA, Privacy and Security.

## Development Phase

During development, versions use the `-dev` suffix.  
This marks them as unstable and not yet ready for production.  

Example version flow:
  - `3.0.4-dev`  
  - `3.0.4-dev.1`  
  - `3.0.4-dev.2`

---

## Release Candidate Phase

When a release is prepared, the first release candidate (RC) is created from the current development version.  
RCs use the `-rc` suffix and represent versions that are feature-complete but still under validation.  

When additional work needs to be done on a release candidate,
a dedicated branch is created for the release, for example: `release/3.1`  

Example progression:
  - `3.1.0-rc`
  - `3.1.0-rc.1`
  - `3.1.0`
  - `3.1.1-rc`
  - `3.1.1-rc.1`

During this release the following checklists are executed. 

- [QA](qa-release-checklist.md)
- [Privacy](privacy-release-checklist.md)
- [Security](security-release-checklist.md)

---

## Final Release

Once the release candidate has successfully passed the full checklist, it is promoted to a final release.  
The `-rc` suffix is removed, resulting in the stable version.  
For example: `3.1.2`. 

---

## Post-Release Development

After the first release candidate is created, the minor version is always incremented for ongoing development.  
This ensures that feature development continues separately from release stabilization.  
For example, after creating `3.1.0-rc`, development continues with `3.2.0-dev`.

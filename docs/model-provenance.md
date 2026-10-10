# Model provenance

This document records which ONNX model binaries exist in this repository and in the artifacts derived from it, and where each one was used. It covers every `.onnx` file tracked in any branch of `logSguarDian` (local and remote), the copies vendored in the sibling repo `logSguarDian-vulnerable-project`, and the published npm package `logsguardian@0.1.0`.

**Method.** Hashes are SHA-256 of the blob content, computed with `git show <commit>:<path> | shasum -a 256` (not the working tree). npm contents were obtained with `npm pack logsguardian@0.1.0` and hashed after extraction. Vendored copies in the vulnerable app were hashed the same way from their commits, and from inside their `vendor/*.tgz`.

**Evidence status.**
- **verified**: reproduced from git or npm object content.
- **unverified**: depends on inference, on prose in documents, or on a run whose inputs are not recorded. Not reproduced here.

## 1. Model pairs

| Pair | `rf.onnx` sha256 | `if.onnx` sha256 | Version | Origin (commit, date) | Where used | Evidence |
|---|---|---|---|---|---|---|
| A | `180837255dffd596a38bf7c29032ccc313005cd70eca5c6238e23e35bdc0d4ec` | `5de374a7f1d19176d7c66d3354e972d37b28a7306a87efa0ce8639278f489150` | rf_v10 / if_v9 | `dc2aaa656e0294b2a4c520ccbd6bf193b956280b`, 2026-08-02, on `develop` | npm `logsguardian@0.1.0`: verified, the tarball contains this pair. Vulnerable app `vendor/logsguardian-0.1.0.tgz` at `4f513a7` and `06316cb`, and `models/` at `06316cb`: verified. Branch `feat/config3-waf-plus-logsguardian` `models/`: verified. Config 3b (`docs/config3b-results.md`, header says rf_v10/if_v9): the label is from prose, the models are verified by the branch tree. | Hashes verified in npm tarball and repo trees. Version label from commit message `dc2aaa6` and prose. |
| B | `a7c015f5a5fa3fabfd91b79ec9338dc7da6a68c392c19ded4b04cc6f0fb903b2` | `3cf8e45c285de19bc86e6dc284e502cd2c24becb888747b9645bed4cfb224417` | rf_v11 / if_v10 (first build) | `734c24fe8cbe51e9f6142e06e91e1798bac8d8df`, 2026-08-30, on `develop` | Vulnerable app `models/` at `14c0e15` (2026-09-09), and on branches `main`, `docs/latency-linux-evidence`, `docs/cmdi-sqli-confusion-rfv11-remeasure`: verified. Vendor tarball `c8b975b2…` on those branches contains this pair: verified. Linux native latency run (2026-09-26, `docs/cybersecurity-objectives-compliance.md`): **unverified**, the run's commit is not recorded; only the branch tree is verified. Config 2 with rf_v11 in `docs/config2-results-v1.md`: **unverified**, see §4. | Hashes verified from git. Version label from commit message `734c24f`. |
| C | `25b407e649283606a231665a5a8c8ea1c2c7ad4fd0374a8945b3f119651b0870` | `5be28ee8437643b2f13708eee1ac3175348a350ea6fb8f8daeb09bd5717f797e` | rf_v11 / if_v10 (current on `develop`) | `03de50f00d8aae7e365bf78fb561f6250ca9efa6`, 2026-09-26, on `develop`. The same blobs also appear in `244e1f7` (2026-09-26), which is **not** an ancestor of `develop`. | `training/models/*.onnx` on `develop`: verified. `training/results/v11_test_results.json` fields `rf_onnx_sha256` and `if_onnx_sha256`: verified, both match this pair. `training/models/parity_report.json` (tracked) names rf_v11 / if_v10 but has no hash field. `03de50f` also adds `training/retrain_v11_contract69.py` and changes both binaries, which supports the description "retrain of 2026-09-26": verified from `git show --stat`. npm 0.1.0: **not used**, see §4. Vulnerable app: not found in any branch checked. Round 5 evaluation: **unverified**, see §3. | Hashes verified from git and JSON. |
| Baseline | `a4dddbb778d40b37ed934e2625c910806df75dee8732d179dcb4f2ff0e54bd54` (`rf_current_split`) | `6fd2017613aa0da4d7e7fcced55989bdefe1704ade904987033491b07d151a60` (`if_current_split`) | Not a deployed version. Name only; **unverified** that it is `rf_v11` or any other version. | `fc47a5b`, 2026-09-25, on `develop` | `training/models/baselines/`. Not in the npm tarball and not in any vendored copy checked: verified. Use in `docs/model-comparison.md`: **unverified** beyond the commit message. | Hashes verified from git. |
| Baseline | `659c814537291c3098910c114532e564420baa73ccdab73df75b8c49e0d6c356` (`mlp`) | — | Baseline. Not deployed. | `fc47a5b`, 2026-09-25 | `training/models/baselines/mlp.onnx`. Not in npm or vendored copies: verified. | Hash verified from git. |
| Baseline | `18602bbf91d06f78886d59f13be0846ddf679f8ea49823baa8404009ea8e370e` (`autoencoder`) | — | Baseline. Not deployed. | `fc47a5b`, 2026-09-25 | `training/models/baselines/autoencoder.onnx`. Not in npm or vendored copies: verified. | Hash verified from git. |

Other models used in the vulnerable app's history:

| Pair | `rf.onnx` sha256 | `if.onnx` sha256 | Version (from commit subject / docs) | Where used | Evidence |
|---|---|---|---|---|---|
| R4 | `7fba60bb36e5d6671417acb182c0138909e86c84190cead12c662594c9b2d271` | `6bc02cf1ce153a545ccbe38942ee7813ea26c9adaf9faae656319967d099b98c` | rf_v4 / if_v3 | Vulnerable app `models/` at `640d9b2` (2026-07-24) | Hashes verified. Version label from `docs/config2-results.md` Run 2 and commit message. |
| R3 | `77e1f63c40fd093df9404d68458180cdb31bb71568e278e7dd986d6fbb92534a` | `e4bc29c1c39ab85254fb7087d2c2cd5347f4d9f7917d55cad23a319c6b25d084` | rf_v3 (logSguarDian `e74a8c6`, "full retrain v3") | Vulnerable app `models/` at `d9d25b2` (2026-07-24). `docs/config2-results.md` Run 1 labels these rf_v3 / if_v2. | Hashes verified. The `if_v2` label is **unverified**: the `if.onnx` hash equals the one from `e74a8c6`, which the commit subject labels as v3. |

## 2. Full history

### 2.1 `training/models/rf.onnx` and `training/models/if.onnx` in `logSguarDian`

Every commit that changed either file, oldest first. `(develop)` marks commits that are ancestors of `develop`. `244e1f7` is not, and carries the same blobs as `03de50f`.

| Commit | Date | Subject | rf.onnx sha256 | if.onnx sha256 | rf bytes | if bytes |
|---|---|---|---|---|---|---|
| `ca10c3d` (develop) | 2026-06-11 | feat(training): complete ML training pipeline — models trained, parity | `d9ffebe28da10ad7f837ed52f2d0207f3b62dc8a8e362038d71060fdb437cb55` | `436e6c9b2c870f52c7ef06d387ca88c88e4becb7a97aa433515d1e891f08aa9d` | 46281801 | 1047888 |
| `7e36942` (develop) | 2026-06-14 | fix: resolve F4.4 memory gate via model size reduction | `3a04d9e730c977b038a4b7d5859a1dc3adb3389502533d0d32acc9d313c80b96` | `436e6c9b2c870f52c7ef06d387ca88c88e4becb7a97aa433515d1e891f08aa9d` | 11326890 | 1047888 |
| `e74a8c6` (develop) | 2026-07-23 | feat: E2E detection suite + full retrain v3 (F5.7 GATE PASS) | `77e1f63c40fd093df9404d68458180cdb31bb71568e278e7dd986d6fbb92534a` | `e4bc29c1c39ab85254fb7087d2c2cd5347f4d9f7917d55cad23a319c6b25d084` | 11923702 | 1031516 |
| `744f8d5` (develop) | 2026-07-24 | feat(models): retrain rf_v4 + if_v3 on corrected feature space | `7fba60bb36e5d6671417acb182c0138909e86c84190cead12c662594c9b2d271` | `6bc02cf1ce153a545ccbe38942ee7813ea26c9adaf9faae656319967d099b98c` | 11389593 | 1001282 |
| `e7924ce` (develop) | 2026-07-24 | feat(models): retrain rf_v5 + if_v4 on percent-decoded XSS features | `031e26ef82e55c0d723c741bd17ff3d8352eedf95378e610c5761344f7f59ad0` | `4b73497c9f2a1d01efae2212f109f5d3c4be7ccc0cebf44eec236f777784d398` | 10996383 | 997159 |
| `877f129` (develop) | 2026-07-24 | feat(models): retrain rf_v6 + if_v5 on per-field body analysis feature | `b98025576b1a7eaaf41441800b558c5f9620526610c04981cb9e2d59f442ba36` | `9706dc7f4c21fb0f1ad2c1ae553f0cda7622b57f38750220fe4b683e1be9203e` | 10459420 | 1047622 |
| `81c75cc` (develop) | 2026-07-25 | feat(models): retrain rf_v7 + if_v6 on the tie-break fix | `1b0970b0f3a48ab84612aa1067841527f04a01d0a6013c06205931d985d6e605` | `753b70bab07f0f5ebe22b4d7b4ca7c3d254b031171a860866eb2bd3432b4abdd` | 10330416 | 1036689 |
| `392916e` (develop) | 2026-07-25 | feat: v8 retrain — dual feature vectors, non_form_operator_count, stab | `f1e9e181e3a1d41a1884fdbb4f1d5db128ae8afded08234da314d43f86fcc056` | `ae3ca30454d92054061bd5ca29a80c79e5253e154ae4d50fb4c977c50578936a` | 10373085 | 1946637 |
| `0bdb56b` (develop) | 2026-07-26 | feat: v9 retrain — recursive decode + deriveRawPayload fix + real cmdi | `b4da46aeeb52880baa3dc5042faf1b61041a2bc5dceaeb3177e11a60d4a3e902` | `e36522cb7509be20933b6ccb1a416478c6e2be32ba511242b91d78eb608a78a6` | 9132701 | 1962864 |
| `dc2aaa6` (develop) | 2026-08-02 | feat: retrain v10 with cmdi minimal-context fix (RF v10 + IF v9) | `180837255dffd596a38bf7c29032ccc313005cd70eca5c6238e23e35bdc0d4ec` | `5de374a7f1d19176d7c66d3354e972d37b28a7306a87efa0ce8639278f489150` | 9091595 | 1999160 |
| `734c24f` (develop) | 2026-08-30 | feat: v11 retrain — rf_v11 + if_v10 with Windows/compound cmdi fix | `a7c015f5a5fa3fabfd91b79ec9338dc7da6a68c392c19ded4b04cc6f0fb903b2` | `3cf8e45c285de19bc86e6dc284e502cd2c24becb888747b9645bed4cfb224417` | 8833043 | 2094695 |
| `244e1f7` | 2026-09-26 | fix: re-derive orphaned rf_v11/if_v10 test-set numbers, close split-pr | `25b407e649283606a231665a5a8c8ea1c2c7ad4fd0374a8945b3f119651b0870` | `5be28ee8437643b2f13708eee1ac3175348a350ea6fb8f8daeb09bd5717f797e` | 8904933 | 2158297 |
| `03de50f` (develop) | 2026-09-26 | fix: re-derive orphaned rf_v11/if_v10 test-set numbers, close split-pr | `25b407e649283606a231665a5a8c8ea1c2c7ad4fd0374a8945b3f119651b0870` | `5be28ee8437643b2f13708eee1ac3175348a350ea6fb8f8daeb09bd5717f797e` | 8904933 | 2158297 |

### 2.2 `models/` and `vendor/` in `logSguarDian-vulnerable-project`

Every commit that changed `models/*.onnx` or `vendor/logsguardian-0.1.0.tgz`, with the `.onnx` files found inside each tarball. Tarball contents show `none` where the tarball has no `.onnx` file.

| Commit | Date | models/rf.onnx | models/if.onnx | vendor/logsguardian-0.1.0.tgz contents (rf / if) |
|---|---|---|---|---|
| `14c0e15` | 2026-09-09 | `a7c015f5a5fa3fabfd91b79ec9338dc7da6a68c392c19ded4b04cc6f0fb903b2` | `3cf8e45c285de19bc86e6dc284e502cd2c24becb888747b9645bed4cfb224417` | `a7c015f5a5fa3fabfd91b79ec9338dc7da6a68c392c19ded4b04cc6f0fb903b2` / `3cf8e45c285de19bc86e6dc284e502cd2c24becb888747b9645bed4cfb224417` |
| `4f513a7` | 2026-08-16 | `180837255dffd596a38bf7c29032ccc313005cd70eca5c6238e23e35bdc0d4ec` | `5de374a7f1d19176d7c66d3354e972d37b28a7306a87efa0ce8639278f489150` | `180837255dffd596a38bf7c29032ccc313005cd70eca5c6238e23e35bdc0d4ec` / `5de374a7f1d19176d7c66d3354e972d37b28a7306a87efa0ce8639278f489150` |
| `06316cb` | 2026-08-05 | `180837255dffd596a38bf7c29032ccc313005cd70eca5c6238e23e35bdc0d4ec` | `5de374a7f1d19176d7c66d3354e972d37b28a7306a87efa0ce8639278f489150` | `180837255dffd596a38bf7c29032ccc313005cd70eca5c6238e23e35bdc0d4ec` / `5de374a7f1d19176d7c66d3354e972d37b28a7306a87efa0ce8639278f489150` |
| `99eef5d` | 2026-07-30 | `b4da46aeeb52880baa3dc5042faf1b61041a2bc5dceaeb3177e11a60d4a3e902` | `e36522cb7509be20933b6ccb1a416478c6e2be32ba511242b91d78eb608a78a6` | none / none |
| `8dbfe00` | 2026-07-30 | `b98025576b1a7eaaf41441800b558c5f9620526610c04981cb9e2d59f442ba36` | `9706dc7f4c21fb0f1ad2c1ae553f0cda7622b57f38750220fe4b683e1be9203e` | none / none |
| `640d9b2` | 2026-07-24 | `7fba60bb36e5d6671417acb182c0138909e86c84190cead12c662594c9b2d271` | `6bc02cf1ce153a545ccbe38942ee7813ea26c9adaf9faae656319967d099b98c` | none / none |
| `d9d25b2` | 2026-07-24 | `77e1f63c40fd093df9404d68458180cdb31bb71568e278e7dd986d6fbb92534a` | `e4bc29c1c39ab85254fb7087d2c2cd5347f4d9f7917d55cad23a319c6b25d084` | none / none |

## 3. Other places

- **npm `logsguardian@0.1.0`.** Verified: contains `package/models/rf.onnx` = `180837255dffd596a38bf7c29032ccc313005cd70eca5c6238e23e35bdc0d4ec` and `package/models/if.onnx` = `5de374a7f1d19176d7c66d3354e972d37b28a7306a87efa0ce8639278f489150`. This is pair A, the rf_v10 / if_v9 pair, not pair C.
- **`packages/core/models/`.** The `*.onnx` files there are git-ignored (`.gitignore`, line 68) and never committed. `docs/architecture.md` says they are copied from `training/models/` before build and publish. The contents of any local build are **unverified**.
- **Round 5 (clean corpus, Config 2 only)**, `docs/config3b-results.md` in `logSguarDian-vulnerable-project`. The section does not name a model version, and no Round 5 run record was found with a vendor hash. Which model Round 5 used is **unverified**. Settling it requires the branch and commit where Round 5 ran, then its vendored hash.
- **Config 1** (`docs/baseline-config1.md`): no logSguarDian middleware, so no model is involved.
- **Config 2 and Config 3b**: Config 3b is pair A per its branch tree (§1). Config 2 depends on the branch; the vulnerable app's `main` branch is pair B (verified). See §4 for the Config 2 claim that does not match.

## 4. Addendum (2026-10-09): corrections to earlier claims

Each entry below was checked against the git and npm evidence above. Entries marked **Corrected** change what an earlier document says. Entries marked **Confirmed** support it. This PR does not edit the documents named here; the corrections are recorded so the documents can be fixed in follow-up commits.

1. **Corrected.** `training/results/v11_test_results.json`, field `eval_note`, says the R2 test read used "the ONNX models actually published in npm". This is false. The npm package `logsguardian@0.1.0` contains pair A (`180837255dffd596a38bf7c29032ccc313005cd70eca5c6238e23e35bdc0d4ec`, `5de374a7f1d19176d7c66d3354e972d37b28a7306a87efa0ce8639278f489150`), not pair C (`25b407e649283606a231665a5a8c8ea1c2c7ad4fd0374a8945b3f119651b0870`, `5be28ee8437643b2f13708eee1ac3175348a350ea6fb8f8daeb09bd5717f797e`), which the same file lists as the evaluated models. The hashes in that file are correct for pair C. Only the claim about npm is wrong. Any thesis text that cites the R2 read as the npm model must say pair C was evaluated and that npm ships pair A.
2. **Corrected.** `docs/cybersecurity-objectives-compliance.md`, the Linux latency section, says the vendored `rf.onnx` (`a7c015f5…`, pair B) was probably "synced earlier the same day (2026-09-26), before the PR #79 orphan fix". The git history contradicts this. Pair B was copied into the vulnerable app at `14c0e15` on 2026-09-09, and the binary itself dates from `734c24f` on 2026-08-30. No vendor sync in the vulnerable repo's branches checked is dated 2026-09-26. The reason pair B differs from pair C is the retrain in `03de50f`, not a same-day sync.
3. **Confirmed.** The same document's header says the current `rf.onnx`/`if.onnx` is a 2026-09-26 retrain verified by checksum. The checksum part holds (§1, pair C). The retrain part holds: `03de50f` changes both binaries and adds `training/retrain_v11_contract69.py`.
4. **Corrected.** `docs/config2-results-v1.md` states that the container's loaded ONNX files matched `training/models/*.onnx` on `develop` byte for byte. Its commit reference is not given. The vulnerable app's vendored models were pair B at `14c0e15` (2026-09-09) and on `main`. They are not pair C, which is current on `develop`. The match therefore holds only against a `develop` snapshot that contained pair B, and the document should name that snapshot.

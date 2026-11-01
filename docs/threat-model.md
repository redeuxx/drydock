# Drydock threat model

Drydock backs up and restores containers on Docker hosts it reaches through a socket proxy or over SSH. Anyone who controls drydock controls every host it manages: it can create containers with any bind mount. This document lists the threats drydock defends against, how it defends, and the automated tests that prove each defence. `tests/test_threat_model.py` fails if a threat names no test or names a test that does not exist.

## Assets

- **Managed hosts.** Drydock's Docker access is root-equivalent on each of them.
- **The secret key** (`DRYDOCK_SECRET_KEY`). It encrypts stored credentials, signs archives and derives every archive passphrase.
- **Stored credentials.** SSH private keys, storage passwords and tokens, notification URLs.
- **Archives.** They hold container data, images, compose files and environment variables, which often include secrets.
- **The database and `/data`.** Users, sessions, jobs, the audit log, staged restores and uploads.
- **Availability of managed containers.** Backups stop or pause them, and restores replace them.

## Attackers

1. **Network attacker.** Reaches the drydock port but has no account. By default the port binds to 127.0.0.1 only.
2. **Cross-site attacker.** Controls a web page that a logged-in user visits.
3. **Lower-privileged user.** Has a viewer, operator or admin account and wants more.
4. **Malicious archive source.** Controls an archive on storage, an upload or a file in the restore inbox.
5. **Hostile network path.** Sits between drydock and an SSH host or a remote storage server.
6. **Compromised container.** Controls what a managed container reports to Docker (names, labels, compose files) or prints from a hook.
7. **Local reader.** Can read the `/data` volume or a database dump, but not the secret key.

## Trust boundaries

- Browser to drydock: sessions, CSRF tokens, `Origin` and `Sec-Fetch-Site` checks, CSP, the `Host` allowlist.
- Drydock to Docker: the socket proxy for the local host, a pinned-key SSH forward for remote hosts.
- Drydock to storage: an allowlist of local roots, and rclone over a private socket with a fixed option allowlist and pinned host keys or certificates.
- Archives to drydock: signatures, checksums and tar structure checks, then a second pass bound to the same file.
- Restore plans to hosts: path denylists, risk flags that need a superadmin, and a plan digest the user confirms.

## Threats

### T1. Taking over a fresh install through the setup wizard

**Threat:** while no account exists, anyone who reaches `/setup` becomes superadmin. A DNS rebinding page could reach it through a victim's browser.
**Defence:** the port binds to 127.0.0.1, every route redirects to `/setup` until it completes, setup runs under `BEGIN IMMEDIATE` so exactly one superadmin is created, a warning is logged at every start, the `Host` header must be on the allowlist, and the source IP is audited.
**Tests:**
- `tests/test_setup.py::test_everything_redirects_to_setup_before_first_user`
- `tests/test_setup.py::test_startup_warns_while_no_superadmin`
- `tests/test_setup.py::test_concurrent_setup_creates_exactly_one_superadmin`
- `tests/test_setup.py::test_setup_audit_row_records_source_ip`
- `tests/test_csrf.py::test_foreign_host_header_gets_400`
- `tests/test_deploy.py::test_compose_binds_loopback_and_hardens_the_container`

### T2. Guessing passwords and finding usernames

**Threat:** an attacker guesses passwords, or learns which usernames exist from timing or error messages.
**Defence:** Argon2 hashes, a dummy verify for unknown users, identical failures, a limit of 10 failures per 15 minutes per username and IP, and `X-Forwarded-For` honoured only from `FORWARDED_ALLOW_IPS`.
**Tests:**
- `tests/test_login.py::test_wrong_username_and_wrong_password_look_identical`
- `tests/test_login.py::test_failed_login_never_stores_the_submitted_username`
- `tests/test_login.py::test_disabled_user_gets_the_same_failure`
- `tests/test_login.py::test_eleventh_failure_is_rate_limited`
- `tests/test_login.py::test_forwarded_for_ignored_from_untrusted_peer`
- `tests/test_login.py::test_forwarded_for_honored_from_trusted_proxy`
- `tests/test_login.py::test_reverse_proxy_without_trusted_proxy_warns`

### T3. Stealing or fixing a session

**Threat:** an attacker reuses a stolen or planted session token, or a session outlives a password or role change.
**Defence:** 32-byte opaque tokens stored only as sha256, rotation at login, 1 h idle and 12 h absolute timeouts, `__Host-` cookies that are `Secure`, `HttpOnly` and `SameSite=Lax`, and revocation on password, role or disabled changes.
**Tests:**
- `tests/test_login.py::test_login_rotates_session_and_stores_only_hashes`
- `tests/test_login.py::test_idle_and_absolute_timeouts`
- `tests/test_login.py::test_logout_ends_the_session`
- `tests/test_login.py::test_password_change_revokes_other_sessions`
- `tests/test_users.py::test_role_change_disable_and_reset_revoke_sessions`
- `tests/test_cookies.py::test_secure_host_cookies_for_loopback_and_https`
- `tests/test_cookies.py::test_plain_http_lan_address_drops_secure_and_warns`

### T4. Cross-site request forgery

**Threat:** a page on another site makes the user's browser change something in drydock.
**Defence:** a synchronizer token on every unsafe request after login, a double-submit cookie before login, and `Origin` and `Sec-Fetch-Site` checks on both.
**Tests:**
- `tests/test_csrf.py::test_setup_presession_csrf`
- `tests/test_csrf.py::test_login_presession_csrf`
- `tests/test_csrf.py::test_post_login_csrf_header_and_field`
- `tests/test_routes.py::test_every_unsafe_route_rejects_missing_csrf_and_cross_site`
- `tests/test_uploads.py::test_a_missing_csrf_header_gets_403`

### T5. A route that skips its checks

**Threat:** a new route ships without a session check, a role check, CSRF or an audit record.
**Defence:** every route must appear in the route inventory with its minimum role. The inventory tests read each route's dependencies and then call every route as each lower role.
**Tests:**
- `tests/test_routes.py::test_every_route_is_classified`
- `tests/test_routes.py::test_every_private_route_requires_a_session`
- `tests/test_routes.py::test_every_route_refuses_every_role_below_its_minimum`
- `tests/test_routes.py::test_every_unsafe_route_audits_its_success`
- `tests/test_routes.py::test_nothing_is_served_outside_the_inventory`

### T6. A lower role gaining more power

**Threat:** a viewer, operator or admin does something reserved for a higher role, or the last superadmin is removed.
**Defence:** the role matrix is enforced on the server for every route. The last superadmin cannot be demoted, disabled or deleted. Hooks, users, notification targets, remote storage and passphrase reveals are superadmin only.
**Tests:**
- `tests/test_routes.py::test_role_matrix`
- `tests/test_routes.py::test_every_route_refuses_every_role_below_its_minimum`
- `tests/test_users.py::test_last_superadmin_is_protected`
- `tests/test_restore_routes.py::test_operator_cannot_restore_or_cancel_restores`
- `tests/test_uploads.py::test_viewers_and_operators_get_403`
- `tests/test_uploads.py::test_viewers_and_operators_cannot_restore_an_upload`
- `tests/test_hooks_routes.py::test_hook_edits_need_superadmin_and_recent_auth`
- `tests/test_hooks_routes.py::test_viewers_see_hook_names_but_never_argv`
- `tests/test_hosts_routes.py::test_hosts_are_admin_only_but_the_inventory_is_not`
- `tests/test_scheduler.py::test_preview_is_for_admins_only`

### T7. An unattended session doing something dangerous

**Threat:** someone at an unlocked browser changes roles, reveals a passphrase, edits hooks or overwrites a container.
**Defence:** these actions need the password re-entered within the last 10 minutes.
**Tests:**
- `tests/test_users.py::test_role_change_requires_recent_auth`
- `tests/test_users.py::test_user_creation_requires_recent_auth`
- `tests/test_jobs.py::test_passphrase_reveal_needs_superadmin_and_recent_auth`
- `tests/test_hosts_routes.py::test_changes_need_recent_auth`
- `tests/test_remote_storage.py::test_remote_storage_is_changed_by_superadmins_with_recent_auth`
- `tests/test_notify.py::test_targets_are_edited_by_superadmins_with_recent_auth`
- `tests/test_gdrive_storage.py::test_only_superadmins_with_recent_auth_connect`
- `tests/test_restore_routes.py::test_overwrite_needs_typed_name_and_recent_auth`
- `tests/test_restore_routes.py::test_data_only_needs_recent_auth`

### T8. Side effects from GET requests

**Threat:** a link, prefetch or image tag changes state, which CSRF checks do not cover.
**Defence:** GET routes write nothing except `sessions.last_seen_at`. The only exception is the OAuth callback, guarded by a single-use state bound to the user.
**Tests:**
- `tests/test_routes.py::test_get_routes_write_nothing_but_last_seen`
- `tests/test_routes.py::test_restore_plan_page_writes_nothing_in_any_state`
- `tests/test_gdrive_storage.py::test_starting_is_a_post`
- `tests/test_gdrive_storage.py::test_listing_a_refused_drive_writes_nothing`

### T9. Open redirects

**Threat:** a crafted `next` value or `Referer` sends the user to another site after they enter a password.
**Defence:** redirect targets must be absolute paths on drydock with no scheme, host, backslash or control character.
**Tests:**
- `tests/test_routes.py::test_redirect_targets_stay_on_drydock`
- `tests/test_users.py::test_role_change_requires_recent_auth`

### T10. Script injection and framing

**Threat:** a username, container name, label, archive name, hook argument or log line carries HTML or script, or drydock is framed for clickjacking.
**Defence:** autoescaped templates, a nonce-based CSP with Trusted Types and `frame-ancestors 'none'`, no inline scripts or styles, no external assets, and htmx gated on the page nonce so injected markup cannot send requests. Run logs escape control characters.
**Tests:**
- `tests/test_headers.py::test_csp_and_security_headers_everywhere`
- `tests/test_headers.py::test_csp_nonce_is_fresh_and_matches_the_page`
- `tests/test_headers.py::test_every_htmx_element_carries_the_page_nonce`
- `tests/test_headers.py::test_templates_have_no_inline_script_or_style`
- `tests/test_headers.py::test_templates_have_no_external_urls`
- `tests/test_headers.py::test_templates_load_only_the_bundled_assets`
- `tests/test_users.py::test_usernames_render_escaped`
- `tests/test_hosts_routes.py::test_escaping`
- `tests/test_restore_routes.py::test_archive_strings_are_escaped`
- `tests/test_hooks_routes.py::test_hook_argv_is_shown_escaped`
- `tests/test_jobs.py::test_run_log_redacts_secrets_and_escapes_control_characters`

### T11. Exhausting memory, disk or connections with request bodies

**Threat:** large or slow request bodies fill memory or the disk, or hold connections open.
**Defence:** a 64 KiB body limit on every route except octet-stream uploads. Uploads check headers and free space before reading, stream to disk, stop at the declared size, drop stalled clients and remove partial files.
**Tests:**
- `tests/test_headers.py::test_oversized_bodies_are_rejected`
- `tests/test_uploads.py::test_other_types_keep_the_body_limit`
- `tests/test_uploads.py::test_bad_headers_are_refused_unread`
- `tests/test_uploads.py::test_more_than_the_free_space_is_507_unread`
- `tests/test_uploads.py::test_uploads_in_flight_count_against_the_free_space`
- `tests/test_uploads.py::test_a_body_past_its_content_length_is_413_and_removed`
- `tests/test_uploads.py::test_a_stalled_upload_is_dropped`
- `tests/test_uploads.py::test_a_disconnect_removes_the_partial_file`
- `tests/test_uploads.py::test_complete_uploads_expire_after_24_hours`
- `tests/test_uploads.py::test_a_5_gib_upload_streams`

### T12. Reading secrets from the database or `/data`

**Threat:** a local reader or a database dump exposes credentials, session tokens or passwords.
**Defence:** credentials are Fernet-encrypted with a key kept outside the database, session tokens are stored as hashes, passwords as Argon2 hashes, and data files are mode 0600. Archive passphrases are derived, never stored.
**Tests:**
- `tests/test_crypto.py::test_round_trip_never_contains_plaintext`
- `tests/test_crypto.py::test_wrong_key_raises`
- `tests/test_crypto.py::test_subkeys_are_independent`
- `tests/test_login.py::test_login_rotates_session_and_stores_only_hashes`
- `tests/test_lifespan.py::test_data_files_are_private`
- `tests/test_hosts.py::test_generated_key_is_ed25519_and_stored_encrypted`
- `tests/test_remote_storage.py::test_secrets_are_stored_encrypted_and_never_shown`
- `tests/test_notify.py::test_urls_are_encrypted_and_never_shown`

### T13. Secrets leaking into pages, logs, audit records or errors

**Threat:** a stored secret, an entered passphrase, a hook's output or an error from rclone or Docker shows a secret to a user or writes it to a log.
**Defence:** secrets are never rendered back, refused forms do not echo them, the audit log redacts secret-like keys, run logs and hook output are redacted, rclone gets secrets only obscured through its private API, and upstream error bodies are not quoted.
**Tests:**
- `tests/test_audit.py::test_redaction`
- `tests/test_config.py::test_error_message_never_echoes_the_key`
- `tests/test_hosts_routes.py::test_pasted_key_with_passphrase_is_never_echoed`
- `tests/test_hosts.py::test_daemon_errors_do_not_echo_the_response_body`
- `tests/test_remote_storage.py::test_keys_passphrases_and_tokens_are_never_shown`
- `tests/test_remote_storage.py::test_a_refused_form_never_echoes_secrets`
- `tests/test_notify.py::test_refused_destinations_are_never_echoed`
- `tests/test_rclone_backend.py::test_secrets_reach_rclone_only_obscured`
- `tests/test_rclone_backend.py::test_logs_hold_no_secret_and_no_connection_string`
- `tests/test_rclone_backend.py::test_storage_errors_never_quote_rclone`
- `tests/test_rclone_rc.py::test_no_secret_on_the_command_line_and_a_clean_environment`
- `tests/test_rclone_rc.py::test_the_input_dump_in_rclones_log_is_redacted`
- `tests/test_hooks.py::test_secret_across_a_cut_is_redacted`
- `tests/test_hooks.py::test_output_is_not_logged_by_default`
- `tests/test_hooks_docker.py::test_output_is_redacted_and_capped`
- `tests/test_hosts_docker.py::test_no_key_material_on_disk_after_connecting`
- `tests/test_foreign_archives.py::test_a_foreign_encrypted_archive_needs_its_passphrase`

### T14. A weak, missing or rotated secret key

**Threat:** drydock starts with a weak or unreadable key, or a key rotation makes old secrets and archives unreadable.
**Defence:** startup refuses a missing, malformed, low-entropy or unreadable key. Keys are a list, newest first: old values still decrypt, old signatures still verify, and writes use the newest key.
**Tests:**
- `tests/test_config.py::test_missing_key_is_rejected`
- `tests/test_config.py::test_malformed_key_is_rejected`
- `tests/test_config.py::test_low_entropy_key_is_rejected`
- `tests/test_config.py::test_unreadable_key_file_is_rejected`
- `tests/test_config.py::test_server_exits_non_zero_with_clear_message`
- `tests/test_crypto.py::test_old_key_still_decrypts_and_writes_use_newest`
- `tests/test_crypto.py::test_hmac_from_old_key_verifies_after_rotation`
- `tests/test_restore_verify.py::test_rotated_out_key_still_verifies_as_signed`

### T15. Restoring a tampered or forged archive

**Threat:** an attacker with write access to storage changes an archive, or plants one, so a restore runs their container.
**Defence:** every archive carries an HMAC-signed manifest of member checksums. A tampered archive fails before any Docker call. An archive signed by another key is "unsigned", and restoring it needs a superadmin. Risky settings in it need a superadmin to acknowledge them.
**Tests:**
- `tests/test_archive.py::test_flipping_any_byte_fails`
- `tests/test_archive.py::test_changed_member_fails_even_in_a_rebuilt_archive`
- `tests/test_archive.py::test_recomputed_checksums_without_the_key_fail`
- `tests/test_archive.py::test_archive_from_another_key_is_unsigned`
- `tests/test_archive.py::test_tampered_encrypted_archive_fails`
- `tests/test_restore_dispatch.py::test_tampered_archive_fails_with_zero_docker_calls`
- `tests/test_restore_verify.py::test_renamed_archive_is_refused`
- `tests/test_foreign_archives.py::test_an_unsigned_archive_is_superadmin_only`
- `tests/test_restore_routes.py::test_unsigned_risky_archive_needs_superadmin_acknowledgement_and_reauth`

### T16. Swapping an archive between verification and restore

**Threat:** the file changes after it was verified and before it is applied.
**Defence:** verification is bound to one open file and its fstat identity. Pass 2 re-hashes every member against the checksums pass 1 recorded, and staged images and data are checked again before use.
**Tests:**
- `tests/test_restore_verify.py::test_verification_binds_to_one_open_file`
- `tests/test_restore_verify.py::test_pass_two_rehashes_every_member_against_pass_one`
- `tests/test_restore_verify.py::test_pass_two_reader_rehashes_and_detects_changes`
- `tests/test_restore_verify.py::test_staged_image_that_changed_is_gone`
- `tests/test_restore_verify.py::test_staged_data_that_was_changed_or_removed_is_gone`
- `tests/test_remote_restore.py::test_pass_2_refuses_a_download_changed_since_pass_1`
- `tests/test_restore_paths.py::test_a_symlink_swapped_in_after_the_check_is_caught`

### T17. Malicious tar content

**Threat:** a crafted archive exploits the tar parser, differences between Python's and Go's tar readers, path traversal, special files, setid hard links or a costly scrypt work factor.
**Defence:** headers are checked before `tarfile` reads them, only regular members listed in the manifest are accepted, the inner image and data tars pass a guard that reads them as Docker's Go code does, and age headers with a high work factor are refused early.
**Tests:**
- `tests/test_archive.py::test_structure_violations_fail`
- `tests/test_archive.py::test_non_regular_member_fails`
- `tests/test_archive.py::test_tar_extended_headers_are_checked_before_tarfile_reads_them`
- `tests/test_archive.py::test_trailing_data_after_the_archive_fails`
- `tests/test_archive.py::test_manifest_rejects_unsafe_or_unreferenced_members`
- `tests/test_archive.py::test_a_high_scrypt_work_factor_is_refused_quickly`
- `tests/test_restore_verify.py::test_fuzz_corpus_is_rejected`
- `tests/test_restore_verify.py::test_inner_guard_refuses_headers_go_reads_differently`
- `tests/test_restore_verify.py::test_inner_guard_flags_setid_hard_links`
- `tests/test_restore_verify.py::test_inner_guard_refuses_image_names_docker_reads_differently`
- `tests/test_restore_verify.py::test_image_tar_with_unlisted_tag_is_refused`
- `tests/test_restore_verify.py::test_symlinked_archive_is_refused`
- `tests/test_restore_verify.py::test_fifo_archive_is_refused_without_blocking`

### T18. Reading archives on storage

**Threat:** whoever can read the storage reads the archives, including the environment secrets in them.
**Defence:** jobs can encrypt archives with age. Each job's passphrase is derived from the secret key and the job UUID, so it is never stored, and a wrong passphrase fails during verification. Unencrypted archives remain readable; the README says to encrypt.
**Tests:**
- `tests/test_archive.py::test_encrypted_archive_needs_the_passphrase`
- `tests/test_archive.py::test_encrypted_flag_must_match_the_manifest`
- `tests/test_capture.py::test_encrypted_capture`
- `tests/test_crypto.py::test_job_passphrase_is_derived_from_key_and_job_only`
- `tests/test_restore_verify.py::test_wrong_passphrase_fails_during_verification`
- `tests/test_foreign_archives.py::test_after_losing_the_database_the_secret_key_restores_everything`

### T19. A restore writing to sensitive host paths

**Threat:** an archive or a restore choice maps a bind mount or compose folder onto `/etc`, `/`, Docker's state, other runtimes' sockets, system binaries or drydock's own files.
**Defence:** host paths are resolved and checked against a denylist before any change, and again when they are used. Writes outside the usual data trees are flagged for a superadmin.
**Tests:**
- `tests/test_restore_plan.py::test_bind_remap_onto_etc_or_root_is_rejected`
- `tests/test_restore_plan.py::test_denylisted_create_binds_are_rejected`
- `tests/test_restore_plan.py::test_other_runtimes_state_and_sockets_are_refused`
- `tests/test_restore_plan.py::test_system_binaries_are_never_written`
- `tests/test_restore_plan.py::test_ostree_real_paths_are_never_written`
- `tests/test_restore_plan.py::test_own_host_paths_cannot_be_mounted_or_written`
- `tests/test_restore_plan.py::test_writes_outside_the_data_trees_are_flagged`
- `tests/test_restore_plan.py::test_resolved_paths_are_checked_again`
- `tests/test_restore_routes.py::test_bind_remap_onto_etc_or_root_is_rejected_for_superadmin`
- `tests/test_stack_restore_plan.py::test_compose_dir_under_etc_is_rejected`
- `tests/test_restore_apply.py::test_compose_dir_resolving_into_etc_is_rejected`
- `tests/test_stack_restore_docker.py::test_compose_dir_under_etc_is_rejected_end_to_end`

### T20. Symlink and mount tricks on host paths during a restore

**Threat:** a path is swapped for a symlink, or restored data plants one, so a write lands somewhere else. A mount inside a target makes a wipe reach another filesystem.
**Defence:** paths are resolved in the helper container and checked again before writing, symlinked bind sources and compose folders are refused, and a wipe refuses a target with a mount inside it.
**Tests:**
- `tests/test_restore_apply.py::test_symlinked_bind_source_is_refused_before_any_mutation`
- `tests/test_restore_apply.py::test_file_bind_onto_a_symbolic_link_is_refused`
- `tests/test_restore_apply.py::test_a_path_that_changed_before_any_write_leaves_the_originals_running`
- `tests/test_restore_apply.py::test_compose_dir_mounted_through_a_link_is_refused_before_any_mutation`
- `tests/test_restore_apply_docker.py::test_host_path_resolution_follows_symlinks`
- `tests/test_restore_apply_docker.py::test_restored_data_cannot_redirect_a_later_mount`
- `tests/test_restore_apply_docker.py::test_compose_dir_swapped_for_a_link_is_never_written_through`
- `tests/test_restore_apply_docker.py::test_data_is_not_written_through_a_mount_below_a_bind_directory`
- `tests/test_restore_apply_docker.py::test_wipe_refuses_a_target_with_a_mount_inside`

### T21. A restored container with dangerous settings

**Threat:** an archive restores a privileged container, one with host devices, added capabilities, host networking or cgroup changes, one that joins drydock's own deployment, or one that moves an image tag other containers use.
**Defence:** the planner refuses host settings hidden in the container config, flags every risky setting for a superadmin to acknowledge, refuses drydock's own containers and labels, and refuses tag moves on protected repositories.
**Tests:**
- `tests/test_restore_plan.py::test_config_cannot_carry_networking_or_host_config`
- `tests/test_restore_plan.py::test_risk_flags_cover_the_plan_list`
- `tests/test_restore_plan.py::test_cgroup_oom_and_volume_driver_fields_are_flagged`
- `tests/test_restore_plan.py::test_network_driver_and_options_are_flagged`
- `tests/test_restore_plan.py::test_existing_host_networks_that_a_restore_joins_are_flagged`
- `tests/test_restore_plan.py::test_own_deployment_cannot_be_joined`
- `tests/test_restore_plan.py::test_drydock_labels_are_never_restored`
- `tests/test_restore_plan.py::test_setid_data_written_into_host_backed_volumes_is_flagged`
- `tests/test_restore_plan.py::test_tag_moves_are_flagged_and_protected_repos_refused`
- `tests/test_restore_dispatch.py::test_execute_refuses_unacknowledged_flags`
- `tests/test_restore_routes.py::test_signed_flagged_archive_still_needs_superadmin`

### T22. Executing a plan other than the one reviewed

**Threat:** the plan changes between the page the user confirmed and the execution, or one confirmation runs twice.
**Defence:** execution needs the digest of the plan shown, plans again under the locks and compares, and runs once.
**Tests:**
- `tests/test_restore_dispatch.py::test_execute_refuses_a_changed_plan`
- `tests/test_restore_dispatch.py::test_execute_refuses_a_plan_stored_after_it_was_seen`
- `tests/test_restore_dispatch.py::test_execute_is_single_shot`
- `tests/test_restore_dispatch.py::test_execute_plans_again_once_it_holds_the_locks`
- `tests/test_restore_routes.py::test_execute_refuses_a_plan_replaced_after_it_was_shown`

### T23. Losing data in a failed or interrupted overwrite

**Threat:** an overwrite restore fails or drydock is killed halfway, leaving the original container gone and the new one broken.
**Defence:** every step is journaled before it happens. A failure rolls back under the same locks, startup recovery rolls back interrupted restores, and binds are wiped only when the user opts in.
**Tests:**
- `tests/test_restore_apply.py::test_apply_journals_before_each_mutation`
- `tests/test_restore_apply.py::test_archive_is_opened_before_any_mutation`
- `tests/test_restore_dispatch.py::test_failed_overwrite_rolls_back_under_the_lock`
- `tests/test_restore_dispatch.py::test_startup_recovery_rolls_back_interrupted_restores`
- `tests/test_restore_docker.py::test_kill_9_during_an_overwrite_restore_after_the_wipe`
- `tests/test_restore_docker.py::test_overwrite_never_wipes_a_bind_that_was_not_opted_in`
- `tests/test_restore_dispatch.py::test_backup_and_restore_never_overlap_on_a_container`

### T24. Over-privileged helper containers

**Threat:** the short-lived helper containers drydock creates to read and write data have more privileges than they need, run an image that can change, or are left behind.
**Defence:** helpers drop all capabilities except the two or three each needs, use an image pinned by digest, carry an installation label, and are removed after use and at startup.
**Tests:**
- `tests/test_hosts_docker.py::test_helper_is_hardened_and_removed`
- `tests/test_restore_apply_docker.py::test_wipe_helper_has_exactly_dac_override_and_fowner`
- `tests/test_restore_apply_docker.py::test_data_helper_has_exactly_chown_fowner_and_fsetid`
- `tests/test_hosts.py::test_helper_image_must_be_pinned_by_digest`
- `tests/test_hosts_docker.py::test_startup_reaper_removes_only_this_installations_helpers`
- `tests/test_maintenance.py::test_the_reaper_skips_helpers_in_use`

### T25. Full Docker API access through the local socket

**Threat:** drydock, or anyone who takes it over, uses Docker endpoints it does not need.
**Defence:** drydock reaches the local daemon only through a hardened socket proxy that enables exactly the endpoints drydock uses. The proxy narrows the API; it is not a security boundary, since creating containers stays root-equivalent.
**Tests:**
- `tests/test_deploy.py::test_socket_proxy_enables_exactly_the_planned_endpoints`
- `tests/test_deploy.py::test_socket_proxy_is_hardened`
- `tests/test_deploy.py::test_drydock_reaches_docker_only_through_the_proxy`
- `tests/test_hosts_docker.py::test_proxy_denies_disabled_endpoints`

### T26. A machine in the middle of an SSH connection

**Threat:** an attacker on the path to an SSH host intercepts the Docker forward.
**Defence:** host keys are pinned per host. A host is never contacted before a key is trusted, a scanned key must still match when trusted, and changing the address or port clears the trusted key.
**Tests:**
- `tests/test_hosts.py::test_no_code_path_skips_host_key_verification`
- `tests/test_hosts.py::test_client_options_pin_the_host_key_and_ignore_the_environment`
- `tests/test_hosts.py::test_pinned_host_key_must_name_exactly_this_host`
- `tests/test_hosts.py::test_unusable_ssh_host_is_never_contacted`
- `tests/test_hosts_docker.py::test_host_key_mismatch_refuses_the_connection`
- `tests/test_hosts_routes.py::test_trust_refuses_a_key_that_changed_after_the_scan`
- `tests/test_hosts_routes.py::test_changing_address_or_port_clears_the_trusted_key`
- `tests/test_hosts_routes.py::test_untrusted_ssh_host_is_never_contacted`

### T27. Misusing drydock's SSH key or Docker URLs

**Threat:** drydock's SSH key is used for a shell on the remote host, or a Docker URL points drydock at its own sockets, at a proxy from the environment or at another protocol.
**Defence:** the suggested `authorized_keys` options allow only the forward, keys with costly passphrase KDFs are refused, Docker URLs must be unix sockets or http, drydock's own run directory is refused, and proxy environment variables are ignored.
**Tests:**
- `tests/test_hosts_docker.py::test_authorized_key_options_refuse_commands`
- `tests/test_hosts.py::test_keys_with_costly_passphrase_kdfs_are_refused`
- `tests/test_hosts.py::test_only_socket_and_http_urls_are_accepted`
- `tests/test_hosts.py::test_clients_ignore_proxy_environment`
- `tests/test_hosts_routes.py::test_drydock_run_dir_sockets_are_refused`
- `tests/test_hosts.py::test_symlinked_socket_directory_is_refused`

### T28. Hooks as a way to run commands

**Threat:** a hook runs a command in a container the job does not cover, runs through a shell, or is changed by someone who should not run code.
**Defence:** only superadmins edit hooks. Hooks are argv lists run without a shell, bound to a container of the job, and checked again at run time.
**Tests:**
- `tests/test_hooks_docker.py::test_argv_is_passed_literally_without_a_shell`
- `tests/test_hooks.py::test_parse_argv_accepts_literals_and_rejects_bad_shapes`
- `tests/test_hooks.py::test_resolve_refuses_containers_outside_the_targets`
- `tests/test_hooks_routes.py::test_attaching_a_hook_outside_the_job_is_rejected`
- `tests/test_hooks_routes.py::test_hook_rebinding_is_checked_against_attached_jobs`
- `tests/test_stack_dispatch.py::test_binding_is_checked_again_at_run_time`
- `tests/test_stacks_docker.py::test_hook_bound_to_another_project_is_refused_at_run_time`

### T29. Backups acting on the wrong container

**Threat:** a job name or a compose label makes drydock stop, read or capture drydock itself or an unrelated container, or read host files outside the project.
**Defence:** names never fall back to ID prefixes, drydock's own deployment is refused, compose labels inherited from an image are ignored, and compose paths in system locations are refused and capped in size.
**Tests:**
- `tests/test_runs_docker.py::test_a_name_never_falls_back_to_an_id_prefix`
- `tests/test_stack_dispatch.py::test_own_deployment_is_refused_in_every_mode`
- `tests/test_capture.py::test_compose_labels_inherited_from_the_image_are_ignored`
- `tests/test_capture.py::test_compose_paths_in_system_locations_are_refused`
- `tests/test_capture.py::test_compose_files_are_capped`

### T30. Containers left down after a crash

**Threat:** drydock stops or pauses containers for a backup and dies before starting them again.
**Defence:** the containers drydock changes are recorded before the change. Shutdown and startup recovery start or unpause them, and the compose file gives drydock 90 s to stop.
**Tests:**
- `tests/test_runs_docker.py::test_drydock_killed_mid_backup`
- `tests/test_runs_docker.py::test_compose_down_and_up_mid_backup_keeps_state`
- `tests/test_stacks_docker.py::test_drydock_dies_or_stops_mid_pause`
- `tests/test_stacks_docker.py::test_drydock_killed_mid_stack_stop_restarts_every_container`
- `tests/test_stack_dispatch.py::test_startup_recovery_unpauses_then_restarts`
- `tests/test_stack_dispatch.py::test_pause_list_is_written_before_the_first_pause`
- `tests/test_jobs.py::test_shutdown_cancels_runs`

### T31. Escaping a local storage root

**Threat:** a storage path, job name or symlink makes drydock write or list outside the allowed roots, or inside its own data.
**Defence:** roots must sit inside `DRYDOCK_LOCAL_STORAGE_ROOTS` and outside drydock's directories, archive names come from IDs and a slug, and roots that become symlinks or leave the allowlist are refused later.
**Tests:**
- `tests/test_storage.py::test_root_outside_the_allowlist_is_rejected`
- `tests/test_storage.py::test_empty_allowlist_rejects_everything`
- `tests/test_storage.py::test_root_overlapping_drydock_directories_is_rejected`
- `tests/test_storage.py::test_unsafe_names_are_refused`
- `tests/test_storage.py::test_job_named_dot_dot_writes_inside_the_root`
- `tests/test_storage.py::test_root_swapped_for_a_symlink_is_refused`
- `tests/test_storage.py::test_root_removed_from_allowlist_is_refused_later`
- `tests/test_storage.py::test_list_ignores_partials_symlinks_and_foreign_files`

### T32. Injecting rclone options or reaching its API

**Threat:** a storage form sets an rclone option that reads local files, runs a command or turns off checks, or another process on the host calls rclone's API.
**Defence:** each backend has an option allowlist matched to the pinned rclone, file options and other types are refused, drydock sets its security options last, every value is quoted, rclone transfers only to and from the staging folder, and its API listens on a private unix socket with per-boot credentials.
**Tests:**
- `tests/test_rclone_backend.py::test_options_outside_the_allowlist_are_refused`
- `tests/test_rclone_backend.py::test_drydock_sets_the_security_options_last`
- `tests/test_rclone_backend.py::test_connection_strings_quote_every_value`
- `tests/test_rclone_backend.py::test_a_closing_bracket_is_refused_before_the_ranged_read`
- `tests/test_rclone_backend.py::test_put_takes_only_drydock_staging_files`
- `tests/test_rclone_backend.py::test_get_writes_only_below_staging`
- `tests/test_remote_storage.py::test_file_fields_are_refused`
- `tests/test_remote_storage.py::test_other_rclone_types_are_refused`
- `tests/test_remote_storage.py::test_repeated_fields_are_refused`
- `tests/test_remote_storage.py::test_the_allowlist_matches_the_pinned_rclone`
- `tests/test_rclone_rc.py::test_listens_only_on_a_private_unix_socket`
- `tests/test_rclone_rc.py::test_calls_need_the_per_boot_credentials`
- `tests/test_rclone_rc.py::test_method_names_are_checked`

### T33. A machine in the middle of a storage connection, or secrets sent to a new destination

**Threat:** an attacker intercepts SFTP or WebDAV traffic, or an admin repoints a target so its stored password or token goes to a server they control.
**Defence:** SFTP host keys and WebDAV certificates are pinned, WebDAV needs HTTPS, and changing the host, folder, host key, certificate or OAuth client means entering the secrets again.
**Tests:**
- `tests/test_rclone_backend.py::test_a_wrong_host_key_is_refused`
- `tests/test_rclone_backend.py::test_no_valid_host_key_is_refused_before_any_call`
- `tests/test_sftp_storage.py::test_the_host_key_is_checked`
- `tests/test_smb_webdav_storage.py::test_an_unpinned_or_wrong_certificate_is_refused`
- `tests/test_smb_webdav_storage.py::test_a_trusted_connection_never_serves_another_certificate`
- `tests/test_smb_webdav_storage.py::test_webdav_needs_https_and_fixed_options`
- `tests/test_remote_storage.py::test_a_new_destination_needs_the_secrets_again`
- `tests/test_remote_storage.py::test_a_new_webdav_folder_needs_the_secrets_again`
- `tests/test_sftp_storage.py::test_a_new_host_key_needs_the_secrets_again`
- `tests/test_smb_webdav_storage.py::test_changing_the_pinned_certificate_needs_the_secrets_again`
- `tests/test_gdrive_storage.py::test_a_new_client_drops_the_token`

### T34. Hijacking the Google Drive OAuth flow

**Threat:** an attacker completes another user's OAuth flow, replays a state or code, or connects their own Drive to a victim's target.
**Defence:** PKCE, a single-use state bound to the user and the target that expires after ten minutes, a pasted address that must be the loopback redirect, and checks on Google's answer.
**Tests:**
- `tests/test_gdrive_storage.py::test_the_verifier_must_match_the_challenge`
- `tests/test_gdrive_storage.py::test_a_state_is_bound_to_its_user`
- `tests/test_gdrive_storage.py::test_a_state_expires`
- `tests/test_gdrive_storage.py::test_unknown_states_are_refused`
- `tests/test_gdrive_storage.py::test_a_flow_completes_only_for_its_storage`
- `tests/test_gdrive_storage.py::test_a_pasted_address_must_be_the_loopback_one`
- `tests/test_gdrive_storage.py::test_too_many_fields_in_a_pasted_address`
- `tests/test_gdrive_storage.py::test_googles_answer_is_checked`

### T35. Retention deleting the wrong archives

**Threat:** a retention policy deletes archives of another job, foreign files, the last good backup or an archive a restore is reading.
**Defence:** retention selects only the job's own prefix, always keeps the newest backup, never runs without a stored backup, and skips archives a restore holds.
**Tests:**
- `tests/test_retention.py::test_nothing_outside_the_jobs_prefix_is_selected`
- `tests/test_retention.py::test_the_newest_backup_always_survives`
- `tests/test_stack_dispatch.py::test_retention_never_runs_without_a_stored_backup`
- `tests/test_remote_restore.py::test_retention_and_a_remote_restore_never_cross`

### T36. Partial or overwritten archives on storage

**Threat:** a full disk, a cancel or a crash leaves a truncated archive that looks complete, or a new archive replaces an old one.
**Defence:** free space is checked first, archives are written under a partial name and published only when complete, and publishing never replaces an existing archive.
**Tests:**
- `tests/test_archive.py::test_low_disk_space_fails_early`
- `tests/test_archive.py::test_disk_full_while_writing_is_insufficient_space`
- `tests/test_runs_docker.py::test_full_disk_fails_cleanly`
- `tests/test_storage.py::test_archive_written_in_place_is_published_without_replacing`
- `tests/test_storage.py::test_cancelled_put_leaves_nothing`
- `tests/test_rclone_backend.py::test_put_never_replaces_an_existing_archive`
- `tests/test_rclone_backend.py::test_an_upload_is_invisible_until_complete`

### T37. Notification URLs as a way to reach other services

**Threat:** a notification target sends requests to an internal service or to a scheme Apprise supports but drydock does not intend, or one URL hides several destinations.
**Defence:** only superadmins edit targets, URLs must match an allowlist of schemes, a webhook is always one JSON service, and a stored string is never split into several URLs.
**Tests:**
- `tests/test_notify.py::test_disallowed_urls_are_refused`
- `tests/test_notify.py::test_a_webhook_is_one_service_whatever_its_path_holds`
- `tests/test_notify.py::test_a_partial_destination_is_refused_not_ignored`
- `tests/test_notify.py::test_a_stored_multi_url_string_is_never_split_at_send_time`
- `tests/test_notify.py::test_targets_are_edited_by_superadmins_with_recent_auth`

### T38. Reading files on the drydock host through the restore inbox

**Threat:** a restore from a server path reads a file outside the inbox through `..`, a symlink, a swap after the check, a FIFO or a device, or a route widens the allowlist.
**Defence:** the path is resolved and must stay inside `DRYDOCK_RESTORE_PATHS`, it is opened with `O_NOFOLLOW` and `O_NONBLOCK`, the opened descriptor's path must match, only regular files with archive names are accepted, and the allowlist comes only from the environment.
**Tests:**
- `tests/test_restore_paths.py::test_relative_and_dot_dot_paths_are_refused`
- `tests/test_restore_paths.py::test_a_path_outside_the_allowlist_is_refused`
- `tests/test_restore_paths.py::test_nothing_is_allowed_without_an_allowlist`
- `tests/test_restore_paths.py::test_a_symlink_pointing_outside_is_refused`
- `tests/test_restore_paths.py::test_a_symlink_swapped_in_after_the_check_is_caught`
- `tests/test_restore_paths.py::test_the_last_component_swapped_for_a_symlink_is_refused`
- `tests/test_restore_paths.py::test_a_directory_and_a_fifo_are_refused`
- `tests/test_restore_paths.py::test_only_archive_names_are_opened`
- `tests/test_restore_paths.py::test_no_route_can_change_the_allowlist`
- `tests/test_deploy.py::test_compose_mounts_the_restore_inbox_read_only`

### T39. Tampering with or denying actions in the audit log

**Threat:** a user denies a change, or someone with database access rewrites history through drydock.
**Defence:** every unsafe route audits its outcome, setup records the source IP, and SQLite triggers block UPDATE and DELETE on audit events.
**Tests:**
- `tests/test_audit.py::test_audit_events_are_append_only`
- `tests/test_audit.py::test_logins_and_user_changes_are_audited`
- `tests/test_routes.py::test_every_unsafe_route_audits_its_success`
- `tests/test_setup.py::test_setup_audit_row_records_source_ip`

### T40. A weakly configured deployment or a vulnerable image

**Threat:** the container runs as root, with a writable root filesystem or extra capabilities, from an image or binary that can change under it or carries known vulnerabilities, or two drydocks share one `/data`.
**Defence:** the image runs as uid 10001 with a read-only root filesystem, no capabilities and `no-new-privileges`. Base images are pinned by digest, age and rclone are checksummed, and a second process cannot take the `/data` lock. CI scans the image for high and critical vulnerabilities and secrets; findings that cannot be fixed yet need a dated exception in `.trivyignore.yaml`. Releases carry an SBOM and provenance for amd64 and arm64.
**Tests:**
- `tests/test_deploy.py::test_compose_binds_loopback_and_hardens_the_container`
- `tests/test_deploy.py::test_dockerfile_runtime_stage`
- `tests/test_deploy.py::test_smoke_app_matches_production_hardening`
- `tests/test_deploy.py::test_every_base_image_is_pinned_by_digest`
- `tests/test_deploy.py::test_runtime_image_carries_a_checksummed_age`
- `tests/test_deploy.py::test_runtime_image_carries_a_checksummed_rclone`
- `tests/test_lifespan.py::test_second_process_cannot_take_the_flock`
- `tests/test_deploy.py::test_ci_images_are_pinned_by_digest`
- `tests/test_deploy.py::test_scan_exceptions_say_why_and_expire`
- `tests/test_deploy.py::test_releases_carry_an_sbom_and_provenance_for_both_platforms`

## Accepted risks

These are known limits of v1. The README explains each one to operators; no test can remove them.

- **Drydock is root-equivalent on every host it manages.** Anyone with a superadmin account, the secret key or code execution in the drydock container controls those hosts.
- **The socket proxy is not a security boundary.** It narrows the Docker API, but the endpoints drydock needs (create, start, put archive) are enough to take over the host.
- **The remote SSH user is root-equivalent** on its host, because it can reach the Docker socket.
- **Admins can restore signed archives** that carry no risk flags without a superadmin. A compromised admin account can therefore replace containers with older signed versions.
- **Unencrypted archives expose their contents**, including environment variables and `.env` files, to whoever can read the storage.
- **Losing the secret key loses** stored credentials, archive signatures and every encrypted archive.
- **Live mode is crash-consistent at best.** Databases need hooks for consistent backups.
- **No second factor.** TOTP and SSO are deferred.
- **Plain-HTTP LAN deployments** send the session cookie without `Secure`. Drydock warns at every start.

# 🛡️ State of MCP Security Report (2026)

## 🚨 Detailed Vulnerability Log

### 📦 Repository: REDACTED_REPO_1

**Tools Detected:** `tier_stats, dashboard, report_costs, create_team, inspect_template, enable, utilities_init, list_runs, utilities_status, utilities_scan, metrics, list_cmd, cleanup_executions, docs_short, memory_patterns, review_short, show_analytics, service_stop, show_session_stats, show_migration_guide, memory_stop, create_agent, natural_language_run, init, utilities_dashboard, telemetry_export, tier_set, utilities_cheatsheet, progressive_report, detect_intent, memory_start, test_short, service_start, status, memory_stats, history, report_health, sync_claude, run_workflow, disable, progressive_analytics, cheatsheet, workflow_describe, memory_scan, report_patterns, orchestrate_run, hot_files, list_templates, do_command, health_command, watch, tier_recommend, ship_command, telemetry_show, scan_command, telemetry_reset, memory_test, utilities_costs, security_short, service_status, generate_plan_cmd, costs, progressive_list, suggest_defaults_cmd, delete, workflow_list, report_telemetry, show_execution, memory_status, workflow_run, utilities_sync_claude, search_memory`

#### 💻 Code Execution Risks
* 🔴 **Tool `scan_command`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `ship_command`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `health_command`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `report_costs`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `report_health`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `report_patterns`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `report_telemetry`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `memory_status`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `memory_start`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `memory_stop`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `memory_patterns`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `utilities_init`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `utilities_dashboard`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `utilities_sync_claude`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `utilities_costs`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `utilities_status`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `workflow_list`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `workflow_run`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `workflow_describe`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `orchestrate_run`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `telemetry_show`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `telemetry_export`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `telemetry_reset`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `service_status`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `service_start`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `service_stop`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `progressive_list`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `progressive_report`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `progressive_analytics`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `tier_recommend`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `tier_stats`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `memory_stats`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `memory_scan`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `memory_test`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `hot_files`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `sync_claude`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `dashboard`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `costs`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `init`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `status`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `cleanup_executions`** [UNRESTRICTED_FILE_WRITE]: `shutil.rmtree()` inside agent tool

---

### 📦 Repository: REDACTED_REPO_2

**Tools Detected:** `where, fleet_stats_cmd, watch_cmd, apply_command, fleet_list_cmd, ingest_external_scan, gpu_infra_scan, license_compliance_scan, rescan_command, iac_cmd, registry_status, dataset_card_scan, serve_cmd, dashboard_cmd, ollama_cmd, registry_glama_sync, api_cmd, generate_sbom, protect_cmd, skills_rescan_cmd, db_path_cmd, registry_list, blast_radius, verify, fleet_sync_cmd, registry_sync_all, db_status, inventory, registry_smithery_sync, validate, teardown_cmd, vector_db_scan, history_cmd, proxy_cmd, aws_cmd, graph_export, policy_check, schedule_add, gcp_cmd, diff, db_update_frameworks, compliance_narrative_cmd, remediate, completions_cmd, mcp_scan_cmd, schedule_list, marketplace_check, fs_cmd, audit_replay_cmd, code_cmd, model_file_scan, registry_mcp_sync, analytics_cmd, secrets_cmd, databricks_cmd, analytics_query, skills_scan_cmd, introspect_cmd, proxy_configure_cmd, tool_risk_assessment, registry_enrich_cves, sbom_cmd, upgrade_cmd, policy_template, fleet_scan, db_update, registry_update, cis_benchmark, runtime_correlate, image_cmd, registry_search, scan, diff_cmd, check, context_graph, aisvs_benchmark, azure_cmd, snowflake_cmd, huggingface_cmd, browser_extension_scan, registry_lookup, run_cmd, doctor_cmd, mcp_server_cmd, registry_enrich, code_scan, mesh_cmd, skill_verify, prompt_scan, compliance, skill_trust, posture_cmd, graph_cmd, model_provenance_scan, guard_cmd, ai_inventory_scan, training_pipeline_scan, skills_verify_cmd, remediate_cmd, schedule_remove, sidecar_injector_cmd, proxy_bootstrap_cmd, connectors_cmd, skill_scan`

#### 💻 Code Execution Risks
* 🔴 **Tool `dashboard_cmd`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `doctor_cmd`** [ENV_SECRET_ACCESS, POTENTIAL_DATA_EXFILTRATION]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars | `urllib.request.urlopen()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `protect_cmd`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟠 **Tool `scan`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`

---

### 📦 Repository: REDACTED_REPO_3

**Tools Detected:** `main_cli`

#### 💻 Code Execution Risks
* 🟡 **Tool `main_cli`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_4

**Tools Detected:** `weakness_analysis, feedback, about, find_exploited, find_ai_tool, tables, trending, whats_new, list_workflows, search, cve_lookup, software_risk, get_status, query, status, describe, workflows, search_tables_tool, login, attack_chain, list_tables_tool, search_tables, describe_table_tool, vendor_profile, submit_feedback_tool`

#### 💻 Code Execution Risks
* 🟠 **Tool `about`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `cve_lookup`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `software_risk`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `vendor_profile`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `find_exploited`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `weakness_analysis`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `attack_chain`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `whats_new`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_5

**Tools Detected:** `reverse, calculator, echo, weather, search, get_current_date_time`

#### 💻 Code Execution Risks
* 🔴 **Tool `calculator`** [CODE_EXECUTION]: Bare call to `eval()`

---

### 📦 Repository: REDACTED_REPO_6

**Tools Detected:** `list_dbs, query_table_diskusage, query_dolphindb, list_tbs`

#### 💻 Code Execution Risks
* 🟠 **Tool `list_dbs`** [DATABASE_MUTATION]: `db.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `list_tbs`** [DATABASE_MUTATION]: `db.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `query_table_diskusage`** [DATABASE_MUTATION]: `db.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `query_dolphindb`** [DATABASE_MUTATION]: `db.execute()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_7

**Tools Detected:** `get_stats, list_pages, propose_edit, list_claims, post_comment, register_agent, ask_question, get_claim_evidence, read_page, get_knowledge_graph, vote_on_proposal`

#### 💻 Code Execution Risks
* 🟡 **Tool `register_agent`** [POTENTIAL_DATA_EXFILTRATION]: `httpx.post()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `propose_edit`** [POTENTIAL_DATA_EXFILTRATION]: `httpx.post()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `vote_on_proposal`** [POTENTIAL_DATA_EXFILTRATION]: `httpx.post()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `post_comment`** [POTENTIAL_DATA_EXFILTRATION]: `httpx.post()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `ask_question`** [POTENTIAL_DATA_EXFILTRATION]: `httpx.post()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_8

**Tools Detected:** `install, agents_match, stop_cmd, prompts_ab_start, worker, bernstein_run, rate_limit, chaos_status, compare, watch_cmd, wrap_up, report, eu_ai_act_status, _quarantine_clear, workspace_validate, postmortem_cmd, config_validate, bernstein_cost, prompts_promote, incident_cmd, quickstart_cmd, list_users, init, bernstein_tasks, agents_list, _load_evolve_config_from_seed, list_tasks, manifest_list, cost_cmd, sync, agents_discover, list_memory, test_cmd, chaos_slo, disable_framework, session_replay, eval_report, eval_failures, benchmark_compare, chat_logout, templates_hooks_list, benchmark_swe_bench, pending, reject_tool_cmd, list_policies, eval_run, bernstein_status, help_all, cloud_status, agents_validate, check_policies, enable_framework, uninstall_cmd, hooks_run, export_cmd, reject, bernstein_stop, query_cmd, evolve_status, debug_cmd, ticket_import, completions, plan, cloud_deploy, approve, history_cmd, changelog_cmd, delegate, prompts_show, cloud_cost, prompts_seed, mock, replay_filter_cmd, aliases_cmd, bernstein_approve, logs_search, chat_status, assess, start_cmd, remote_test, bernstein_health, _verify_merge_result, dry_run_cmd, man_pages_cmd, config_conflicts, graph_tasks, validate_plan, inspect_cache_entry, auth_status, cloud_logout, slo_cmd, listen_cmd, manifest_show, agents_sync, completions_cmd, pr_cmd, token_report_cmd, eval_swe_bench, undo_cmd, add_user, benchmark_run, cancel, ci_watch, trace_cmd, explain_help_cmd, hooks_check, config_diff, validate_cmd, list_cache_entries, clear_cache_entries, disk_full, auth_login, _github_test_webhook, dep_impact_cmd, report_cmd, self_update_cmd, dashboard, verify_cmd, doctor, cloud_runs, logs_cmd, status_cmd, plan_generate, estimate_cmd, list_cmd, config_get, remote_forget, test_adapter, live, list_marketplace, dr_backup_cmd, triggers_history, restart_cmd, templates_show, evolve_export, triggers_list, init_wizard_cmd, test_server, diff_cmd, verify_hmac_cmd, recap, evolve_review, prompts_ab_stop, ps_cmd, agent_kill, ideate, config_path_cmd, cloud_login, remote_run, _github_setup, bernstein_create_subtask, cloud_init, remove_memory, eval, graph_impact, checkpoint_cmd, prompts_compare, add_memory, logs_tail, list_scenarios, api_check_cmd, explain_cmd, cook, add_task, doctor_cmd, _quarantine_list, dr_restore_cmd, benchmark_simulate, config_set, review_cmd, workspace_clone, demo, install_hooks, chat_serve, stop, hooks_list, agents_showcase, profile_cmd, skills_list, plugins_cmd, ci_fix, config_view_mode, _notes_legacy, agents_sandbox_backends, approve_tool_cmd, evolve_approve, _resolve_corpus_index, prompts_list, templates_hooks_use, replay_cmd, install_marketplace_entry, templates_use, status, show_cmd, retro, from_ticket, session_show, export_rego, triggers_fire, skills_show, cleanup_cmd, load_skill, ab_test_cmd, manifest_diff, auth_logout, file_remove, agent_oom, eval_golden, remove_user, cloud_run, fingerprint_build_cmd, commit_stats_cmd, session_list, usage_report, seal_cmd, config_list, run_changelog_cmd, templates_list`

#### 💻 Code Execution Risks
* 🟠 **Tool `test_adapter`** [UNRESTRICTED_FILE_WRITE]: `shutil.rmtree()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `auth_login`** [POTENTIAL_DATA_EXFILTRATION]: `httpx.post()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `auth_status`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `auth_logout`** [POTENTIAL_DATA_EXFILTRATION]: `httpx.post()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `chat_serve`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `install`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟠 **Tool `quickstart_cmd`** [UNRESTRICTED_FILE_WRITE]: `shutil.rmtree()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `remote_test`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `remote_run`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_9

**Tools Detected:** `evolution_run_backtest, check_trade_legitimacy, doctor, evolution_fetch_market_data, demo, evolution_discover_patterns, get_strategy_performance, check_active_plans, export_audit_trail, config, compute_dqs, get_agent_state, get_trade_reflection, create_trading_plan, validate_strategy, setup, evolution_get_log, get_behavioral_analysis, remember_trade, evolution_evolve_strategy, recall_memories, verify_audit_hash`

#### 💻 Code Execution Risks
* 🟠 **Tool `recall_memories`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_10

#### ⚙️ Configuration & Permission Risks
* 🔴 **CODE_EXECUTION_NO_CONFIRMATION** (in `mcp.json`): Server can execute code (eval, exec) without human confirmation gate

---

### 📦 Repository: REDACTED_REPO_11

**Tools Detected:** `get_media_pool_unique_id, timeline_create_compound_clip, ti_get_linked_items, set_clip_third_party_metadata, create_gallery_still_album, get_current_project_folder, add_clip_flag, graph_reset_all_grades, ti_set_cdl, timeline_export, get_fusion_object, link_clip_proxy_media, timeline_get_marker_by_custom_data, get_quick_export_render_presets, media_pool, open_settings, update_clip_marker_custom_data, timeline_get_unique_id, graph_get_node_cache_mode, ti_add_fusion_comp, timeline_get_media_pool_item, create_timeline, timeline_item_color, get_folder_clip_list, ti_get_fusion_comp_info, add_subfolder, ti_stabilize, timeline_markers, timeline_get_current_video_item, load_render_preset, ti_set_clip_enabled, ti_get_stereo_convergence_values, ti_delete_fusion_comp, ti_get_color_group, set_current_media_pool_folder, delete_project_folder, timeline_delete_marker_by_custom_data, ti_finalize_take, export_media_pool_metadata, ti_add_marker, ti_get_marker_by_custom_data, gallery, ti_assign_to_color_group, replace_clip, ti_get_flag_list, ti_get_track_type_and_index, ti_get_takes_info, switch_page, timeline_get_marker_custom_data, timeline_get_track_sub_type, save_color_preset, inspect_custom_object, set_project_property_tool, graph_set_node_cache_mode, ti_add_flag, get_clip_unique_id_by_name, ti_get_cache_status, media_pool_item_markers, import_media, ti_load_fusion_comp, add_user_to_cloud_project_tool, folder_clear_transcription, get_color_groups_list, ti_export_lut, delete_render_preset, ti_load_burn_in_preset, timeline_create_subtitles_from_audio, timeline_ai, graph_get_tools_in_node, modify_keyframe, timeline_delete_marker_at_frame, set_optimized_media_mode, get_project_unique_id, enable_keyframes, timeline_insert_generator, add_color_group, delete_media, graph, relink_clips, get_timeline_by_index, render_with_quick_export, set_timeline_item_stabilization, resolve_control, folder_transcribe_audio, timeline_import_into, timeline_delete_track, stop_rendering, import_cloud_project_tool, timeline_delete_clips, create_stereo_clip, get_clip_property, set_clip_mark_in_out, clear_clip_transcription, get_current_render_format_and_codec, move_clips_to_folder, set_cache_path, ti_delete_take, timeline_item, set_superscale_settings_tool, ti_add_version, add_items_to_media_pool_from_storage, timeline_get_is_track_locked, set_current_timeline, ti_clear_clip_color, set_proxy_mode, render_presets, timeline_duplicate, move_media_to_bin, set_current_database, ti_select_take, timeline_set_current_timecode, get_clip_marker_custom_data, set_project_name, timeline_add_marker, set_project_setting, set_timeline_item_retime, render, ti_set_clip_color, get_clip_matte_list, export_stills_from_album, timeline_get_mark_in_out, create_empty_timeline, ti_load_version, delete_timeline, ti_update_sidecar, save_layout_preset_tool, remove_user_from_cloud_project_tool, transcribe_clip_audio, get_color_group_pre_clip_node_graph, delete_layout_preset_tool, graph_get_num_nodes, export_project_to_cloud_tool, project_manager, ti_get_source_start_time, project_settings, restore_project, set_clip_color, ti_rename_version, export_burn_in_preset, get_clip_audio_mapping, timeline_insert_title, set_project_preset, object_help, set_color_space_tool, get_fusion_comp_by_name, refresh_media_pool_folders, project_manager_folders, get_media_storage_subfolders, reveal_in_media_storage, timeline, unlink_clip_proxy_media, timeline_get_is_track_enabled, clear_folder_transcription, timeline_analyze_dolby_vision, timeline_set_track_name, transcribe_audio, set_gallery_album_name, ti_get_media_pool_item, ti_set_color_output_cache, ti_delete_marker_by_custom_data, get_folder_unique_id, graph_apply_arri_cdl_lut, auto_sync_audio, ti_import_fusion_comp, create_cloud_project_tool, media_pool_item, archive_project, delete_clip_mattes, list_timelines_tool, set_render_settings, clear_transcription, get_clip_markers, graph_apply_grade_from_drx, delete_keyframe, graph_set_lut, get_gallery_still_albums, add_timeline_mattes_to_media_pool, set_timeline_item_audio, export_render_preset, set_keyframe_interpolation, ti_create_magic_mask, get_clip_media_id, add_render_job, get_render_resolutions, set_timeline_item_crop, import_render_preset, get_render_job_list, restore_cloud_project_tool, color_group, set_current_render_mode, project_manager_database, ti_get_property, timeline_get_track_name, save_as_new_render_preset, timeline_item_fusion, delete_clip_markers_by_color, get_clip_third_party_metadata, quit_resolve, get_clip_flag_list, set_timeline_setting, load_cloud_project, ti_delete_version, timeline_set_track_enable, get_database_list, get_project_folder_list, open_project_folder, get_clip_marker_by_custom_data, layout_presets, add_clip_to_timeline, set_current_still_album, timeline_convert_to_stereo, import_burn_in_preset, transcribe_folder_audio, update_layout_preset, export_project_to_file, ti_smart_reframe, timeline_insert_fusion_generator, timeline_get_current_clip_thumbnail, start_rendering_jobs, clear_clip_flags, ti_clear_flags, clear_clip_mark_in_out, unlink_clips, generate_optimized_media, get_album_stills, ti_get_version_name_list, get_keyframe_mode, graph_set_node_enabled, get_gallery_album_name, clear_clip_color, timeline_get_markers, insert_audio_to_current_track, ti_set_property, get_clip_color, delete_stills_from_album, timeline_insert_fusion_title, set_current_render_format_and_codec, timeline_grab_all_stills, get_current_render_mode, get_clip_metadata, create_timeline_from_clips, get_current_still_album, timeline_insert_ofx_generator, get_still_label, timeline_delete_markers_by_color, timeline_add_track, get_color_group_clips, project_manager_cloud, add_clip_mattes_to_media_pool, apply_color_preset, timeline_set_clips_linked, export_lut, create_project_folder, timeline_item_markers, load_burn_in_preset, ti_get_stereo_floating_window_params, open_project, set_timeline_format_tool, get_render_formats, goto_parent_project_folder, ti_get_source_audio_channel_mapping, delete_color_group, ti_get_clip_color, clear_render_queue, ti_update_marker_custom_data, open_app_preferences, timeline_get_current_timecode, ti_set_fusion_output_cache, timeline_detect_scene_cuts, ti_get_markers, ti_regenerate_magic_mask, set_timeline_item_composite, add_marker, ti_get_info, unlink_proxy_media, get_current_database, set_still_label, import_timeline_from_file, link_proxy_media, ti_export_fusion_comp, get_timeline_matte_list, create_project, import_folder_from_file, move_media_pool_folders, gallery_stills, ti_get_current_version, close_project, timeline_update_marker_custom_data, timeline_clear_mark_in_out, delete_render_job, timeline_set_start_timecode, get_render_job_status, create_sub_clip, ti_remove_from_color_group, delete_clip_marker_at_frame, import_stills_to_album, timeline_grab_still, apply_lut, set_cache_mode, timeline_item_takes, set_color_science_mode_tool, create_bin, create_gallery_power_grade_album, replace_media_pool_clip, ti_delete_markers_by_color, ti_copy_grades, folder, export_all_powergrade_luts, is_rendering_in_progress, graph_get_node_label, restart_app, timeline_create_fusion_clip, get_media_storage_files, start_render, export_current_frame_as_still, folder_export, get_clip_mark_in_out, quit_app, delete_optimized_media, timeline_set_mark_in_out, set_timeline_item_transform, ti_rename_fusion_comp, media_storage, get_color_group_post_clip_node_graph, set_keyframe_mode, goto_root_project_folder, get_resolve_version_fields, ti_get_node_graph, import_project_from_file, delete_project, create_color_preset_album, get_render_codecs, set_clip_metadata, export_layout_preset_tool, copy_grade, timeline_set_name, timeline_get_node_graph, load_layout_preset_tool, delete_clip_marker_by_custom_data, export_folder, set_selected_clip, get_selected_clips, save_project, timeline_set_track_lock, delete_timelines_by_id, set_clip_property, graph_get_lut, get_mounted_volumes, set_proxy_quality, delete_color_preset, ti_add_take, delete_media_pool_folders, delete_media_pool_clips, fusion_comp, ti_delete_marker_at_frame, refresh_lut_list, delete_color_preset_album, get_folder_is_stale, get_gallery_power_grade_albums, set_color_wheel_param, get_folder_subfolder_list, add_node, timeline_insert_fusion_composition, get_project_preset_list, add_to_render_queue, import_layout_preset_tool, add_clip_marker, ti_get_marker_custom_data, add_keyframe`

#### 💻 Code Execution Risks
* 🟠 **Tool `save_project`** [UNRESTRICTED_FILE_WRITE]: `os.remove()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `gallery_stills`** [UNRESTRICTED_FILE_WRITE]: `os.remove()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_12

**Tools Detected:** `project_geometry, transform_coordinates, simplify, download_worldcover, tile_raster, calculate_geodetic_distance, difference, calculate_geodetic_area, convex_hull, concat_bands, make_valid, metadata_raster, nearest_point_on_geometry, is_valid, getis_ord_g, get_utm_zone, clip_raster_with_shapefile, download_boundaries, voronoi, distance_band_weights, dissolve_gpd, overlay_gpd, raster_histogram, write_raster, geojson_to_geometry, gearys_c, get_coordinates, get_raster_crs, symmetric_difference, create_web_map, ols_with_spatial_diagnostics_safe, gamma_statistic, raster_algebra, translate_geometry, zonal_statistics, explode_gpd, get_geometry_type, triangulate_geometry, append_gpd, unary_union_geometries, get_area, adbscan, save_results, spatial_markov, hillshade, reclassify_raster, extract_band, weights_from_shapefile, get_geod_info, get_species_info, gm_lag, clip_vector, sjoin_gpd, get_available_crs, buffer, weighted_band_sum, create_map, raster_band_statistics, get_geocentric_crs, download_species_occurrences, dynamic_lisa, sjoin_nearest_gpd, calculate_shortest_path, write_file_gpd, download_climate_data, reproject_raster, get_utm_crs, normalize_geometry, get_bounds, moran_local, minimum_rotated_rectangle, point_in_polygon, get_crs_info, union, focal_statistics, snap_geometry, compute_s2_ndvi, rotate_geometry, get_length, morans_i, join_counts, build_transform_and_save_weights, envelope, read_file_gpd, join_counts_local, intersection, download_street_network, get_centroid, getis_ord_g_local, compute_ndvi, download_satellite_imagery, scale_geometry, resample_raster, geometry_to_geojson, calculate_geodetic_point, merge_gpd, build_and_transform_weights, knn_weights`

#### 💻 Code Execution Risks
* 🟠 **Tool `download_species_occurrences`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`

---

### 📦 Repository: REDACTED_REPO_13

**Tools Detected:** `get_account_info, search_interests, estimate_audience_size, get_ad_creatives, save_ad_image_locally, get_ad_image, get_ad_details, search_geo_locations, create_ad_creative, search_pages_by_name, search_behaviors, compute_image_crops, search, get_campaign_details, upload_ad_image, get_insights, get_creative_details, fetch, duplicate_ad, duplicate_campaign, get_account_pages, search_ads_archive, create_budget_schedule, create_ad, get_ads, update_adset, update_ad_creative, get_ad_video, search_demographics, get_interest_suggestions, duplicate_creative, update_ad, generate_report, get_adset_details, update_campaign, create_campaign, duplicate_adset, get_adsets, create_adset, get_ad_accounts, get_campaigns`

#### 💻 Code Execution Risks
* 🟠 **Tool `save_ad_image_locally`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟡 **Tool `estimate_audience_size`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_14

**Tools Detected:** `list_projects, get_service, get_run_step, list_builds, open_pipeline_run_dashboard, get_stack_component, list_stacks, list_run_steps, list_stack_components, get_deployment_logs, list_deployments, list_service_connectors, get_flavor, list_artifacts, get_project, list_secrets, list_services, get_stack, easter_egg, list_users, get_user, get_active_user, list_pipeline_runs, trigger_pipeline, get_step_code, get_build, list_flavors, get_pipeline_details, get_step_logs, get_model_version, diagnose_zenml_setup, list_run_templates, get_service_connector, get_tag, list_model_versions, list_pipelines, get_pipeline_run, get_snapshot, open_run_activity_chart, get_active_project, list_artifact_versions, get_deployment, get_schedule, get_model, list_schedules, get_artifact_version, list_models, list_tags, get_run_template, list_snapshots`

#### 💻 Code Execution Risks
* 🟡 **Tool `get_step_logs`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_15

**Tools Detected:** `qdrant_find_adv`

#### 💻 Code Execution Risks
* 🟡 **Tool `qdrant_find_adv`** [POTENTIAL_DATA_EXFILTRATION]: `httpx.post()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_16

**Tools Detected:** `get_voices, text_to_speech, get_models, create_voice, remove_voice`

#### 💻 Code Execution Risks
* 🟠 **Tool `text_to_speech`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`

---

### 📦 Repository: REDACTED_REPO_17

**Tools Detected:** `open_workflows_folder, remove_workflow_tool, get_workflow_tool_detail, save_workflow_tool, reload_workflows_tool, list_workflows, list_workflows_tool, install_examples, i_crop, add_runninghub_workflow`

#### 💻 Code Execution Risks
* 🔴 **Tool `open_workflows_folder`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_18

**Tools Detected:** `delete_override, bump_version, start_project_server, edit_override, edit, auto_approve, dashboard_viewer, init, create_override, list, activate, index, description, start_mcp_server, print_system_prompt, create, index_file, health_check, setup, is_ignored_path, delete, cleanup, list_overrides, remind`

#### 💻 Code Execution Risks
* 🔴 **Tool `bump_version`** [OS_COMMAND_EXECUTION]: `os.system()` inside agent tool
* 🟠 **Tool `delete`** [UNRESTRICTED_FILE_WRITE]: `os.remove()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `delete_override`** [UNRESTRICTED_FILE_WRITE]: `os.remove()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_19

**Tools Detected:** `get_job_details, get_job_status, list_jobs, run_sql_query`

#### 💻 Code Execution Risks
* 🟠 **Tool `run_sql_query`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_20

**Tools Detected:** `deeplook_lookup, deeplook_research_with_judgment, deeplook_research`

#### 💻 Code Execution Risks
* 🟡 **Tool `deeplook_research`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `deeplook_research_with_judgment`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_21

**Tools Detected:** `filter_table_names, all_table_names, schema_definitions, execute_query`

#### 💻 Code Execution Risks
* 🟠 **Tool `execute_query`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`

---

### 📦 Repository: REDACTED_REPO_22

**Tools Detected:** `get_tests_for, list_projects, hybrid_search, serve, hook_install_agent, setup_guide, get_signature, workspace_search, show_status, config_vscode, codebase_map, semantic_search, platform_conditionals, get_communities, blame_symbol, get_platform_variants, get_symbol, relevant_learnings, workspace_index, embedding_health, hook_install, detect_changes, record_learning, get_dependents, search, status, get_implementors, find_dead_code, find_pattern, index, git_hotspots, index_status, get_execution_flows, embedding_status, workspace_status, get_callers, get_build_targets, get_impact, hook_uninstall, workspace_add, get_community, workspace_init, hook_status, get_callees, recent_changes, conversation_summary, hook_uninstall_agent, reindex, symbols, restart_server, whats_changed, workspace_list, changes_to, server_stats, workspace_remove, find_imports, get_type_hierarchy, learning_stats, config_cursor, search_symbols, symbols_in_file, config_claude_code`

#### 💻 Code Execution Risks
* 🟡 **Tool `restart_server`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_23

**Tools Detected:** `execute_manim_code, cleanup_manim_temp_dir`

#### 💻 Code Execution Risks
* 🔴 **Tool `execute_manim_code`** [OS_COMMAND_EXECUTION, UNRESTRICTED_FILE_WRITE]: Bare call to `open()` | `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `cleanup_manim_temp_dir`** [UNRESTRICTED_FILE_WRITE]: `shutil.rmtree()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_24

**Tools Detected:** `search_photos`

#### 💻 Code Execution Risks
* 🟡 **Tool `search_photos`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_25

**Tools Detected:** `size, balance, whoami, info, usage, register, pricing, transactions, risk, auth, evaluate`

#### 💻 Code Execution Risks
* 🟡 **Tool `whoami`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_26

**Tools Detected:** `get_regime_win_rates, run_scenario, refine_cohort_with_filters, report_feedback, get_pattern_degradation, clusters, analyze, compare_to_peers, detect_anomaly, get_regime_accuracy, context, get_cohort_distribution, get_follow_through, get_market_context, explain, search_batch, search, analyze_pattern, get_status, get_pattern_summary, get_crowding, get_portfolio_health, get_earnings_reaction, get_sector_rotation, check_ticker, portfolio, anchor_fetch, live_search, get_risk_adjusted_picks, get_volume_profile, get_exit_signal, decompose, get_discover_picks, get_correlation_shift, cohort, search_charts, explain_cohort_filters`

#### 💻 Code Execution Risks
* 🟡 **Tool `report_feedback`** [POTENTIAL_DATA_EXFILTRATION]: `requests.post()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_27

**Tools Detected:** `update_credentials, get_album_thumbnails, update_album, get_connection_info, ping, get_statistics, update_asset_metadata, remove_assets_from_album, search_smart, get_map_markers, get_album, get_server_version, add_assets_to_album, get_asset_thumbnail, list_shared_links, get_thumbnails_batch, get_asset_info, list_albums, create_album, create_shared_link, search_metadata, delete_album`

#### 💻 Code Execution Risks
* 🟡 **Tool `update_credentials`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_28

**Tools Detected:** `move_cell, start_command, insert_cell, list_notebooks, delete_cell, list_files, connect_command, read_notebook, execute_cell, connect_to_jupyter, execute_code, overwrite_cell_source, unuse_notebook, insert_execute_code_cell, list_kernels, edit_cell_source, stop_command, restart_notebook, use_notebook, read_cell`

#### 💻 Code Execution Risks
* 🟡 **Tool `connect_command`** [POTENTIAL_DATA_EXFILTRATION]: `httpx.put()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_29

**Tools Detected:** `run_esp_idf_install, setup_project_esp_target, run_pytest, build_esp_project, list_esp_serial_ports, flash_esp_project, create_esp_project`

#### 💻 Code Execution Risks
* 🟠 **Tool `build_esp_project`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟠 **Tool `setup_project_esp_target`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟠 **Tool `create_esp_project`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟠 **Tool `flash_esp_project`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟠 **Tool `list_esp_serial_ports`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟠 **Tool `run_esp_idf_install`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟠 **Tool `run_pytest`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`

---

### 📦 Repository: REDACTED_REPO_30

**Tools Detected:** `get_scene_info, download_sketchfab_model, import_generated_asset, poll_rodin_job_status, get_object_info, search_polyhaven_assets, generate_hunyuan3d_model, import_generated_asset_hunyuan, get_sketchfab_status, poll_hunyuan_job_status, execute_blender_code, get_sketchfab_model_preview, download_polyhaven_asset, set_texture, search_sketchfab_models, generate_hyper3d_model_via_images, get_hunyuan3d_status, get_viewport_screenshot, get_polyhaven_status, get_polyhaven_categories, generate_hyper3d_model_via_text, get_hyper3d_status`

#### 💻 Code Execution Risks
* 🟠 **Tool `get_viewport_screenshot`** [UNRESTRICTED_FILE_WRITE]: `os.remove()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_31

**Tools Detected:** `thinkneo_verification_dashboard, thinkneo_audit_export, thinkneo_list_alerts, thinkneo_a2a_flow_map, thinkneo_get_observability_dashboard, thinkneo_register_claim, thinkneo_router_explain, thinkneo_check_pii_international, thinkneo_registry_get, thinkneo_agent_roi, thinkneo_bridge_generate_agent_card, thinkneo_compliance_list, thinkneo_evaluate_guardrail, thinkneo_compliance_generate, thinkneo_cache_store, thinkneo_registry_review, thinkneo_schedule_demo, thinkneo_sla_status, thinkneo_get_proof, thinkneo_decision_cost, thinkneo_usage, thinkneo_cache_stats, thinkneo_registry_search, thinkneo_start_trace, thinkneo_sla_breaches, thinkneo_registry_publish, thinkneo_get_budget_status, thinkneo_set_baseline, thinkneo_evaluate_trust_score, thinkneo_log_risk_avoidance, thinkneo_provider_status, thinkneo_bridge_a2a_to_mcp, thinkneo_policy_violations, thinkneo_detect_injection, thinkneo_route_model, thinkneo_benchmark_report, thinkneo_simulate_savings, thinkneo_check_spend, thinkneo_read_memory, thinkneo_business_impact, thinkneo_cache_lookup, thinkneo_get_savings_report, thinkneo_policy_list, thinkneo_set_audit_export, thinkneo_compare_models, thinkneo_optimize_prompt, thinkneo_benchmark_compare, thinkneo_get_trace, thinkneo_sla_define, thinkneo_sla_dashboard, thinkneo_rotate_key, thinkneo_write_memory, thinkneo_policy_evaluate, thinkneo_bridge_mcp_to_a2a, thinkneo_policy_create, thinkneo_estimate_tokens, thinkneo_log_event, thinkneo_check_policy, thinkneo_end_trace, thinkneo_registry_install, thinkneo_scan_secrets, thinkneo_a2a_audit, thinkneo_log_decision, thinkneo_check, thinkneo_verify_claim, thinkneo_a2a_log, thinkneo_bridge_list_mappings, thinkneo_detect_waste, thinkneo_get_compliance_status, thinkneo_audit_export_status, thinkneo_get_trust_badge, thinkneo_a2a_set_policy`

#### 💻 Code Execution Risks
* 🟠 **Tool `thinkneo_a2a_log`** [DATABASE_MUTATION]: SQL mutation keyword in execute() call
* 🟠 **Tool `thinkneo_a2a_set_policy`** [DATABASE_MUTATION]: SQL mutation keyword in execute() call
* 🟠 **Tool `thinkneo_set_audit_export`** [DATABASE_MUTATION]: SQL mutation keyword in execute() call
* 🟠 **Tool `thinkneo_audit_export_status`** [DATABASE_MUTATION]: SQL mutation keyword in execute() call
* 🟠 **Tool `thinkneo_cache_lookup`** [DATABASE_MUTATION]: SQL mutation keyword in execute() call
* 🟠 **Tool `thinkneo_cache_store`** [DATABASE_MUTATION]: SQL mutation keyword in execute() call
* 🟠 **Tool `thinkneo_rotate_key`** [DATABASE_MUTATION]: SQL mutation keyword in execute() call
* 🟠 **Tool `thinkneo_set_baseline`** [DATABASE_MUTATION]: SQL mutation keyword in execute() call
* 🟠 **Tool `thinkneo_log_decision`** [DATABASE_MUTATION]: SQL mutation keyword in execute() call
* 🟠 **Tool `thinkneo_log_risk_avoidance`** [DATABASE_MUTATION]: SQL mutation keyword in execute() call

---

### 📦 Repository: REDACTED_REPO_32

**Tools Detected:** `list_functions_by_file, search_declarations, generate_ctags, list_api_files, list_indexed_apis`

#### 💻 Code Execution Risks
* 🟠 **Tool `search_declarations`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `list_indexed_apis`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `list_api_files`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `list_functions_by_file`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `generate_ctags`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_33

**Tools Detected:** `generate_sql_query, execute_sql_query, improve_sql_query`

#### 💻 Code Execution Risks
* 🟠 **Tool `execute_sql_query`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_34

**Tools Detected:** `version, setup, info, remove, list`

#### 💻 Code Execution Risks
* 🟠 **Tool `setup`** [ENV_SECRET_ACCESS, UNRESTRICTED_FILE_WRITE]: Bare call to `open()` | `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟠 **Tool `remove`** [ENV_SECRET_ACCESS, UNRESTRICTED_FILE_WRITE]: Bare call to `open()` | `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_35

**Tools Detected:** `get_fund_team, get_fund_detail, search_funds, get_all_funds, get_fund_basic`

#### 💻 Code Execution Risks
* 🟡 **Tool `search_funds`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `get_all_funds`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `get_fund_basic`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `get_fund_detail`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `get_fund_team`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_36

**Tools Detected:** `agoragentic_passport, agoragentic_search, agoragentic_invoke, agoragentic_memory_read, agoragentic_execute, execute_capability, agoragentic_memory_search, agoragentic_learning_queue, agoragentic_match, agoragentic_register, agoragentic_secret_store, agoragentic_save_learning_note, agoragentic_memory_write, agoragentic_vault, agoragentic_secret_retrieve`

#### 💻 Code Execution Risks
* 🟡 **Tool `execute_capability`** [POTENTIAL_DATA_EXFILTRATION]: `requests.post()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `agoragentic_register`** [POTENTIAL_DATA_EXFILTRATION]: `requests.post()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `agoragentic_invoke`** [POTENTIAL_DATA_EXFILTRATION]: `requests.post()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `agoragentic_memory_write`** [POTENTIAL_DATA_EXFILTRATION]: `requests.post()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `agoragentic_secret_store`** [POTENTIAL_DATA_EXFILTRATION]: `requests.post()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `agoragentic_execute`** [POTENTIAL_DATA_EXFILTRATION]: `requests.post()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_37

**Tools Detected:** `delete_webhook, create_new_webhook, get_webhook_details, list_all_webhooks`

#### 💻 Code Execution Risks
* 🟡 **Tool `create_new_webhook`** [POTENTIAL_DATA_EXFILTRATION]: `httpx.post()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_38

**Tools Detected:** `resize_sheet_dimensions, download_chat_attachment, format_sheet_range, get_doc_as_markdown, get_form_response, list_deployments, list_contact_groups, get_presentation, get_gmail_messages_content_batch, manage_drive_access, create_drive_file, get_script_metrics, export_doc_to_pdf, list_versions, debug_table_structure, manage_task_list, list_tasks, modify_sheet_values, get_contact_group, list_drive_items, manage_task, search_messages, modify_gmail_message_labels, search_custom, manage_out_of_office, get_gmail_threads_content_batch, list_task_lists, get_drive_file_permissions, list_gmail_labels, insert_doc_elements, create_reaction, check_drive_file_public_access, list_script_processes, get_page_thumbnail, list_sheet_tables, search_gmail_messages, manage_focus_time, get_doc_content, search_docs, query_freebusy, manage_contact, get_gmail_message_content, get_task, append_table_rows, create_drive_folder, get_script_project, manage_contacts_batch, update_paragraph_style, draft_gmail_message, get_messages, get_drive_shareable_link, list_spaces, set_drive_file_permissions, create_version, manage_contact_group, manage_gmail_filter, delete_doc_tab, list_calendars, get_task_list, get_version, modify_doc_text, batch_update_presentation, get_gmail_thread_content, create_sheet, create_script_project, read_sheet_values, search_contacts, inspect_doc_structure, create_table_with_data, search_drive_files, batch_update_doc, get_spreadsheet_info, manage_gmail_label, create_spreadsheet, delete_script_project, start_google_auth, list_contacts, copy_drive_file, create_form, update_script_content, create_presentation, get_script_content, get_search_engine_info, manage_conditional_formatting, send_gmail_message, list_docs_in_folder, get_drive_file_download_url, list_script_projects, generate_trigger_code, send_message, set_publish_settings, get_gmail_attachment_content, get_contact, create_doc, manage_event, list_spreadsheets, get_page, run_script_function, import_to_google_doc, manage_deployment, batch_modify_gmail_message_labels, update_drive_file, list_gmail_filters, insert_doc_image, get_drive_file_content, debug_docs_runtime_info, insert_doc_tab, update_doc_tab, update_doc_headers_footers, create_calendar, batch_update_form, get_form, find_and_replace_doc, list_form_responses, get_events`

#### 💻 Code Execution Risks
* 🟡 **Tool `search_custom`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `get_search_engine_info`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_39

**Tools Detected:** `eq_compare, eq_search, eq_targets, eq_profile, eq_sync, eq_recommend, eq_ranking`

#### 💻 Code Execution Risks
* 🟠 **Tool `eq_search`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `eq_profile`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `eq_recommend`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `eq_ranking`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `eq_targets`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_40

#### ⚙️ Configuration & Permission Risks
* 🔴 **HARDCODED_SECRET_IN_ENV** (in `claude_desktop_config.json`): Env var 'GEMINI_API_KEY' appears to contain a hardcoded secret (value: REPL***). Secrets in config files are leaked when config is committed to version control

---

### 📦 Repository: REDACTED_REPO_41

**Tools Detected:** `port_forward, get_limit_ranges, vind_resume, helm_pull, kind_delete_cluster, kind_ingress_setup, get_analysis_runs, browser_screenshot_argocd, analyze_network_policies, get_idle_resources, delete_resource, get_cluster_info, gitops_app_status, helm_repo_list, kubectl_cp, helm_get_values, vind_pause, kind_version, restart_rollout, kubevirt_vm_migrate, get_policy, helm_show_values, detect_cilium, get_pods, helm_dependency_build, get_overprovisioned_resources, vind_connect, helm_get_all, get_persistent_volumes, get_admission_webhooks, browser_install, istio_peerauthentications_list, kind_cluster_status, get_storage_classes, capi_get_cluster, check_crd_exists, kind_set_kubeconfig, explain_cert_status, capi_list_machinehealthchecks, get_previous_logs, node_top, istio_virtualservices_list, get_nodes, get_evicted_pods, kubevirt_vm_start, browser_open_cloud_console, get_namespace_cost_allocation, capi_list_machinesets, get_replicasets, kind_port_mappings, discover_crds, browser_session_load, gitops_apps_list, keda_scaledobjects_list, browser_open, kind_registry_status, helm_show_readme, istio_virtualservice_get, browser_session_switch, get_rollout, browser_click, annotate_resource, kubectl_describe, create_deployment, render_k8s_dashboard_screenshot, detect_backup, check_secrets_security, get_pod_security_info, multi_cluster_health, kind_images_list, get_current_context, keda_hpa_list, disable_kubeconfig_watching, cilium_list_nodes, helm_get_manifest, promote_rollout, helm_history, kind_node_restart, kind_load_image, keda_triggerauth_get, kind_provider_info, list_backup_locations, exec_in_pod, kubevirt_datasources_list, get_rbac_roles, get_events, list_backup_schedules, get_pod_events, vind_list_clusters, helm_get_notes, helm_dependency_update, helm_template, get_services, list_restores, get_resource_trends, browser_session_list, istio_gateways_list, health_check, istio_sidecar_status, istio_destinationrules_list, get_service_accounts, kind_create_cluster, get_configmaps, list_crds, kubevirt_vm_pause, kind_cluster_info, kubevirt_vm_unpause, kind_get_nodes, keda_detect, get_hubble_flows, helm_dependency_list, compare_namespaces, kubevirt_vm_restart, get_api_versions, get_logs, browser_screenshot_service, get_secrets, check_dns_resolution, get_namespaces, helm_package, create_backup, create_restore, gitops_source_get, trace_service_chain, set_server_stateless_mode, restart_deployment, get_statefulsets, vind_status, browser_snapshot, detect_capi, get_priority_classes, gitops_app_get, gitops_detect_engine, browser_get_text, kubevirt_instancetypes_list, kind_export_logs, kind_registry_create, kubectl_patch, set_namespace_for_context, show_pods_dashboard_ui, capi_list_clusterclasses, kind_network_inspect, kind_registry_connect, browser_screenshot_grafana, capi_list_machinedeployments, get_flagger_canaries, get_pvcs, get_node_metrics, vind_platform_start, search_crds, capi_get_cluster_kubeconfig, helm_env, renew_cert, istio_authorizationpolicies_list, abort_rollout, kind_node_labels, kind_node_exec, helm_search_hub, cilium_list_identities, helm_show_all, explain_policy_denial, browser_form_submit, kind_config_show, helm_template_apply, helm_repo_add, cilium_list_policies, get_hpa, capi_get_machine, kind_get_kubeconfig, browser_close, get_rollout_status, show_events_timeline_ui, upgrade_helm_chart, browser_test_ingress, describe_crd, create_backup_schedule, multi_cluster_pod_count, switch_context, vind_delete_cluster, node_management, istio_analyze, wait_for_condition, browser_pdf_export, detect_policy_engines, kubevirt_vm_get, backup_resource, kubeconfig_view, list_cert_challenges, kubevirt_vm_stop, kind_config_validate, get_cert, browser_session_save, kubectl_create, list_cert_requests, kind_node_inspect, get_rollouts_list, run_pod, get_jobs, get_endpoints, get_resource_quotas_usage, get_resource_recommendations, browser_set_viewport, cilium_get_policy, keda_scaledobject_get, keda_triggerauths_list, list_cert_issuers, get_ingress, node_logs, vind_logs, list_custom_resources, vind_disconnect, cilium_list_endpoints, show_pod_logs_ui, kubectl_rollout, enable_kubeconfig_watching, get_nodes_summary, get_deployments, kubectl_generic, taint_node, kubectl_explain, kind_list_clusters, delete_backup, get_crds, vind_create_cluster, get_pod_metrics, capi_list_clusters, helm_get_hooks, kind_available_images, diagnose_network_connectivity, get_backup, browser_connect_cdp, show_resource_yaml_ui, kubevirt_detect, browser_get_url, get_cert_issuer, helm_show_chart, kind_build_node_image, istio_proxy_status, kubevirt_vmis_list, kind_detect, detect_crds, get_resource_quotas, capi_list_machines, istio_detect, node_stats_summary, kind_config_generate, get_pdb, get_policy_violations, retry_rollout, kind_load_image_archive, helm_list, list_backups, get_policy_list, kubevirt_vms_list, get_flagger_canary, get_cluster_roles, helm_test, list_contexts, vind_get_kubeconfig, get_restore, browser_open_with_headers, gitops_sources_list, label_resource, get_resource_usage, kubevirt_datavolumes_list, get_daemonsets, audit_rbac_permissions, kubectl_apply, helm_status, multi_cluster_query, audit_policies, install_helm_chart, browser_health_check, detect_rollouts, helm_version, get_cluster_version, detect_pending_pods, gitops_app_sync, kind_node_logs, cilium_get_status, get_pod_conditions, get_server_config_status, diagnose_pod_crash, helm_search_repo, vind_upgrade, get_cost_analysis, check_pod_health, keda_scaledjobs_list, show_cluster_overview_ui, helm_rollback, detect_certs, get_api_resources, optimize_resource_requests, list_certs, get_context_details, kind_delete_all_clusters, helm_lint, browser_fill, browser_screenshot, helm_show_crds, uninstall_helm_chart, scale_deployment, capi_scale_machinedeployment, browser_set_provider, helm_repo_remove, analyze_pod_security, vind_describe, get_custom_resource, vind_detect, helm_create, helm_repo_update, cleanup_pods, browser_wait`

#### 💻 Code Execution Risks
* 🔴 **Tool `kubeconfig_view`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `switch_context`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `set_namespace_for_context`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `get_cluster_info`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `health_check`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `kubectl_explain`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `get_api_resources`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `get_api_versions`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `check_crd_exists`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `list_crds`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `node_logs`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `node_stats_summary`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `node_top`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `multi_cluster_query`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `get_resource_usage`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `get_idle_resources`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `get_overprovisioned_resources`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `get_resource_trends`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `optimize_resource_requests`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `scale_deployment`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `restart_deployment`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `get_pod_metrics`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `get_node_metrics`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `install_helm_chart`** [OS_COMMAND_EXECUTION, UNRESTRICTED_FILE_WRITE]: `subprocess.check_output()` inside agent tool — no human-in-the-loop confirmation parameter | `os.unlink()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `upgrade_helm_chart`** [OS_COMMAND_EXECUTION, UNRESTRICTED_FILE_WRITE]: `subprocess.check_output()` inside agent tool — no human-in-the-loop confirmation parameter | `os.unlink()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `uninstall_helm_chart`** [OS_COMMAND_EXECUTION]: `subprocess.check_output()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_list`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_status`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_history`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_get_values`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_get_manifest`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_get_notes`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_get_hooks`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_get_all`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_show_chart`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_show_values`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_show_readme`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_show_crds`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_show_all`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_search_repo`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_search_hub`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_repo_list`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_repo_add`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_repo_remove`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_repo_update`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_rollback`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool
* 🔴 **Tool `helm_test`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_lint`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_package`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_dependency_update`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_dependency_list`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_dependency_build`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_pull`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_create`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_version`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_env`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_template`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `helm_template_apply`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `diagnose_network_connectivity`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `check_dns_resolution`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `port_forward`** [OS_COMMAND_EXECUTION]: `subprocess.Popen()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `kubectl_apply`** [OS_COMMAND_EXECUTION, UNRESTRICTED_FILE_WRITE]: `os.unlink()` inside agent tool — no human-in-the-loop confirmation parameter | `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `kubectl_describe`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `kubectl_generic`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `kubectl_patch`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `kubectl_rollout`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `kubectl_create`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `delete_resource`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `kubectl_cp`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `backup_resource`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `label_resource`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `annotate_resource`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `taint_node`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `wait_for_condition`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `node_management`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool
* 🔴 **Tool `exec_in_pod`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `cleanup_pods`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `get_previous_logs`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `show_resource_yaml_ui`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_42

#### ⚙️ Configuration & Permission Risks
* 🔴 **HARDCODED_SECRET_IN_ENV** (in `claude_desktop_config.json`): Env var 'APIKEY' appears to contain a hardcoded secret (value: 7v9H***). Secrets in config files are leaked when config is committed to version control

---

### 📦 Repository: REDACTED_REPO_43

**Tools Detected:** `convert_pdf, version, bench, analyze_pdf, serve, doctor, get_pdf_metadata, batch_convert, analyze, convert, benchmark, extract_structured`

#### 💻 Code Execution Risks
* 🟡 **Tool `serve`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_44

**Tools Detected:** `bing_web_search, bing_image_search, bing_news_search`

#### 💻 Code Execution Risks
* 🟡 **Tool `bing_web_search`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `bing_news_search`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `bing_image_search`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_45

**Tools Detected:** `list_services, get_db_credentials, ask_agent, execute_sql, update_ip_allowlist, delete_db, launch_serverless_db, list_agents`

#### 💻 Code Execution Risks
* 🟠 **Tool `execute_sql`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_46

**Tools Detected:** `language, review_log_dir, view, models, show_config, mcp, review, debug_mode, model, proactive_multiturn_threshold`

#### 💻 Code Execution Risks
* 🔴 **Tool `mcp`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_47

**Tools Detected:** `health_check, modify_smali_file, get_workspace_info, list_smali_files, clean_project, get_apktool_yml, modify_resource_file, get_smali_file, list_resources, get_manifest, build_apk, get_resource_file, analyze_project_structure, decode_apk, search_in_files, list_smali_directories`

#### 💻 Code Execution Risks
* 🟠 **Tool `modify_smali_file`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟠 **Tool `modify_resource_file`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟠 **Tool `clean_project`** [UNRESTRICTED_FILE_WRITE]: `shutil.rmtree()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_48

**Tools Detected:** `get_relationships, get_available_tables, store, get_manifest, get_version, validate, upgrade, list_cmd, reset, instructions, list_remote_constraints, get_table_info, recall, dump, init, deploy, forget, parse_types_cmd, dry_plan, status, query, get_table_columns_info, describe, index, debug, version, parse_type_cmd, show, fetch, get_current_data_source_type, get_column_info, deploy_manifest, build, rm, get_available_functions, dry_run, is_deployed, health_check, get_wren_guide, mdl_validate_manifest, docs_connection_info, add, list_queries, load, list_remote_tables, switch`

#### 💻 Code Execution Risks
* 🟡 **Tool `mdl_validate_manifest`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_49

**Tools Detected:** `get_agent, update_message_feedback, get_traffic_report, get_agent_stats, update_source_settings, delete_conversation, list_pages, create_plugin, create_agent_license, get_message_details, get_citation, get_analysis_report, list_agents, update_plugin, send_message, create_agent, update_user_profile, get_page_metadata, update_page_metadata, delete_source, get_conversation_messages, update_conversation, update_agent, list_plugins, delete_page, get_license_details, get_intelligence_report, search_team_member, create_source, update_agent_settings, send_conversation_message, update_license, delete_license, list_agent_licenses, get_conversations_report, list_conversations, validate_api_key, get_agent_settings, get_user_profile, list_sources, delete_agent, get_queries_report, stream_to_claude, get_usage_limits, replicate_agent, create_conversation, synchronize_source, preview_page, get_server_info, reindex_page`

#### 💻 Code Execution Risks
* 🟡 **Tool `list_agents`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `validate_api_key`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_50

**Tools Detected:** `text_to_speech`

#### 💻 Code Execution Risks
* 🟡 **Tool `text_to_speech`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_51

#### ⚙️ Configuration & Permission Risks
* 🔴 **CODE_EXECUTION_NO_CONFIRMATION** (in `mcp.json`): Server can execute code (exec) without human confirmation gate

---

### 📦 Repository: REDACTED_REPO_52

**Tools Detected:** `tools_command, models_command, prompts_command, servers_command, providers_command, tokens_command, _interactive_command, cmd_command, ping_command, _chat_command, theme_command, resources_command, cli_entry, provider_command, token_command`

#### 💻 Code Execution Risks
* 🟡 **Tool `_chat_command`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_53

**Tools Detected:** `health_check, delete_pipeline, execute_tql, explain_query, list_pipelines, describe_table, create_pipeline, dryrun_pipeline, execute_sql, list_dashboards, query_range, delete_dashboard, create_dashboard`

#### 💻 Code Execution Risks
* 🟠 **Tool `describe_table`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `health_check`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `execute_tql`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `query_range`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `explain_query`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `list_pipelines`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_54

**Tools Detected:** `get_portfolio_summary, add_holding, get_price, portfolio_value_history`

#### 💻 Code Execution Risks
* 🟠 **Tool `get_portfolio_summary`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `add_holding`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `portfolio_value_history`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_55

**Tools Detected:** `numeric_planner, validate_pddl_syntax, classic_planner, save_plan, get_state_transition`

#### 💻 Code Execution Risks
* 🟠 **Tool `save_plan`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`

---

### 📦 Repository: REDACTED_REPO_56

**Tools Detected:** `gdpr_generate_report, validate_api_key, generate_annex4_package, check_compliance, certify_compliance_report, gdpr_check_compliance, get_pricing, generate_report, register_free_key, gdpr_generate_templates, suggest_risk_category, generate_compliance_templates, scan_project, combined_compliance_report, gdpr_scan_project, generate_compliance_roadmap`

#### 💻 Code Execution Risks
* 🟡 **Tool `register_free_key`** [POTENTIAL_DATA_EXFILTRATION]: `urllib.request.urlopen()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_57

#### ⚙️ Configuration & Permission Risks
* 🔴 **CODE_EXECUTION_NO_CONFIRMATION** (in `tools.json`): Server can execute code (exec) without human confirmation gate

---

### 📦 Repository: REDACTED_REPO_58

**Tools Detected:** `list_memories, get_cache_stats, retrieve_memory, store_memory, search_by_tag, delete_memory, ingest_document, list_formats, check_database_health, test_store_memory, memory_graph, server, status, ingest_directory, test_health`

#### 💻 Code Execution Risks
* 🟡 **Tool `server`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_59

**Tools Detected:** `serve, reject, log, edit, approve, skills_list, team_sync, team_activate, team_edit, team_deactivate, team_create, init, skills_export, config, show, skills_import, team_list, team_show, path, pending, export, ingest, skills_delete`

#### 💻 Code Execution Risks
* 🔴 **Tool `edit`** [ENV_SECRET_ACCESS, OS_COMMAND_EXECUTION]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars | `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `team_edit`** [ENV_SECRET_ACCESS, OS_COMMAND_EXECUTION]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars | `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_60

**Tools Detected:** `context_default, bundle_export, bundle_import, doctor, find_by_name, analyze_complexity, find_by_content_search, context_delete, config_reset, config_set, analyze_callers, mcp_start, mcp_setup_alias, analyze_chain, export_shortcut, find_by_decorator_search, context_create, list_repositories, analyze_dead_code, registry_request, registry_search, cypher_legacy, version_cmd, analyze_overrides, analyze_dependencies, context_mode, index, find_by_pattern, find_by_type, bundle_load, analyze_calls, find_by_variable, neo4j_setup, watching, analyze_inheritance_tree, watch, config_db, stats, help, clean, list_abbrev, analyze_variable_usage, context_list, mcp_tools, mcp_setup, query_graph, find_by_argument_search, delete_abbrev, watch_abbrev, config_show, delete, registry_list, unwatch, load_shortcut, registry_download, visualize_abbrev, neo4j_setup_alias, visualize, index_abbrev, add_package`

#### 💻 Code Execution Risks
* 🟡 **Tool `doctor`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_61

**Tools Detected:** `save_draft, scrape_article`

#### 💻 Code Execution Risks
* 🟠 **Tool `save_draft`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`

---

### 📦 Repository: REDACTED_REPO_62

**Tools Detected:** `store_memory, recall_memory`

#### 💻 Code Execution Risks
* 🟡 **Tool `recall_memory`** [POTENTIAL_DATA_EXFILTRATION]: `httpx.post()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `store_memory`** [POTENTIAL_DATA_EXFILTRATION]: `httpx.post()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_63

**Tools Detected:** `store_memory, recall_memory`

#### ⚙️ Configuration & Permission Risks
* 🟠 **DESTRUCTIVE_TOOL_NO_CONFIRMATION** (in `mcp.json`): Server exposes destructive operations (delete) without require_confirmation. Prompt injection can trigger irreversible data deletion

---

### 📦 Repository: REDACTED_REPO_64

**Tools Detected:** `idalib_switch, callgraph, export_funcs, server_warmup, put_int, idalib_current, dbg_gpregs, disasm, decompile, insn_query, infer_types, define_code, analyze_batch, read_struct, define_func, lookup_funcs, idalib_list, dbg_exit, dbg_regs, dbg_regs_named_remote, dbg_stacktrace, xref_query, trace_data_flow, open_file, imports, idalib_unbind, dbg_regs_all, idalib_save, type_apply_batch, get_global_value, imports_query, list_instances, basic_blocks, analyze_component, idalib_close, get_bytes, entity_query, stack_frame, dbg_step_over, search_text, declare_type, search_structs, rename, append_comments, dbg_gpregs_remote, dbg_delete_bp, find_regex, callees, dbg_toggle_bp, xrefs_to_field, patch, list_funcs, diff_before_after, find_xref_signatures, dbg_continue, idalib_open, type_inspect, xrefs_to, declare_stack, dbg_write, dbg_step_into, select_instance, type_query, delete_stack, py_eval, idb_save, py_exec_file, set_type, patch_asm, undefine, dbg_bps, dbg_start, survey_binary, set_comments, int_convert, dbg_run_to, func_profile, idalib_health, dbg_regs_remote, dbg_regs_named, server_health, get_string, list_globals, find_bytes, dbg_read, make_signature, get_int, dbg_add_bp, make_signature_for_function, analyze_function, idalib_warmup, enum_upsert, func_query, make_signature_for_range, find`

#### 💻 Code Execution Risks
* 🔴 **Tool `open_file`** [OS_COMMAND_EXECUTION]: `subprocess.Popen()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `py_eval`** [CODE_EXECUTION]: Bare call to `exec()`
* 🔴 **Tool `py_exec_file`** [CODE_EXECUTION]: Bare call to `exec()`

---

### 📦 Repository: REDACTED_REPO_65

**Tools Detected:** `dbt_model_analyzer_agent, dbt_mcp_tool, dbt_compile`

#### 💻 Code Execution Risks
* 🔴 **Tool `dbt_compile`** [ENV_SECRET_ACCESS, OS_COMMAND_EXECUTION]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars | `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `dbt_model_analyzer_agent`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_66

**Tools Detected:** `install, snapshot_list, whoami, report, feedback, telemetry_on, drift_cmd, quarantine_list, init, validate_adapter, adapters, capture, telemetry_status, golden_list, autopr, snapshot_show, lookup_order, tavily_search_results_json, check_order, baseline_set, calculator, inspect_cmd, view, skill_test, generate, visualize_cmd, replay_trace, skill_generate_tests, monitor, connect, telemetry_off, search_kb, quickstart, quarantine_add, traces_export, baseline_clear, trends, simulate, badge, model_check, skill_validate, slack_digest_cmd, trace_cmd, import_logs, list_cmd, quarantine_remove, compare_cmd, record, baseline_show, log_cmd, traces_show, golden_show, uninstall_hooks, judge, check, expand, golden_save, mcp_serve, snapshot_delete, golden_delete, send_reply, traces_list, skill_doctor, ci_comment, replay, mcp_delete, demo, install_hooks, mcp_snapshot, mcp_show, mcp_check, benchmark_cmd, since_cmd, create_ticket, login, check_policy, gym, openclaw_check, watch, skill_list, add, progress_cmd, logout, mcp_list, traces_cost_report, chat`

#### 💻 Code Execution Risks
* 🟠 **Tool `add`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟡 **Tool `capture`** [POTENTIAL_DATA_EXFILTRATION]: `httpx.post()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `check`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟡 **Tool `ci_comment`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟠 **Tool `demo`** [UNRESTRICTED_FILE_WRITE]: `shutil.rmtree()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `quickstart`** [ENV_SECRET_ACCESS, OS_COMMAND_EXECUTION, POTENTIAL_DATA_EXFILTRATION]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars | `urllib.request.urlopen()` inside agent tool — no human-in-the-loop confirmation parameter | `subprocess.Popen()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `judge`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟡 **Tool `telemetry_status`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `telemetry_on`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `tavily_search_results_json`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_67

**Tools Detected:** `search_nearby`

#### 💻 Code Execution Risks
* 🟡 **Tool `search_nearby`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_68

**Tools Detected:** `get_api_status, list_teams, list_event_types, list_users, list_webhooks, list_schedules, create_booking, get_bookings`

#### 💻 Code Execution Risks
* 🟡 **Tool `create_booking`** [POTENTIAL_DATA_EXFILTRATION]: `requests.post()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_69

**Tools Detected:** `add, release, purge, generate`

#### 💻 Code Execution Risks
* 🟠 **Tool `purge`** [UNRESTRICTED_FILE_WRITE]: `shutil.rmtree()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_70

**Tools Detected:** `get_world_bank_indicator, get_weather_forecast, get_population_stats, get_historical_typhoons_ph, get_weather_alerts, get_poverty_stats, get_usgs_earthquakes_ph, get_procurement_summary, get_air_quality, get_volcano_status, get_latest_earthquakes, get_vegetation_index, get_active_typhoons, assess_area_risk, get_solar_and_climate, get_earthquake_bulletin, search_procurement`

#### 💻 Code Execution Risks
* 🟡 **Tool `get_weather_forecast`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_71

**Tools Detected:** `unfollow_playlist, get_current_user_playlists, test_steam_credentials, get_trending_videos, test_spotify_credentials, get_user_saved_shows, get_user_comments, steam_credentials, get_bilibili_watch_history, get_user_karma_breakdown, get_user_submitted_posts, my_steam_recent_activity, get_contributor_subreddits, get_steam_config, get_youtube_config, get_steam_friends, get_friends_current_games, get_bilibili_config, get_moderated_subreddits, get_spotify_token_status, get_bilibili_user_videos, get_playlist_items, setup_youtube_oauth, reddit_token_status, get_user_subreddits, bilibili_search, youtube_trending, get_user_trophies, get_reddit_config, get_inbox_messages, get_bilibili_toview_list, complete_youtube_oauth, get_youtube_subscriptions, get_downvoted_content, spotify_credentials, get_hidden_posts, refresh_reddit_token, get_bilibili_following_list, get_user_playlists, steam_profile, get_youtube_liked_videos, get_user_profile, follow_playlist, setup_spotify_oauth, get_youtube_playlists, get_player_summary, get_reddit_token_status, complete_spotify_oauth, get_my_bilibili_profile, refresh_spotify_token, complete_reddit_oauth, serve, get_video_details, onboarding, get_spotify_config, get_user_recently_played, get_sent_messages, setup_reddit_oauth, youtube_credentials, reddit_credentials, get_user_saved_audiobooks, get_bilibili_user_info, search_youtube_videos, refresh_youtube_token, auto_refresh_reddit_token_if_needed, get_player_achievements, auto_refresh_youtube_token_if_needed, follow_artists_or_users, test_connection, get_steam_library, get_saved_content, get_steam_recent_activity, get_unread_messages, get_steam_profile, list_profiles, get_friend_game_recommendations, test_youtube_credentials, get_bilibili_video_info, test_reddit_credentials, test_bilibili_credentials, get_current_user_profile, get_user_game_stats, get_followed_artists, get_user_overview, get_user_preferences, steam_library, get_user_top_items, spotify_recent, status, unfollow_artists_or_users, bilibili_video_info, spotify_token_status, get_user_saved_episodes, bilibili_credentials, auto_refresh_spotify_token_if_needed, get_bilibili_favorites, compare_games_with_friend, get_user_saved_albums, get_channel_info, get_user_saved_tracks, get_upvoted_content, search_bilibili_videos, youtube_search, add, reddit_subreddits, get_personalization_status, get_youtube_token_status`

#### 💻 Code Execution Risks
* 🟡 **Tool `onboarding`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `setup_reddit_oauth`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `complete_reddit_oauth`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `get_steam_friends`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `my_steam_recent_activity`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `get_steam_config`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `get_player_summary`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `get_player_achievements`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `get_user_game_stats`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `get_friends_current_games`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `compare_games_with_friend`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `get_friend_game_recommendations`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟠 **Tool `complete_youtube_oauth`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟡 **Tool `get_youtube_subscriptions`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `get_youtube_playlists`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `get_youtube_liked_videos`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_72

**Tools Detected:** `kagi_summarizer, kagi_search_fetch`

#### 💻 Code Execution Risks
* 🟡 **Tool `kagi_summarizer`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_73

**Tools Detected:** `tv_launch, license_remove, tv_history, cache_show, scene_create_cmd, tv_screen, tv_groups, whats_on, tv_state, history, info, tv_display, tv_status, audio_volume_cmd, play, tv_resolve, audio_stop_cmd, scene_delete_cmd, display_message, group_create_cmd, insights_cmd, tv_cast, tv_volume, pause, group_list_cmd, tv_recommend, scene_run_cmd, apps, setup, resolve, multi_list, license_status, doctor, serve, queue_add_cmd, mute, notify, screen_time_cmd, cast, multi_add, queue_show_cmd, tv_insights, tv_power, tv_notify, search, tv_queue, volume, tv_audio, launch, queue_clear_cmd, cache_set, display_dashboard, audio_play_cmd, display_url, multi_default, recommend, queue_skip_cmd, tv_next, cache_contribute, tv_state_watch, sub_value_cmd, multi_remove, queue_play_cmd, scene_list_cmd, tv_scene, on, tv_play, tv_sync, status, cache_get, close, tv_whats_on, group_delete_cmd, license_set, next, display_clock, off, tv_list_tvs`

#### 💻 Code Execution Risks
* 🟡 **Tool `license_status`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_74

#### ⚙️ Configuration & Permission Risks
* 🔴 **HARDCODED_SECRET_IN_ENV** (in `claude_desktop_config.json`): Env var 'AGENT_PRIVATE_KEY' appears to contain a hardcoded secret (value: 0xYO***). Secrets in config files are leaked when config is committed to version control

---

### 📦 Repository: REDACTED_REPO_75

**Tools Detected:** `config, search, help, media, extract`

#### 💻 Code Execution Risks
* 🟡 **Tool `config`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_76

**Tools Detected:** `search_slots, get_supplier_info, book_slot, get_booking_status, preview_slot, book_from_itinerary`

#### 💻 Code Execution Risks
* 🟡 **Tool `preview_slot`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_77

**Tools Detected:** `check_if_snippets_are_valid_typst_syntax, latex_snippets_to_typst, get_docs_chapters, latex_snippet_to_typst, get_docs_chapter, typst_snippet_to_image, check_if_snippet_is_valid_typst_syntax, list_docs_chapters`

#### 💻 Code Execution Risks
* 🔴 **Tool `latex_snippet_to_typst`** [OS_COMMAND_EXECUTION, UNRESTRICTED_FILE_WRITE]: Bare call to `open()` | `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `check_if_snippet_is_valid_typst_syntax`** [OS_COMMAND_EXECUTION, UNRESTRICTED_FILE_WRITE]: Bare call to `open()` | `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `typst_snippet_to_image`** [OS_COMMAND_EXECUTION, UNRESTRICTED_FILE_WRITE]: Bare call to `open()` | `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_78

**Tools Detected:** `restore_drive_revision, resize_sheet_dimensions, download_chat_attachment, format_slides_text, format_sheet_range, get_doc_as_markdown, get_form_response, list_deployments, list_contact_groups, get_presentation, get_gmail_messages_content_batch, manage_drive_access, create_drive_file, insert_slides_image, get_script_metrics, protect_sheet_range, export_doc_to_pdf, list_versions, debug_table_structure, manage_task_list, insert_doc_link, modify_sheet_values, list_tasks, get_contact_group, list_drive_items, format_slides_paragraph, manage_task, search_messages, modify_gmail_message_labels, search_custom, manage_out_of_office, insert_doc_file_chip, get_gmail_threads_content_batch, list_task_lists, list_doc_tabs, get_drive_file_permissions, list_gmail_labels, insert_doc_elements, create_reaction, check_drive_file_public_access, list_script_processes, get_page_thumbnail, list_sheet_tables, search_gmail_messages, get_slides_speaker_notes, create_slides_text_box, manage_sheet_tabs, duplicate_slide, manage_focus_time, add_sheet_data_validation, apply_continuous_numbering, get_doc_content, search_docs, query_freebusy, manage_contact, get_gmail_message_content, style_slides_shape, get_task, append_table_rows, create_drive_folder, get_script_project, manage_contacts_batch, update_paragraph_style, draft_gmail_message, get_messages, get_drive_shareable_link, insert_doc_person_chip, list_spaces, set_drive_file_permissions, create_version, manage_contact_group, manage_gmail_filter, delete_doc_tab, list_calendars, get_task_list, get_version, modify_doc_text, batch_update_presentation, get_gmail_thread_content, create_sheet, create_script_project, read_sheet_values, search_contacts, inspect_doc_structure, create_table_with_data, search_drive_files, batch_update_doc, get_spreadsheet_info, update_slides_speaker_notes, manage_gmail_label, get_drive_revisions, create_spreadsheet, delete_script_project, start_google_auth, list_contacts, copy_drive_file, create_form, update_script_content, create_presentation, get_script_content, copy_drive_folder, get_search_engine_info, delete_slides_element, get_doc_smart_chips, create_slides_shape, manage_conditional_formatting, send_gmail_message, list_docs_in_folder, reorder_slides, get_drive_file_download_url, list_script_projects, format_all_slides_text, generate_trigger_code, send_message, set_publish_settings, get_gmail_attachment_content, set_slides_background, get_contact, create_doc, manage_event, list_spreadsheets, get_page, run_script_function, import_to_google_doc, manage_deployment, batch_modify_gmail_message_labels, update_drive_file, insert_doc_markdown, insert_doc_image, list_gmail_filters, get_drive_file_content, replace_slides_text, debug_docs_runtime_info, insert_doc_tab, add_sheet_named_range, update_doc_tab, update_doc_headers_footers, create_calendar, batch_update_form, get_form, find_and_replace_doc, list_form_responses, get_events`

#### 💻 Code Execution Risks
* 🟡 **Tool `search_custom`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `get_search_engine_info`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_79

#### ⚙️ Configuration & Permission Risks
* 🔴 **LETHAL_TRIFECTA** (in `tools.json`): Server has all three Lethal Trifecta legs — private data access (sql, mysql), untrusted input exposure (https, http), exfiltration vector (https, http). A single prompt injection can exfiltrate all private data silently
* 🔴 **CODE_EXECUTION_NO_CONFIRMATION** (in `tools.json`): Server can execute code (exec) without human confirmation gate
* 🟠 **DESTRUCTIVE_TOOL_NO_CONFIRMATION** (in `tools.json`): Server exposes destructive operations (envDomainManagement, writeNoSqlDatabaseStructure, deleteFiles) without require_confirmation. Prompt injection can trigger irreversible data deletion

---

### 📦 Repository: REDACTED_REPO_80

**Tools Detected:** `wait_for_resource, describe_resource, enable_resource, list_resources, get_resource_logs, disable_resource, trigger_resource`

#### 💻 Code Execution Risks
* 🔴 **Tool `trigger_resource`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `enable_resource`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `disable_resource`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `wait_for_resource`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_81

**Tools Detected:** `get_situation_summary, get_block_count, get_address_transactions, analyze_transaction, get_network_info, get_difficulty_adjustment, analyze_next_block, get_btc_price, get_mining_pool_rankings, get_chain_tx_stats, get_node_status, get_fee_recommendation, check_utxo, get_halving_countdown, get_mempool_entry, analyze_psbt_security, get_blockchain_info, estimate_transaction_cost, get_address_balance, list_rpc_commands, get_address_utxos, send_raw_transaction, get_utxo_set_info, get_block_stats, get_mempool_info, explain_script, generate_keypair, get_address_history, decode_raw_transaction, estimate_smart_fee, compare_blocks, get_indexed_transaction, decode_xpub, explain_inscription_listing_security, get_market_sentiment, compare_fee_estimates, get_supply_info, search_blocks, get_mempool_ancestors, get_mining_info, analyze_block, get_chain_tips, decode_bolt11_invoice, get_peer_info, describe_rpc_command, get_indexer_status, search_blockchain, validate_address, query_remote_api, analyze_mempool, get_fee_estimates`

#### ⚙️ Configuration & Permission Risks
* 🔴 **LETHAL_TRIFECTA** (in `tools.json`): Server has all three Lethal Trifecta legs — private data access (query), untrusted input exposure (network), exfiltration vector (network). A single prompt injection can exfiltrate all private data silently

#### 💻 Code Execution Risks
* 🟡 **Tool `estimate_transaction_cost`** [POTENTIAL_DATA_EXFILTRATION]: `urllib.request.urlopen()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `get_mining_pool_rankings`** [POTENTIAL_DATA_EXFILTRATION]: `urllib.request.urlopen()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `get_situation_summary`** [POTENTIAL_DATA_EXFILTRATION]: `urllib.request.urlopen()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `get_btc_price`** [POTENTIAL_DATA_EXFILTRATION]: `urllib.request.urlopen()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `get_market_sentiment`** [POTENTIAL_DATA_EXFILTRATION]: `urllib.request.urlopen()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_82

**Tools Detected:** `compare_contexts_across_registries, count_schemas, update_global_config, get_default_registry, compare_registries, get_subject_config, register_schema, list_available_workflows, get_subject_mode, ping, migrate_schema, describe_workflow, export_subject, create_context_interactive, bulk_schema_update, guided_disaster_recovery, get_schema, get_schema_versions, get_registry_info, clear_context_batch, count_schema_versions, list_workflows, list_registries, list_available_resources, get_elicitation_request, bulk_operations_wizard, export_schema, list_subjects, submit_elicitation_response, test_all_registries, get_elicitation_status, generate_resource_templates, bulk_configuration_update, suggest_resource_for_tool, count_contexts, delete_subject, bulk_schema_cleanup, migrate_context_interactive, add_subject_alias, find_missing_schemas, update_subject_mode, export_global, set_default_registry, test_oauth_discovery_endpoints, abort_workflow, create_context, get_global_config, workflow_status, test_registry_connection, update_mode, delete_context, export_context, guided_schema_migration, update_subject_config, get_mcp_compliance_status_tool, guided_context_reorganization, get_workflow_status, clear_multiple_contexts_batch, get_subjects_by_schema_id, check_compatibility_interactive, bulk_schema_migration, export_global_interactive, get_registry_statistics, get_oauth_scopes_info_tool, list_elicitation_requests, start_workflow, guided_schema_evolution, list_contexts, register_schema_interactive, delete_subject_alias, get_schema_by_id, cancel_elicitation_request, check_compatibility, get_mode, migrate_context`

#### ⚙️ Configuration & Permission Risks
* 🟠 **SECRET_IN_ARGS** (in `claude_desktop_config.json`): High-entropy value in args array ('kafka_***') looks like a hardcoded secret. Values in args are visible in process listings and are not protected by environment variable scoping

#### 💻 Code Execution Risks
* 🟡 **Tool `test_oauth_discovery_endpoints`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_83

**Tools Detected:** `podbc_virtuoso_support_ai, podbc_describe_table, podbc_sparql_get_ontologies, podbc_spasql_query, podbc_execute_query_md, podbc_sparql_get_entity_types_detailed, podbc_get_tables, podbc_execute_query, podbc_sparql_get_entity_types, podbc_get_schemas, podbc_query_database, podbc_filter_table_names, podbc_sparql_func, podbc_sparql_get_entity_types_samples`

#### 💻 Code Execution Risks
* 🟠 **Tool `podbc_execute_query`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `podbc_execute_query_md`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `podbc_query_database`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `podbc_spasql_query`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `podbc_virtuoso_support_ai`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `podbc_sparql_func`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_84

**Tools Detected:** `inspect_sprite, capture_frames, pyxel_info, inspect_tilemap, inspect_animation, play_and_capture, validate_script, run_and_capture, inspect_screen, inspect_layout, inspect_palette, inspect_state, compare_frames, render_audio, inspect_bank`

#### 💻 Code Execution Risks
* 🟠 **Tool `run_and_capture`** [UNRESTRICTED_FILE_WRITE]: `os.unlink()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `render_audio`** [UNRESTRICTED_FILE_WRITE]: `os.unlink()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `capture_frames`** [UNRESTRICTED_FILE_WRITE]: `shutil.rmtree()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `play_and_capture`** [UNRESTRICTED_FILE_WRITE]: `shutil.rmtree()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `inspect_bank`** [UNRESTRICTED_FILE_WRITE]: `shutil.rmtree()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_85

**Tools Detected:** `nexo_followup_update, nexo_hot_context_list, nexo_guard_check, nexo_reminder_get, nexo_learning_list, nexo_reminder_create, nexo_continuity_snapshot_read, nexo_continuity_compaction_event, nexo_recent_context_capture, nexo_followup_get, nexo_recent_context, nexo_cortex_check, nexo_drive_act, nexo_continuity_audit, nexo_recent_context_resolve, nexo_followup_restore, nexo_plugin_remove, nexo_answer, nexo_startup, nexo_followup_note, nexo_index_dirs, nexo_task_open, nexo_workflow_open, nexo_reminder_note, nexo_files, nexo_session_log_create, nexo_learning_apply_retroactively, nexo_task_frequency, nexo_task_close, nexo_session_portable_context, nexo_drive_signals, nexo_learning_delete, nexo_transcript_search, nexo_ask, nexo_continuity_resume_bundle, nexo_untrack, nexo_reindex, nexo_learning_quality, nexo_credential_create, nexo_credential_update, nexo_task_acknowledge_guard, nexo_followup_delete, nexo_drive_dismiss, nexo_transcript_read, nexo_credential_delete, nexo_pre_action_context, nexo_task_log, nexo_index_remove_dir, nexo_checkpoint_save, nexo_status, nexo_credential_list, nexo_heartbeat, nexo_context_packet, nexo_followup_create, nexo_session_log_close, nexo_drive_reinforce, nexo_tool_explain, nexo_transcript_recent, nexo_continuity_snapshot_write, nexo_reminders, nexo_followup_complete, nexo_session_export_bundle, nexo_guardian_rule_override, nexo_learning_update, nexo_reminder_delete, nexo_task_list, nexo_learning_add, nexo_plugin_list, nexo_credential_get, nexo_smart_startup, nexo_stop, nexo_plugin_load, nexo_reminder_complete, nexo_hook_runs, nexo_send, nexo_track, nexo_workflow_update, nexo_menu, nexo_checkpoint_read, nexo_learning_search, nexo_index_add_dir, nexo_system_catalog, nexo_check_answer, nexo_reminder_restore, nexo_reminder_update`

#### 💻 Code Execution Risks
* 🟠 **Tool `nexo_reindex`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_86

**Tools Detected:** `describe_table, list_tables, read_query`

#### 💻 Code Execution Risks
* 🟠 **Tool `read_query`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `list_tables`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `describe_table`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_87

**Tools Detected:** `mcp_get_deployment_status, list_remove, json_nummultby, rabbitmq_broker_is_in_alarm, connect_jump_host_serverless, check_security_services, check_network_security_tool, mcp_containerize_app, sp_performance, list_custom_line_item_versions, rabbitmq_broker_get_guideline, create_token_with_iam, dsql_search_documentation, delete_study, generate_infrastructure_code, create_datastore, cost_explorer, get_resource_policy, update_db_instance, json_arrappend, generate_data_access_layer, rabbitmq_broker_list_connections, sorted_set_rank, delete_resource, delete_cache_cluster, string_increment, dsql_recommend, stream_group_destroy, dynamodb_data_model_schema_converter, set_cardinality, list_policies, influxdb_query, delete, create_queue, search_cdk_samples_and_constructs, influxdb_write_line_protocol, sorted_set_remove_by_lex, read_image, finch_create_ecr_repo, attach_group_policy, stream_read_group, attach_user_policy, hll_add, update_table_metadata_location, get_available_workspaces, list_db_clusters_by_status, influxdb_list_buckets, string_get_range, list_knowledge_bases_tool, sorted_set_range, audit_slos, sorted_set_popmin, list_datastores, get_table_metadata_location, string_increment_float, json_arrpop, list_clusters_tool, start_dicom_export_job, cache_delete, sorted_set_remove_by_rank, delete_access_key, modify_replication_group, get_pricing, resolve_support_case, delete_datastore, get_log_events, cache_delete_many, import_csv_to_table, search_by_patient_id, list_dicom_import_jobs, read_sections, string_append, start_dicom_import_job, sorted_set_range_by_lex, sorted_set_range_by_score, connect_jump_host_rg, tag_resource, list_insert_after, list_groups, set_contains, delete_role_policy, set_remove, list_user_policies, list_table_buckets, get_patient_series, stream_info_consumers, get_aws_session_info, list_tables_tool, validate_cloudformation_template, get_pricing_service_attributes, list_range, analyze_cdk_project_wrapper, sorted_set_add, create_api_cache, bcm_pricing_calc, stream_group_create, create_channel_namespace, set_members, stream_delete, cache_quit, mcp_ecs_resource_management, rabbimq_broker_initialize_connection_with_oauth, put_role_policy, get_schema, mcp_delete_ecs_infrastructure, describe_service_updates, get_dicom_import_job, cache_cas, hash_random_field, delete_user, detach_user_policy, hash_set_if_not_exists, json_del, hash_get_all, delete_user_policy, modify_serverless_cache, list_account_associations, describe_support_cases, stream_length, bulk_delete_by_criteria, transact, create_table, stream_trim, search_places_open_now, influxdb_create_bucket, create_jump_host_serverless, batch_stop_update_action, set_add, mcp_validate_ecs_express_mode_prerequisites, dbsize, suggest_aws_commands, create_configuration, read_documentation, list_resources, hash_increment, get_resource, info, list_pricing_rules, get_cost_and_usage, bitmap_set, list_billing_views, update_image_set_metadata, cache_gets, get_image_frame, search_cloudformation_documentation, get_price_list_urls, delete_series_by_uid, cache_prepend, create_log_group, describe_events, delete_serverless_cache, delete_replication_group, create_topic, json_strlen, rabbitmq_broker_get_broker_definition, remove_series_from_image_set, get_ssh_tunnel_command_cc, hll_count, simulate_principal_policy, get_aws_account_info, cache_set_multi, delete_instance_in_series, copy_image_set, rabbitmq_broker_purge_queue, string_length, list_source_views_for_billing_view, source_db_analyzer, get_status, get_job_status, hash_exists, json_objkeys, get_execution_plan, cache_stats, list_db_instances_by_status, mcp_ecs_troubleshooting_tool, list_db_instances_for_cluster, search_places, expire, get_database_connection_info, rabbitmq_broker_get_queue_info, create_resource, detach_group_policy, create_resolver, create_graphql_api, get_user_policy, list_delivery_streams, json_arrindex, run_opencypher_query, readonly_query, sorted_set_popmax, kendra_query_tool, describe_services, list_tags_for_resource, cache_set, list_roles, list_tables, rabbitmq_broker_list_vhosts, run_query, run_checkov, list_trim, recommend, authorize_qindex, get_available_services, cache_replace, mcp_create_ecs_infrastructure, mcp_delete_app, rabbimq_broker_initialize_connection, dynamodb_data_model_schema_validator, create_broker, hash_keys, string_set_range, hash_set, delete_image_set, get_bucket_metadata_config, delete_patient_studies, create_jump_host_cc, get_recommendation_details, get_billing_group_cost_report, string_set, hash_values, create_function, modify_cache_cluster, list_pop_left, import_parquet_to_table, get_bedrock_patterns, get_role_policy, string_get, add_user_to_group, create_cluster, rabbitmq_broker_delete_queue, list_role_policies, cache_set_many, create_replication_group, troubleshoot_cloudformation_deployment, cache_version, list_billing_group_cost_reports, create_access_key, get_db_parameter_group, stream_add, execute_query, list_users, json_toggle, get_user, get_datastore, cost_anomaly, describe_table, dynamodb_data_modeling, hash_get, cache_touch, rabbitmq_broker_list_consumers, rabbitmq_broker_get_shovel_info, stream_read, qbiz_local_query, rabbitmq_broker_get_cluster_nodes_info, sorted_set_cardinality, list_resources_associated_to_custom_line_item, optimize_waypoints, run_gremlin_query, set_pop, type, json_clear, connect_jump_host_cc, cache_get_many, list_schemas_tool, stream_info, check_storage_encryption_tool, list_insert_before, update_resource, compute_performances_and_costs, list_position, hash_random_field_with_values, list_prepend, create_role, search_relevant_content, session_sql, finch_build_container_image, list_get, sorted_set_score, set_move, connect_to_database, cost_optimization_hub, dynamodb_data_model_validation, update_patient_study_metadata, analyze_terraform_project_wrapper, sorted_set_remove_by_score, dsql_read_documentation, call_aws, rabbitmq_broker_get_exchange_info, influxdb_list_orgs, rabbitmq_broker_list_shovels, aws_pricing, describe_cache_clusters, list_append, get_maintenance_job_status, analyze_query_performance, get_group, sorted_set_add_incr, delete_group, stream_range, assume_role_with_identity_context, hash_strlen, list_namespaces, rename, cache_append, get_server_info, rename_table, execute_query_tool, list_image_set_versions, delete_db_instance, json_set, delete_instance_in_study, describe_cache_engine_versions, describe_log_groups, create_jump_host_rg, get_patient_studies, describe_engine_default_parameters, get_resource_schema_information, create_user, rabbitmq_broker_list_users, reverse_geocode, search_image_sets, list_columns_tool, kendra_list_indexes_tool, describe_log_streams, test_migration, json_objlen, get_series_primary_image_set, list_pricing_plans, modify_replication_group_shard_configuration, json_get, search_by_study_uid, create_db_instance, rabbitmq_broker_list_exchanges, rabbitmq_broker_is_quorum_critical, calculate_route, rabbitmq_broker_list_queues, string_get_set, query_knowledge_bases_tool, json_strappend, get_table_schema, compute_optimizer, list_append_multiple, create_template, rabbitmq_broker_delete_exchange, list_prepend_multiple, json_arrlen, client_list, generate_resources, check_environment_variables, cdk_best_practices, describe_replication_groups, cache_get, stream_group_set_id, create_group, filter_log_events, string_decrement, cache_delete_multi, bitmap_count, list_metrics, complete_migration, generate_cost_report_wrapper, get_table_maintenance_config, get_managed_policy_document, get_place, finch_push_image, list_canaries, get_image_set, create_namespace, describe_severity_levels, list_length, mcp_build_and_push_image_to_ecr, create_serverless_cache, hash_length, get_image_set_metadata, get_ssh_tunnel_command_serverless, search_nearby, get_metric_statistics, get_stored_security_context, batch_apply_update_action, search_documentation, describe_serverless_caches, untag_resource, describe_keyspace, search_cdk_documentation, bulk_update_patient_metadata, hash_set_multiple, cache_decr, bitmap_get, update_db_cluster, create_db_cluster, search_by_series_uid, list_databases_tool, ri_performance, list_billing_groups, create_table_bucket, budgets, put_user_policy, cache_get_multi, list_set, extract_slides_as_images, mcp_wait_for_service_ready, cache_add, cost_comparison, get_ssh_tunnel_command_rg, get_billing_view, storage_lens_run_query, create_api, audit_services, list_keyspaces, get_db_cluster, execute_range_query, query_database, cache_incr, json_arrtrim, geocode, sorted_set_remove, create_schema, is_database_connected, stream_group_delete_consumer, get_pricing_attribute_values, remove_user_from_group, get_cloudformation_pre_deploy_validation_instructions, explain, create_cache_cluster, append_rows_to_table, get_security_findings, get_dicom_export_job, add_communication_to_case, get_pricing_service_codes, analyze_canary_failures, list_pricing_rules_associated_to_pricing_plan, get_study_primary_image_sets, create_support_case, influxdb_create_org, set_random_member, get_resource_request_status, start_migration, get_patient_dicomweb_studies, cache_flush_all, create_datasource, free_tier_usage, delete_db_cluster, audit_service_operations, bitmap_pos, read_document, check_cloudformation_template_compliance, list_db_clusters, create_domain_name, json_type, list_move, list_pricing_plans_associated_with_pricing_rule, create_db_parameter_group, get_db_instance, remove_instance_from_image_set, json_numincrby, list_services_in_region_tool, list_custom_line_items, list_pop_right, list_db_parameter_groups, create_api_key, list_db_instances, list_dicom_export_jobs, bump_package, stream_info_groups, influxdb_write_points`

#### 💻 Code Execution Risks
* 🟡 **Tool `kendra_list_indexes_tool`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `kendra_query_tool`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `create_token_with_iam`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `assume_role_with_identity_context`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `storage_lens_run_query`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `get_available_workspaces`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_88

**Tools Detected:** `get_transaction_insights, create_database, explain_query, drop_index, drop_table, get_slow_queries, list_databases, analyze_performance, list_views, drop_view, execute_query, describe_table, drop_database, create_index, get_table_relationships, get_replication_status, get_active_connections, get_index_recommendations, get_connection_status, create_view, get_query_insights, get_cluster_status, execute_transaction, connect_database, get_query_history, list_tables, get_database_settings, get_contention_events, connect, bulk_import, analyze_schema, switch_database, create_table, show_running_queries`

#### 💻 Code Execution Risks
* 🟠 **Tool `create_database`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `drop_database`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `create_table`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `bulk_import`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `drop_table`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `create_index`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `drop_index`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `create_view`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `drop_view`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_89

**Tools Detected:** `resize_image, rotate_image, extract_frames, get_video_info, compress_image, apply_filter, get_image_info, convert_video, crop_image, flip_image, create_thumbnail, convert_image, strip_metadata`

#### 💻 Code Execution Risks
* 🔴 **Tool `get_video_info`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `extract_frames`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `convert_video`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_90

**Tools Detected:** `preinstall, diff_command, verify_deps, map_command, baseline_show, registry_list_advisories, init, scan, baseline_list, scan_npm, status, inspect, decode, sanitize, registry_export, baseline_record, baseline_check_cmd, baseline_export, baseline_reset, setup, comply, scan_python, session_status, registry_list, registry_check_npm, audit, registry_lookup, registry_check_cmd, configure`

#### ⚙️ Configuration & Permission Risks
* 🔴 **CODE_EXECUTION_NO_CONFIRMATION** (in `mcp-config.json`): Server can execute code (execute_code, shell) without human confirmation gate

---

### 📦 Repository: REDACTED_REPO_91

**Tools Detected:** `check_responder_availability, find_related_incidents, suggest_solutions, list_shifts, create_incident, check_oncall_health_risk, get_oncall_shift_metrics, get_oncall_handoff_summary, create_override_recommendation, list_incidents, get_server_version, get_shift_incidents, get_oncall_schedule_summary, update_incident, get_alert_by_short_id, get_incident, list_endpoints, collect_incidents, search_incidents`

#### 💻 Code Execution Risks
* 🟡 **Tool `check_oncall_health_risk`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_92

**Tools Detected:** `delimit_hot_reload, delimit_impact, delimit_obs_status, delimit_session_handoff, delimit_secret_get, delimit_release_history, delimit_deploy_site, delimit_config_import, delimit_playbook, delimit_review, delimit_deploy_status, delimit_obs_logs, delimit_intel_dataset_freeze, delimit_daemon_status, delimit_intel_dataset_list, delimit_gov_run, delimit_repo_analyze, delimit_ledger_propose, delimit_scan, delimit_diff_report, delimit_social_history, delimit_gov_verify, delimit_context_init, delimit_version, delimit_webhook_manage, delimit_gov_health, delimit_ledger_list, delimit_repo_config_validate, delimit_github_scan, delimit_ventures, delimit_policy, delimit_docs_generate, delimit_lint, delimit_data_backup, delimit_test_generate, delimit_prompt_drift, delimit_social_post, delimit_sensor_github_issue, delimit_ledger, delimit_handoff_acknowledge, delimit_design_extract_tokens, delimit_sensor_github_migrations, delimit_security_audit, delimit_models, delimit_ledger_links, delimit_loop_status, delimit_design_component_library, delimit_ledger_link, delimit_context_write, delimit_reddit_scan, delimit_deploy_verify, delimit_gov_policy, delimit_revive, delimit_cost_analyze, delimit_social_approve, delimit_collision_check, delimit_explain, delimit_deliberation_status, delimit_handoff_create, delimit_generate_scaffold, delimit_data_migrate, delimit_next_task, delimit_session_history, delimit_evidence_verify, delimit_story_generate, delimit_content_schedule, delimit_release_status, delimit_evidence_collect, delimit_agent_status, delimit_context_branch, delimit_social_target, delimit_release_rollback, delimit_content_publish, delimit_init, delimit_notify_routing, delimit_content_intel_weekly, delimit_deploy_rollback, delimit_drift_check, delimit_changelog, delimit_cost_controls, delimit_diff, delimit_generate_template, delimit_swarm, delimit_deploy_publish, delimit_social_accounts, delimit_build_loop, delimit_activate, delimit_audit, delimit_os_status, delimit_diagnose, delimit_intel_snapshot_ingest, delimit_deliberate, delimit_ledger_done, delimit_config_export, delimit_memory_store, delimit_social_generate, delimit_os_gates, delimit_build_loop_daemon, delimit_loop_config, delimit_reddit_fetch_thread, delimit_security_scan, delimit_release_sync, delimit_design_generate_tailwind, delimit_data_validate, delimit_ledger_context, delimit_daemon_classify, delimit_toolcard_cache, delimit_sense, delimit_repo_config_audit, delimit_siem, delimit_social_target_config, delimit_semver, delimit_design_generate_component, delimit_intel_dataset_register, delimit_memory_recent, delimit_tracker_sync, delimit_vault_search, delimit_redact, delimit_resource_drivers, delimit_repo_diagnose, delimit_agent_policy, delimit_license_status, delimit_drift_history, delimit_agent_link, delimit_context_list, delimit_context_snapshot, delimit_task_complete, delimit_gov_status, delimit_agent_handoff, delimit_agent_check, delimit_docs_validate, delimit_vault_health, delimit_ledger_add, delimit_cost_optimize, delimit_secret_access_log, delimit_social_daemon, delimit_external_pr_check, delimit_agent_complete, delimit_test_coverage, delimit_test_smoke, delimit_agent_dispatch, delimit_ledger_query, delimit_handoff_list, delimit_gov_evaluate, delimit_deploy_build, delimit_screen_record, delimit_inbox_daemon, delimit_project_config, delimit_story_visual_test, delimit_context_read, delimit_obs_metrics, delimit_spec_health, delimit_os_plan, delimit_executor, delimit_intel_query, delimit_digest, delimit_gov_new_task, delimit_ledger_update, delimit_story_accessibility, delimit_notify, delimit_content_intel_daily, delimit_vault_snapshot, delimit_release_plan, delimit_secret_revoke, delimit_obs_alerts, delimit_secret_store, delimit_agent_dashboard, delimit_quickstart, delimit_screenshot, delimit_deploy_npm, delimit_content_queue, delimit_content_intel_topic, delimit_cost_alert, delimit_daemon_run, delimit_design_validate_responsive, delimit_story_build, delimit_work_orders, delimit_release_validate, delimit_zero_spec, delimit_resource_list, delimit_notify_inbox, delimit_memory_search, delimit_secret_list, delimit_help, delimit_resource_get, delimit_soul_capture, delimit_deploy_plan, delimit_security_ingest, delimit_security_deliberate`

#### 💻 Code Execution Risks
* 🔴 **Tool `delimit_security_ingest`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `delimit_sensor_github_issue`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `delimit_diagnose`** [POTENTIAL_DATA_EXFILTRATION, UNRESTRICTED_FILE_WRITE]: `shutil.rmtree()` inside agent tool | `urllib.request.urlopen()` inside agent tool
* 🟡 **Tool `delimit_models`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🔴 **Tool `delimit_scan`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `delimit_tracker_sync`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_93

**Tools Detected:** `csv_to_dashboard, propose_field_mapping, save_workbook, configure_dual_axis, set_hyper_connection, inspect_target_schema, open_workbook, remove_calculated_field, add_trend_line, recommend_template, add_reference_line, inspect_csv, mysql_to_dashboard, list_dashboards, validate_calc_fields, migrate_twb_guided, add_dashboard_action, repair_calc_fields, preview_twb_migration, inspect_hyper, add_dashboard, apply_twb_migration, csv_to_hyper, list_fields, set_mysql_connection, hyper_to_dashboard, profile_csv, reset_rules, generate_layout_json, profile_twb_for_migration, recommend_template_for_csv, add_calculated_field, export_rules, create_workbook, add_reference_band, configure_worksheet_style, set_rule, list_gallery_templates, profile_data_source, apply_color_palette, apply_style_reference, list_capabilities, list_worksheets, set_mssql_connection, analyze_twb, suggest_charts_for_csv, describe_capability, configure_chart, diff_template_gap, undo_last_change, add_parameter, validate_workbook, mssql_to_dashboard, configure_chart_recipe, get_active_rules, set_tableauserver_connection, add_worksheet, apply_dashboard_theme`

#### 💻 Code Execution Risks
* 🟠 **Tool `export_rules`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟠 **Tool `generate_layout_json`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`

---

### 📦 Repository: REDACTED_REPO_94

#### ⚙️ Configuration & Permission Risks
* 🔴 **CODE_EXECUTION_NO_CONFIRMATION** (in `mcp-config.json`): Server can execute code (eval) without human confirmation gate
* 🔴 **CODE_EXECUTION_NO_CONFIRMATION** (in `mcp.json`): Server can execute code (eval, exec) without human confirmation gate

---

### 📦 Repository: REDACTED_REPO_95

**Tools Detected:** `get_style_an_element, run_javascript_and_get_console_output, get_network_logs, get_an_element, get_elements, local_storage_remove, local_storage_read, take_screenshot, local_storage_read_all, get_console_logs, click_to_element, get_direct_children, check_page_ready, navigate, run_javascript_in_console, local_storage_add, local_storage_remove_all, get_response, set_value_to_input_element`

#### 💻 Code Execution Risks
* 🟠 **Tool `navigate`** [UNRESTRICTED_FILE_WRITE]: `os.remove()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_96

**Tools Detected:** `list_accounts, run_keyword_planner, run_gaql`

#### 💻 Code Execution Risks
* 🟡 **Tool `run_keyword_planner`** [POTENTIAL_DATA_EXFILTRATION]: `requests.post()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_97

**Tools Detected:** `get_session_memories, dashboard, mark_contradiction, run_cleanup, get_contradictions, summarize_session, set_session_topic, validate_embeddings, seed, recall_with_fallback, pre_compact, resolve_contradiction, metrics_status, demote, remember, db_maintenance, recall_by_tag, run_mining, recall, seed_from_file, import_beads, hot_cache_status, unlink_memories, validate_memory, forget, predict_next, warm_cache, cross_session_patterns, status, memory_stats, embedding_info, get_related_memories, end_session, bootstrap_project, pin, recategorize, access_patterns, predictive_cache_status, unpin, preview_consolidation, retrieval_quality_stats, bootstrap, approve_candidate, bulk_reject_candidates, log_response, get_sessions, find_contradictions, invalidate_memory, promote, db_info, mining_status, relationship_stats, consolidate, link_memories, db_rebuild_vectors, list_memories, audit_history, mark_memory_used, get_trust_history, log_output, run_consolidation, review_candidates, seed_from_text, hook_check, reject_candidate, get_session`

#### 💻 Code Execution Risks
* 🔴 **Tool `log_response`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `pre_compact`** [OS_COMMAND_EXECUTION]: `subprocess.Popen()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `import_beads`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `recategorize`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool

---

### 📦 Repository: REDACTED_REPO_98

**Tools Detected:** `run_locust`

#### 💻 Code Execution Risks
* 🔴 **Tool `run_locust`** [ENV_SECRET_ACCESS, OS_COMMAND_EXECUTION]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars | `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_99

**Tools Detected:** `interactive_legacy, install_completion_command, list_deployments, show_status, stop, list_tools, cleanup_resources, remove_server, deploy_template, deploy, clear_config, list, status, get_logs, unselect_template, list_servers, show_help, show_config, list_templates, configure_template, logs, stop_server, call_tool, select_template, interactive`

#### ⚙️ Configuration & Permission Risks
* 🟠 **DESTRUCTIVE_TOOL_NO_CONFIRMATION** (in `tools.json`): Server exposes destructive operations (list_directory, write_file) without require_confirmation. Prompt injection can trigger irreversible data deletion
* 🟠 **DESTRUCTIVE_TOOL_NO_CONFIRMATION** (in `tools.json`): Server exposes destructive operations (delete_file, remove_sub_issue, delete_pending_pull_request_review) without require_confirmation. Prompt injection can trigger irreversible data deletion

#### 💻 Code Execution Risks
* 🟡 **Tool `list_templates`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `list_tools`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `list_servers`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_100

**Tools Detected:** `info, check, quantize, push, recommend, evaluate`

#### 💻 Code Execution Risks
* 🟠 **Tool `push`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`

---

### 📦 Repository: REDACTED_REPO_101

**Tools Detected:** `follow_up, get_space_info, ask_genie`

#### 💻 Code Execution Risks
* 🟡 **Tool `ask_genie`** [POTENTIAL_DATA_EXFILTRATION]: `requests.post()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `follow_up`** [POTENTIAL_DATA_EXFILTRATION]: `requests.post()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_102

**Tools Detected:** `manage_group, delete_execution_logs, generate_dashboard, generate_flow, get_instance_info, manage_executions, manage_tests, manage_apps, invite_user, backfill_executions, namespace_directory_action, manage_kv_store, add_execution_labels, delete_flow_logs, create_flow_from_yaml, generate_test, execute_flow, get_execution_logs, replay_execution, restart_execution, find_flow, namespace_file_action, search_flows, search_logs, list_flows_in_namespace, list_executions, resume_execution, generate_app, force_run_execution, change_taskrun_state, manage_announcements, manage_flow, list_flows_with_triggers, download_execution_logs, search_apps, list_namespace_dependencies, manage_invitations, list_namespaces, follow_execution_logs`

#### 💻 Code Execution Risks
* 🟡 **Tool `backfill_executions`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `invite_user`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `manage_tests`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `manage_group`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_103

**Tools Detected:** `trust_stack_info, coc_tail, coc_anchor, arp_rate, verify_agent_identity, arp_check, coc_init, coc_add, coc_status, get_trust_evidence, coc_verify`

#### 💻 Code Execution Risks
* 🟠 **Tool `coc_verify`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟠 **Tool `coc_anchor`** [POTENTIAL_DATA_EXFILTRATION, UNRESTRICTED_FILE_WRITE]: `urllib.request.urlopen()` inside agent tool — no human-in-the-loop confirmation parameter | Bare call to `open()`
* 🟡 **Tool `verify_agent_identity`** [POTENTIAL_DATA_EXFILTRATION]: `urllib.request.urlopen()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_104

**Tools Detected:** `search_web, report, get_arbitrum_invoice, get_status, search_news, get_invoice`

#### 💻 Code Execution Risks
* 🟠 **Tool `report`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`

---

### 📦 Repository: REDACTED_REPO_105

**Tools Detected:** `context_init, context_stats, context_dashboard, context_save, context_search, context_load_checkpoint`

#### 💻 Code Execution Risks
* 🟠 **Tool `context_load_checkpoint`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_106

**Tools Detected:** `list_trails, get_dispute_status, rate_trail, submit_evidence, list_dispute_types, execute_trail, get_leaderboard, open_dispute, get_karma, submit_action, apply_ruling, get_trail, attest_action, get_action_detail, register_trail`

#### 💻 Code Execution Risks
* 🟠 **Tool `submit_action`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `attest_action`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `get_karma`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `get_action_detail`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `register_trail`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `list_trails`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `get_trail`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `execute_trail`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `rate_trail`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `get_leaderboard`** [DATABASE_MUTATION]: `conn.execute()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_107

**Tools Detected:** `db_execute, show_create_table, db_query, create_db_user, get_tidb_serverless_address, remove_db_user, show_tables`

#### 💻 Code Execution Risks
* 🟠 **Tool `db_query`** [DATABASE_MUTATION]: `db.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `db_execute`** [DATABASE_MUTATION]: `db.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `create_db_user`** [DATABASE_MUTATION]: `db.execute()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `remove_db_user`** [DATABASE_MUTATION]: `db.execute()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_108

**Tools Detected:** `crawl_site, sf_check, list_crawls, crawl_status, delete_crawl, storage_summary, export_crawl, read_crawl_data`

#### 💻 Code Execution Risks
* 🟠 **Tool `crawl_site`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟠 **Tool `export_crawl`** [UNRESTRICTED_FILE_WRITE]: `shutil.rmtree()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `delete_crawl`** [UNRESTRICTED_FILE_WRITE]: `shutil.rmtree()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_109

**Tools Detected:** `list_projects, execute_cleanup, get_recent_sessions, get_index_stats, search_bugfixes, search_tests, validate_doc, analyze_knowledge_repo, get_file_context, check_update, check_knowledge_quality, write_architecture_doc, search_docs, set_project, write_bugfix_summary, write_best_practice, git_pull_reindex, write_changelog_entry, analyze_codebase, search_by_type, setup_project, reindex, write_test_case, get_active_project, write_setup_doc, classify_documents, write_api_doc, save_session_summary`

#### 💻 Code Execution Risks
* 🔴 **Tool `check_update`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_110

#### ⚙️ Configuration & Permission Risks
* 🔴 **CODE_EXECUTION_NO_CONFIRMATION** (in `tools.json`): Server can execute code (exec) without human confirmation gate
* 🟠 **DESTRUCTIVE_TOOL_NO_CONFIRMATION** (in `tools.json`): Server exposes destructive operations (equivalent) without require_confirmation. Prompt injection can trigger irreversible data deletion

---

### 📦 Repository: REDACTED_REPO_111

**Tools Detected:** `memory_list_compact, memory_link, memory_list, memory_create_todo, memory_create_section, memory_clusters, memory_validate_tags, memory_rebuild_crossrefs, memory_upload_image, memory_export, memory_merge, memory_export_graph, memory_delete, memory_hybrid_search, memory_boost, memory_absorb, memory_events_clear, memory_tags, memory_related, memory_stats, memory_create_issue, memory_hierarchy, memory_get, memory_delete_document, memory_events_poll, memory_create_batch, memory_import, memory_delete_batch, memory_update, memory_insights, memory_find_duplicates, memory_detect_supersessions, memory_unlink, memory_tag_hierarchy, memory_create, memory_backfill_tags, memory_rebuild_embeddings, memory_semantic_search, memory_get_document, memory_migrate_images, memory_store_document`

#### 💻 Code Execution Risks
* 🟡 **Tool `memory_insights`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_112

#### ⚙️ Configuration & Permission Risks
* 🟠 **DESTRUCTIVE_TOOL_NO_CONFIRMATION** (in `tools.json`): Server exposes destructive operations (file_write) without require_confirmation. Prompt injection can trigger irreversible data deletion
* 🔴 **CODE_EXECUTION_NO_CONFIRMATION** (in `tools.json`): Server can execute code (shell) without human confirmation gate
* 🔴 **CODE_EXECUTION_NO_CONFIRMATION** (in `tools.json`): Server can execute code (shell) without human confirmation gate
* 🔴 **CODE_EXECUTION_NO_CONFIRMATION** (in `tools.json`): Server can execute code (shell) without human confirmation gate
* 🔴 **CODE_EXECUTION_NO_CONFIRMATION** (in `tools.json`): Server can execute code (shell) without human confirmation gate
* 🔴 **CODE_EXECUTION_NO_CONFIRMATION** (in `tools.json`): Server can execute code (shell) without human confirmation gate
* 🟠 **DESTRUCTIVE_TOOL_NO_CONFIRMATION** (in `tools.json`): Server exposes destructive operations (shell_kill_process) without require_confirmation. Prompt injection can trigger irreversible data deletion
* 🟠 **DESTRUCTIVE_TOOL_NO_CONFIRMATION** (in `tools.json`): Server exposes destructive operations (browser_restart) without require_confirmation. Prompt injection can trigger irreversible data deletion
* 🟠 **DESTRUCTIVE_TOOL_NO_CONFIRMATION** (in `tools.json`): Server exposes destructive operations (browser_input) without require_confirmation. Prompt injection can trigger irreversible data deletion
* 🟠 **DESTRUCTIVE_TOOL_NO_CONFIRMATION** (in `tools.json`): Server exposes destructive operations (browser_select_option) without require_confirmation. Prompt injection can trigger irreversible data deletion
* 🔴 **CODE_EXECUTION_NO_CONFIRMATION** (in `tools.json`): Server can execute code (exec) without human confirmation gate
* 🔴 **CODE_EXECUTION_NO_CONFIRMATION** (in `Tools.json`): Server can execute code (bash, exec, shell, terminal) without human confirmation gate
* 🟠 **FILESYSTEM_PLUS_NETWORK** (in `Tools.json`): Server has simultaneous filesystem and network access. Prompt injection can read local files and send them outbound
* 🟠 **DESTRUCTIVE_TOOL_NO_CONFIRMATION** (in `Tools.json`): Server exposes destructive operations (str_replace_editor, workflows_remove_run_config_tool, execute_sql_tool) without require_confirmation. Prompt injection can trigger irreversible data deletion
* 🔴 **LETHAL_TRIFECTA** (in `Tools.json`): Server has all three Lethal Trifecta legs — private data access (file_read, sql), untrusted input exposure (fetch, web_search), exfiltration vector (api_calls). A single prompt injection can exfiltrate all private data silently
* 🔴 **CODE_EXECUTION_NO_CONFIRMATION** (in `Tools.json`): Server can execute code (exec) without human confirmation gate
* 🟠 **DESTRUCTIVE_TOOL_NO_CONFIRMATION** (in `Tools.json`): Server exposes destructive operations (ReadFile, SearchRepo, GenerateDesignInspiration) without require_confirmation. Prompt injection can trigger irreversible data deletion

---

### 📦 Repository: REDACTED_REPO_113

**Tools Detected:** `crawl_site, search_pages, list_pages, read_page, extract_data`

#### 💻 Code Execution Risks
* 🟡 **Tool `extract_data`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---

### 📦 Repository: REDACTED_REPO_114

#### ⚙️ Configuration & Permission Risks
* 🟠 **DESTRUCTIVE_TOOL_NO_CONFIRMATION** (in `tools.json`): Server exposes destructive operations (foodblock_approve_draft) without require_confirmation. Prompt injection can trigger irreversible data deletion

---

### 📦 Repository: REDACTED_REPO_115

**Tools Detected:** `fill_area_at, set_palette, draw_rectangle_at, start_preview_server, set_frame_duration_all, set_cel_position, fill_area, remap_colors_in_cel_range, get_pixel_color, duplicate_frame_range, tween_cel_positions, copy_layers_between_sprites, set_frame_duration, draw_line, export_sprite, flip_layer, propagate_cels, draw_circle_at, animation_sanitize, tween_cel_scale_eased, draw_pixels, get_pixels_rect, set_tag, copy_cel, set_layer, crop_canvas, animation_workflow_guide, create_cel, propagate_frame_to_range, tween_cel_positions_eased, draw_pixels_at, draw_path, get_sprite_info, draw_rectangle, ensure_layers_present, get_palette, offset_cel_positions, validate_scene, clear_cel, set_onion_skin, apply_gradient_rect, add_layer, stop_preview_server, copy_sprite, create_canvas, add_frames, copy_frame, oscillate_cel_positions, resize_canvas, add_frame, draw_line_at, set_layer_visibility, rotate_layer, draw_polygon, set_layer_opacity, tween_cel_opacity_eased, set_frame, audit_animation, draw_circle`

#### 💻 Code Execution Risks
* 🔴 **Tool `start_preview_server`** [OS_COMMAND_EXECUTION, UNRESTRICTED_FILE_WRITE]: `os.remove()` inside agent tool — no human-in-the-loop confirmation parameter | `subprocess.Popen()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `stop_preview_server`** [OS_COMMAND_EXECUTION, UNRESTRICTED_FILE_WRITE]: `os.remove()` inside agent tool — no human-in-the-loop confirmation parameter | `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_116

**Tools Detected:** `worker, like, whoami, ticket_breakdown, contact_form, deactivate_all, server_info, set_light_attributes, name_shrimp, ping, usage_trend, take_screenshot, activate_finance, check_app_status, list_users, async_multiply, search_items, employee_directory, delete_item, translate, set_group_attributes, inspector, submit_answer, execute_trade, refresh, charge, get_market_data, list_scenes, get_test_file_from_server, google_echo, google_info, post, repost, project_overview, analyze_sentiment, reverse_string, remember, github_echo, show_map, filter_data, team_directory, echo_with_logs, process, get_status, reset_user_password, get_example_data, immediate, multiply, get_weather_forecast, save_contact, get_summary, auth_status, echo_message, apps, activate_admin, add_item, fail_tool, filter_by_category, get_news_headlines, generate_qr, quarterly_revenue, read_profile, list_requests, set_brightness, write_haiku, summarize, read_all_lights, toggle_light, system_status, analyze_data, submit_form, list_session_info, update_quantity, list_files, set_value, search_contacts, echo, list_lights_by_group, search, list_groups, activate_scene, reject_request, inspect, analyze_colors, hub_status, get_json_data, showcase, farewell, get_request_details, list_contacts, analyze_portfolio, github_info, fibonacci, calculate, get_info, text_me, word_count, survey, fail, add_comment, validate_command, store_files, greet, sales_dashboard, demo, create_thread, get_access_token_claims, approve_request, echo_tool, follow, health, version, get_value, feature_flags, get_test_pdf_from_url, read_file, ask_assistant, create_command, plan_dinner, sales_chart, add, api_health, prepare, to_uppercase, slow_computation`

#### 💻 Code Execution Risks
* 🟠 **Tool `create_command`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🔴 **Tool `inspector`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `inspect`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_117

**Tools Detected:** `compliance_history, scan_code, generate_compliance_report, classify_risk, scan_gdpr, add_trust_layer, scan_file, validate_action, suggest_fix, scan_project, explain_article, analyze_with_model, check_injection, scan_bias`

#### 💻 Code Execution Risks
* 🔴 **Tool `analyze_with_model`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `scan_gdpr`** [UNRESTRICTED_FILE_WRITE]: `os.unlink()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `scan_bias`** [UNRESTRICTED_FILE_WRITE]: `os.unlink()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_118

**Tools Detected:** `get_logger_info, get_class_info, get_thread_info, get_jstat_output, get_jvm_info, search_method, get_jmx_gc_histogram, get_jmx_memory_info, get_stack_trace, get_jvm_status, watch_method, get_index, get_stack_trace_by_method, get_dashboard, get_jmx_thread_dump, get_jcmd_output, list_indices, list_java_processes, set_logger_level, get_memory_info, decompile_class`

#### 💻 Code Execution Risks
* 🔴 **Tool `list_java_processes`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_119

**Tools Detected:** `omniparser_drags, omniparser_click, omniparser_scroll, omniparser_write, omniparser_get_keys_list, omniparser_mouse_move, omniparser_wait, omniparser_input_key, omniparser_details_on_screen`

#### 💻 Code Execution Risks
* 🟡 **Tool `omniparser_details_on_screen`** [POTENTIAL_DATA_EXFILTRATION]: `requests.post()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_120

**Tools Detected:** `find_mcp_config_path, deep_search_planning, configure_mcp_plan, file_system_config_setup, quick_search, fetch_readme, example_mcp_config_file`

#### 💻 Code Execution Risks
* 🟠 **Tool `fetch_readme`** [DATABASE_MUTATION]: `cursor.execute()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_121

**Tools Detected:** `worker, check_compliance, agents_trace, route_by_quality, mcp_connect, replay, validate, agents_connect, analyze_tax_implications, agents_inspect, dev, workers, agents_activate, analyze_photos, init, get_client_profile, agents_list, assess_risk_score, fork, save_note, lookup_policy, a2a_discover, fetch_earnings, inspect, build_portfolio_allocation, check_fraud, agents_discover, eval_compare, events, check_sentiment, get_weather, get_stock_data, get_market_data, web_search, eval_run, calculate, propose_frame, eval_export, search_documents`

#### 💻 Code Execution Risks
* 🔴 **Tool `calculate`** [CODE_EXECUTION]: Bare call to `eval()`
* 🟠 **Tool `init`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🔴 **Tool `dev`** [OS_COMMAND_EXECUTION]: `subprocess.Popen()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `eval_run`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟠 **Tool `eval_export`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`

---

### 📦 Repository: REDACTED_REPO_122

**Tools Detected:** `install, service, mfp_play, whisper_model_unified, service_stop, whisper_service_enable, audio_command, list_config_keys, devices, whisper_service_logs, converse, history, whisper_restart_alias, whisper_install, disable, voice_status, info, config_reload, soundfonts_on, list_whisper_versions, soundfonts_off, list_tts_voices, whisper_service_stop, play, view, kokoro_uninstall, favorite, resume, show_config_files, hooks_remove, config_edit, tail, update_config, whisper_service_disable, enable, completions, voice_statistics_reset, registry, whisper_model_install, pause, kokoro_install, restart, list_kokoro_versions, service_start, service_disable, whisper_disable_alias, whisper_service_install, whisper_uninstall, auth_status, whisper_logs_alias, service_health, whisper_service_uninstall, whisper_stop_alias, deps, hooks_add, voice_statistics_recent, logs, export, library_stats, whisper_start_alias, check_audio_dependencies, whisper_service_start, serve, library_scan, voice_statistics, voice_registry, config_get, mfp_sync, search, volume, whisper_service_health, voice_statistics_export, voice_statistics_summary, whisper_health_alias, stats, service_enable, whisper_service_restart, service_restart, prev, whisper_status_alias, service_logs, config_set, check_audio_devices, stop, hooks_list, mfp_list, whisper_install_alias, whisper_uninstall_alias, soundfonts_status, refresh_provider_registry, status, voice_mode_info, health, login, get_provider_details, service_status, next, logout, transcribe_audio_command, whisper_enable_alias, whisper_service_status, service_install, config_list, uninstall, find`

#### 💻 Code Execution Risks
* 🔴 **Tool `service_health`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `health`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `whisper_service_health`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `config_get`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🔴 **Tool `config_edit`** [ENV_SECRET_ACCESS, OS_COMMAND_EXECUTION]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars | `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟡 **Tool `converse`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🔴 **Tool `whisper_model_unified`** [OS_COMMAND_EXECUTION]: `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🟠 **Tool `export`** [UNRESTRICTED_FILE_WRITE]: Bare call to `open()`
* 🟡 **Tool `status`** [ENV_SECRET_ACCESS]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🔴 **Tool `kokoro_install`** [OS_COMMAND_EXECUTION, UNRESTRICTED_FILE_WRITE]: `shutil.rmtree()` inside agent tool — no human-in-the-loop confirmation parameter | `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `kokoro_uninstall`** [OS_COMMAND_EXECUTION, UNRESTRICTED_FILE_WRITE]: `shutil.rmtree()` inside agent tool — no human-in-the-loop confirmation parameter | `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `whisper_install`** [ENV_SECRET_ACCESS, OS_COMMAND_EXECUTION, UNRESTRICTED_FILE_WRITE]: `os.environ.get()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars | `shutil.rmtree()` inside agent tool — no human-in-the-loop confirmation parameter | `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `whisper_uninstall`** [OS_COMMAND_EXECUTION, UNRESTRICTED_FILE_WRITE]: `shutil.rmtree()` inside agent tool — no human-in-the-loop confirmation parameter | `subprocess.run()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_123

**Tools Detected:** `list_ros2_nodes, find_ros2_package, run_ros2_executable, run_ros2_doctor, check_ros2_topic_hz, launch_rqt_graph, launch_turtlesim, list_ros2_services, show_ros2_interface, get_ros2_node_info, call_ros2_service, echo_ros2_topic, launch_turtlebot3_world, launch_turtlebot3_empty_world, clean_all_ros2_nodes, get_topic_info, launch_gazebo, publish_ros2_topic, check_topic_status, launch_rviz, list_topics, list_ros2_actions, debug_ros2_environment, send_ros2_action_goal`

#### 💻 Code Execution Risks
* 🔴 **Tool `check_topic_status`** [OS_COMMAND_EXECUTION]: `subprocess.Popen()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `run_ros2_executable`** [OS_COMMAND_EXECUTION]: `subprocess.Popen()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `publish_ros2_topic`** [OS_COMMAND_EXECUTION]: `subprocess.Popen()` inside agent tool — no human-in-the-loop confirmation parameter
* 🔴 **Tool `check_ros2_topic_hz`** [OS_COMMAND_EXECUTION]: `subprocess.Popen()` inside agent tool — no human-in-the-loop confirmation parameter

---

### 📦 Repository: REDACTED_REPO_124

#### ⚙️ Configuration & Permission Risks
* 🟠 **DESTRUCTIVE_TOOL_NO_CONFIRMATION** (in `mcp.json`): Server exposes destructive operations (delete_issue, delete_comment, delete_sprint) without require_confirmation. Prompt injection can trigger irreversible data deletion

---

### 📦 Repository: REDACTED_REPO_125

**Tools Detected:** `bridge_transfer, list_bridgeable_tokens, list_chains, get_quotes`

#### 💻 Code Execution Risks
* 🟡 **Tool `get_quotes`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars
* 🟡 **Tool `bridge_transfer`** [ENV_SECRET_ACCESS]: `os.getenv()` inside agent tool — if injected, agent may be directed to read and expose sensitive env vars

---


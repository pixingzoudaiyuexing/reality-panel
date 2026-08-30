# rc.7 状态机故障注入矩阵

本矩阵复用生产状态机入口和现有测试 fixture。故障注入发生在持久化边界，
通过丢弃进程内 lock/worker 上下文并重新读取 LKG、KVS 或 sync row 模拟重启；
不在生产代码中保留故障开关，也不访问真实 DNS 或服务器。

## 全局不变量

- 新 desired 已满足全部依赖时，最终必须是 Active 且写入 LKG。
- 新 desired 未满足依赖或执行失败时，旧 LKG 必须继续有权威性，并报告明确的
  Failed、Retrying、DependencyWithheld 或 rollback 状态。
- 重复、迟到或复用 revision 的配置不得覆盖更新的 runtime/LKG。
- Notify 只能降低延迟；持久状态加后续 tick 必须足以恢复收敛。
- 不允许 Unknown、假 PASS、永久 Pending，或依赖管理员重新保存规则。

## Node 重启边界

| 边界 | 注入/恢复断言 | 覆盖测试 |
| --- | --- | --- |
| DNS 已传播、ACME 未开始 | desired 保持 withheld/retrying，旧路由继续工作，后续 tick 可启动证书工作 | `reconciler::tests::dependency_withheld_update_preserves_previous_active_route`、`camouflage_site::tests::desired_failure_retries_then_commits_new_site_and_lkg` |
| TXT 已 present | challenge identity 持久化；见 Panel active TXT restart | `acme_dns01::tests::active_txt_challenge_survives_panel_restart_and_cleans_from_persisted_state` |
| Certbot 运行中 | 状态读取不被 ACME gate 阻塞，重复 desired 不创建第二个 worker | `camouflage_site::tests::desired_reconcile_returns_and_reports_while_acme_gate_is_blocked`、`repeated_identical_desired_does_not_queue_duplicate_certificate_jobs` |
| 证书已生成、未 install | 无效 candidate/install 结果不替换旧 generation | `certificate_lifecycle::tests::failed_acme_and_candidate_install_preserve_old_generation`、`invalid_renewal_output_retains_old_usable_certificate` |
| 已 install、未 activate | candidate 只有通过 runtime apply 才能成为 active/LKG；失败保留旧 LKG | `camouflage_site::tests::failed_candidate_validation_does_not_overwrite_lkg`、`nginx_test_failure_restores_runtime_and_preserves_lkg` |
| Camouflage Nginx 已应用 | listener 未就绪时保持 dependency 状态，周期 replay 可继续 | `reconciler::tests::periodic_replay_converges_completed_certificate_without_notify` |
| Listener 未应用 | 旧 active route/LKG 保留，不因新依赖未就绪而删除 | `reconciler::tests::dependency_withheld_update_preserves_previous_active_route` |
| Listener Nginx 已应用 | listener、listener LKG、camouflage cleanup 严格顺序，失败可重试 | `reconciler::tests::listener_lkg_finalization_precedes_camouflage_cleanup_and_retries` |
| LKG tmp 已写、rename 前 | tmp 不提升为 authority；重启加载旧 primary 并清理 tmp | `poller::tests::fault_injection_restart_before_and_after_lkg_rename_preserves_authority` |
| rename 后 | 重启加载新 primary，并保留旧 primary 为 backup | `poller::tests::fault_injection_restart_before_and_after_lkg_rename_preserves_authority` |

## Panel 重启边界

| 边界 | 注入/恢复断言 | 覆盖测试 |
| --- | --- | --- |
| TXT challenge active | 清空进程内 SNI lock 后，cleanup 从 KVS 恢复 provider identity，只删除自己的 TXT | `acme_dns01::tests::active_txt_challenge_survives_panel_restart_and_cleans_from_persisted_state` |
| DNS switch halfway | 从 KVS journal 与 sync rows 恢复 switching，不提交部分传播结果 | `relay_preference::tests::restart_during_switch_and_rollback_resumes_from_persisted_journal` |
| DNS rollback halfway | 保留 preferred/pending 和 rollback journal，后续 tick 完成 `failed_rolled_back` | `relay_preference::tests::restart_during_switch_and_rollback_resumes_from_persisted_journal` |
| Config revision increment 前后 | duplicate 可幂等重放；旧 revision 和同 revision 不同 fingerprint 被忽略 | `reconciler::tests::duplicate_and_out_of_order_panel_snapshots_keep_latest_revision_active` |

## 乱序与延迟矩阵

| 场景 | 覆盖测试 |
| --- | --- |
| duplicate WS push / duplicate HTTP poll | `reconciler::tests::duplicate_and_out_of_order_panel_snapshots_keep_latest_revision_active`、`healthy_repeated_snapshot_is_observed_noop` |
| old HTTP arrives late | `reconciler::tests::duplicate_and_out_of_order_panel_snapshots_keep_latest_revision_active` |
| rapid p1 -> q1 -> q2 | `reconciler::tests::duplicate_and_out_of_order_panel_snapshots_keep_latest_revision_active` |
| certificate worker delayed | `camouflage_site::tests::slow_certificate_work_does_not_hold_camouflage_state_lock`、`periodic_replay_converges_completed_certificate_without_notify` |
| DNS propagation delayed | `acme_dns01::tests::authoritative_propagation_accumulates_each_ns_without_same_round_unanimity` |
| one authoritative NS stale | `acme_dns01::tests::authoritative_propagation_never_ignores_a_stale_ns` |
| Relay target/rollback 部分失败 | `relay_preference::tests::partial_target_failure_rolls_back_every_record_before_terminal_failure`、`rollback_failure_exposes_split_dns_and_requires_manual_intervention` |

真实 Huawei TXT 写入不属于本地故障注入。本矩阵只使用模拟 Provider；任何真实 DNS
实测仍须单独获得授权。

# Test fixtures

`auditd/splunk_excerpts.log` contains unmodified lines copied from the public
[Splunk Attack Data](https://github.com/splunk/attack_data) repository
(commit `4389fa7a4e74a7c083c0fbe448fa2c7c32378981`, Apache License 2.0):

| Lines | Source file (under `datasets/attack_techniques/`) | Format |
| --- | --- | --- |
| 1-3 | `T1053.003/linux_auditd_crontab_edit/linux_auditd_crontab_edit.log` | raw + ENRICHED, SYSCALL with PATH records |
| 4 | `T1068/linux_auditd_copy_fail/linux_auditd.log` | raw SYSCALL |
| 5 | `T1016/linux_auditd_net_tool_new/linux_auditd_net_tool_bucket_new.log` | `ausearch -i` SYSCALL, user names |
| 6 | `T1030/linux_auditd_split_syscall_new/linux_auditd_new_split.log` | `ausearch -i` SYSCALL |
| 7 | `T1574.006/linux_auditd_ldpreload/linux_auditd_ldpreload.log` | raw EXECVE without its SYSCALL |
| 8 | `T1548.003/linux_auditd_sudo_su/auditd_proctitle_sudo.log` | `ausearch -i` PROCTITLE |
| 9 | `T1489/linux_auditd_osquerd_service_stop/linux_auditd_osquerd_service_stop.log` | ENRICHED SERVICE_STOP |

The full dataset is downloaded by `scripts/fetch_datasets.py`; it is not stored in Git.

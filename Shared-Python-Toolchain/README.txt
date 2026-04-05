Fresh 5.4 package (reset).

Use:
1) run-setup.cmd
2) Start_Codex54.cmd

Tests:
- use `py -3.13 .\scripts\run_pytest.py -- tests\test_soc_dashboard.py -q` for bounded pytest runs

If login is stale:
1) . .\logincodex.ps1
2) logincodex -Reset

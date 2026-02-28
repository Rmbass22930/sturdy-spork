AnyUser Memory Optimizer (J:)

Purpose
- A second copy of setup that anyone can use.
- Interactive setup asks questions and configures Memory Optimizer for the local machine.

Run
1) Double-click run-memory-optimizer-setup.cmd
or
2) powershell -ExecutionPolicy Bypass -File .\setup-memory-optimizer-wizard.ps1

What it configures
- memory_optimizer hyperv-setup for your VM name
- startup registration (scheduled task or HKCU Run fallback)
- optional privacy gate (None, Malwarebytes, or custom commands)

Default project source path
- J:\gdrive\BallisticTarget\src\Shared-Python-Toolchain

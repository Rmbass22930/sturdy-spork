AnyUser Memory Optimizer Portable (USB)

Goal
- Run installer from a jump drive for any user machine.
- Ask setup questions and configure Memory Optimizer startup.

Quick start
1) (Recommended) Run prepare-usb-payload.cmd to copy Shared-Python-Toolchain into this folder.
2) Move/copy this whole folder to jump drive.
3) On target machine, run run-from-jump-drive.cmd.

Alternate source layout
- If payload is not inside this folder, installer will also try sibling Shared-Python-Toolchain.

What installer can do
- Optional copy of source to local machine so it works after USB is removed.
- Optional dependency install/repair: python -m pip install -e .
- Hyper-V setup with startup mode fallback (scheduled task -> HKCU Run key).
- Privacy gate options: none, Malwarebytes VPN service, custom commands.

Default local install path
- C:\ProgramData\AnyUserMemoryOptimizer\Shared-Python-Toolchain

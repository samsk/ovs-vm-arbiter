# OVS command helper (ovs-vsctl, ovs-ofctl)
import asyncio
import json
import subprocess
from typing import Any


class OVSCommand:
    """Unified OVS command execution with JSON parsing (sync and async)."""

    @staticmethod
    def _run_cmd(cmd: list[str], timeout: int) -> tuple[int, str, str]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout or "", r.stderr or ""
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return -1, "", str(e)

    @staticmethod
    def run_vsctl(
        args: list[str],
        timeout: int = 10,
        json_output: bool = True,
    ) -> tuple[bool, Any]:
        cmd = ["ovs-vsctl", "--no-syslog"]
        if json_output:
            cmd.append("--format=json")
        cmd.extend(args)
        ret, out, err = OVSCommand._run_cmd(cmd, timeout)
        if ret != 0:
            return False, err.strip()
        if json_output and out:
            try:
                return True, json.loads(out)
            except json.JSONDecodeError as e:
                return False, str(e)
        return True, out.strip()

    @staticmethod
    def _build_ofctl_cmd(action: str, bridge: str, args: list[str] | str) -> list[str]:
        cmd = ["ovs-ofctl", action, bridge]
        if isinstance(args, list):
            cmd.extend(args)
        elif args:
            cmd.append(args)
        return cmd

    @staticmethod
    def run_appctl(*args: str, timeout: int = 5) -> tuple[bool, str]:
        """Run ovs-appctl with given args (e.g. fdb/show, bridge). Returns (ok, output)."""
        cmd = ["ovs-appctl"] + list(args)
        ret, out, err = OVSCommand._run_cmd(cmd, timeout)
        output = (out or err or "").strip()
        return ret == 0, output

    @staticmethod
    def run_ofctl(
        action: str,
        bridge: str,
        args: list[str] | str = "",
        timeout: int = 5,
    ) -> tuple[bool, str]:
        cmd = OVSCommand._build_ofctl_cmd(action, bridge, args)
        ret, out, err = OVSCommand._run_cmd(cmd, timeout)
        output = (out or err or "").strip()
        return ret == 0, output

    @staticmethod
    async def run_ofctl_async(
        action: str,
        bridge: str,
        args: list[str] | str = "",
        timeout: int = 5,
    ) -> tuple[bool, str]:
        cmd = OVSCommand._build_ofctl_cmd(action, bridge, args)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            out_s = (stdout or b"").decode()
            err_s = (stderr or b"").decode()
            output = (out_s or err_s or "").strip()
            return proc.returncode == 0, output
        except asyncio.TimeoutError:
            proc.kill()
            return False, "timeout"
        except (FileNotFoundError, OSError) as e:
            return False, str(e)

    @staticmethod
    def parse_table_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
        rows = data.get("data") or []
        headings = data.get("headings") or []
        if not headings or not rows:
            return []
        return [dict(zip(headings, row)) for row in rows]

from __future__ import annotations

import importlib.metadata
import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass


@dataclass
class PipPackage:
    name: str
    version: str
    location: str


@dataclass
class SystemPackage:
    name: str
    version: str
    arch: str


@dataclass
class SystemService:
    name: str
    status: str
    enabled: bool
    description: str


class LibInspector:
    def pip_packages(self) -> list[PipPackage]:
        packages: list[PipPackage] = []
        for dist in importlib.metadata.distributions():
            metadata = dist.metadata
            packages.append(
                PipPackage(
                    name=metadata.get("Name") or "unknown",
                    version=metadata.get("Version") or "?",
                    location=str(dist.locate_file("")),
                )
            )
        return sorted(packages, key=lambda package: package.name.lower())

    def pip_outdated(self) -> list[dict]:
        try:
            result = subprocess.run(
                ["pip", "list", "--outdated", "--format=json"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return []
            return json.loads(result.stdout)
        except Exception:
            return []

    def system_packages(self) -> list[SystemPackage]:
        if shutil.which("dpkg-query"):
            return self._dpkg_packages()
        if shutil.which("rpm"):
            return self._rpm_packages()
        if shutil.which("pacman"):
            return self._pacman_packages()
        return []

    def services(self) -> list[SystemService]:
        if not shutil.which("systemctl"):
            return []

        try:
            result = subprocess.run(
                [
                    "systemctl",
                    "list-units",
                    "--type=service",
                    "--all",
                    "--no-pager",
                    "--plain",
                    "--no-legend",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except Exception:
            return []

        services: list[SystemService] = []
        for line in result.stdout.strip().splitlines():
            parts = line.split(None, 4)
            if len(parts) < 4:
                continue
            name = parts[0].removesuffix(".service")
            load = parts[1]
            active = parts[2]
            sub = parts[3]
            description = parts[4] if len(parts) > 4 else ""
            if load != "loaded":
                continue
            services.append(
                SystemService(
                    name=name,
                    status=sub,
                    enabled=active == "active",
                    description=description,
                )
            )
        return services

    def failed_services(self) -> list[SystemService]:
        return [service for service in self.services() if service.status == "failed"]

    def autostart_entries(self) -> list[str]:
        import glob

        paths = glob.glob(os.path.expanduser("~/.config/autostart/*.desktop"))
        paths.extend(glob.glob("/etc/xdg/autostart/*.desktop"))
        return paths

    def summary_dict(self) -> dict:
        pip_packages = self.pip_packages()
        system_packages = self.system_packages()
        failed_services = self.failed_services()
        return {
            "pip_packages_count": len(pip_packages),
            "pip_top_packages": [package.name for package in pip_packages[:20]],
            "system_packages_count": len(system_packages),
            "failed_services": [service.name for service in failed_services],
        }

    def _dpkg_packages(self) -> list[SystemPackage]:
        try:
            result = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except Exception:
            return []
        return self._parse_tabular_packages(result.stdout)

    def _rpm_packages(self) -> list[SystemPackage]:
        try:
            result = subprocess.run(
                ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\t%{ARCH}\n"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except Exception:
            return []
        return self._parse_tabular_packages(result.stdout)

    def _pacman_packages(self) -> list[SystemPackage]:
        try:
            result = subprocess.run(
                ["pacman", "-Q"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except Exception:
            return []

        packages: list[SystemPackage] = []
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) == 2:
                packages.append(SystemPackage(parts[0], parts[1], ""))
        return packages

    def _parse_tabular_packages(self, raw: str) -> list[SystemPackage]:
        packages: list[SystemPackage] = []
        for line in raw.strip().splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                packages.append(SystemPackage(*parts))
        return packages


def get_system_packages_summary() -> dict:
    return LibInspector().summary_dict()

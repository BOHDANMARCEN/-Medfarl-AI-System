from __future__ import annotations

import platform
import time
from dataclasses import asdict, dataclass

import psutil


@dataclass
class CPUInfo:
    model: str
    physical_cores: int
    logical_cores: int
    freq_mhz: float
    usage_percent: float
    per_core_percent: list[float]


@dataclass
class MemoryInfo:
    total_gb: float
    available_gb: float
    used_gb: float
    percent: float
    swap_total_gb: float
    swap_used_gb: float


@dataclass
class DiskInfo:
    device: str
    mountpoint: str
    fstype: str
    total_gb: float
    used_gb: float
    free_gb: float
    percent: float


@dataclass
class ProcessInfo:
    pid: int
    name: str
    cpu_percent: float
    memory_mb: float
    status: str


@dataclass
class GPUInfo:
    index: int
    name: str
    memory_total_mb: float
    memory_used_mb: float
    utilization_percent: float
    temperature_c: float


@dataclass
class SystemSnapshot:
    platform: str
    kernel: str
    hostname: str
    uptime_hours: float
    cpu: CPUInfo
    memory: MemoryInfo
    disks: list[DiskInfo]
    top_processes: list[ProcessInfo]
    temperatures: dict[str, float]
    gpus: list[GPUInfo]
    network: dict[str, dict]


class SystemScanner:
    def snapshot(self) -> SystemSnapshot:
        return SystemSnapshot(
            platform=platform.system(),
            kernel=platform.release(),
            hostname=platform.node(),
            uptime_hours=self._uptime(),
            cpu=self._cpu(),
            memory=self._memory(),
            disks=self._disks(),
            top_processes=self._top_processes(),
            temperatures=self._temperatures(),
            gpus=self._gpus(),
            network=self._network(),
        )

    def to_dict(self) -> dict:
        snap = self.snapshot()
        return {
            "platform": snap.platform,
            "kernel": snap.kernel,
            "hostname": snap.hostname,
            "uptime_hours": round(snap.uptime_hours, 2),
            "cpu": {
                "model": snap.cpu.model,
                "cores_physical": snap.cpu.physical_cores,
                "cores_logical": snap.cpu.logical_cores,
                "freq_mhz": snap.cpu.freq_mhz,
                "usage_percent": snap.cpu.usage_percent,
                "per_core_percent": snap.cpu.per_core_percent,
            },
            "memory": asdict(snap.memory),
            "disks": [asdict(disk) for disk in snap.disks],
            "top_processes": [asdict(proc) for proc in snap.top_processes],
            "temperatures": snap.temperatures,
            "gpus": [asdict(gpu) for gpu in snap.gpus],
            "network": snap.network,
        }

    def _uptime(self) -> float:
        return (time.time() - psutil.boot_time()) / 3600

    def _cpu(self) -> CPUInfo:
        freq = psutil.cpu_freq()
        return CPUInfo(
            model=self._cpu_model(),
            physical_cores=psutil.cpu_count(logical=False) or 1,
            logical_cores=psutil.cpu_count(logical=True) or 1,
            freq_mhz=round(freq.current, 1) if freq else 0.0,
            usage_percent=psutil.cpu_percent(interval=0.5),
            per_core_percent=psutil.cpu_percent(interval=0.1, percpu=True),
        )

    def _cpu_model(self) -> str:
        try:
            if platform.system() == "Linux":
                with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as file:
                    for line in file:
                        if "model name" in line:
                            return line.split(":", 1)[1].strip()
            if platform.system() == "Windows":
                import winreg

                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                )
                return winreg.QueryValueEx(key, "ProcessorNameString")[0]
        except Exception:
            pass
        return platform.processor() or "Unknown CPU"

    def _memory(self) -> MemoryInfo:
        vm = psutil.virtual_memory()
        sw = psutil.swap_memory()
        gb = 1024**3
        return MemoryInfo(
            total_gb=round(vm.total / gb, 2),
            available_gb=round(vm.available / gb, 2),
            used_gb=round(vm.used / gb, 2),
            percent=vm.percent,
            swap_total_gb=round(sw.total / gb, 2),
            swap_used_gb=round(sw.used / gb, 2),
        )

    def _disks(self) -> list[DiskInfo]:
        disks: list[DiskInfo] = []
        gb = 1024**3
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except (PermissionError, OSError):
                continue
            disks.append(
                DiskInfo(
                    device=part.device,
                    mountpoint=part.mountpoint,
                    fstype=part.fstype,
                    total_gb=round(usage.total / gb, 2),
                    used_gb=round(usage.used / gb, 2),
                    free_gb=round(usage.free / gb, 2),
                    percent=usage.percent,
                )
            )
        return disks

    def _top_processes(self, count: int = 10) -> list[ProcessInfo]:
        processes: list[ProcessInfo] = []
        for proc in psutil.process_iter(
            ["pid", "name", "cpu_percent", "memory_info", "status"]
        ):
            try:
                memory_info = proc.info.get("memory_info")
                processes.append(
                    ProcessInfo(
                        pid=proc.info["pid"],
                        name=proc.info.get("name") or "unknown",
                        cpu_percent=proc.info.get("cpu_percent") or 0.0,
                        memory_mb=(memory_info.rss / 1024**2) if memory_info else 0.0,
                        status=proc.info.get("status") or "unknown",
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return sorted(processes, key=lambda proc: proc.cpu_percent, reverse=True)[
            :count
        ]

    def _temperatures(self) -> dict[str, float]:
        temperatures: dict[str, float] = {}
        try:
            sensors = psutil.sensors_temperatures()
        except (AttributeError, Exception):
            return temperatures

        for name, entries in sensors.items():
            for entry in entries:
                label = f"{name}/{entry.label or 'main'}"
                temperatures[label] = entry.current
        return temperatures

    def _gpus(self) -> list[GPUInfo]:
        gpus: list[GPUInfo] = []
        try:
            import pynvml

            pynvml.nvmlInit()
            count = pynvml.nvmlDeviceGetCount()
            for index in range(count):
                handle = pynvml.nvmlDeviceGetHandleByIndex(index)
                mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
                util = pynvml.nvmlDeviceGetUtilizationRates(handle)
                temp = pynvml.nvmlDeviceGetTemperature(
                    handle, pynvml.NVML_TEMPERATURE_GPU
                )
                name = pynvml.nvmlDeviceGetName(handle)
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                gpus.append(
                    GPUInfo(
                        index=index,
                        name=name,
                        memory_total_mb=round(mem.total / 1024**2, 2),
                        memory_used_mb=round(mem.used / 1024**2, 2),
                        utilization_percent=util.gpu,
                        temperature_c=temp,
                    )
                )
        except Exception:
            return gpus
        return gpus

    def _network(self) -> dict[str, dict]:
        result: dict[str, dict] = {}
        try:
            counters = psutil.net_io_counters(pernic=True)
            addrs = psutil.net_if_addrs()
        except Exception:
            return result

        for iface, stats in counters.items():
            result[iface] = {
                "bytes_sent_mb": round(stats.bytes_sent / 1024**2, 2),
                "bytes_recv_mb": round(stats.bytes_recv / 1024**2, 2),
                "packets_sent": stats.packets_sent,
                "packets_recv": stats.packets_recv,
                "addresses": [
                    addr.address
                    for addr in addrs.get(iface, [])
                    if addr.address and not addr.address.startswith("fe80")
                ],
            }
        return result


def get_system_snapshot() -> dict:
    return SystemScanner().to_dict()

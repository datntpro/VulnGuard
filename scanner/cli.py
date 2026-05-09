"""
VulnGuard CLI — Command line interface để trigger scans.
Usage:
  python -m scanner.cli scan --path /workspace --project "My App" --stacks java,python,terraform
"""
import asyncio
import typer
import httpx
import json
import sys
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

app = typer.Typer(help="VulnGuard — Local DevSecOps Security Scanner")
console = Console()

API_URL = "http://localhost:8080"

SCAN_TYPE_MAP = {
    "java": ["SAST", "SCA"],
    "kotlin": ["SAST", "SCA"],
    "python": ["SAST", "SCA"],
    "javascript": ["SAST", "SCA"],
    "typescript": ["SAST", "SCA"],
    "go": ["SAST", "SCA"],
    "c": ["SAST"],
    "cpp": ["SAST"],
    "terraform": ["IAC"],
    "ansible": ["IAC"],
    "kubernetes": ["IAC", "CONTAINER"],
    "k8s": ["IAC", "CONTAINER"],
    "docker": ["CONTAINER", "IAC"],
    "container": ["CONTAINER"],
    "secrets": ["SECRETS"],
}


@app.command()
def scan(
    path: str = typer.Option("/workspace", "--path", "-p", help="Đường dẫn thư mục cần scan"),
    project: str = typer.Option(..., "--project", "-n", help="Tên project"),
    stacks: Optional[str] = typer.Option(None, "--stacks", "-s", help="Tech stacks: java,python,terraform (mặc định: all)"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Bỏ qua AI analysis"),
    api_url: str = typer.Option(API_URL, "--api", help="URL của VulnGuard API"),
):
    """Scan source code và báo cáo vulnerabilities."""
    asyncio.run(_scan(path, project, stacks, not no_ai, api_url))


async def _scan(path: str, project_name: str, stacks: Optional[str], run_ai: bool, api_url: str):
    console.print(Panel.fit(
        f"[bold cyan]VulnGuard Security Scanner[/bold cyan]\n"
        f"Path: [yellow]{path}[/yellow]\n"
        f"Project: [green]{project_name}[/green]",
        border_style="cyan"
    ))

    async with httpx.AsyncClient(base_url=api_url, timeout=30) as client:
        # Tìm hoặc tạo project
        console.print("[bold]1.[/bold] Kiểm tra project...")
        resp = await client.get("/api/projects")
        projects = resp.json()
        project = next((p for p in projects if p["name"] == project_name), None)

        if not project:
            console.print(f"   → Tạo project mới: [green]{project_name}[/green]")
            resp = await client.post("/api/projects", json={
                "name": project_name,
                "language_stacks": stacks.split(",") if stacks else [],
            })
            if resp.status_code != 201:
                console.print(f"[red]Lỗi tạo project: {resp.text}[/red]")
                sys.exit(1)
            project = resp.json()
        else:
            console.print(f"   → Project tồn tại: [green]{project_name}[/green] (ID: {project['id'][:8]}...)")

        # Xác định scan types
        scan_types = _resolve_scan_types(stacks)
        console.print(f"[bold]2.[/bold] Scan types: [yellow]{', '.join(scan_types)}[/yellow]")

        # Trigger scan
        console.print(f"[bold]3.[/bold] Bắt đầu scan [yellow]{path}[/yellow]...")
        resp = await client.post(
            f"/api/projects/{project['id']}/scans",
            json={
                "scan_path": path,
                "scan_types": scan_types,
                "run_ai_analysis": run_ai,
            },
            timeout=30,
        )
        if resp.status_code not in (200, 201, 202):
            console.print(f"[red]Lỗi trigger scan: {resp.text}[/red]")
            sys.exit(1)

        scan = resp.json()
        scan_id = scan["id"]
        console.print(f"   → Scan ID: [dim]{scan_id}[/dim]")

        # Poll scan status
        console.print(f"[bold]4.[/bold] Đang scan... (AI analysis: {'ON' if run_ai else 'OFF'})")
        with console.status("[bold green]Scanning...") as status:
            while True:
                await asyncio.sleep(3)
                resp = await client.get(f"/api/projects/scans/{scan_id}")
                if resp.status_code != 200:
                    break
                scan = resp.json()
                if scan["status"] in ("COMPLETED", "FAILED"):
                    break
                status.update(f"[bold green]Scanning... ({scan['status']})")

        if scan["status"] == "FAILED":
            console.print(f"[red]Scan thất bại: {scan.get('error_message', 'Unknown error')}[/red]")
            sys.exit(1)

        # Lấy kết quả
        resp = await client.get(f"/api/projects/scans/{scan_id}/vulns")
        vulns = resp.json()

        # Approve check
        resp = await client.get(
            f"/api/projects/{project['id']}/approve-check",
            params={"scan_id": scan_id}
        )
        approve = resp.json()

        # Hiển thị kết quả
        _display_results(vulns, scan, approve)


def _resolve_scan_types(stacks: Optional[str]) -> list:
    if not stacks:
        return ["SAST", "SCA", "IAC", "CONTAINER", "SECRETS"]

    types = set()
    for stack in stacks.split(","):
        for t in SCAN_TYPE_MAP.get(stack.strip().lower(), ["SAST", "SCA"]):
            types.add(t)
    types.add("SECRETS")  # Luôn scan secrets
    return list(types)


def _display_results(vulns: list, scan: dict, approve: dict):
    summary = scan.get("summary", {})

    console.print()
    console.print(Panel.fit(
        f"[bold]Kết quả Scan #{scan.get('scan_number', '?')}[/bold]\n"
        f"[red]CRITICAL: {summary.get('CRITICAL', 0)}[/red]  "
        f"[orange3]HIGH: {summary.get('HIGH', 0)}[/orange3]  "
        f"[yellow]MEDIUM: {summary.get('MEDIUM', 0)}[/yellow]  "
        f"[green]LOW: {summary.get('LOW', 0)}[/green]  "
        f"Total: {summary.get('total', len(vulns))}",
        border_style="white"
    ))

    # Approve status
    approve_status = approve.get("approve_status", "UNKNOWN")
    if approve_status == "BLOCKED":
        console.print(f"\n[bold red]⛔ {approve.get('message', 'BLOCKED')}[/bold red]")
    else:
        console.print(f"\n[bold green]✅ {approve.get('message', 'APPROVED')}[/bold green]")

    # Top 10 critical/high
    critical_vulns = [v for v in vulns if v["severity"] in ("CRITICAL", "HIGH")][:10]
    if critical_vulns:
        table = Table(title="\nTop CRITICAL/HIGH Vulnerabilities", show_lines=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Tool", width=15)
        table.add_column("Title", width=40)
        table.add_column("File", width=30)
        table.add_column("Status", width=12)

        for v in critical_vulns:
            sev = v["severity"]
            color = "red" if sev == "CRITICAL" else "orange3"
            table.add_row(
                f"[{color}]{sev}[/{color}]",
                v["tool"],
                v["title"][:38],
                f"{v.get('file_path', '')[:28]}:{v.get('line_start', '')}",
                v["status"],
            )
        console.print(table)

    console.print(f"\n[dim]→ Xem chi tiết tại: http://localhost:8080[/dim]")
    console.print(f"[dim]→ Scan ID: {scan['id']}[/dim]")


if __name__ == "__main__":
    app()

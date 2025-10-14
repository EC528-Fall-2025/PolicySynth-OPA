# cli.py
from pathlib import Path
import os
import json
import typer

from discover import run as discover_run
from translate import run as translate_run
from sync import run as sync_run

app = typer.Typer(help="Policy Synthesizer CLI")

DATA_DIR = Path("data")
POLICY_DIR = Path("policy") / "terraform"
GUARDRAILS_JSON = DATA_DIR / "guardrails.json"

@app.command(help="Discover cloud guardrails (using existing SCPFetcher) and output to data/guardrails.json")
def discover(
    profile: str = typer.Option(None, help="AWS CLI profile name"),
    region: str = typer.Option("us-east-1", help="AWS region"),
    mock: bool = typer.Option(False, help="Force using local mock instead of accessing AWS"),
    strict: bool = typer.Option(False, help="Strict mode: raise error immediately if real call fails")
):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = discover_run(output_path=GUARDRAILS_JSON, profile=profile, region=region, mock=mock, strict=strict)
    typer.echo(f"[discover] wrote -> {path}")

@app.command(help="Translate guardrails.json into OPA/Rego policies, output to policy/terraform/")
def translate():
    POLICY_DIR.mkdir(parents=True, exist_ok=True)
    translate_run(input_path=GUARDRAILS_JSON, out_dir=POLICY_DIR)
    typer.echo(f"[translate] policies -> {POLICY_DIR}")

@app.command(help="Generate policy bundle summary (hash manifest) for later sync/compare")
def sync():
    sync_run(policy_dir=POLICY_DIR)
    typer.echo("[sync] bundle.manifest.json generated")

@app.command(help="Run discover -> translate -> sync")
def all(
    profile: str = typer.Option(None, help="AWS CLI profile name"),
    region: str = typer.Option("us-east-1", help="AWS region"),
    mock: bool = typer.Option(False, help="Force using local mock instead of accessing AWS"),
    strict: bool = typer.Option(False, help="Strict mode: raise error immediately if real call fails")
):
    discover(profile=profile, region=region, mock=mock, strict=strict)
    translate()
    sync()

@app.command()
def version():
    typer.echo("policy-synthesizer 0.1.0")

if __name__ == "__main__":
    app()
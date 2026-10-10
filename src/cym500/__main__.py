from __future__ import annotations

import typer
from dotenv import load_dotenv

# Load .env (GITHUB_TOKEN, registry API keys, DATA_ROOT, ...) before any module
# reads os.environ. python-dotenv is a declared dependency; this is the one place
# it is wired in. Real environment variables take precedence over the file.
load_dotenv(override=False)

from cym500.collectors.cli import collectors_app
from cym500.classification.cli import classify_app
from cym500.analysis.cli import analyze_app
from cym500.sandbox.cli import sandbox_app
from cym500.redteam.cli import redteam_app
from cym500.benchmark.cli import benchmark_app

app = typer.Typer(no_args_is_help=True, help="CYM500 MCP measurement + benchmark CLI")
app.add_typer(collectors_app, name="collect")
app.add_typer(classify_app, name="classify")
app.add_typer(analyze_app, name="analyze")
app.add_typer(sandbox_app, name="sandbox")
app.add_typer(redteam_app, name="redteam")
app.add_typer(benchmark_app, name="benchmark")


if __name__ == "__main__":
    app()

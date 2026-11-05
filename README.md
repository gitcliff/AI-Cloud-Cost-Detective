# AI Cloud Cost Detective for AWS

An intelligent AWS cost optimization tool that combines **deterministic pricing calculations** with **LLM-powered analysis** to find wasteful cloud spending and deliver actionable fix commands.

Unlike tools that rely solely on AI guesses, Cloud Cost Detective calculates savings from real AWS pricing data and resource configuration — then uses an LLM only to explain findings, assess severity, and generate remediation commands.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────
│                              Browser                                   │
│                   React + TypeScript + Tailwind CSS                    │
│                                                                        │
│   ┌──────────┐   ┌───────────┐ ┌──────────┐   ┌────────┐  ┌──────────┐ │
│   │  Login/  |   │ Dashboard │ │ Progress │   │History │  │  Report  │ │
│   │  Signup  |   │  Region   │ │ Tracker  │   │  List  │  │  Detail  │ │
│   │          │   │  Selector │ │   (WS)   │   │        │  │          │ │
│   └──────────┘   └─────┬─────┘ └────┬─────┘   └───┬────┘  └────┬─────┘ │
└────────────────────────┼────────────┼─────────────┼────────────┼───────┘
                         │ REST       │ WebSocket   │ REST       │ REST
                         ▼            ▼             ▼            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     Nginx Reverse Proxy (:80)                           │
│              /api/* → backend:8000    /ws/* → backend:8000              │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   FastAPI Backend (:8000)                               │
│                                                                         │
│  ┌─────────────┐   ┌──────────────┐   ┌───────────────────────────┐     │
│  │ JWT Auth    │   │ AWS Scanner  │   │ Cost Explorer Integration │     │
│  │ signup/login│   │ 8 services   │   │ 3-month spend history     │     │
│  └──────┬──────┘   │ 16 regions   │   │ service breakdown         │     │
│         │          └──────┬───────┘   └────────────┬──────────────┘     │
│         │                 │                        │                    │
│         │                 ▼                        ▼                    │
│         │    ┌─────────────────────────────────────────────┐            │
│         │    │         Pricing Engine (Deterministic)      |            │
│         │    │  9 calculators · AWS Pricing API + fallback |            │
│         │    │  confidence levels · savings formulas       |            │
│         │    └──────────────────────┬──────────────────────┘            │
│         │                           │                                   |
│         │                           ▼                                   |
│         │    ┌─────────────────────────────────────────────┐            │
│         │    │          LLM Analysis Layer                 |            │
│         │    │  Groq · OpenAI · Anthropic · Gemini         |            │
│         │    │  Explains issues · generates fix commands   |            │
│         │    │  Cannot override deterministic savings      |            │
│         │    └──────────────────────┬──────────────────────┘            │
│         │                          │                                    │
│         ▼                          ▼                                    │
│  ┌──────────────────────────────────────────┐                           │
│  │          PostgreSQL Database             |                           │
│  │  users · analyses (JSONB results)        │                           │
│  └──────────────────────────────────────────┘                           │
└─────────────────────────────────────────────────────────────────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                  ▼
        ┌──────────┐   ┌──────────────┐   ┌────────────┐
        │ AWS APIs │   │ AWS Pricing  │   │  LLM API   │
        │ (boto3)  │   │ API (free)   │   │ (provider) │
        └──────────┘   └──────────────┘   └────────────┘
```

### Analysis Pipeline

```
Start Analysis
     │
     ├──── Scan AWS Resources (8 services, parallel boto3 calls)
     │          └──── EC2, RDS, S3, EBS, EIPs, ELBs, Lambda, NAT GW
     │
     ├──── Fetch Cost Explorer Data (actual spend, optional)
     │          └──── 3-month history, service breakdown, per-resource costs
     │
     ├──── Merge Costs with Resources
     │          └──── Attach actual spend + cost trends to each resource
     │
     ├──── Deterministic Pricing Engine (9 calculators)
     │          └──── Calculate exact savings with formulas + assumptions
     │
     ├──── LLM Analysis (explain, don't calculate)
     │          └──── Severity · Explanations · Fix commands · New findings
     │
     └──── Store Results → PostgreSQL (JSONB)
```

---

## Project Structure

```
AI-Cloud-Cost-Detective/
├── docker-compose.yml              # 3-service orchestration
│
├── backend/
│   ├── Dockerfile                  # Python 3.12-slim
│   ├── requirements.txt            # FastAPI, boto3, asyncpg, groq, etc.
│   ├── .env.example                # All configuration options documented
│   ├── main.py                     # FastAPI app, endpoints, WebSocket, pipeline
│   ├── models.py                   # Pydantic request/response models
│   ├── auth.py                     # JWT + bcrypt authentication
│   ├── db.py                       # PostgreSQL pool + table management
│   ├── aws_scanner.py              # Multi-region AWS resource scanner
│   ├── cost_explorer.py            # AWS Cost Explorer integration
│   ├── pricing_engine.py           # Deterministic savings calculators
│   └── ai_analyzer.py              # Multi-provider LLM analysis
│
├── frontend/
│   ├── Dockerfile                  # Multi-stage: Node 20 build → Nginx
│   ├── nginx.conf                  # Reverse proxy + SPA routing
│   ├── package.json                # React 18, Vite, Tailwind, TypeScript
│   └── src/
│       ├── App.tsx                 # Router setup + auth guards
│       ├── api/client.ts           # Axios with JWT interceptor
│       ├── types/index.ts          # Shared TypeScript interfaces
│       ├── components/
│       │   ├── Navbar.tsx           # Navigation + logout
│       │   └── ProgressTracker.tsx  # WebSocket progress display
│       └── pages/
│           ├── Login.tsx            # Authentication
│           ├── Signup.tsx           # Registration
│           ├── Dashboard.tsx        # Region selector + analysis launcher
│           ├── History.tsx          # Past analyses list
│           └── Report.tsx           # Detailed results with issue cards
```

---

## Technical Decisions

### Why a deterministic pricing engine instead of letting the LLM estimate costs?

LLMs hallucinate dollar amounts. Their training data contains outdated pricing, and they have no way to verify figures at inference time. The pricing engine calculates savings from AWS's own pricing tables with explicit formulas (e.g., `100 GB x $0.10/GB = $10.00/mo`) — every number is traceable. The LLM's role is limited to what it does well: explaining *why* something is wasteful and *how* to fix it.

### Why confidence levels on every estimate?

Not all savings carry the same certainty. An unattached EBS volume's cost is a mathematical fact (high confidence). An old-generation instance upgrade depends on pricing API availability and workload compatibility (medium confidence). An LLM-discovered issue uses estimated pricing from training data (low confidence). Users see this distinction clearly in the UI, so they can act on verified savings first.

### Why support 4 LLM providers?

Cost and accessibility. Groq and Gemini offer free tiers that make this tool zero-cost to try. OpenAI and Anthropic provide higher-quality analysis for production use. Swapping providers is a single environment variable change — no code modifications needed.

### Why PostgreSQL with JSONB for analysis results?

Analysis results are complex nested structures (issues, assumptions, formulas, cost breakdowns) that don't map cleanly to relational tables. JSONB stores the full result as a document while still supporting indexing and querying. The relational parts (users, analysis metadata) stay normalized.

### Why WebSocket for progress instead of polling?

An analysis involves 6 sequential stages (scan, cost fetch, merge, price, analyze, store) that take 30-90 seconds total. WebSocket delivers real-time progress updates without the client hammering the server with poll requests. The UI shows exactly which stage is running and the percentage complete.

### Why Nginx as a reverse proxy in Docker?

The frontend is a static SPA that needs to route API calls (`/api/*`) and WebSocket connections (`/ws/*`) to the backend. Nginx handles this cleanly in production, serves static assets efficiently, and provides the SPA fallback routing (`try_files`) that React Router requires.

---

## What Makes This Project Useful

**Evidence-based savings** — Every savings estimate includes the formula used to calculate it, the assumptions made, and a confidence level. No black-box AI guesses on dollar amounts.

**Actionable fix commands** — Each issue comes with a ready-to-run AWS CLI command. Copy, review, execute.

**Real cost data integration** — Optionally pulls actual spend from AWS Cost Explorer, so you see what you're *actually* paying alongside what you *could* save.

**9 automated detectors** covering the most common AWS cost wastes:

| Detector | What it finds | Confidence |
|----------|--------------|------------|
| Unattached EBS | Volumes not attached to any instance | High |
| GP2 → GP3 migration | Older volume type costing more for same performance | High |
| Unassociated Elastic IPs | IPs you're paying $3.60/mo for but not using | High |
| Idle NAT Gateways | Gateways with zero traffic in the last 7 days | High |
| Idle Load Balancers | ALB/NLB/CLB with no healthy targets | High |
| Zero-invocation Lambda | Functions not called in 30 days | High |
| Stopped EC2 EBS costs | EBS volumes still billing on stopped instances | High |
| Old-gen instances | t2, m3/m4, c3/c4, r3/r4 that should be upgraded | Medium |
| Multi-AZ RDS | Databases where single-AZ would suffice | Medium |

**Multi-region scanning** — Analyze any of 16 AWS regions. Most tools only check us-east-1.

**Live progress tracking** — WebSocket-powered real-time updates as each pipeline stage completes. No staring at a spinner wondering if it's stuck.

**Full analysis history** — Every analysis is stored with its complete results. Compare cost optimization over time.

---

## Getting Started

### Prerequisites

- **AWS credentials** with read-only access (see [IAM permissions](#iam-permissions) below)
- **LLM API key** — free options available (Groq or Gemini)

### Option 1: Docker Compose (recommended)

The fastest way to get running. Requires only Docker.

```bash
# Clone the repository
git clone https://github.com/gitcliff/AI-Cloud-Cost-Detective.git
cd AI-Cloud-Cost-Detective

# Configure the backend
cp backend/.env.example backend/.env
# Edit backend/.env — set at minimum:
#   LLM_API_KEY=your-key-here
#   AWS_ACCESS_KEY_ID=your-aws-key
#   AWS_SECRET_ACCESS_KEY=your-aws-secret

# Build and start all services
docker compose up --build
```

The app is available at **http://localhost**. The backend API is at **http://localhost:8000**.

To stop:

```bash
docker compose down            # stop services
docker compose down -v         # stop and remove database volume
```

### Option 2: Local Development

Requires Python 3.12+, Node 20+, and a running PostgreSQL instance.

**1. Start PostgreSQL**

```bash
# Using Docker (easiest)
docker run -d --name costdetective-db \
  -e POSTGRES_USER=costdetective \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=costdetective \
  -p 5432:5432 \
  postgres:16-alpine

# Or use an existing PostgreSQL instance — update DATABASE_URL in .env
```

**2. Backend**

```bash
cd backend

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env — set LLM_API_KEY and AWS credentials

# Start the server
uvicorn main:app --reload --port 8000
```

**3. Frontend**

```bash
cd frontend

# Install dependencies
npm install

# Start dev server (proxies API to backend automatically)
npm run dev
```

The app is available at **http://localhost:5173**. Vite proxies `/api` and `/ws` requests to the backend at port 8000.

---

## IAM Permissions

The minimum IAM policy for scanning (read-only):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "rds:Describe*",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketVersioning",
        "s3:GetLifecycleConfiguration",
        "elasticloadbalancing:Describe*",
        "lambda:ListFunctions",
        "lambda:GetFunction",
        "cloudwatch:GetMetricStatistics",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

For actual cost data (optional, adds ~$0.02 per analysis):

```json
{
  "Effect": "Allow",
  "Action": "ce:GetCostAndUsage",
  "Resource": "*"
}
```

For real-time pricing lookups (optional, free):

```json
{
  "Effect": "Allow",
  "Action": "pricing:GetProducts",
  "Resource": "*"
}
```

---

## Configuration

All configuration is via environment variables in `backend/.env`:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LLM_PROVIDER` | No | `groq` | LLM provider: `groq`, `openai`, `anthropic`, `gemini` |
| `LLM_API_KEY` | Yes | — | API key for the selected provider |
| `LLM_MODEL` | No | Provider default | Override the default model |
| `DATABASE_URL` | No | `postgresql://costdetective:password@localhost:5432/costdetective` | PostgreSQL connection string |
| `JWT_SECRET` | No | `change-me-in-production` | Secret for signing JWT tokens |
| `AWS_ACCESS_KEY_ID` | Yes* | — | AWS access key (*or use IAM roles / `~/.aws/credentials`) |
| `AWS_SECRET_ACCESS_KEY` | Yes* | — | AWS secret key |
| `CORS_ORIGIN` | No | `http://localhost:5173` | Allowed frontend origin |

---

## License

MIT

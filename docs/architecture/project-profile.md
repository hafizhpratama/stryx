# Project Profile Architecture

> **Status (2026-05-20):** Phase 1 shipped in v0.3.0 — the cheap-pass
> detector (`stryx_index::profile::detect`) reads package.json,
> lockfiles, and a small set of config files; the resulting
> `ProjectProfile` is surfaced via `ScanResult.profile` and the JSON
> envelope. Source-evidence collection during the extract pass,
> `WorkspaceProfile` for monorepos, the `--profile` flag, and
> `[profile]` config overrides remain planned for Phase 2+.

The project profile is Stryx's stack-detection layer. It runs before
rules produce user-facing findings and tells the rest of the engine which
TypeScript backend/platform surfaces are present.

The profile does not replace rules. It answers: "what stack is this?"
Adapters then translate that stack into sources, sinks, sanitisers, and
guards that existing flow rules can use.

## Design goals

1. Detect common TypeScript backend stacks with explicit evidence.
2. Enable only relevant adapters by default.
3. Support multiple runtimes/frameworks in one monorepo.
4. Keep detection deterministic and cheap.
5. Avoid React/client UI analysis entirely.

## Pipeline location

The target pipeline becomes:

```text
Scan root
  ↓
Collect files + package/config evidence
  ↓
Build ProjectProfile
  ↓
Layer 1: parse TS/JS with oxc
  ↓
Layer 2: project index + stack adapters + rules + taint engine
  ↓
Layer 3: optional LLM escalation on uncertain zones
  ↓
Findings + profile + enabled adapters
```

Profile construction has two passes:

1. **Cheap evidence pass** before parsing: lockfiles, package manager,
   `package.json`, `tsconfig.json`, config files, workspace layout.
2. **Source evidence pass** during extraction: imports, known globals,
   route shapes, call expressions, decorator usage, and framework
   idioms.

The cheap pass is enough to print early "Detecting ..." lines. The
source pass can refine confidence before adapters run.

## Data model

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectProfile {
    pub language: LanguageHint,
    pub runtimes: Vec<Detected<RuntimeHint>>,
    pub frameworks: Vec<Detected<FrameworkHint>>,
    pub data_layers: Vec<Detected<DataLayerHint>>,
    pub validators: Vec<Detected<ValidatorHint>>,
    pub auth_layers: Vec<Detected<AuthHint>>,
    pub llm_sdks: Vec<Detected<LlmSdkHint>>,
    pub deployments: Vec<Detected<DeploymentHint>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detected<T> {
    pub id: T,
    pub confidence: f32,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub path: PathBuf,
    pub detail: String,
    pub weight: f32,
}
```

Hints should be open enough to grow, but closed enough to make reporter
output stable:

```rust
pub enum LanguageHint {
    Unknown,
    JavaScript,
    TypeScript,
    Mixed,
}

pub enum RuntimeHint {
    Node,
    Bun,
    Deno,
    CloudflareWorkers,
    VercelEdge,
}

pub enum FrameworkHint {
    Generic,
    NextJsBackend,
    Hono,
    Express,
    Fastify,
    NestJs,
    Elysia,
    Oak,
}

pub enum DataLayerHint {
    Prisma,
    Drizzle,
    Kysely,
    Knex,
    Pg,
    Mysql2,
    BunSql,
    BunSqlite,
    Mongoose,
}

pub enum ValidatorHint {
    Zod,
    Valibot,
    Yup,
    Joi,
    Ajv,
    ArkType,
    TypeBox,
}

pub enum AuthHint {
    BetterAuth,
    AuthJs,
    Clerk,
    SupabaseAuth,
    Lucia,
    Custom,
}

pub enum LlmSdkHint {
    OpenAi,
    Anthropic,
    VercelAiSdk,
    LangChain,
}

pub enum DeploymentHint {
    Vercel,
    Cloudflare,
    AwsLambda,
    Netlify,
    FlyIo,
    Docker,
}
```

## Evidence types

```rust
pub enum EvidenceKind {
    PackageManager,
    Dependency,
    DevDependency,
    PackageScript,
    Lockfile,
    ConfigFile,
    TsConfig,
    ImportSpecifier,
    GlobalIdentifier,
    CallExpression,
    Decorator,
    RouteShape,
    EnvironmentVariable,
}
```

Examples:

| Hint | Evidence |
|---|---|
| `RuntimeHint::Bun` | `bun.lock`, `bunfig.toml`, `packageManager: "bun@..."`, `Bun.serve`, `import { $ } from "bun"` |
| `FrameworkHint::Hono` | dependency `hono`, imports from `hono`, `new Hono()`, `c.req.json()` |
| `DataLayerHint::Drizzle` | dependency `drizzle-orm`, imports from `drizzle-orm`, `db.insert`, `sql.raw` |
| `ValidatorHint::Zod` | dependency `zod`, imports from `zod`, `.parse`, `.safeParse` |
| `AuthHint::BetterAuth` | dependency `better-auth`, imports from `better-auth`, `auth.api.getSession` |

## Confidence

Confidence is numeric because a project can contain partial or stale
evidence. Reporter output should map confidence into simple terms:

| Confidence | Meaning | Default adapter behavior |
|---|---|---|
| `>= 0.80` | Found | Enable adapter |
| `0.60-0.79` | Inferred | Enable adapter, mark inferred in verbose profile |
| `0.35-0.59` | Possible | Do not enable by default; show with `--profile` |
| `< 0.35` | Weak | Ignore |

Confidence should combine independent evidence, capped at `1.0`.
Multiple weak signals should beat one weak signal, but one direct source
usage should beat package metadata alone.

Example weighting:

| Evidence | Weight |
|---|---|
| Direct runtime global/API call | `0.50` |
| Import from package | `0.45` |
| Runtime/framework config file | `0.40` |
| Runtime lockfile/package manager | `0.35` |
| Dependency in package.json | `0.30` |
| Script command | `0.20` |

## Monorepo behavior

Profiles should support both root-level and project-level detection:

```rust
pub struct WorkspaceProfile {
    pub root: ProjectProfile,
    pub projects: Vec<ProjectProfileForPath>,
}

pub struct ProjectProfileForPath {
    pub root: PathBuf,
    pub profile: ProjectProfile,
}
```

If a workspace contains `apps/api` with Hono and `apps/web` with
Next.js, Stryx should report and scan the selected project profile, not
flatten all evidence into one misleading stack.

## Integration points

### CLI

The CLI owns the user-facing detection flow:

- build cheap profile evidence
- print detection lines
- pass the profile into `scan`
- include profile in JSON/human output

### ProjectIndex

The index should store the final profile and continue to store per-file
framework hints:

```rust
pub struct ProjectIndex {
    profile: ProjectProfile,
    files: HashMap<PathBuf, FileSummary>,
    // existing fields...
}
```

Per-file summaries can include local profile overrides for mixed
projects:

```rust
pub struct FileSummary {
    pub path: PathBuf,
    pub framework: FrameworkHint,
    pub runtime: Option<RuntimeHint>,
    // existing fields...
}
```

### RuleContext

Rules and adapters need read-only access:

```rust
pub struct RuleContext<'a, 'b> {
    pub file: &'a ParsedFile<'b>,
    pub index: Option<&'a ProjectIndex>,
    pub profile: Option<&'a ProjectProfile>,
}
```

### Reporters

Reporters should surface:

- detected profile
- enabled adapters
- findings
- suppressed findings count
- scan file count and timing

The JSON schema must include profile evidence because CI tools and bug
reports need to explain why an adapter was active.

Findings should continue to link to rule fix guides. The profile explains
why an adapter was enabled; the rule page explains how to fix the unsafe
flow that adapter exposed.

## Configuration

Users need explicit override controls:

```toml
[profile]
force_runtime = ["bun"]
force_framework = ["hono"]
disable_adapters = ["auth/custom"]
enable_possible_adapters = false

[profile.ignore]
dependencies = ["@types/*"]
paths = ["examples/**"]
```

Manual overrides should be recorded as evidence with
`EvidenceKind::ConfigFile`, so output remains explainable.

## Tests

Each profile detector needs:

- package-only fixture
- import-only fixture
- API-call fixture
- mixed monorepo fixture
- stale dependency false-positive fixture
- confidence threshold fixture

Profile tests should not require the full rule suite. They should run
against a tiny synthetic project tree and assert the final profile JSON.

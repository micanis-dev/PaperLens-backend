# PaperLens backend deployment runbook

This repository owns two production targets: the Go API on **Fly.io** and the
PostgreSQL schema on **Supabase**. It does not deploy the frontend or any
Cloudflare resource.

## Fixed production targets

| Item | Required value |
| --- | --- |
| Working directory | Repository root containing this file |
| Git repository | `micanis-dev/PaperLens-backend` |
| Git branch | `main` |
| Fly app | `paperlens-api` |
| Fly primary region | `nrt` |
| API URL | `https://api.paperlens.micanis.dev` |
| Fly config | `fly.toml` |
| Supabase project | `paperlens-free` |
| Supabase project ref | `ewxmrxapokgudhtfmitm` |
| Supabase config | `supabase/config.toml` |
| Supabase migrations | `supabase/migrations` |

## Preflight: stop on any mismatch

Run every command from this repository, never from the parent `PaperLens`
directory.

```sh
test "$(basename "$PWD")" = "backend"
test -f fly.toml
test -f supabase/config.toml
test "$(git remote get-url origin)" = "https://github.com/micanis-dev/PaperLens-backend.git"
test "$(git branch --show-current)" = "main"
grep -F 'app = "paperlens-api"' fly.toml
grep -F 'project_id = "ewxmrxapokgudhtfmitm"' supabase/config.toml
git status --short --branch
flyctl status --app paperlens-api
supabase projects list
```

The Supabase output must identify `paperlens-free` with ref
`ewxmrxapokgudhtfmitm` as linked. Stop if it identifies `paperlens` or any other
project.

## Database migration procedure

Inspect both sides before applying anything.

```sh
supabase migration list --linked
```

If the local and remote columns already match, do not run `db push`. If there
are local-only migrations, inspect their SQL and then apply exactly those
migrations:

```sh
supabase db push --linked --dry-run
supabase db push --linked
supabase migration list --linked
```

Never repair a mismatch by marking arbitrary migrations as applied or reverted.
Never run a reset against the linked production project.

## API validation and deployment

```sh
go test ./...
flyctl config validate --config fly.toml
flyctl deploy --app paperlens-api --config fly.toml
```

Wait for the deploy command to finish. Do not start a second deploy because the
first one appears quiet; check status first.

## Required verification

```sh
flyctl status --app paperlens-api
flyctl releases --app paperlens-api
curl -fsS https://api.paperlens.micanis.dev/v1/healthz
curl -fsS -D - -o /dev/null \
  -H 'Origin: https://paperlens.micanis.dev' \
  https://api.paperlens.micanis.dev/v1/healthz \
  | grep -i 'access-control-allow-origin: https://paperlens.micanis.dev'
supabase migration list --linked
```

The current Fly release must be complete, at least one `nrt` machine must be
started with passing checks, the API must report `status: ok`, and migrations
must match.

## Fly rollback

Current `flyctl` does not provide a `releases rollback` subcommand. Inspect the
release images, choose a known-good image, and explicitly deploy that immutable
image. Do not guess an image reference.

```sh
flyctl releases --app paperlens-api --image
flyctl deploy --app paperlens-api --config fly.toml --image <KNOWN_GOOD_IMAGE>
flyctl status --app paperlens-api
curl -fsS https://api.paperlens.micanis.dev/v1/healthz
```

Database migrations require a separately reviewed forward-fix migration. Do
not destructively roll back the production database.

## Forbidden operations

- Do not run deployment commands from the parent `PaperLens` directory.
- Do not deploy unless the Fly app is exactly `paperlens-api`.
- Do not push migrations unless the linked Supabase ref is exactly
  `ewxmrxapokgudhtfmitm`.
- Do not use `supabase db reset`, destructive SQL, or migration repair on the
  linked production database.
- Do not put secret values in commands, logs, Git, `.env.example`, or docs.
- Do not run Wrangler or deploy any Cloudflare Worker or Pages project here.
- Do not start overlapping Fly deployments.
- Do not delete apps, machines, projects, databases, domains, or releases as a
  troubleshooting shortcut.

Frontend deployment instructions live in the frontend repository's
`DEPLOYMENT.md`.

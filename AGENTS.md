# Agent deployment guardrails

Before changing or deploying infrastructure, read `DEPLOYMENT.md` completely.

- This repository owns only Fly app `paperlens-api` and Supabase project
  `paperlens-free` (`ewxmrxapokgudhtfmitm`).
- Always work from this repository root; the parent directory is not a Git repository.
- Validate tests, Git target, Fly target, and Supabase link before mutation.
- Never deploy a frontend or run Wrangler here.
- Never reset or destructively roll back the linked production database.
- Never start a second Fly deployment while another may still be running.
- If any target differs from `DEPLOYMENT.md`, stop instead of improvising.

# Sprint 08: DockerHub Publish Workflow

## Goal

Prepare a small release workflow for building, tagging, and pushing the Docker image to DockerHub so the app can be shared and pulled consistently.

## Scope

- Choose the DockerHub repository name and tag naming convention
- Document the login and push workflow for local development
- Verify the image builds cleanly before publishing
- Confirm the pushed image starts correctly when pulled from DockerHub
- Add a short release note to the docs or README if needed

## Implementation

- A PowerShell helper script now lives at `scripts/Publish-DockerHub.ps1`
- The helper builds the local image, tags it for DockerHub, pushes it, and pulls it back
- The helper can optionally start a smoke-test container after the push completes
- The README documents both the helper and the equivalent manual `docker` commands

## Non-Goals

- No automated CI/CD pipeline in this mini-sprint
- No multi-architecture build matrix unless it becomes a release requirement later
- No changes to the app runtime behavior unless a packaging issue is discovered during publish testing

## Prerequisites

- A DockerHub account and target repository name
- The Docker image must already build locally from the existing `Dockerfile`
- Runtime secrets continue to be injected at launch, not baked into the image

## Testing

- Build the image locally with the chosen release tag
- Log in to DockerHub from the command line
- Push the tagged image to the target repository
- Pull the image back and confirm the container starts successfully
- Verify the app still boots with the expected runtime environment variables

## Acceptance Criteria

- A developer can publish the app image to DockerHub using documented steps
- The published image can be pulled and run without local rebuilds
- The published image behaves the same as the local Docker image for demo and QA use
- The docs clearly state the image tag and publish workflow
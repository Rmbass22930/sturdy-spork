"""Shared Docker resource catalog for all toolchain programs."""
from __future__ import annotations

from datetime import UTC, datetime

from security_gateway.models import DockerResourceRecord

_DOCKER_RESOURCES: tuple[DockerResourceRecord, ...] = (
    DockerResourceRecord(
        resource_key="offload-ga-2026-04-02",
        title="Docker Offload now generally available",
        url="https://www.docker.com/blog/",
        summary="Remote build and runtime capacity for local Docker workflows is now generally available.",
        category="runtime",
        announced_at=datetime(2026, 4, 2, tzinfo=UTC),
        toolchain_relevance="Useful when local workstation constraints make container-heavy toolchain tasks slow or unreliable.",
    ),
    DockerResourceRecord(
        resource_key="sandboxes-2026-03-31",
        title="Docker Sandboxes for agent execution",
        url="https://www.docker.com/blog/",
        summary="Sandboxed, isolated environments for autonomous agents and risky execution paths.",
        category="agent-runtime",
        announced_at=datetime(2026, 3, 31, tzinfo=UTC),
        toolchain_relevance="Relevant for safely running agent-driven toolchain tasks and untrusted automation in isolated containers.",
    ),
    DockerResourceRecord(
        resource_key="hub-mcp-server-2025-07-08",
        title="Docker Hub MCP Server",
        url="https://www.docker.com/blog/introducing-docker-hub-mcp-server/",
        summary="An MCP surface for discovering, inspecting, and managing container images from Docker Hub.",
        category="mcp",
        announced_at=datetime(2025, 7, 8, tzinfo=UTC),
        toolchain_relevance="Directly relevant to Codex/MCP workflows if the toolchain starts consuming Docker image metadata or Hub operations.",
    ),
    DockerResourceRecord(
        resource_key="hardened-images-open-2025-12-17",
        title="Docker Hardened Images free, open, and transparent",
        url="https://www.docker.com/press-release/docker-makes-hardened-images-free-open-and-transparent-for-everyone/",
        summary="Docker expanded access to hardened container images aimed at reducing supply-chain and base-image risk.",
        category="security",
        announced_at=datetime(2025, 12, 17, tzinfo=UTC),
        toolchain_relevance="Relevant for packaging the toolchain into more defensible container bases when container distribution becomes a priority.",
    ),
    DockerResourceRecord(
        resource_key="desktop-4-41-model-runner-2025-04-29",
        title="Docker Desktop 4.41 Model Runner, Compose, and Testcontainers support",
        url="https://www.docker.com/blog/docker-desktop-4-41/",
        summary="Model Runner support on Windows plus Compose and Testcontainers integrations.",
        category="desktop",
        announced_at=datetime(2025, 4, 29, tzinfo=UTC),
        toolchain_relevance="Relevant to local Windows development and test orchestration if the toolchain adopts Docker-backed test or model workflows.",
    ),
)


def list_docker_resources() -> list[DockerResourceRecord]:
    return sorted(_DOCKER_RESOURCES, key=lambda item: item.announced_at, reverse=True)


def get_docker_resource(resource_key: str) -> DockerResourceRecord | None:
    for resource in _DOCKER_RESOURCES:
        if resource.resource_key == resource_key:
            return resource
    return None


__all__ = ["DockerResourceRecord", "get_docker_resource", "list_docker_resources"]

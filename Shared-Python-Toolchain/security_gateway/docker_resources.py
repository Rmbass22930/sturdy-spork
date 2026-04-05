"""Compatibility wrapper for shared Docker resources."""

from toolchain_resources.docker_resources import DockerResourceRecord, get_docker_resource, list_docker_resources

__all__ = ["DockerResourceRecord", "get_docker_resource", "list_docker_resources"]

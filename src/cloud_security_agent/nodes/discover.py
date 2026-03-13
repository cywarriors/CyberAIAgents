"""Discover resources node - enumerates cloud resources across accounts."""

from cloud_security_agent.models.state import CloudPostureState
from cloud_security_agent.models import CloudResource, CloudProvider, ExposureLevel


async def discover_resources(state: CloudPostureState) -> CloudPostureState:
    """Enumerate cloud resources across all configured accounts."""

    resources: list[CloudResource] = []

    if state.resource_inventory:
        # Resources already provided (e.g., from mock data injection)
        resources = state.resource_inventory
    else:
        # In production, would call cloud provider APIs
        for account in state.cloud_accounts:
            # Placeholder for real discovery
            pass

    state.resource_inventory = resources
    state.metrics["total_resources"] = len(resources)
    state.metrics["resources_by_provider"] = {}
    for resource in resources:
        provider = resource.provider.value
        state.metrics["resources_by_provider"][provider] = (
            state.metrics["resources_by_provider"].get(provider, 0) + 1
        )

    return state

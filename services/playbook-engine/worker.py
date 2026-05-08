"""Temporal worker — hosts the ResponseWorkflow and its activities.

Connects to the Temporal namespace (creating it if missing) and registers
all workflows + activities in this package. Best-effort startup: if Temporal
is unreachable, logs and exits the worker coroutine without taking down the
rest of the process.
"""

from __future__ import annotations
import asyncio
from typing import Optional

import structlog
from temporalio.client import Client as TemporalClient
from temporalio.service import RPCError
from temporalio.worker import Worker

from .activities.response_activities import ALL_ACTIVITIES
from .config import PlaybookEngineConfig
from .workflows.response_workflow import ResponseWorkflow

logger = structlog.get_logger(__name__)


async def _ensure_namespace(client: TemporalClient, namespace: str) -> None:
    """Create the namespace via Temporal's gRPC API if it doesn't exist."""
    try:
        await client.workflow_service.describe_namespace(
            client.workflow_service.protos.DescribeNamespaceRequest(namespace=namespace)
        )
        return
    except Exception:
        pass

    try:
        from temporalio.api.workflowservice.v1 import RegisterNamespaceRequest
        from google.protobuf.duration_pb2 import Duration
        retention = Duration()
        retention.seconds = 86400 * 7  # 7 days
        await client.workflow_service.register_namespace(
            RegisterNamespaceRequest(
                namespace=namespace,
                workflow_execution_retention_period=retention,
            )
        )
        logger.info("playbook_worker.namespace_created", namespace=namespace)
    except Exception as e:
        logger.warning("playbook_worker.namespace_setup_failed", error=str(e))


async def build_temporal_client(cfg: PlaybookEngineConfig) -> Optional[TemporalClient]:
    """Connect to the default namespace, ensure the target namespace exists,
    then reconnect into it. Returns None if any step fails."""
    try:
        bootstrap = await TemporalClient.connect(cfg.temporal_host, namespace="default")
    except (RPCError, OSError, RuntimeError) as e:
        logger.warning("playbook_worker.temporal_unreachable", error=str(e))
        return None

    try:
        await _ensure_namespace(bootstrap, cfg.temporal_namespace)
    except Exception as e:
        logger.warning("playbook_worker.namespace_check_failed", error=str(e))

    try:
        return await TemporalClient.connect(cfg.temporal_host, namespace=cfg.temporal_namespace)
    except Exception as e:
        logger.warning("playbook_worker.connect_target_failed", error=str(e))
        return None


async def run_worker(cfg: PlaybookEngineConfig) -> None:
    """Run the worker forever. Returns only when the worker exits."""
    client = await build_temporal_client(cfg)
    if client is None:
        # Don't take down the process — surface keeps serving REST.
        # Re-attempt periodically so the worker comes online once Temporal does.
        while True:
            await asyncio.sleep(15)
            client = await build_temporal_client(cfg)
            if client is not None:
                break

    # Skip the sandbox: our workflow imports from a runtime-registered
    # package alias (`playbook_engine` in run.py) which the sandbox's
    # fresh import context can't resolve. Activities are still isolated.
    from temporalio.worker import UnsandboxedWorkflowRunner

    worker = Worker(
        client,
        task_queue=cfg.temporal_task_queue,
        workflows=[ResponseWorkflow],
        activities=ALL_ACTIVITIES,
        workflow_runner=UnsandboxedWorkflowRunner(),
    )
    logger.info(
        "playbook_worker.started",
        task_queue=cfg.temporal_task_queue,
        namespace=cfg.temporal_namespace,
    )
    await worker.run()

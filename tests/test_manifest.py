from datetime import datetime, timezone

from reconforge.core.models import (
    ExecutionStatus,
    ManifestExecution,
    ScanManifest,
    ScanStatus,
)


def test_manifest_and_execution_contract() -> None:
    now = datetime.now(timezone.utc)
    execution = ManifestExecution(
        phase="discovery",
        artifact="discovery.xml",
        status=ExecutionStatus.COMPLETED,
        started_at=now,
        finished_at=now,
        duration=2.5,
        exit_code=0,
        arguments=("-sn", "-oX", "discovery.xml"),
    )
    manifest = ScanManifest(
        schema_version=1,
        scan_id="scan-1",
        target="192.168.1.0/24",
        workflow="default",
        reconforge_version="0.1.0",
        nmap_version=None,
        created_at=now,
        updated_at=now,
        scan_status=ScanStatus.RUNNING,
        executions=(execution,),
    )

    assert manifest.executions[0].status is ExecutionStatus.COMPLETED
    assert manifest.executions[0].artifact == "discovery.xml"


def test_manifest_can_represent_skipped_and_failed_phases() -> None:
    skipped = ManifestExecution("ports", None, ExecutionStatus.SKIPPED)
    failed = ManifestExecution("os", "os.xml", ExecutionStatus.FAILED, exit_code=1)

    assert skipped.status is ExecutionStatus.SKIPPED
    assert failed.status is ExecutionStatus.FAILED
    assert failed.exit_code == 1

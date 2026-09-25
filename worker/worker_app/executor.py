"""Stand-in for `task_executor` from Delegate Design.md. Reads the
reconstructed workspace, does a bit of visible work (so the log stream has
something to carry), and writes a result file into the output workspace.
"""
import os
import time


def run_stub_task(workspace_dir: str, output_dir: str, log_fn) -> None:
    os.makedirs(output_dir, exist_ok=True)
    entries = sorted(os.listdir(workspace_dir))
    log_fn(f"workspace contains {len(entries)} entries: {entries}")

    for step in range(1, 4):
        log_fn(f"step {step}/3 running...")
        time.sleep(1)

    result_path = os.path.join(output_dir, "result.txt")
    with open(result_path, "w") as f:
        f.write("Delegate POC stub execution completed successfully.\n")
        f.write(f"Processed {len(entries)} workspace entries: {entries}\n")

    log_fn("execution complete")

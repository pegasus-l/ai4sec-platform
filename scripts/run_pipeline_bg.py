import subprocess, sys, os
os.chdir(r"D:\漏洞挖掘\洞察工具\dashboard\ai4sec-platform-vke")
os.environ["PYTHONPATH"] = "src"
result = subprocess.run(
    [sys.executable, "-u", "-m", "ai4sec_platform.cli.run_pipeline",
     "--pipeline", "threats.huawei_full_migration_pipeline",
     "--params", '{"source_records_path": "output/merged_source_records.json"}',
     "--reset"],
    capture_output=True, text=True, timeout=300
)
print(result.stdout[-2000:] if result.stdout else "no stdout")
print("STDERR:", result.stderr[-500:] if result.stderr else "none")
print("DONE")

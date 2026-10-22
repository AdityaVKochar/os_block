# Project documents

This folder contains the written project artifacts and the scripts used to regenerate them.

## Generated documents

- `B-SCAF_Code_Guide_Setup_and_Viva_Preparation.docx` - **companion guide**: pitches, what every code file does and how they work together, setup on any computer, a viva demo, and 139 viva questions with answers (built by `builders/build_viva_guide.py`).
- `Blockchain_System_Call_Audit_Framework_Final_Report.docx` - **final report**: design, implementation and evaluation (recorded attack data, live eBPF capture, attack tests, benchmarks), generated from the measured results in `data/`.
- `Blockchain_System_Call_Audit_Framework.docx` - original project brief.
- `Blockchain_System_Call_Audit_Framework_Formal_Draft.docx` - formal academic draft.
- `B-SCAF_Architecture_Native_Shapes.docx` - diagram-only Word document built from editable native shapes.
- `Blockchain_System_Call_Audit_Framework.txt` - verified source text and bibliography.

## Builders

The `builders/` directory contains the Python scripts that generate the Word documents. Each builder resolves paths relative to this folder, so it works after the repository is moved.

Run a builder from the repository root, for example:

```powershell
python .\project-documents\builders\build_formal_draft.py
```

The final report needs `python-docx` and `Pillow` (`pip install -e .[docs]`). To build it in the project container with the Windows fonts used for the diagram:

```bash
sudo docker run --rm -v "$PWD":/app -v /mnt/c/Windows/Fonts:/fonts:ro -w /app bscaf bash -c "pip install --user -q python-docx pillow matplotlib && python project-documents/builders/build_final_report.py"
```

`data/real-data-summary.json` and `data/live-summary.json` are snapshots of the outputs of `scripts/run_real_data.py` and `scripts/live_capture.py`. Copy fresh outputs from `results/` to update the report.

Supporting diagram files are stored under `assets/`. The final-report builder draws `bscaf-final-architecture.png`, the project diagrams in `assets/diagrams/` (`report_diagrams.py`: evidence structure, witness protocol sequence, live deployment, verification flow) and the result charts in `assets/charts/` (`report_charts.py`, matplotlib; needs `pip install matplotlib`). Temporary rendering output belongs under `render-output/` and is excluded from Git.

The `archive/` directory preserves the earlier binary copies that were previously stored at the repository root. `archive/original-brief/` contains the exact original brief, while `archive/pre-reorganization/` contains the earlier formal draft and native-shape diagram. They are retained only for comparison and recovery; the current generated documents are the files at the top of `project-documents/`.

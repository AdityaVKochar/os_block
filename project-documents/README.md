# Project documents

This folder contains the written project artifacts and the scripts used to regenerate them.

## Generated documents

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

Supporting diagram files are stored under `assets/`. Temporary rendering output belongs under `render-output/` and is excluded from Git.

The `archive/pre-reorganization/` directory preserves the earlier binary copies that were previously stored at the repository root. They are retained only for comparison and recovery; the current generated documents are the files at the top of `project-documents/`.

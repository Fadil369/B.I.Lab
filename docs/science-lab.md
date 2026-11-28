# Antigravity for Science & Biomedical Research Workflows

Reusable `uv`-powered GitHub Actions CI, stdlib biomedical artifact verification (`science_lab_verify.py`), and an Antigravity workspace skill (`bilab-science-lab`) connecting Genomics, Structural Biology, Chemistry, and Scientific Literature / Zenodo RDM provenance across BrainSAIT B.I.Lab and BPR Research Hub repositories.

> **Read this first.** `science_lab_verify.py` validates file structure, domain identifier formats, score bounds, and Zenodo/DataCite deposit rules so malformed research outputs or HTTP-400 metadata traps fail fast in CI. It does **not** validate clinical efficacy, diagnostic accuracy, wet-lab reproducibility, or regulatory clearance, and all repositories handling biomedical data must remain 100% free of real PHI (`healthcare-security-scan.yml@v1`).

**ملخص بالعربية:** منظومة عمل علمية قابلة لإعادة الاستخدام لمختبر BrainSAIT B.I.Lab تربط إضافات Antigravity for Science الأربع (الجينوميات، البيولوجيا البنيوية، الكيمياء المعلوماتية، والأدبيات العلمية وتوثيق Zenodo RDM) عبر بيئة `uv` السريعة وأداة الفحص المعيارية `science_lab_verify.py`. تتحقق المنظومة من سلامة ملفات VCF وFASTA وPDB وSMILES ومعرّفات الأبحاث (DOI وPMID وPMCID وNCT) وقواعد نشر المعرّفات الرقمية في Zenodo، مع ضمان خلو المستودعات من البيانات الصحية الشخصية عبر `healthcare-security-scan.yml@v1`.

---

## Quick start

Add `.github/workflows/science-ci.yml` to any BrainSAIT biomedical or computational research repository (copy directly from [`examples/science-research-pipeline.yml`](../examples/science-research-pipeline.yml)):

```yaml
name: Science Research & Security Pipeline

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  science-ci:
    uses: Fadil369/B.I.Lab/.github/workflows/science-research-ci.yml@v1
    permissions:
      contents: read
    with:
      python-version: "3.12"
      pipeline-command: "uv run python scripts/generate_summary.py"
      test-command: "uv run pytest -q"
      require-citation: true
      fail-on: medium
    secrets:
      tools-token: ${{ secrets.BILAB_READ_TOKEN }}  # only needed while B.I.Lab is private

  healthcare-security:
    uses: Fadil369/B.I.Lab/.github/workflows/healthcare-security-scan.yml@v1
    permissions:
      contents: read
      security-events: write
      actions: read
      packages: read
    with:
      codeql-languages: '["python","actions"]'
      phi-fail-on: medium
    secrets:
      tools-token: ${{ secrets.BILAB_READ_TOKEN }}  # only needed while B.I.Lab is private
```

---

## Four Science Pillars & Artifact Rules

`script/science-lab/science_lab_verify.py` runs on Python 3.10+ using only the Python standard library and keeps stdout strictly under 50 lines while writing complete structured diagnostics to `--output science-lab-report.json`.

| Pillar | Antigravity Science Skills | Verified Artifacts & Rules |
|---|---|---|
| **Genomics** (`genomics`) | `alphagenome-single-variant-analysis`, `alphagenome-variant-impact-score`, `clinvar-database`, `gnomad-database`, `opentargets-database`, `gtex-database` | `.vcf` (`#CHROM\tPOS\tID\tREF\tALT` header, `POS >= 1`, `ACGTN` bases, `rs\d+` IDs) and variant JSON/TSV manifests (`rsid`, HGVS notation, `[0, 1]` bounds on `alphagenome_score`, `clinvar_score`, `gnomad_af`). |
| **Structural Biology** (`structural-biology`) | `alphafold-database-fetch-and-analyze`, `biomolecular-structure-viewer`, `pdb-database`, `uniprot-database`, `foldseek-structural-search`, `reactome-database` | `.fasta` / `.fa` / `.faa` / `.fna` (non-empty sequences, IUPAC amino-acid and nucleotide alphabets), `.pdb` (`ATOM`/`HETATM` numeric X/Y/Z coordinates and `END` record), and AlphaFold metadata JSON (`pLDDT` in `[0, 100]`, UniProt accessions, 4-character PDB IDs). |
| **Chemistry** (`chemistry`) | `rdkit-general`, `cheminformatics-core`, `cheminformatics-ml`, `cheminformatics-cofolding`, `chembl-database`, `pubchem-database` | Molecular JSON/CSV/TSV manifests: non-empty `smiles` with balanced `()`, `[]`, and paired ring-closure digits (`1`–`9`, `%10`–`%99`), `inchikey` (`^[A-Z]{14}-[A-Z]{10}-[A-Z]$`), `CHEMBL\d+`, and positive integer PubChem `CID`. |
| **Scientific Literature & Zenodo RDM** (`literature-zenodo`) | `pubmed-database`, `literature-search-europepmc`, `literature-search-openalex`, `clinical-trials-database`, `openfda-database` | `CITATION.cff`, `zenodo_metadata.json` / `zenodo*.json`, and citation manifests: mandatory `metadata.title`, `metadata.upload_type`, `metadata.creators`, **mandatory `metadata.publisher`**, valid DataCite `related_identifiers` relations (explicitly rejecting `isrelatedto` HTTP 400 errors), plus DOI (`10.\d{4,9}/...`), `PMID`, `PMC\d+`, and `NCT\d{8}` checks. |

---

## Zenodo RDM Provenance Checklist

When publishing BrainSAIT datasets, structures, or research code to Zenodo / InvenioRDM:

1. **Always include `metadata.publisher`** (e.g. `"BrainSAIT"` or `"Zenodo"`). DataCite v4.x DOI registration fails when `publisher` is omitted (`LIT003`).
2. **Never use `"isrelatedto"`** in `metadata.related_identifiers[].relation_type` or `relation`. Zenodo rejects `isrelatedto` with an HTTP `400 Bad Request` (`LIT004`). Use an explicit relation such as `cites`, `iscitedby`, `issupplementto`, `ispartof`, `haspart`, `isderivedfrom`, or `isnewversionof`.
3. **Keep `CITATION.cff` synchronized** with `zenodo_metadata.json` (`cff-version`, `title`, `authors`, and canonical `10.\d{4,9}/...` `doi`).

---

## `science-research-ci.yml` Inputs

| Input | Default | Description |
|---|---|---|
| `python-version` | `"3.12"` | Python version installed and pinned for `uv`. |
| `uv-version` | `""` | Specific `uv` version (defaults to `pyproject.toml` or latest release). |
| `working-directory` | `"."` | Relative subdirectory for `uv` dependency sync, pipeline, and test commands. |
| `enable-cache` | `true` | Cache `uv` wheels and lockfile dependencies in GitHub Actions cache. |
| `sync-command` | `""` | Custom install command; auto-runs `uv sync --frozen` (or `uv sync`) when `pyproject.toml` exists. |
| `pipeline-command` | `""` | Optional `uv run ...` command to generate or verify research outputs. |
| `test-command` | `""` | Optional `uv run ...` test runner command (e.g. `uv run pytest -q`). |
| `verify-artifacts` | `true` | Run `science_lab_verify.py` and upload `science-lab-report.json`. |
| `verify-path` | `"."` | Relative path inside the calling repo passed to `--root`. |
| `pillars` | `"all"` | `all` or comma-separated subset of `genomics,structural-biology,chemistry,literature-zenodo`. |
| `require-citation` | `false` | Fail if neither `CITATION.cff` nor `zenodo*.json` exists under `verify-path`. |
| `fail-on` | `"medium"` | Lowest severity that fails the job (`low`, `medium`, `high`, `none`). |
| `artifact-retention-days` | `90` | Days to retain the uploaded `science-lab-report` JSON artifact. |
| `tools-ref` | `"v1"` | Git ref of `Fadil369/B.I.Lab` used to sparse-checkout `script/science-lab`. |

---

## Local CLI & Workspace Skill Usage

- **Workspace agent skill**: [`.agents/skills/bilab-science-lab/SKILL.md`](../.agents/skills/bilab-science-lab/SKILL.md) is automatically discovered by Antigravity agents working in `B.I.Lab`.
- **Run local verification**:
  ```bash
  python3 script/science-lab/science_lab_verify.py \
    --root . \
    --require-citation \
    --output science-lab-report.json \
    --fail-on medium
  ```
- **Run unit tests & doctests**:
  ```bash
  python3 -m unittest -v script/science-lab/test_science_lab_verify.py
  python3 -m doctest -v script/science-lab/science_lab_verify.py
  ```

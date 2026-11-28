---
name: bilab-science-lab
description: Bridge Antigravity's four Science plugins (Genomics, Structural Biology, Scientific Literature, Chemistry) with BrainSAIT B.I.Lab & BPR Research Hub uv execution, zero-PHI guardrails, Zenodo RDM DOI provenance, and science-research-ci.yml@v1.
---

# BrainSAIT B.I.Lab — Antigravity for Science Workspace Skill

Use this skill whenever designing, running, validating, or publishing biomedical, genomic, structural, cheminformatics, or clinical-literature workflows across `Fadil369/B.I.Lab` and downstream BrainSAIT / BPR Research Hub repositories.

## 1. Installed Antigravity Science Plugin Matrix

Route domain tasks to the four installed Antigravity Science plugins and their specialized skills, then verify every generated artifact with `script/science-lab/science_lab_verify.py`:

### Genomics
- `alphagenome-single-variant-analysis` — deep regulatory & splicing dissection of single variants.
- `alphagenome-variant-impact-score` — batch regulatory variant impact scoring in `[0.0, 1.0]`.
- `clinvar-database` — clinical pathogenicity assertions, review star status, and HGVS mappings.
- `gnomad-database` — population allele frequencies (`gnomad_af`) and constraint metrics.
- `opentargets-database` — variant-to-gene-to-disease evidence scoring and target prioritization.
- `gtex-database` — tissue-specific eQTL / sQTL gene expression effects.

### Structural Biology
- `alphafold-database-fetch-and-analyze` — fetch AlphaFold models, PAE matrices, and per-residue `pLDDT` (`[0, 100]`).
- `biomolecular-structure-viewer` — interactive 3D inspection of `.pdb` / `.cif` complexes and binding pockets.
- `pdb-database` — experimental macromolecular structures (`ATOM` / `HETATM` records, resolution, ligands).
- `uniprot-database` — canonical protein sequences (`.fasta`), functional domains, and UniProt accessions.
- `foldseek-structural-search` — rapid 3Di structural homology search across PDB and AlphaFoldDB.
- `reactome-database` — curated biological pathways and molecular reaction networks.

### Scientific Literature
- `pubmed-database` — MEDLINE / PubMed biomedical literature search and `PMID` metadata retrieval.
- `literature-search-europepmc` — full-text open-access biomedical articles, preprints, and `PMC\d+` IDs.
- `literature-search-openalex` — citation graphs, author ORCID disambiguation, and institutional bibliometrics.
- `clinical-trials-database` — ClinicalTrials.gov study registries, endpoints, and `NCT\d{8}` identifiers.
- `openfda-database` — FDA drug labeling, FAERS adverse event reports, and recall records.

### Chemistry
- `rdkit-general` — SMILES canonicalization, InChIKey generation, substructure queries, and 2D/3D descriptors.
- `cheminformatics-core` — molecular standardization, salt stripping, Lipinski/QED/ADMET filtering, and scaffolds.
- `cheminformatics-ml` — molecular fingerprints, GNN/QSAR featurization, and activity/toxicity modeling.
- `cheminformatics-cofolding` — protein-ligand docking and biomolecular co-folding input/pose preparation.
- `chembl-database` — bioactivity assays (`IC50`, `Ki`, `Kd`) and `CHEMBL\d+` compound records.
- `pubchem-database` — chemical identifiers, safety/GHS properties, and integer PubChem `CID` lookups.

---

## 2. Execution & Output Discipline (`uv run` + File-Based JSON)

1. **Always execute Python via `uv run`**:
   - Project repositories: commit `pyproject.toml` + `uv.lock` and execute `uv sync --frozen && uv run pytest`.
   - Standalone analysis scripts: declare PEP 723 inline script metadata (`# /// script` with `requires-python = ">=3.12"` and pinned `dependencies`) and invoke `uv run scripts/analyze.py`.
2. **File-based JSON outputs & `<50` line stdout cap**:
   - Write full tabular or structured results to deterministic JSON/CSV/TSV/VCF/FASTA/PDB artifacts on disk (e.g. `results/variants.json`, `results/molecules.csv`, `science-lab-report.json`).
   - Keep console stdout strictly under **50 lines** (summary counts + top findings + output file path) so agent context windows stay clean.

---

## 3. Artifact Verification CLI (`science_lab_verify.py`)

Run the zero-dependency stdlib verifier locally before opening PRs or minting Zenodo DOIs:

```bash
uv run --no-project python script/science-lab/science_lab_verify.py \
  --root . \
  --require-citation \
  --pillars all \
  --fail-on medium \
  --output science-lab-report.json
```

### CLI Flags
- `--root <path>`: Directory or single artifact file to validate (default `.`).
- `--require-citation` / `--no-require-citation`: Require `CITATION.cff` or `zenodo*.json` in `--root` (`LIT000`).
- `--pillars <list>`: `all` (default) or comma-separated subset of `genomics,structural-biology,chemistry,literature-zenodo`.
- `--output <file>`: Write structured JSON report (`summary`, `artifacts_checked`, `findings`, `passed`).
- `--markdown-summary <file>`: Append Markdown summary table (used with `$GITHUB_STEP_SUMMARY` in CI).
- `--fail-on {low,medium,high,none}`: Minimum finding severity that returns exit code `1` (default `medium`).

### Rule Coverage Summary
- **Genomics (`GEN001`–`GEN007`)**: `.vcf` `#CHROM\tPOS\tID\tREF\tALT` header, `POS >= 1`, `ACGTN` alleles, `rs\d+` dbSNP IDs, HGVS expressions, and `[0, 1]` bounds on `alphagenome_score`, `clinvar_score`, and `gnomad_af`.
- **Structural Biology (`STR001`–`STR009`)**: `.fasta`/`.fa` non-empty records and IUPAC residue/base alphabets, `.pdb` `ATOM`/`HETATM` numeric X/Y/Z coordinates + terminal `END`, AlphaFold `pLDDT` in `[0, 100]`, UniProt accessions, and 4-char PDB IDs.
- **Chemistry (`CHM001`–`CHM004`)**: Non-empty SMILES with balanced `()`, `[]`, and closed ring digits (`1`–`9`, `%10`–`%99`), IUPAC InChIKey `^[A-Z]{14}-[A-Z]{10}-[A-Z]$`, `CHEMBL\d+`, and positive integer PubChem CIDs.
- **Scientific Literature & Zenodo RDM (`LIT000`–`LIT008`)**: `CITATION.cff`, `zenodo_metadata.json` / `zenodo*.json`, DOI `10.\d{4,9}/...`, numeric `PMID`, `PMC\d+`, and `NCT\d{8}` clinical trial identifiers.

---

## 4. BrainSAIT Zenodo RDM DOI Publishing Rules

Every BrainSAIT dataset, model bundle, or research software release prepared for Zenodo / InvenioRDM MUST satisfy:

1. **Required core fields**: `metadata.title`, `metadata.upload_type` (`dataset`, `software`, `publication`, etc.), and non-empty `metadata.creators` (`[{"name": "Family, Given", "affiliation": "BrainSAIT"}]`).
2. **Mandatory `metadata.publisher`**: Always set `"publisher": "BrainSAIT"` (or `"Zenodo"`) inside `metadata`. Omitting `publisher` blocks DataCite v4.x DOI registration (`LIT003`).
3. **Valid `related_identifiers` relation vocabulary**: NEVER use `"isrelatedto"` in `related_identifiers[].relation` or `relation_type` — Zenodo's REST API rejects `isrelatedto` with **HTTP 400** (`LIT004`). Always choose a specific DataCite relation such as `"cites"`, `"iscitedby"`, `"issupplementto"`, `"ispartof"`, `"haspart"`, `"isderivedfrom"`, or `"isnewversionof"`.

---

## 5. Zero-PHI Synthetic Data Guardrail (`phi_scan.py`)

Research repositories must **never** commit real patient identifiers, clinical DICOM/HL7 payloads, Saudi National IDs / Iqamas, IBANs, or MRNs:

```bash
python3 script/phi-scan/phi_scan.py --root . --fail-on medium
```

Always use public reference accessions (e.g. `rs429358`, `P04637`, `1TUP`, `CHEMBL25`, `NCT04280705`) or clearly synthetic fixtures, and pair `science-research-ci.yml@v1` with `healthcare-security-scan.yml@v1` in CI.

---

## 6. Reusable CI Integration (`science-research-ci.yml@v1`)

Call `Fadil369/B.I.Lab/.github/workflows/science-research-ci.yml@v1` alongside `healthcare-security-scan.yml@v1` in any BrainSAIT research repo (see [`examples/science-research-pipeline.yml`](../../../examples/science-research-pipeline.yml) and [`docs/science-lab.md`](../../../docs/science-lab.md)):

```yaml
jobs:
  science:
    uses: Fadil369/B.I.Lab/.github/workflows/science-research-ci.yml@v1
    with:
      python-version: "3.12"
      pipeline-command: "uv run python scripts/run_study.py"
      test-command: "uv run pytest -q"
      require-citation: true
      fail-on: medium
```

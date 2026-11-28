#!/usr/bin/env python3
"""Unit tests for script/science-lab/science_lab_verify.py."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import science_lab_verify as slv  # noqa: E402


VALID_PDB = (
    "HEADER    TUMOR SUPPRESSOR                        01-JAN-26   1TUP\n"
    "ATOM      1  N   MET A   1      11.104  13.207   9.542  1.00 92.40           N\n"
    "ATOM      2  CA  MET A   1      12.560  13.207   9.542  1.00 94.10           C\n"
    "HETATM    3  O   HOH A 101      15.000  14.000  10.000  1.00 80.00           O\n"
    "END\n"
)


class ScienceLabVerifyTests(unittest.TestCase):
    def _run_cli(self, args: list[str]) -> tuple[int, str, str]:
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = slv.main(args)
        return code, out.getvalue(), err.getvalue()

    def test_clean_four_pillar_bundle_passes_and_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 1. Genomics
            (root / "cohort_synthetic.vcf").write_text(
                "##fileformat=VCFv4.2\n"
                "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n"
                "chr19\t44908684\trs429358\tT\tC\t99\tPASS\tAF=0.14\n"
                "chr17\t43045705\t.\tG\tA,<DEL>\t80\tPASS\tAF=0.01\n",
                encoding="utf-8",
            )
            (root / "alphagenome_variants.json").write_text(
                json.dumps(
                    {
                        "variants": [
                            {
                                "rsid": "rs429358",
                                "hgvs": "NM_000041.4:c.388T>C",
                                "alphagenome_score": 0.87,
                                "clinvar_score": 0.91,
                                "gnomad_af": 0.142,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            # 2. Structural Biology
            (root / "tp53_domain.fasta").write_text(
                ">sp|P04637|P53_HUMAN Cellular tumor antigen p53\n"
                "MEEPQSDPSVEPPLSQETFSDLWKLLPENNVLSPLPSQAMDDLMLSPDDIEQWFTEDPGP\n",
                encoding="utf-8",
            )
            (root / "tp53_model.pdb").write_text(VALID_PDB, encoding="utf-8")
            (root / "alphafold_summary.json").write_text(
                json.dumps(
                    {
                        "uniprot_accession": "P04637",
                        "pdb_id": "1TUP",
                        "mean_plddt": 93.4,
                        "per_residue_plddt": [91.2, 94.8, 94.2],
                    }
                ),
                encoding="utf-8",
            )

            # 3. Chemistry
            (root / "molecules.csv").write_text(
                "compound_id,smiles,inchikey,chembl_id,pubchem_cid\n"
                "aspirin,CC(=O)Oc1ccccc1C(=O)O,BSYNRYMUTXBXSQ-UHFFFAOYSA-N,CHEMBL25,2244\n"
                "bicyclic,C%10CCCCC%10,,CHEMBL545,241\n",
                encoding="utf-8",
            )

            # 4. Scientific Literature & Zenodo RDM Provenance
            (root / "CITATION.cff").write_text(
                "cff-version: 1.2.0\n"
                "title: BrainSAIT Synthetic Genomics Benchmark\n"
                "doi: 10.5281/zenodo.1234567\n"
                "authors:\n"
                "  - family-names: Al-Fadil\n"
                "    given-names: Mohamed\n",
                encoding="utf-8",
            )
            (root / "zenodo_metadata.json").write_text(
                json.dumps(
                    {
                        "metadata": {
                            "title": "BrainSAIT Synthetic Genomics Benchmark",
                            "upload_type": "dataset",
                            "publisher": "BrainSAIT Research Hub",
                            "creators": [{"name": "Al-Fadil, Mohamed", "affiliation": "BrainSAIT"}],
                            "related_identifiers": [
                                {
                                    "identifier": "10.1038/s41586-021-03819-2",
                                    "relation_type": "cites",
                                    "scheme": "doi",
                                },
                                {
                                    "identifier": "PMC8371605",
                                    "relation": "isSupplementTo",
                                    "scheme": "pmcid",
                                },
                            ],
                        }
                    }
                ),
                encoding="utf-8",
            )
            (root / "literature_references.json").write_text(
                json.dumps(
                    [
                        {
                            "doi": "https://doi.org/10.1038/s41586-021-03819-2",
                            "pmid": "34265844",
                            "pmcid": "PMC8371605",
                            "nct_id": "NCT04280705",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            report_file = root / "out" / "science-lab-report.json"
            md_file = root / "out" / "summary.md"
            code, stdout, stderr = self._run_cli(
                [
                    "--root",
                    str(root),
                    "--require-citation",
                    "--output",
                    str(report_file),
                    "--markdown-summary",
                    str(md_file),
                    "--fail-on",
                    "low",
                ]
            )
            self.assertEqual(code, 0, msg=f"stdout={stdout}\nstderr={stderr}")
            self.assertEqual(stderr, "")
            self.assertLess(len(stdout.splitlines()), 50)
            self.assertTrue(report_file.is_file())
            self.assertTrue(md_file.is_file())

            report = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertTrue(report["passed"])
            self.assertEqual(report["summary"]["total_findings"], 0)
            self.assertEqual(report["summary"]["total_files_checked"], 9)
            self.assertIn("Antigravity Science Lab Verification (`PASS`)", md_file.read_text())

    def test_genomics_invalid_vcf_and_variant_scores(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad.vcf").write_text(
                "CHROM\tPOS\tID\tREF\tALT\n"
                "chr1\t0\trsBAD\tTX\tZ\n",
                encoding="utf-8",
            )
            (root / "variants.tsv").write_text(
                "rsid\thgvs\talphagenome_score\tclinvar_score\n"
                "bad_rs\tnot_hgvs\t1.45\t-0.2\n",
                encoding="utf-8",
            )
            report = slv.scan_repository(root)
            rule_ids = {f["rule_id"] for f in report["findings"]}
            self.assertIn("GEN001", rule_ids)  # bad VCF header
            self.assertIn("GEN003", rule_ids)  # POS <= 0
            self.assertIn("GEN004", rule_ids)  # invalid bases TX / Z
            self.assertIn("GEN005", rule_ids)  # malformed rsID
            self.assertIn("GEN006", rule_ids)  # malformed HGVS
            self.assertIn("GEN007", rule_ids)  # score outside [0, 1]

    def test_structural_biology_fasta_pdb_and_alphafold_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad.fasta").write_text(
                ">empty_record\n"
                ">bad_chars\n"
                "ACDEF12345$$$\n",
                encoding="utf-8",
            )
            (root / "bad.pdb").write_text(
                "HEADER    BROKEN PDB\n"
                "ATOM      1  N   MET A   1      not_num  13.207   9.542\n",
                encoding="utf-8",
            )
            (root / "alphafold_meta.json").write_text(
                json.dumps(
                    {
                        "uniprot_id": "INVALID_UNIPROT",
                        "pdb_id": "ZZZZZ",
                        "plddt": 108.5,
                    }
                ),
                encoding="utf-8",
            )
            report = slv.scan_repository(root)
            rule_ids = {f["rule_id"] for f in report["findings"]}
            self.assertIn("STR002", rule_ids)  # empty FASTA sequence
            self.assertIn("STR003", rule_ids)  # invalid IUPAC chars
            self.assertIn("STR005", rule_ids)  # non-numeric PDB coords
            self.assertIn("STR006", rule_ids)  # missing PDB END
            self.assertIn("STR007", rule_ids)  # pLDDT > 100
            self.assertIn("STR008", rule_ids)  # invalid UniProt ID
            self.assertIn("STR009", rule_ids)  # invalid PDB ID

    def test_chemistry_smiles_inchikey_chembl_and_cid_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "molecules.json").write_text(
                json.dumps(
                    {
                        "molecules": [
                            {
                                "smiles": "CC(=O)O)",  # unbalanced paren
                                "inchikey": "SHORT-KEY-N",
                                "chembl_id": "12345",
                                "pubchem_cid": -9,
                            },
                            {
                                "smiles": "c1ccccc",  # unclosed ring digit 1
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            report = slv.scan_repository(root)
            rule_ids = [f["rule_id"] for f in report["findings"]]
            self.assertEqual(rule_ids.count("CHM001"), 2)
            self.assertIn("CHM002", rule_ids)
            self.assertIn("CHM003", rule_ids)
            self.assertIn("CHM004", rule_ids)

    def test_zenodo_flags_missing_publisher_and_invalid_isrelatedto(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "zenodo_metadata.json").write_text(
                json.dumps(
                    {
                        "metadata": {
                            "title": "BrainSAIT Study",
                            "upload_type": "software",
                            "creators": [{"name": "Al-Fadil, Mohamed"}],
                            # publisher intentionally omitted -> LIT003
                            "related_identifiers": [
                                {
                                    "identifier": "10.5281/zenodo.999999",
                                    "relation_type": "isrelatedto",  # Zenodo 400 trap -> LIT004
                                    "scheme": "doi",
                                }
                            ],
                        }
                    }
                ),
                encoding="utf-8",
            )
            (root / "trials.json").write_text(
                json.dumps(
                    [
                        {
                            "doi": "bad-doi",
                            "pmid": "ABC",
                            "pmcid": "12345",
                            "nct_id": "NCT123",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            report = slv.scan_repository(root)
            findings = report["findings"]
            rule_ids = {f["rule_id"] for f in findings}
            self.assertIn("LIT003", rule_ids)  # missing mandatory publisher
            self.assertIn("LIT004", rule_ids)  # invalid isrelatedto
            self.assertIn("LIT005", rule_ids)  # bad DOI
            self.assertIn("LIT006", rule_ids)  # bad PMID
            self.assertIn("LIT007", rule_ids)  # bad PMCID
            self.assertIn("LIT008", rule_ids)  # bad NCT ID
            rel_msgs = " ".join(f["message"] for f in findings if f["rule_id"] == "LIT004")
            self.assertIn("isrelatedto", rel_msgs)
            self.assertIn("HTTP 400", rel_msgs)

    def test_require_citation_and_stdout_line_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Generate 40 broken molecule rows to verify stdout stays < 50 lines.
            rows = ["smiles,inchikey"] + [f"c1cccc,BADKEY{i}" for i in range(40)]
            (root / "compounds.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")

            code, stdout, _ = self._run_cli(
                ["--root", str(root), "--require-citation", "--fail-on", "medium"]
            )
            self.assertEqual(code, 1)
            self.assertLess(
                len(stdout.splitlines()),
                50,
                msg=f"Expected < 50 stdout lines, got {len(stdout.splitlines())}",
            )
            self.assertIn("LIT000", stdout)
            self.assertIn("omitted from stdout", stdout)


if __name__ == "__main__":
    unittest.main()

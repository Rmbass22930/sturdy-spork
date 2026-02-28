# Comparison to Known Projects (as of February 27, 2026)

This compares your `experiment-template.md` against well-known projects in the same broad area (cold fusion/LENR or metal-lattice-assisted fusion).

## Quick verdict

Your template is closer to the strongest modern practice (Google-style reproducibility framing) than to early cold-fusion-era workflows.

## Side-by-side comparison

| Project | Timeframe | What was tested | Strengths | Main limitation/outcome | How your template compares |
|---|---|---|---|---|---|
| Fleischmann-Pons initial electrolysis claim | 1989 | Electrochemical Pd-D system, claimed fusion-related excess heat | High-impact hypothesis; triggered global replication attempts | Rapid replication failures and major controversy; evidence standard/controls criticized by broader community | Your template is much stronger on pre-registration, controls, uncertainty accounting, and blinding |
| DOE LENR review (field-level assessment) | 2004 | Review of submitted LENR evidence across groups | External expert review; emphasized documentation quality and nuclear signature rigor | No broad consensus that evidence proved cold fusion; encouraged better-designed proposals | Your template operationalizes that recommendation with explicit pass/fail gates and replication requirements |
| Google-funded multi-lab cold fusion reassessment | 2015-2019 (published 2019) | Multiple hypotheses and experiments under modern instrumentation | Multi-institution effort; explicit rigor focus; transparent negative result reporting | Reported no evidence of cold fusion in tested conditions | Your template is closely aligned; add explicit multi-lab handoff packet to match this level |
| NASA/PRC lattice-confinement fusion work | 2020 onward | Nuclear reactions in deuterated metal lattices under beam/photon-driven conditions | Peer-reviewed neutron diagnostics; clearer nuclear observables than heat-only claims | Not a demonstrated net-energy tabletop power source; different regime than classic cold fusion claims | Your template is compatible if you include stricter detector calibration traceability and background subtraction plans |
| Electrochemical loading + beam-target fusion-rate study (Nature) | 2025 | Whether electrochemical loading changes measured D-D fusion rate in Pd target | Published in Nature; quantifies effect size with stated uncertainty | Reported fusion-rate enhancement, not net-energy break-even | Your template fits well; add requirement to separate "rate enhancement" from "energy gain" claims in decision gates |

## Gaps to close in your current template

1. Add a dedicated "Claim Class" line: `artifact`, `rate enhancement`, `excess heat`, or `net energy gain`.
2. Add a mandatory independent background run schedule (before/after every active run block).
3. Add a replication handoff bundle checklist (raw data, calibration files, BOM/version hashes, analysis scripts).
4. Add explicit minimum evidence for nuclear signatures when any nuclear claim is made.
5. Add a hard rule that no press/public claim is made before independent replication.

## Suggested one-line upgrade to template

Insert in Section 1:

`- Claim class: Artifact check / Rate enhancement / Excess heat / Net energy gain (select one)`

## Sources

- Fleischmann, Pons (1989), Journal of Electroanalytical Chemistry, DOI: 10.1016/0022-0728(89)80006-3  
  https://doi.org/10.1016/0022-0728(89)80006-3
- U.S. DOE review context (reported by Nature, Dec 2, 2004):  
  https://www.nature.com/articles/news041129-11
- Berlinguette et al., "Revisiting the cold case of cold fusion" (Nature, May 27, 2019), DOI: 10.1038/s41586-019-1256-6  
  https://www.nature.com/articles/s41586-019-1256-6
- Steinetz et al., "Novel nuclear reactions observed in bremsstrahlung-irradiated deuterated metals" (Phys. Rev. C, Apr 20, 2020), DOI: 10.1103/PhysRevC.101.044610  
  https://doi.org/10.1103/PhysRevC.101.044610
- NASA Lattice Confinement Fusion overview page (updated 2025):  
  https://www.nasa.gov/glenn/glenn-expertise-space-exploration/lattice-confinement-fusion/
- Chen et al., "Electrochemical loading enhances deuterium fusion rates in a metal target" (Nature, Aug 2025), DOI: 10.1038/s41586-025-09042-7 (PubMed record)  
  https://pubmed.ncbi.nlm.nih.gov/40836130/

# Third-party resources

The source repository does not vendor corpora, model weights, Debian archives,
or compiled FSTs. Bootstrap scripts acquire those artifacts directly on the
supported build host; this table records the upstream notices relevant to the pinned runtime.
It is a provenance summary, not legal advice.

| Component | Pinned/current source | License and authoritative notice | Use |
|---|---|---|---|
| `apertium-kaz` | [commit `95c6dd0d8536ee69a7058634b03a3e82100b6b6e`](https://github.com/apertium/apertium-kaz/tree/95c6dd0d8536ee69a7058634b03a3e82100b6b6e) | [GPL-3.0](https://github.com/apertium/apertium-kaz/blob/95c6dd0d8536ee69a7058634b03a3e82100b6b6e/COPYING) | Kazakh lexicon, morphotactics, two-level rules, Constraint Grammar |
| HFST command-line tools | Ubuntu 24.04 `hfst=3.16.0-5build4` | Main code GPL-3.0-or-later; the source package also contains GPL-2.0-or-later, LGPL, Apache-2.0, and custom-notice files. See the [exact Ubuntu package copyright](https://changelogs.ubuntu.com/changelogs/pool/universe/h/hfst/hfst_3.16.0-5build4/copyright) and [HFST repository](https://github.com/hfst/hfst). | FST compilation and optimized lookup |
| `libhfst` | Ubuntu 24.04 `libhfst55=3.16.0-5build4` | `libhfst/*` is LGPL-3.0-or-later in the Ubuntu notice; linked/bundled back ends have their own terms. HFST specifically warns redistributors to inspect the selected back-end licenses. See the [Ubuntu copyright](https://changelogs.ubuntu.com/changelogs/pool/universe/h/hfst/hfst_3.16.0-5build4/copyright) and [HFST licensing warning](https://github.com/hfst/hfst#dependencies). | Runtime library used by HFST tools |
| foma library | Ubuntu 24.04 `libfoma0t64=1:0.10.0+s311-1.2build2` | [Apache-2.0](https://changelogs.ubuntu.com/changelogs/pool/universe/f/foma/foma_0.10.0+s311-1.2build2/copyright) | HFST foma back end |
| OpenFst library | Ubuntu 24.04 `libfst22=1.7.9-5build1` | [Apache-2.0](https://www.openfst.org/twiki/bin/view/FST/DistCopying); see also the [Ubuntu package copyright](https://changelogs.ubuntu.com/changelogs/pool/universe/o/openfst/openfst_1.7.9-5build1/copyright). | HFST weighted-FST back end |
| CG-3 executable and library | Ubuntu 24.04 `cg3=1.4.6-1build2`, `libcg3-1=1.4.6-1build2` | Main code GPL-3.0-or-later. The packaged source also contains GPL-2.0-or-later Emacs files, Expat and ICU components, and a public-domain file; see the [exact Ubuntu package copyright](https://changelogs.ubuntu.com/changelogs/pool/universe/c/cg3/cg3_1.4.6-1build2/copyright) and [upstream repository](https://github.com/GrammarSoft/cg3). | Constraint Grammar compilation/runtime |
| Stanza 1.14.0 code | [PyPI/GitHub release](https://github.com/stanfordnlp/stanza) | [Apache-2.0](https://github.com/stanfordnlp/stanza/blob/main/LICENSE) | Optional contextual pipeline code |
| Stanza Kazakh KTB model files | Exact files/sizes/SHA-256 values in `scripts/neural_assets.lock.json`; [Stanza 1.14 resource index](https://github.com/stanfordnlp/stanza-resources/blob/main/resources_1.14.0.json) | Licensing requires caution. Stanford's [official language-pack statement](https://stanfordnlp.github.io/stanza/performance.html) says model licensing is unclear and offers the packs under [ODC-By-1.0](https://opendatacommons.org/licenses/by/1-0/) only to the extent Stanford owns the relevant rights; it directs users to the underlying data terms. The [Hugging Face model card](https://huggingface.co/stanfordnlp/stanza-kk) labels its repository Apache-2.0, but that adjacent repository metadata does not by itself resolve the exact `stanza.download()` bundle, which contains no model-specific license file. KTB is [CC BY-SA 4.0](https://github.com/UniversalDependencies/UD_Kazakh-KTB/blob/r2.18/LICENSE.txt), and the Stanza code's Apache license must not be assumed to license the weights. QazMorph downloads but does not redistribute them; verify all applicable terms before redistribution. | Optional candidate reranking |
| UD Kazakh-KTB 2.18 | tag `r2.18`, commit `c850e5334a50befaf35a0907df766c4de89f68a1` | [CC BY-SA 4.0](https://github.com/UniversalDependencies/UD_Kazakh-KTB/blob/r2.18/LICENSE.txt) | Full-corpus FST/CG diagnostic and tiny Stanza-unseen audit; not a canonical held-out split or independent gold |
| Multidomain Kazakh Dataset | [`kz-transformers/multidomain-kazakh-dataset`](https://huggingface.co/datasets/kz-transformers/multidomain-kazakh-dataset), pinned sampler revision `7a1fcdf9830b1c34b44b3038aafb672447f41890` | The [dataset card](https://huggingface.co/datasets/kz-transformers/multidomain-kazakh-dataset/blob/main/README.md) states Apache-2.0; its many underlying web sources still require separate provenance review before redistribution. | Raw coverage/OOV/performance data only, never morphology gold |

The checked-in toolchain lock fixes every Debian archive's filename, package,
version, architecture, byte size, and SHA-256. Bootstrap rejects a changed or
unexpected archive before extraction, then records every extracted toolchain
file and required executable. Resource manifests also record source/build-script
inputs, compiled resources, and the formal generator-subset verification gate.
They use the locked source commit timestamp rather than wall-clock build time,
so two byte-identical builds have the same manifest and content address. The
runtime verifies the resource hashes before loading.

The optional neural lock verifies the `uv` executable, exact model bytes,
project-source bytes, the Python/Torch/CUDA values declared by the lock, and
exact versions for the selected venv and host packages named there. The
environment manifest additionally records every visible Python distribution.
This is not a byte-locked dependency closure: the venv uses system site
packages, unselected visible packages are recorded rather than locked, and the
downloaded wheel bytes are not pinned. Models and venvs live persistently under
the checkout's `.qazmorph/` directory; installer caches are ephemeral. Model
weights and dependency wheels are not redistributed by this repository.

MyStem is not a dependency and is not redistributed. Its public documentation
and published 2003 paper inform interface/algorithm comparison. Yandex's
official Linux 3.1 binary was downloaded and executed only as a black box for
the fixed serializer-envelope probes recorded in `docs/MYSTEM_COMPATIBILITY.md`;
it was not decompiled, disassembled, modified, or incorporated.

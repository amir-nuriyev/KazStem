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

## macOS arm64 detached runtime (0.2.3)

The macOS arm64 binary asset uses the unchanged f03e `apertium-kaz` resource
bundle above, but does not claim that f03e was built by the macOS tools. The
resource manifest continues to bind its original Ubuntu r4 build toolchain.
The active runtime is a separate, checked-in identity generated from
`scripts/platform_runtime_sources.lock.json`.

The only native input archives are the following Apertium Project.JJ artifacts:

| Archive | Bytes | SHA-256 |
|---|---:|---|
| [`hfst-3.17.2+g4028~e16268eb.arm64.tar.bz2`](https://apertium.projectjj.com/osx/nightly/arm64/hfst-3.17.2+g4028~e16268eb.arm64.tar.bz2) | 17,328,650 | `c5396b147315eae17a3d3b193b8545f90354ba90324310b31593b4f6ccef5ab1` |
| [`cg3-1.6.8+g2347~8d5fa4dd.arm64.tar.bz2`](https://apertium.projectjj.com/osx/nightly/arm64/cg3-1.6.8+g2347~8d5fa4dd.arm64.tar.bz2) | 14,551,351 | `78b4b47596dfa06222e225e5fc45cae385643c9bec33260d3ad3a8b92ae7017c` |

HFST's archive is not independently closed: its foma library loads
`@rpath/libz.1.dylib`, which is supplied by the pinned CG-3 archive. KazStem
therefore verifies and treats the minimal merged dependency set as one runtime
bundle. It includes three command entry points, their complete non-system Mach-O
closure, and no compilation tools or neural-model weights.

| Redistributed component | Exact source/version | License / notice |
|---|---|---|
| HFST tools and `libhfst` | [`e16268ebb6af72590d82da3867dcbb5f48e3f11c`](https://github.com/hfst/hfst/tree/e16268ebb6af72590d82da3867dcbb5f48e3f11c) | Tools are GPL-3.0-or-later; `libhfst` is LGPL-3.0-or-later and its selected back ends retain their own terms. See the source `COPYING` files. |
| CG-3 / `libcg3` | [`8d5fa4ddc396bcb9cbee76baafa0aa025f182dbc`](https://github.com/GrammarSoft/cg3/tree/8d5fa4ddc396bcb9cbee76baafa0aa025f182dbc) | GPL-3.0-or-later; see [`COPYING`](https://github.com/GrammarSoft/cg3/blob/8d5fa4ddc396bcb9cbee76baafa0aa025f182dbc/COPYING). |
| foma | [`5a800702f8e49ef994fc4058c442a365c22ceeca`](https://github.com/TinoDidriksen/foma/tree/5a800702f8e49ef994fc4058c442a365c22ceeca) | Apache-2.0. |
| OpenFst | [`04a59153ece50a28829ef8e68f820ffda93805c6`](https://github.com/TinoDidriksen/openfst/tree/04a59153ece50a28829ef8e68f820ffda93805c6) | Apache-2.0. |
| ICU | 78.3 | [Unicode License v3](https://github.com/unicode-org/icu/blob/release-78.3/LICENSE). |
| GNU Readline | 8.3 | GPL-3.0-or-later; [source archive](https://ftp.gnu.org/gnu/readline/readline-8.3.tar.gz). |
| ncurses | 6.6.20251230 | [ncurses permissive notice](https://invisible-island.net/archives/ncurses/current/ncurses-6.6-20251230.tgz). |
| SQLite | 3.51.3 | [Public-domain dedication/blessing](https://www.sqlite.org/copyright.html). |
| zlib | 1.3.2 | [zlib license](https://zlib.net/zlib_license.html). |

The Project.JJ macOS packaging process is public in
[`apertium/packaging`](https://github.com/apertium/packaging/tree/444f3d53dd978fe65c4d227846f3d649de31ee46).
The release bundle retains the applicable license texts and exact corresponding
source archives described by the source lock. Apple `libSystem` and `libc++`
are host System Libraries and are not copied into the archive. The native
executables carry upstream ad-hoc/linker signatures only; they have no Team ID
and the CLI archive is not Developer-ID signed or notarized.

## Windows x86-64 detached runtime (0.2.3)

The Windows asset uses the same unchanged f03e resource bundle and a separate
manifest-bound Project.JJ runtime. The exact original inputs are:

| Archive | Bytes | SHA-256 |
|---|---:|---|
| [`hfst-3.17.2+g4028~e16268eb.x86_64.zip`](https://apertium.projectjj.com/windows/nightly/x86_64/hfst-3.17.2+g4028~e16268eb.x86_64.zip) | 21,970,467 | `a28df94fd80d3d6fe2401f5d71c31b96fad7c01c973e2b26c539ce1016e4542e` |
| [`cg3-1.6.8+g2347~8d5fa4dd.x86_64.zip`](https://apertium.projectjj.com/windows/nightly/x86_64/cg3-1.6.8+g2347~8d5fa4dd.x86_64.zip) | 16,333,576 | `6df5801f2dfec584822b68ade4f3d25618cdfdad6cb0a1fb3704364c9a10c45b` |

The candidate pipeline selects the three required executables and derives the
smallest non-system DLL set recursively reached by their ordinary or
delay-load PE imports. The reviewed Windows runner bound three executables and
16 DLLs, proved every retained PE is AMD64, and rejected every dependency
outside the checked policy. Duplicate ICU/GCC runtime DLLs in the two inputs
must be byte-identical before they are coalesced. Bound components include
HFST/libhfst, CG-3/libcg3, foma, OpenFst, ICU 74.2, Readline
8.2, GNU Termcap 1.3.1, SQLite 3.46.0, zlib 1.3.1, dlfcn-win32 1.4.1, GCC
13.3 runtime libraries, and MinGW-w64 12.0.0 runtime components under the
licenses recorded in
`scripts/platform_runtime_sources.windows-x86_64.lock.json`. That lock also
binds every corresponding-source archive and the MXE/Apertium build recipes.

The checked dependency policy permits `advapi32.dll`, `kernel32.dll`,
`msvcrt.dll`, and `user32.dll` as the Windows system boundary; the native audit
must record the subset actually observed. These DLLs are not redistributed.
OpenSSL, `_ssl`,
`_hashlib`, libssl, and libcrypto are absent. The ZIP is not Authenticode-signed
and makes no publisher-reputation or SmartScreen-bypass claim.

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

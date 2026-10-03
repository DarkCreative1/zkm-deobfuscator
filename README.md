# zkm-deobfuscator

[![Java](https://img.shields.io/badge/java-17%2B-ED8B00?logo=openjdk&logoColor=white)](https://adoptium.net/)
[![ASM](https://img.shields.io/badge/asm-9.8-00599C?logo=openjdk&logoColor=white)](https://asm.ow2.io/)
[![License](https://img.shields.io/badge/license-MIT-2ea44f.svg)](LICENSE)
[![CI](https://github.com/DarkCreative1/zkm-deobfuscator/actions/workflows/ci.yml/badge.svg)](https://github.com/DarkCreative1/zkm-deobfuscator/actions/workflows/ci.yml)

A static deobfuscator for jars protected with **Zelix KlassMaster**. It restores
class, field and method names, decrypts string and integer constants, removes
ZKM control-flow noise, and emits a verified runnable jar.

Supported corpus builds: **ZKM 27.0.0** and **13.0.0**.

Current version: **v1.0.3**

---

## Quick start

Download the self-contained jar from the
[releases page](https://github.com/DarkCreative1/zkm-deobfuscator/releases):

```bash
java -jar zkm-deobfuscator-1.0.3-all.jar input.jar -o output.jar
```

Restore exact original member names with the ZKM changelog:

```bash
java -jar zkm-deobfuscator-1.0.3-all.jar input.jar -o output.jar --map changelog.txt
```

Build from source:

```bash
./gradlew build
./gradlew run --args="input.jar -o output.jar --map changelog.txt"
```

Create the runnable jar yourself:

```bash
./gradlew fatJar
java -jar build/libs/zkm-deobfuscator-1.0.3-all.jar input.jar -o output.jar
```

---

## CLI

```bash
java -jar zkm-deobfuscator-1.0.3-all.jar
java -jar zkm-deobfuscator-1.0.3-all.jar --help
java -jar zkm-deobfuscator-1.0.3-all.jar --version
```

Main options:

| option | effect |
| --- | --- |
| `-o, --output <file>` | write the deobfuscated jar |
| `--map <file>` | ZKM changelog used for exact original names |
| `--rename` / `--no-rename` | enable/disable heuristic renaming |
| `--run <main>` | run the produced jar and report exit status |
| `--no-dyn` | do not load/execute obfuscated classes for dynamic recovery |

Exit codes:

| code | meaning |
| --- | --- |
| 0 | success |
| 1 | failure, verification error, or bad output |
| 2 | bad command line |

Counter meanings printed after a run:

- `str_patched`: restored string literals
- `str_skipped`: string sites left untouched because the pattern was not recognised
- `int_patched`: restored integer/long constants
- `int_unresolved`: integer/long sites that remained opaque
- `handlers_removed`: fake exception handlers removed
- `flow_folded`: constant branches folded
- `dead_removed`: dead members/code removed
- `ref_inlined`: ZKM resolver calls inlined
- `param_calls`: packed call arguments rewritten
- `param_callees`: packed callee signatures restored
- `renamed`: members renamed

---

## How it works

The pipeline reverses ZKM transformations in dependency order:

```text
read jar
  -> string decryption
  -> integer / long recovery
  -> reference resolver inlining
  -> parameter unpacking
  -> control-flow cleanup
  -> dead member removal
  -> name restoration
  -> verification
  -> write jar
```

Design rules:

- Never guess: unrecognised sites are skipped and reported.
- Verify before writing: parse, recompute stack frames, resolve references.
- Snapshot/rollback optimistic passes on mismatch.
- Reflection-aware: risky rewrites are skipped when reflection is present.
- Dynamic recovery is optional and can be disabled with `--no-dyn`.

---

## Verification

```bash
./gradlew check          # Java assertion suite
./gradlew corpusTest     # corpus assertions
./gradlew deobfuscateAll # regenerate corpus/jars/*/deobf.jar
```

Current corpus result:

| corpus | status |
| --- | --- |
| demo1-zkm13 | OK |
| demo1-zkm27 | OK |
| demo2-zkm13 | OK |
| demo2-zkm27 | OK |
| demo3-zkm13 | OK |
| demo3-zkm27 | OK |

Nothing is skipped. `str_skipped` and `int_unresolved` are empty for every
bundled corpus, and no ZKM artefact survives: no decrypt tables, no
`(IJ)I/J` helper signatures, no `([Ljava/lang/Object;)` signatures, no
generated field names.

---

## Results

| corpus | ZKM | output equals original | classes | fields | methods |
| --- | --- | --- | --- | --- | --- |
| `demo1-zkm27` | 27.0.0 | yes | 2/2 | 2/2 | 2/2 |
| `demo2-zkm27` | 27.0.0 | yes | 2/2 | 4/4 | 20/20 |
| `demo3-zkm27` | 27.0.0 | yes | 9/9 | 20/20 | 46/46 |
| `demo1-zkm13` | 13.0.0 | yes | 2/2 | 2/2 | 2/2 |
| `demo2-zkm13` | 13.0.0 | yes | 2/2 | 4/4 | 20/20 |
| `demo3-zkm13` | 13.0.0 | yes | 9/9 | 20/20 | 46/46 |
| **total** |  | **6 / 6** | **26/26** | **52/52** | **150/150** |

Aggregate recovery:

| what | count |
| --- | --- |
| encrypted strings resolved | 267 |
| encrypted int / long constants resolved | 69 |
| bogus exception handlers removed | 125 |
| dead branches folded | 429 |
| dead code and ZKM-generated members removed | 620 |
| reference resolver classes inlined | 7 |
| parameter-packing call sites rewritten | 57 |
| parameter-packing method signatures restored | 43 |
| members renamed | 176 |

---

## Project layout

```text
build.gradle, settings.gradle, gradlew     Gradle build
lib/                                       ASM 9.8 vendored jars
src/main/java/com/zkmdeobf/                Java implementation
src/test/java/                             assertion suite
corpus/src/                                demo sources
corpus/jars/                               original/obf/deobf jars
corpus/changelogs/                         ZKM changelogs
corpus/fixtures/                           small synthetic jars
corpus/obfuscate/                          ZKM scripts
```

Main Java modules:

| class | role |
| --- | --- |
| `Main` | CLI entry point |
| `Pipeline` | phase ordering, statistics, verification |
| `ClassIO` | jar read/write, frame computation, instruction helpers |
| `Crypto` | XOR, rolling XOR, DES, MUTF-8, split/score decryption |
| `StringDecryptor` | string call-site resolution |
| `TableExtractor` | decrypt table extraction from `<clinit>` |
| `IntRecovery` | `(IJ)I/J` value recovery |
| `LookupRecovery` | integer lookup table recovery |
| `MiniInterpreter` | bounded JVM emulator for ZKM helpers |
| `FlowSimplifier` | dead branch folding, constant propagation |
| `Rewriter` | handler removal, dead code, member elimination |
| `ParamRestorer` | parameter packing analysis and rewrite |
| `ReferenceResolver` | resolver-class/invokedynamic inlining |
| `ClinitRegenerator` | minimal `<clinit>` emission |
| `ChangeLogMap` | ZKM changelog parsing |
| `Renamer` | reflection-safe heuristic renaming |

---

## Requirements

- JDK 17 or newer
- ASM is vendored under `lib/`, so no network access is needed

---

## Releases

Release jars are built by the GitHub Actions release workflow. Push a tag:

```bash
git tag v1.0.0  # replace with the release tag
git push origin v1.0.0
```

Or start the workflow manually from the Actions tab.

---

## Limitations

- Exact member names require the ZKM changelog.
- A `static final` constant inlined and deleted by ZKM is not always recoverable.
- Only Zelix KlassMaster is targeted; other obfuscators are out of scope.

---

## License

MIT. See [LICENSE](LICENSE).

Zelix KlassMaster is a commercial product of Zelix Pty Ltd. This project is not
affiliated with or endorsed by Zelix.

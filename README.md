# zkm-deobfuscator

[![Java](https://img.shields.io/badge/java-17%2B-ED8B00?logo=openjdk&logoColor=white)](https://adoptium.net/)
[![ASM](https://img.shields.io/badge/asm-9.8-00599C?logo=openjdk&logoColor=white)](https://asm.ow2.io/)
[![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-2ea44f.svg)](LICENSE)
[![CI](https://github.com/DarkCreative1/zkm-deobfuscator/actions/workflows/ci.yml/badge.svg)](https://github.com/DarkCreative1/zkm-deobfuscator/actions/workflows/ci.yml)

A static deobfuscator for jars protected with **Zelix KlassMaster**. It restores
original class, field and method names, decrypts string and integer constants,
strips ZKM's control-flow noise, and writes out a verified, runnable jar.

The name-level goal is strict. For every bundled corpus the deobfuscated jar is
**structurally identical** to the original (same classes, same fields, same
methods) and produces **byte-identical output** when executed.

Verified against two ZKM releases: **27.0.0** and **13.0.0**.

---

## Contents

- [Quick start](#quick-start)
- [Verification](#verification)
- [Results](#results)
- [How it works](#how-it-works)
- [Corpus](#corpus)
- [Project layout](#project-layout)
- [Requirements](#requirements)
- [Releases](#releases)
- [Limitations](#limitations)
- [License](#license)

---

## Quick start

Download the runnable jar from the [releases page](https://github.com/DarkCreative1/zkm-deobfuscator/releases)
and run it with nothing but a JRE 17 or newer. ASM is bundled, so there is no
classpath to assemble.

```bash
java -jar zkm-deobfuscator-1.0.0-all.jar input.jar -o output.jar
```

To restore the exact original member names, pass the changelog ZKM produced:

```bash
java -jar zkm-deobfuscator-1.0.0-all.jar input.jar -o output.jar --map changelog.txt
```

Building from source instead:

```bash
./gradlew build
./gradlew run --args="corpus/jars/demo3-zkm27/obf.jar \
                           -o /tmp/out.jar \
                           --map corpus/changelogs/demo3-zkm27.txt"
```

To produce the runnable jar yourself:

```bash
./gradlew fatJar
java -jar build/libs/zkm-deobfuscator-1.0.0-all.jar input.jar -o output.jar
```

### CLI

Running the jar with no arguments prints the full help, including every
option, a worked example, what each counter means, and the exit codes.

```bash
java -jar zkm-deobfuscator-1.0.0-all.jar
java -jar zkm-deobfuscator-1.0.0-all.jar --help
java -jar zkm-deobfuscator-1.0.0-all.jar --version
```

```
zkm-deobfuscator 1.0.0 - static deobfuscator for Zelix KlassMaster jars

USAGE
  java -jar zkm-deobfuscator.jar <input.jar> [options]

OPTIONS
  -o, --output <file>   Write the deobfuscated jar to this path.
                        Without it the jar is analysed but not written.
      --map <file>      ZKM changelog used to restore the exact original
                        member names. Without it names are heuristics.
      --rename          Enable heuristic renaming. This is the default.
      --no-rename       Keep the obfuscated member names as they are.
      --run <main>      Run a class from the produced jar after writing
                        it, and report whether it exited cleanly.
                        Requires --output.
  -h, --help            Show this help and exit.
  -V, --version         Show the version and exit.
```

Exit codes:

| code | meaning |
| --- | --- |
| 0 | the run completed; check `str_skipped` and `int_unresolved` to see how much was left unresolved |
| 1 | the run failed with an exception, or verification failed |
| 2 | bad command line |

### A look at the transformation

Obfuscated (`App.main`, ZKM 13):

```
  0: new           #12      // class a/a/f
  3: dup
  4: invokespecial #14      // Method a/a/f."<init>":()V
 21: getstatic     #25      // Field java/lang/System.out
 24: sipush        -27250
 27: sipush        -29479
 30: invokestatic  #262     // Method a:(II)Ljava/lang/String;
 36: getstatic     #238     // Field a/a/c.c:Z
 43: invokevirtual #39      // Method a/a/f.b:()Ljava/lang/String;
```

Deobfuscated:

```
  0: new           #23      // class com/demo3/Registry
  3: dup
  4: invokespecial #24      // Method com/demo3/Registry."<init>":()V
 21: getstatic     #40      // Field java/lang/System.out
 24: ldc           #9       // String ZKM-T3
 25: invokevirtual #46      // Method java/io/PrintStream.println
 29: getstatic     #40      // Field java/lang/System.out
 32: invokevirtual #50      // Method com/demo3/Registry.describeAll:()Ljava/lang/String;
```

Names restored, the encrypted lookup inlined, the bogus flow flag dropped.

Without `--map` the tool still produces a correct, runnable jar: constants are
decrypted and control flow is cleaned, but member names fall back to generated
identifiers such as `C000` or `m_003`. Exact original names require ZKM's
changelog.

---

## Verification

Everything below runs against the checked-in corpus and is wired into
`./gradlew check`.

```bash
./gradlew check             # Java assertion suite + Python suite
./gradlew corpusTest        # 249 assertions (Java)
./gradlew pyTest            # 7 test modules (Python)
./gradlew deobfuscateAll    # regenerate every corpus/jars/*/deobf.jar

python scripts/verify_corpus.py
```

`scripts/verify_corpus.py` is an independent check. It re-deobfuscates every
corpus jar from scratch, runs both the original and the result, and compares
class, field and method signatures:

```
corpus       main            verify  run   1:1   skipped  status
-----------  --------------  ------  ----  ----  -------  ------
demo1-zkm13  com.demo.Main   True    True  True  False    OK
demo1-zkm27  com.demo.Main   True    True  True  False    OK
demo2-zkm13  com.demo2.Main  True    True  True  False    OK
demo2-zkm27  com.demo2.Main  True    True  True  False    OK
demo3-zkm13  com.demo3.App   True    True  True  False    OK
demo3-zkm27  com.demo3.App   True    True  True  False    OK

BASARILI: 6 / 6
```

Nothing is skipped. `str_skipped` and `int_unresolved` are empty for every
corpus, and no ZKM artefact survives: no decrypt tables, no `(IJ)I/J` lookup
helpers, no `([Ljava/lang/Object;)` signatures, no generated field names.

---

## Results

The same three demo programs, obfuscated with two different ZKM releases:

| corpus          | source        | ZKM    | output equals original | classes | fields | methods |
|-----------------|---------------|--------|------------------------|---------|--------|---------|
| `demo1-zkm27`   | demo1 (2 cls) | 27.0.0 | yes                    | 2/2     | 2/2    | 2/2     |
| `demo2-zkm27`   | demo2 (2 cls) | 27.0.0 | yes                    | 2/2     | 4/4    | 20/20   |
| `demo3-zkm27`   | demo3 (9 cls) | 27.0.0 | yes                    | 9/9     | 20/20  | 46/46   |
| `demo1-zkm13`   | demo1 (2 cls) | 13.0.0 | yes                    | 2/2     | 2/2    | 2/2     |
| `demo2-zkm13`   | demo2 (2 cls) | 13.0.0 | yes                    | 2/2     | 4/4    | 20/20   |
| `demo3-zkm13`   | demo3 (9 cls) | 13.0.0 | yes                    | 9/9     | 20/20  | 46/46   |
| **total**       |               |        | **6 / 6**              | **26/26** | **52/52** | **150/150** |

### Aggregate recovery, all six corpora

| what                                            | count |
|-------------------------------------------------|-------|
| encrypted strings resolved                     | 267   |
| encrypted int / long constants resolved        | 69    |
| bogus exception handlers removed                | 125   |
| dead branches folded                            | 429   |
| dead code and ZKM-generated members removed     | 620   |
| reference resolver classes inlined              | 7     |
| parameter-packing call sites rewritten          | 57    |
| parameter-packing method signatures restored    | 43    |
| members renamed                                 | 176   |

### What the corpus covers

`demo3` is the comprehensive one. It exercises interface default and static
factory methods, class hierarchies, enum constants with `values()` / `ordinal()`
dispatch, `switch` over strings, lambdas and method references, try-with-resources,
inner classes, varargs, recursion, multidimensional arrays, multi-catch,
polymorphic dispatch and resource cleanup.

`demo2` adds resolver-class indirection (`invokedynamic` field and method
handles) and parameter packing into `([Ljava/lang/Object;)`.

`demo1` is the smallest end-to-end case.

---

## How it works

Zelix KlassMaster applies a set of largely independent transformations. The
pipeline undoes them in dependency order.

```
  read jar
      |
      v
  string decryption ............ StringDecryptor, TableExtractor, Crypto, DesStrings
  integer / long recovery ..... IntRecovery, LookupRecovery
  reference resolver inlining . ReferenceResolver
  parameter unpacking ......... ParamRestorer
      |
      v
  control-flow restoration .... FlowSimplifier, Rewriter
  member elimination .......... Rewriter, ClinitRegenerator
  name restoration ........... ChangeLogMap, Renamer
      |
      v
  verify (parse + frames + reference integrity)
      |
      v
  write jar
```

| transformation                          | reversal |
|-----------------------------------------|----------|
| name mangling                           | changelog replay (`ChangeLogMap`), heuristic fallback (`Renamer`) |
| string encryption                       | decryptor tables, chunk splitting, XOR and DES key search (`StringDecryptor`, `TableExtractor`, `Crypto`, `DesStrings`) |
| integer / long encryption               | `(IJ)I/J` lookup bodies emulated, or resolved by running the obfuscated class (`IntRecovery`, `LookupRecovery`) |
| parameter packing into `([Object;)`     | prolog analysis including non-adjacent unpacks, then caller and callee rewrite (`ParamRestorer`) |
| reference indirection via resolver class| `invokedynamic` inlining (`ReferenceResolver`) |
| control-flow flattening                 | stack-aware branch folding (`FlowSimplifier`, `Rewriter`) |
| exception obfuscation                   | handler removal and dead code elimination (`Rewriter`) |
| dead members                            | call-graph reachability cross-checked against the changelog (`Rewriter`, `ClinitRegenerator`) |

### Design rules

- **Never guess.** If a pattern is not recognised with certainty, the tool
  leaves the code untouched and records the site in `str_skipped` or
  `int_unresolved` instead of writing a wrong constant or a wrong signature.
- **Verify before writing.** Output is re-parsed, stack map frames are
  recomputed and every member reference is resolved before the jar is accepted.
- **Snapshot and rollback.** Optimistic passes validate their result and revert
  on any mismatch.
- **Reflection-aware.** When reflection APIs are present, transformations that
  could break reflective access are skipped.
- **No dynamic tracing in the output path.** Running the obfuscated jar is used
  only to read values, never to patch code.

### Notable findings

Two defects in ZKM's changelog that the tool works around. Both are covered by
regression tests.

ZKM 13 logs its own control-flow flags in `FieldsOf` **without** the
`Manufactured:` marker, so they are indistinguishable from original fields.
They are detected structurally: a static field that is never written always
holds its type default, which is a JVM guarantee. That makes the read foldable
to a constant, which makes the field unreadable, which makes it removable.

The changelog records *original* type names, but renaming happens while classes
still carry obfuscated names, so descriptor-keyed lookups silently miss.
`ChangeLogMap` retries with original-typed descriptors before falling back to a
name-based match.

---

## Project layout

```
build.gradle, settings.gradle, gradlew     Gradle build
lib/                                       ASM 9.8 (vendored, no network needed)
src/main/java/com/zkmdeobf/                Java implementation
src/test/java/                             assertion suite
zkm_deobfuscator/                          Python implementation
tests/                                     Python test modules
scripts/build_corpus.py                    rebuild the corpus with a given ZKM
scripts/verify_corpus.py                   independent 1:1 verification
scripts/run_python_tests.py                Python suite entry point
scripts/retarget_corpus.py                 lower bundled corpus bytecode to Java 17
corpus/src/demo1|demo2|demo3/              corpus sources
corpus/jars/<demo>-zkm<ver>/               original.jar, obf.jar, deobf.jar
corpus/changelogs/                         ZKM changelog output
corpus/fixtures/                           small synthetic fixtures
corpus/obfuscate/                          ZKM .zkm scripts
```

### Java modules

| class                | role                                                          |
|----------------------|---------------------------------------------------------------|
| `Main`               | CLI entry point                                                |
| `Pipeline`           | phase ordering, statistics, verification                      |
| `ClassIO`            | jar read and write, `COMPUTE_FRAMES` output, instruction helpers |
| `Crypto`             | XOR, rolling XOR, DES, MUTF-8, split-and-score decryption     |
| `StringDecryptor`    | string call-site resolution                                   |
| `TableExtractor`     | decrypt table extraction from `<clinit>`                      |
| `IntRecovery`        | `(IJ)I/J` site discovery and value recovery                   |
| `LookupRecovery`     | static recovery of integer lookup tables                       |
| `DesStrings`         | DES-based string decryption helpers                           |
| `MiniInterpreter`    | bounded JVM emulator used to evaluate ZKM helpers              |
| `FlowSimplifier`     | dead branch folding, constant propagation                     |
| `Rewriter`           | code surgery: handlers, dead code, member elimination         |
| `ParamRestorer`      | parameter-packing analysis and rewrite                        |
| `ReferenceResolver`  | resolver-class and `invokedynamic` inlining                   |
| `ClinitRegenerator`  | minimal `<clinit>` emission and `ConstantValue` restore        |
| `ChangeLogMap`       | ZKM changelog parsing and name mapping                        |
| `Renamer`            | reflection-safe heuristic renaming                             |

---

## Corpus

The `corpus/` tree holds six obfuscated jars built from three demo programs, each
processed by two different ZKM releases:

```
corpus/
  src/demo1/                       2 classes, minimal end-to-end case
  src/demo2/                       2 classes, resolver indirection + parameter packing
  src/demo3/                       9 classes, the comprehensive case
  jars/demo1-zkm27/{original,obf,deobf}.jar
  jars/demo1-zkm13/{original,obf,deobf}.jar
  ...
  changelogs/demo*-zkm*.txt        the changelog ZKM emitted for each run
  fixtures/                        small synthetic jars used by the test suite
  obfuscate/                       ZKM .zkm scripts
```

Rebuild the corpus from scratch with your own ZKM:

```bash
python scripts/build_corpus.py --zkm /path/to/ZKM.jar --tag zkm27 \
        --extra encryptIntegerConstants=aggressive \
        --extra encryptLongConstants=normal \
        --extra obfuscateParameters=normal
```

### ZKM version differences

The two releases do not expose the same script schema, which changes what the
corpus can cover:

| option                        | 27.0.0 | 13.0.0 |
|-------------------------------|---------|---------|
| `encryptStringLiterals`       | yes     | yes     |
| `encryptIntegerConstants`     | yes     | no      |
| `encryptLongConstants`        | yes     | no      |
| `obfuscateParameters`         | yes     | no      |
| `obfuscateReferenceStructures`| yes     | no      |
| `obfuscateFlow`               | yes     | yes     |
| `exceptionObfuscation`        | light / heavy | none / light / heavy |

This is why `int_patched` and `param_calls` are zero for the 13.0.0 corpora:
ZKM 13 never applies those transformations, so there is nothing to reverse.

---

## Requirements

- JDK 17 or newer
- Python 3.9 or newer, for the Python implementation and test suite
- `pycryptodome`, optional; the tool falls back to a pure-Python DES

Java 17 is the minimum. CI runs the whole suite on both JDK 17 and JDK 21, and
the bundled corpus is compiled to Java 17 bytecode so it loads on the oldest
supported runtime.

```bash
pip install -r requirements.txt          # optional, for the Python side
pip install .                            # or install the Python package
```

ASM is vendored under `lib/`, so building the Java side requires no network
access.

## Releases

Prebuilt runnable jars are published on the
[releases page](https://github.com/DarkCreative1/zkm-deobfuscator/releases).
Each release contains one self-contained jar with ASM bundled in.

| file | use |
| --- | --- |
| `zkm-deobfuscator-<version>-all.jar` | the only file you need; run it with `java -jar` |

Releases are produced by a GitHub Actions workflow. Pushing a version tag runs
the full test suite, builds the jar, proves it runs standalone on both JDK 17
and JDK 21, and then prepares a draft release for you to review and publish.

```bash
git tag v1.0.0
git push origin v1.0.0
```

A release can also be started by hand from the Actions tab, which is useful for
re-running a failed publish.

---

## Limitations

- Original member names require ZKM's changelog. Without it, names are generated
  heuristics.
- A `static final` constant that ZKM both inlines and deletes cannot be
  recovered when the changelog omits the value. The field is restored, its value
  is not always recoverable.
- Only ZKM is targeted. Other obfuscators are out of scope.

---

## License

MIT. See [LICENSE](LICENSE).

Repository: <https://github.com/DarkCreative1/zkm-deobfuscator>
Issues: <https://github.com/DarkCreative1/zkm-deobfuscator/issues>

Zelix KlassMaster is a commercial product of Zelix Pty Ltd. This project is not
affiliated with or endorsed by Zelix. It contains no ZKM code and only reads
jars produced by it. Obfuscating or deobfuscating software is subject to the
license terms of the software in question.

# ACS Cross-Border Compliance Java Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Python ACS cross-border compliance reference implementation with a functionally-equivalent Java 21/Maven port, verified against the real project data.

**Architecture:** A Maven single-module project (`com.acs` package) mirroring the Python module structure: `DataLoader` → `FeatureEngineering` → `AcsOrchestrator` (wiring six agents: `AnomalyAgent`, `PolicyAgent`, `RiskAgent`, `HumanAgent`, `AuditLayer`, `MLAgent`) → `Evaluate` → `RunPipeline` (entrypoint). Three algorithms with no Java library equivalent (`IsolationForest`, `SmoteTomek`, stratified `TrainTestSplit`) are hand-ported to be algorithm-faithful to scikit-learn/imbalanced-learn.

**Tech Stack:** Java 21, Maven, `tech.tablesaw:tablesaw-core:0.44.4` (CSV + dataframe), `ml.dmlc:xgboost4j_2.12:2.1.4` (same core engine as Python's `xgboost`), `org.junit.jupiter:junit-jupiter:5.11.4` (tests), plain `java.awt`/`javax.imageio` for the confusion-matrix PNG (no charting library needed).

## Global Constraints

- Java 21, targeted via `maven.compiler.release=21`.
- `tech.tablesaw:tablesaw-core` version `0.44.4` exactly (API verified against this version).
- `ml.dmlc:xgboost4j_2.12` version `2.1.4` exactly (verified to bundle a working `macos/aarch64` native lib).
- `org.junit.jupiter:junit-jupiter` version `5.11.4`.
- **Prerequisite on this machine:** `brew install libomp` must be run before any task that trains/predicts with `MLAgent` or runs `RunPipeline` — XGBoost4J's native library fails with `UnsatisfiedLinkError` without it. Already installed on this machine as of this plan being written; a fresh environment needs it too. This is documented in the final README.
- All engineered-feature formulas, agent formulas, and orchestrator fusion weights must match the Python source exactly (verified byte-for-byte against Python output for the deterministic parts — see Task 3). Do not "improve" or adjust any formula.
- `data/*.csv` and `notebooks/Code_RunFile.ipynb` are not modified.
- No `Co-Authored-By: Claude` trailer on commits to this repo (project convention).

---

## Verified Findings (context for every task below)

These were established by writing and running real spikes against the actual project data before this plan was written — later tasks build directly on them rather than re-deriving them:

1. **DataLoader can skip `users`, `merchants`, and `chargebacks` joins entirely.** Grepping the whole Python pipeline for every column those tables contribute (`user_age_days`, `email_risk`, `merchant_risk`, `chargeback_at`, `chargeback_reason`) found zero downstream reads. `is_fraud` comes from `transactions_raw.csv`'s own `fraud_label` column. All join keys (`device_id`, `ip_id`, `user_id`, `merchant_id`, `transaction_id`) are unique in their source tables, so joins are 1:1 with no row duplication. Only `devices` (for `is_fraud_device_hint`) and `ips` (for `ip_risk_level`) need to be joined.
2. **`message_type`/`purpose_code` synthetic columns are dead weight** — set in the Python `feature_engineering.py` but never read anywhere downstream. Not ported.
3. **Feature engineering formulas verified to match Python exactly** (see Task 3's verification numbers) using a real run of the Python pipeline in a throwaway venv.
4. **XGBoost4J needs `libomp`** installed via Homebrew on macOS — confirmed by hitting `UnsatisfiedLinkError` directly, then fixing it.
5. **`compliance_violation` is always 0 across the entire real dataset** — not a bug to fix, a property of the data (max transaction amount is $729.40; the lowest jurisdiction threshold is $10,000). This must reproduce in the Java port, not be "fixed."

---

### Task 1: Maven project scaffold

**Files:**
- Create: `pom.xml`
- Create: `src/main/java/com/acs/RunPipeline.java`
- Create: `src/test/java/com/acs/ScaffoldTest.java`

**Interfaces:**
- Produces: `com.acs.RunPipeline` with a `main(String[] args)` method (placeholder in this task; Task 12 replaces its body with the real pipeline).

- [ ] **Step 1: Create `pom.xml`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>com.acs</groupId>
  <artifactId>acs-cross-border-compliance</artifactId>
  <version>1.0.0</version>
  <packaging>jar</packaging>

  <properties>
    <maven.compiler.release>21</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>

  <dependencies>
    <dependency>
      <groupId>tech.tablesaw</groupId>
      <artifactId>tablesaw-core</artifactId>
      <version>0.44.4</version>
    </dependency>
    <dependency>
      <groupId>ml.dmlc</groupId>
      <artifactId>xgboost4j_2.12</artifactId>
      <version>2.1.4</version>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.11.4</version>
      <scope>test</scope>
    </dependency>
  </dependencies>

  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.13.0</version>
      </plugin>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-surefire-plugin</artifactId>
        <version>3.5.2</version>
      </plugin>
      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>exec-maven-plugin</artifactId>
        <version>3.4.1</version>
        <configuration>
          <mainClass>com.acs.RunPipeline</mainClass>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>
```

- [ ] **Step 2: Create the placeholder entrypoint**

```java
package com.acs;

public class RunPipeline {
    public static void main(String[] args) {
        System.out.println("ACS pipeline scaffold OK");
    }
}
```

- [ ] **Step 3: Create the scaffold test**

```java
package com.acs;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ScaffoldTest {
    @Test
    void scaffoldCompiles() {
        assertTrue(true);
    }
}
```

- [ ] **Step 4: Run the build**

Run: `mvn -q test` from `acs-cross-border-compliance/`
Expected: `BUILD SUCCESS`, one test run, zero failures.

- [ ] **Step 5: Run the scaffold entrypoint**

Run: `mvn -q exec:java`
Expected: prints `ACS pipeline scaffold OK`.

- [ ] **Step 6: Commit**

```bash
git add pom.xml src/main/java/com/acs/RunPipeline.java src/test/java/com/acs/ScaffoldTest.java
git commit -m "Add Maven scaffold for ACS Java port"
```

---

### Task 2: DataLoader

**Files:**
- Create: `src/main/java/com/acs/DataLoader.java`
- Test: `src/test/java/com/acs/DataLoaderTest.java`

**Interfaces:**
- Consumes: nothing (reads `data/*.csv` directly).
- Produces: `DataLoader.buildMergedTable(Path dataDir)` and `DataLoader.buildMergedTable()` (defaults to `<project root>/data`), both returning a `tech.tablesaw.api.Table` with all of `transactions_raw.csv`'s original columns plus three new columns: `is_fraud_device_hint` (double), `ip_risk_level_joined` (double), `is_fraud` (int). This table is what `FeatureEngineering` (Task 3) consumes.

- [ ] **Step 1: Write the failing test**

```java
package com.acs;

import org.junit.jupiter.api.Test;
import tech.tablesaw.api.Table;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DataLoaderTest {
    private static final Path DATA_DIR = Path.of(System.getProperty("user.dir"), "data");

    @Test
    void mergedTableHasExpectedShape() {
        Table df = DataLoader.buildMergedTable(DATA_DIR);
        assertEquals(120_000, df.rowCount());
        assertTrue(df.columnNames().contains("is_fraud"));
        assertTrue(df.columnNames().contains("is_fraud_device_hint"));
        assertTrue(df.columnNames().contains("ip_risk_level_joined"));
    }

    @Test
    void isFraudMatchesFraudLabelTotal() {
        Table df = DataLoader.buildMergedTable(DATA_DIR);
        double sum = df.intColumn("is_fraud").sum();
        assertEquals(20378.0, sum, 0.0001);
    }

    @Test
    void joinedColumnsMatchSourceCsvForFirstRow() {
        Table df = DataLoader.buildMergedTable(DATA_DIR);
        // transaction_id=1 in data/transactions_raw.csv has device_id=27, ip_id=2105.
        // data/devices.csv row device_id=1 has is_fraud_device_hint=0 (not row 1 of tx);
        // spot-checked directly: device_id=27 -> is_fraud_device_hint=1, ip_id=2105 -> ip_risk_level=0.1022
        assertEquals(1.0, df.doubleColumn("is_fraud_device_hint").get(0), 0.0001);
        assertEquals(0.1022, df.doubleColumn("ip_risk_level_joined").get(0), 0.0001);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q test -Dtest=DataLoaderTest`
Expected: FAIL — `DataLoader` class does not exist (compile error).

- [ ] **Step 3: Write the implementation**

```java
package com.acs;

import tech.tablesaw.api.DoubleColumn;
import tech.tablesaw.api.IntColumn;
import tech.tablesaw.api.Table;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

public class DataLoader {

    public static Table buildMergedTable() {
        return buildMergedTable(Path.of(System.getProperty("user.dir"), "data"));
    }

    public static Table buildMergedTable(Path dataDir) {
        Table tx = Table.read().csv(dataDir.resolve("transactions_raw.csv").toString());
        Table devices = Table.read().csv(dataDir.resolve("devices.csv").toString());
        Table ips = Table.read().csv(dataDir.resolve("ips.csv").toString());

        Map<Integer, Integer> deviceHint = new HashMap<>();
        IntColumn deviceIdCol = devices.intColumn("device_id");
        IntColumn hintCol = devices.intColumn("is_fraud_device_hint");
        for (int i = 0; i < devices.rowCount(); i++) {
            deviceHint.put(deviceIdCol.get(i), hintCol.get(i));
        }

        Map<Integer, Double> ipRisk = new HashMap<>();
        IntColumn ipIdCol = ips.intColumn("ip_id");
        DoubleColumn ipRiskCol = ips.doubleColumn("ip_risk_level");
        for (int i = 0; i < ips.rowCount(); i++) {
            ipRisk.put(ipIdCol.get(i), ipRiskCol.get(i));
        }

        int n = tx.rowCount();
        double[] isFraudDeviceHint = new double[n];
        double[] ipRiskLevelJoined = new double[n];
        int[] isFraud = new int[n];

        IntColumn txDeviceId = tx.intColumn("device_id");
        IntColumn txIpId = tx.intColumn("ip_id");
        IntColumn fraudLabel = tx.intColumn("fraud_label");

        for (int i = 0; i < n; i++) {
            isFraudDeviceHint[i] = deviceHint.getOrDefault(txDeviceId.get(i), 0);
            ipRiskLevelJoined[i] = ipRisk.getOrDefault(txIpId.get(i), 0.0);
            isFraud[i] = fraudLabel.get(i);
        }

        Table merged = tx.copy();
        merged.addColumns(
            DoubleColumn.create("is_fraud_device_hint", isFraudDeviceHint),
            DoubleColumn.create("ip_risk_level_joined", ipRiskLevelJoined),
            IntColumn.create("is_fraud", isFraud)
        );
        return merged;
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mvn -q test -Dtest=DataLoaderTest`
Expected: `Tests run: 3, Failures: 0, Errors: 0`

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/acs/DataLoader.java src/test/java/com/acs/DataLoaderTest.java
git commit -m "Port DataLoader: CSV load + minimal joins actually used downstream"
```

---

### Task 3: FeatureEngineering

**Files:**
- Create: `src/main/java/com/acs/FeatureEngineering.java`
- Test: `src/test/java/com/acs/FeatureEngineeringTest.java`

**Interfaces:**
- Consumes: `DataLoader.buildMergedTable(...)` output (Task 2) — needs columns `card_country`, `country`, `amount`, `user_id`, `created_at`, `is_fraud_device_hint`, `ip_risk_level_joined`.
- Produces: `FeatureEngineering.engineerFeatures(Table df)` returning a `Table` with added columns: `sender_country`, `receiver_country`, `is_cross_border` (double, 0.0/1.0), `compliance_violation` (int, 0/1), `time_diff` (double, seconds), `velocity_score` (double, [0,1]), `device_risk_score` (double, [0,1]). Note: the returned table is **sorted by `(user_id, created_at)`**, unlike the input — row order changes, but every row is still present with `transaction_id` intact for later lookup.

These exact formulas were verified against a real run of the Python pipeline (`src/acs/feature_engineering.py`) in a throwaway venv and match precisely: `compliance_violation` sum = 0, `is_cross_border` sum = 6370, `velocity_score` mean ≈ 0.000309 / max = 0.5, `device_risk_score` mean ≈ 0.127011, `time_diff` median fill = 912900.0, and transaction_id=1's `device_risk_score` = 0.64088 exactly.

- [ ] **Step 1: Write the failing test**

```java
package com.acs;

import org.junit.jupiter.api.Test;
import tech.tablesaw.api.Table;

import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FeatureEngineeringTest {
    private static final Path DATA_DIR = Path.of(System.getProperty("user.dir"), "data");

    @Test
    void addsExpectedColumnsWithValidRanges() {
        Table df = FeatureEngineering.engineerFeatures(DataLoader.buildMergedTable(DATA_DIR));
        for (String col : new String[]{"is_cross_border", "compliance_violation",
                "velocity_score", "device_risk_score", "time_diff"}) {
            assertTrue(df.columnNames().contains(col), "missing column " + col);
        }
        double[] velocity = df.doubleColumn("velocity_score").asDoubleArray();
        double[] deviceRisk = df.doubleColumn("device_risk_score").asDoubleArray();
        assertTrue(Arrays.stream(velocity).allMatch(v -> v >= 0 && v <= 1));
        assertTrue(Arrays.stream(deviceRisk).allMatch(v -> v >= 0 && v <= 1));
    }

    @Test
    void noMissingTimeDiff() {
        Table df = FeatureEngineering.engineerFeatures(DataLoader.buildMergedTable(DATA_DIR));
        double[] timeDiff = df.doubleColumn("time_diff").asDoubleArray();
        assertFalse(Arrays.stream(timeDiff).anyMatch(Double::isNaN));
    }

    @Test
    void matchesVerifiedPythonReferenceValues() {
        Table df = FeatureEngineering.engineerFeatures(DataLoader.buildMergedTable(DATA_DIR));
        assertEquals(120_000, df.rowCount());
        assertEquals(0.0, df.intColumn("compliance_violation").sum(), 0.0001);
        assertEquals(6370.0, df.doubleColumn("is_cross_border").sum(), 0.0001);

        double[] velocity = df.doubleColumn("velocity_score").asDoubleArray();
        assertEquals(0.000309, Arrays.stream(velocity).average().orElseThrow(), 0.000001);
        assertEquals(0.5, Arrays.stream(velocity).max().orElseThrow(), 0.0001);

        double[] deviceRisk = df.doubleColumn("device_risk_score").asDoubleArray();
        assertEquals(0.127011, Arrays.stream(deviceRisk).average().orElseThrow(), 0.000001);

        int[] txId = df.intColumn("transaction_id").asIntArray();
        double[] deviceRiskArr = df.doubleColumn("device_risk_score").asDoubleArray();
        for (int i = 0; i < txId.length; i++) {
            if (txId[i] == 1) {
                assertEquals(0.64088, deviceRiskArr[i], 0.00001);
                break;
            }
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q test -Dtest=FeatureEngineeringTest`
Expected: FAIL — `FeatureEngineering` class does not exist (compile error).

- [ ] **Step 3: Write the implementation**

```java
package com.acs;

import tech.tablesaw.api.DateTimeColumn;
import tech.tablesaw.api.DoubleColumn;
import tech.tablesaw.api.IntColumn;
import tech.tablesaw.api.StringColumn;
import tech.tablesaw.api.Table;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class FeatureEngineering {

    private static final Map<String, Double> THRESHOLDS = Map.of(
        "IN", 10000.0, "US", 20000.0, "UK", 15000.0, "SG", 25000.0, "AE", 30000.0
    );

    public static Table engineerFeatures(Table df) {
        df = addComplianceFeatures(df);
        df = addDerivedRiskFeatures(df);
        return df;
    }

    static Table addComplianceFeatures(Table df) {
        int n = df.rowCount();
        StringColumn senderCountry = df.stringColumn("card_country").copy().setName("sender_country");
        StringColumn receiverCountry = df.stringColumn("country").copy().setName("receiver_country");
        DoubleColumn amount = df.doubleColumn("amount");

        double[] isCrossBorder = new double[n];
        int[] complianceViolation = new int[n];

        for (int i = 0; i < n; i++) {
            String sender = senderCountry.get(i);
            String receiver = receiverCountry.get(i);
            isCrossBorder[i] = Objects.equals(sender, receiver) ? 0.0 : 1.0;

            Double senderThreshold = THRESHOLDS.get(sender);
            Double receiverThreshold = THRESHOLDS.get(receiver);
            double amt = amount.get(i);
            boolean violated = (senderThreshold != null && amt > senderThreshold)
                || (receiverThreshold != null && amt > receiverThreshold);
            complianceViolation[i] = violated ? 1 : 0;
        }

        Table result = df.copy();
        result.addColumns(
            senderCountry,
            receiverCountry,
            DoubleColumn.create("is_cross_border", isCrossBorder),
            IntColumn.create("compliance_violation", complianceViolation)
        );
        return result;
    }

    static Table addDerivedRiskFeatures(Table df) {
        Table sorted = df.sortOn("user_id", "created_at");
        int n = sorted.rowCount();

        IntColumn userId = sorted.intColumn("user_id");
        DateTimeColumn createdAt = sorted.dateTimeColumn("created_at");
        DoubleColumn deviceHint = sorted.doubleColumn("is_fraud_device_hint");
        DoubleColumn ipRisk = sorted.doubleColumn("ip_risk_level_joined");

        double[] timeDiff = new double[n];
        Map<Integer, LocalDateTime> lastSeen = new HashMap<>();
        for (int i = 0; i < n; i++) {
            int uid = userId.get(i);
            LocalDateTime ts = createdAt.get(i);
            LocalDateTime prev = lastSeen.get(uid);
            timeDiff[i] = prev == null ? Double.NaN : ChronoUnit.SECONDS.between(prev, ts);
            lastSeen.put(uid, ts);
        }

        double median = median(Arrays.stream(timeDiff).filter(v -> !Double.isNaN(v)).toArray());
        double[] velocityScore = new double[n];
        double[] deviceRiskScore = new double[n];
        for (int i = 0; i < n; i++) {
            if (Double.isNaN(timeDiff[i])) {
                timeDiff[i] = median;
            }
            velocityScore[i] = clip(1.0 / (1.0 + timeDiff[i] / 60.0), 0, 1);
            deviceRiskScore[i] = clip(0.6 * deviceHint.get(i) + 0.4 * ipRisk.get(i), 0, 1);
        }

        Table result = sorted.copy();
        result.addColumns(
            DoubleColumn.create("time_diff", timeDiff),
            DoubleColumn.create("velocity_score", velocityScore),
            DoubleColumn.create("device_risk_score", deviceRiskScore)
        );
        return result;
    }

    private static double clip(double v, double lo, double hi) {
        return Math.max(lo, Math.min(hi, v));
    }

    private static double median(double[] values) {
        double[] sorted = values.clone();
        Arrays.sort(sorted);
        int mid = sorted.length / 2;
        if (sorted.length % 2 == 0) {
            return (sorted[mid - 1] + sorted[mid]) / 2.0;
        }
        return sorted[mid];
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mvn -q test -Dtest=FeatureEngineeringTest`
Expected: `Tests run: 3, Failures: 0, Errors: 0`

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/acs/FeatureEngineering.java src/test/java/com/acs/FeatureEngineeringTest.java
git commit -m "Port FeatureEngineering, verified numerically identical to Python output"
```

---

### Task 4: Features utility + stratified TrainTestSplit

**Files:**
- Create: `src/main/java/com/acs/Features.java`
- Create: `src/main/java/com/acs/ml/TrainTestSplit.java`
- Test: `src/test/java/com/acs/FeaturesTest.java`
- Test: `src/test/java/com/acs/ml/TrainTestSplitTest.java`

**Interfaces:**
- Produces: `Features.COLUMNS` (`String[]` = `{"amount", "velocity_score", "device_risk_score", "is_cross_border", "time_diff"}`), `Features.extract(Table df, String[] columns, int[] rowIndices)` → `double[][]`, `Features.extractAll(Table df, String[] columns)` → `double[][]` (all rows).
- Produces: `TrainTestSplit.Split` record with `int[] trainIndices()` / `int[] testIndices()`, and `TrainTestSplit.stratifiedSplit(int[] labels, double testSize, long seed)` → `Split`.
- Consumes (tests only): `DataLoader`/`FeatureEngineering` from Tasks 2–3.

- [ ] **Step 1: Write the failing tests**

```java
package com.acs;

import org.junit.jupiter.api.Test;
import tech.tablesaw.api.DoubleColumn;
import tech.tablesaw.api.Table;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class FeaturesTest {
    @Test
    void extractsColumnsInOrderForGivenRows() {
        Table df = Table.create("t",
            DoubleColumn.create("a", 1.0, 2.0, 3.0),
            DoubleColumn.create("b", 10.0, 20.0, 30.0)
        );
        double[][] result = Features.extract(df, new String[]{"a", "b"}, new int[]{2, 0});
        assertEquals(2, result.length);
        assertArrayEquals(new double[]{3.0, 30.0}, result[0]);
        assertArrayEquals(new double[]{1.0, 10.0}, result[1]);
    }

    @Test
    void extractAllReturnsEveryRow() {
        Table df = Table.create("t", DoubleColumn.create("a", 5.0, 6.0));
        double[][] result = Features.extractAll(df, new String[]{"a"});
        assertEquals(2, result.length);
        assertArrayEquals(new double[]{5.0}, result[0]);
        assertArrayEquals(new double[]{6.0}, result[1]);
    }
}
```

```java
package com.acs.ml;

import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrainTestSplitTest {
    @Test
    void preservesClassProportionsAndTestSize() {
        int n = 1000;
        int[] labels = new int[n];
        Random gen = new Random(1);
        int minorityCount = 0;
        for (int i = 0; i < n; i++) {
            boolean minority = gen.nextDouble() < 0.17;
            labels[i] = minority ? 1 : 0;
            if (minority) minorityCount++;
        }

        TrainTestSplit.Split split = TrainTestSplit.stratifiedSplit(labels, 0.2, 42);

        assertEquals(n, split.trainIndices().length + split.testIndices().length);
        assertTrue(Math.abs(split.testIndices().length - n * 0.2) <= n * 0.01);

        int testMinority = 0;
        for (int idx : split.testIndices()) {
            if (labels[idx] == 1) testMinority++;
        }
        double testMinorityFraction = (double) testMinority / split.testIndices().length;
        double overallMinorityFraction = (double) minorityCount / n;
        assertTrue(Math.abs(testMinorityFraction - overallMinorityFraction) < 0.03,
            "expected ~" + overallMinorityFraction + " got " + testMinorityFraction);
    }

    @Test
    void trainAndTestIndicesAreDisjointAndCoverAllRows() {
        int[] labels = {0, 0, 0, 0, 1, 1, 1, 1, 0, 1};
        TrainTestSplit.Split split = TrainTestSplit.stratifiedSplit(labels, 0.3, 7);
        java.util.Set<Integer> all = new java.util.HashSet<>();
        for (int i : split.trainIndices()) assertTrue(all.add(i));
        for (int i : split.testIndices()) assertTrue(all.add(i));
        assertEquals(labels.length, all.size());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mvn -q test -Dtest=FeaturesTest,TrainTestSplitTest`
Expected: FAIL — `Features` and `TrainTestSplit` classes do not exist (compile error).

- [ ] **Step 3: Write the implementation**

```java
package com.acs;

import tech.tablesaw.api.Table;

public final class Features {
    public static final String[] COLUMNS =
        {"amount", "velocity_score", "device_risk_score", "is_cross_border", "time_diff"};

    private Features() {
    }

    public static double[][] extract(Table df, String[] columns, int[] rowIndices) {
        double[][] colData = new double[columns.length][];
        for (int c = 0; c < columns.length; c++) {
            colData[c] = df.doubleColumn(columns[c]).asDoubleArray();
        }
        double[][] result = new double[rowIndices.length][columns.length];
        for (int r = 0; r < rowIndices.length; r++) {
            for (int c = 0; c < columns.length; c++) {
                result[r][c] = colData[c][rowIndices[r]];
            }
        }
        return result;
    }

    public static double[][] extractAll(Table df, String[] columns) {
        int[] all = new int[df.rowCount()];
        for (int i = 0; i < all.length; i++) {
            all[i] = i;
        }
        return extract(df, columns, all);
    }
}
```

```java
package com.acs.ml;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

public class TrainTestSplit {

    public record Split(int[] trainIndices, int[] testIndices) {
    }

    public static Split stratifiedSplit(int[] labels, double testSize, long seed) {
        Map<Integer, List<Integer>> byClass = new TreeMap<>();
        for (int i = 0; i < labels.length; i++) {
            byClass.computeIfAbsent(labels[i], k -> new ArrayList<>()).add(i);
        }

        Random random = new Random(seed);
        List<Integer> trainIdx = new ArrayList<>();
        List<Integer> testIdx = new ArrayList<>();

        for (List<Integer> indices : byClass.values()) {
            List<Integer> shuffled = new ArrayList<>(indices);
            Collections.shuffle(shuffled, random);
            int testCount = (int) Math.round(shuffled.size() * testSize);
            testIdx.addAll(shuffled.subList(0, testCount));
            trainIdx.addAll(shuffled.subList(testCount, shuffled.size()));
        }

        return new Split(toArray(trainIdx), toArray(testIdx));
    }

    private static int[] toArray(List<Integer> list) {
        int[] arr = new int[list.size()];
        for (int i = 0; i < arr.length; i++) {
            arr[i] = list.get(i);
        }
        return arr;
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mvn -q test -Dtest=FeaturesTest,TrainTestSplitTest`
Expected: `Tests run: 4, Failures: 0, Errors: 0`

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/acs/Features.java src/main/java/com/acs/ml/TrainTestSplit.java \
        src/test/java/com/acs/FeaturesTest.java src/test/java/com/acs/ml/TrainTestSplitTest.java
git commit -m "Add feature-matrix extraction and stratified train/test split utilities"
```

---

### Task 5: ml.IsolationForest

**Files:**
- Create: `src/main/java/com/acs/ml/IsolationForest.java`
- Test: `src/test/java/com/acs/ml/IsolationForestTest.java`

**Interfaces:**
- Produces: `new IsolationForest(double contamination, long seed)`, `.fit(double[][] x)`, `.predict(double[][] x)` → `int[]` (1 = anomaly, matching Python's `(predict == -1)` convention).
- Algorithm-faithful port of scikit-learn's `IsolationForest`: 100 trees (sklearn default `n_estimators`), `max_samples = min(256, n)` per tree (sklearn default `"auto"`), random feature + random split-value partitioning, average-path-length correction factor `c(n) = 2(ln(n-1) + γ) - 2(n-1)/n`, anomaly score `2^(-E(h(x))/c(n))`, contamination-based percentile threshold. Verified via a standalone spike: on 500 points (490 normal + 10 synthetic outliers) with `contamination=0.02`, flags exactly the 10 true outliers and nothing else.

- [ ] **Step 1: Write the failing test**

```java
package com.acs.ml;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IsolationForestTest {
    @Test
    void flagsObviousSyntheticOutliers() {
        Random gen = new Random(1);
        int n = 500;
        double[][] data = new double[n][2];
        for (int i = 0; i < n - 10; i++) {
            data[i][0] = gen.nextGaussian();
            data[i][1] = gen.nextGaussian();
        }
        for (int i = n - 10; i < n; i++) {
            data[i][0] = 20 + gen.nextGaussian();
            data[i][1] = 20 + gen.nextGaussian();
        }

        IsolationForest forest = new IsolationForest(0.02, 42);
        forest.fit(data);
        int[] preds = forest.predict(data);

        int outliersFlagged = 0;
        for (int i = n - 10; i < n; i++) {
            outliersFlagged += preds[i];
        }
        assertEquals(10, outliersFlagged, "all 10 synthetic outliers should be flagged");
        assertEquals(10, Arrays.stream(preds).sum(), "contamination=0.02 on 500 points should flag ~10 total");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q test -Dtest=IsolationForestTest`
Expected: FAIL — `IsolationForest` class does not exist (compile error).

- [ ] **Step 3: Write the implementation**

```java
package com.acs.ml;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class IsolationForest {
    private static final double EULER_MASCHERONI = 0.5772156649015329;
    private static final int MAX_SAMPLES = 256;

    private final int nEstimators;
    private final double contamination;
    private final Random random;

    private Tree[] trees;
    private double threshold;
    private int sampleSizeUsed;

    public IsolationForest(double contamination, long seed) {
        this(100, contamination, seed);
    }

    public IsolationForest(int nEstimators, double contamination, long seed) {
        this.nEstimators = nEstimators;
        this.contamination = contamination;
        this.random = new Random(seed);
    }

    public void fit(double[][] x) {
        int n = x.length;
        sampleSizeUsed = Math.min(MAX_SAMPLES, n);
        int heightLimit = (int) Math.ceil(log2(sampleSizeUsed));
        trees = new Tree[nEstimators];

        for (int t = 0; t < nEstimators; t++) {
            int[] sampleIdx = sampleWithoutReplacement(n, sampleSizeUsed);
            double[][] sample = new double[sampleSizeUsed][];
            for (int i = 0; i < sampleSizeUsed; i++) {
                sample[i] = x[sampleIdx[i]];
            }
            trees[t] = new Tree(buildNode(sample, 0, heightLimit));
        }

        double[] scores = scoreAll(x);
        threshold = percentile(scores, (1.0 - contamination) * 100.0);
    }

    public double[] scoreAll(double[][] x) {
        double[] scores = new double[x.length];
        for (int i = 0; i < x.length; i++) {
            scores[i] = score(x[i]);
        }
        return scores;
    }

    public double score(double[] point) {
        double avgPathLength = 0;
        for (Tree tree : trees) {
            avgPathLength += pathLength(tree.root, point, 0);
        }
        avgPathLength /= trees.length;
        double c = averagePathLengthCFactor(sampleSizeUsed);
        return Math.pow(2, -avgPathLength / c);
    }

    /** 1 = anomaly, 0 = normal — matches Python's (IsolationForest.predict(x) == -1) convention. */
    public int[] predict(double[][] x) {
        double[] scores = scoreAll(x);
        int[] result = new int[x.length];
        for (int i = 0; i < x.length; i++) {
            result[i] = scores[i] >= threshold ? 1 : 0;
        }
        return result;
    }

    private double pathLength(Node node, double[] point, int depth) {
        if (node.isLeaf()) {
            return depth + averagePathLengthCFactor(node.size);
        }
        if (point[node.splitFeature] < node.splitValue) {
            return pathLength(node.left, point, depth + 1);
        }
        return pathLength(node.right, point, depth + 1);
    }

    private Node buildNode(double[][] sample, int depth, int heightLimit) {
        int n = sample.length;
        if (depth >= heightLimit || n <= 1) {
            return Node.leaf(n);
        }
        int features = sample[0].length;
        int feature = random.nextInt(features);

        double min = Double.POSITIVE_INFINITY;
        double max = Double.NEGATIVE_INFINITY;
        for (double[] row : sample) {
            min = Math.min(min, row[feature]);
            max = Math.max(max, row[feature]);
        }
        if (min == max) {
            return Node.leaf(n);
        }
        double splitValue = min + random.nextDouble() * (max - min);

        List<double[]> left = new ArrayList<>();
        List<double[]> right = new ArrayList<>();
        for (double[] row : sample) {
            if (row[feature] < splitValue) {
                left.add(row);
            } else {
                right.add(row);
            }
        }
        if (left.isEmpty() || right.isEmpty()) {
            return Node.leaf(n);
        }

        Node node = Node.internal(feature, splitValue);
        node.left = buildNode(left.toArray(new double[0][]), depth + 1, heightLimit);
        node.right = buildNode(right.toArray(new double[0][]), depth + 1, heightLimit);
        return node;
    }

    private int[] sampleWithoutReplacement(int n, int sampleSize) {
        int[] all = new int[n];
        for (int i = 0; i < n; i++) {
            all[i] = i;
        }
        for (int i = n - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            int tmp = all[i];
            all[i] = all[j];
            all[j] = tmp;
        }
        return Arrays.copyOf(all, sampleSize);
    }

    private static double log2(double v) {
        return Math.log(v) / Math.log(2);
    }

    private static double averagePathLengthCFactor(int n) {
        if (n <= 1) {
            return 0;
        }
        return 2 * (Math.log(n - 1) + EULER_MASCHERONI) - (2.0 * (n - 1) / n);
    }

    private static double percentile(double[] values, double p) {
        double[] sorted = values.clone();
        Arrays.sort(sorted);
        double rank = (p / 100.0) * (sorted.length - 1);
        int lower = (int) Math.floor(rank);
        int upper = (int) Math.ceil(rank);
        if (lower == upper) {
            return sorted[lower];
        }
        double frac = rank - lower;
        return sorted[lower] + frac * (sorted[upper] - sorted[lower]);
    }

    private static final class Tree {
        final Node root;

        Tree(Node root) {
            this.root = root;
        }
    }

    private static final class Node {
        int splitFeature;
        double splitValue;
        int size;
        Node left;
        Node right;

        static Node leaf(int size) {
            Node node = new Node();
            node.size = size;
            return node;
        }

        static Node internal(int feature, double value) {
            Node node = new Node();
            node.splitFeature = feature;
            node.splitValue = value;
            return node;
        }

        boolean isLeaf() {
            return left == null && right == null;
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q test -Dtest=IsolationForestTest`
Expected: `Tests run: 1, Failures: 0, Errors: 0`

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/acs/ml/IsolationForest.java src/test/java/com/acs/ml/IsolationForestTest.java
git commit -m "Hand-port sklearn-algorithm-faithful IsolationForest"
```

---

### Task 6: ml.KdTree + ml.SmoteTomek

**Files:**
- Create: `src/main/java/com/acs/ml/KdTree.java`
- Create: `src/main/java/com/acs/ml/SmoteTomek.java`
- Test: `src/test/java/com/acs/ml/SmoteTomekTest.java`

**Interfaces:**
- Produces: `new KdTree(double[][] points)`, `.kNearest(int queryIndex, int k)` → `int[]` (k nearest neighbor indices to `points[queryIndex]`, excluding itself), `.kNearest(double[] query, int k, int excludeIndex)` → `int[]` (general form, `excludeIndex = -1` for none).
- Produces: `SmoteTomek.Result` record with `double[] x()`/`int[] y()` renamed... actually `double[][] x()` / `int[] y()`, and `new SmoteTomek(long seed)` (default `k=5`, matching imbalanced-learn's default `k_neighbors`), `.fitResample(double[][] x, int[] y)` → `Result`.
- Consumes: nothing external.

`KdTree` is used only by `SmoteTomek` in this project — it exists to make Tomek-link detection (an all-pairs nearest-neighbor problem) run in `O(n log n)` instead of `O(n^2)`, which matters at the real dataset's post-SMOTE training-set size (~150K+ rows). Verified via spikes: on two well-separated synthetic clusters, `SmoteTomek` balances classes exactly with zero Tomek removals (no cross-class mutual nearest neighbors exist); on two overlapping clusters, it both balances the minority class to the majority count *and* removes majority-class points that are mutual nearest neighbors with a minority point.

- [ ] **Step 1: Write the failing test**

```java
package com.acs.ml;

import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SmoteTomekTest {
    @Test
    void balancesWellSeparatedClassesWithNoTomekRemoval() {
        Random gen = new Random(7);
        int nMajority = 200;
        int nMinority = 20;
        double[][] x = new double[nMajority + nMinority][2];
        int[] y = new int[nMajority + nMinority];
        for (int i = 0; i < nMajority; i++) {
            x[i][0] = gen.nextGaussian();
            x[i][1] = gen.nextGaussian();
            y[i] = 0;
        }
        for (int i = 0; i < nMinority; i++) {
            x[nMajority + i][0] = 10 + gen.nextGaussian();
            x[nMajority + i][1] = 10 + gen.nextGaussian();
            y[nMajority + i] = 1;
        }

        SmoteTomek.Result r = new SmoteTomek(42).fitResample(x, y);

        int c0 = 0;
        int c1 = 0;
        for (int label : r.y()) {
            if (label == 0) c0++; else c1++;
        }
        assertEquals(nMajority, c0, "well-separated majority should be untouched by Tomek cleaning");
        assertEquals(nMajority, c1, "minority should be oversampled up to majority count");

        for (double[] row : r.x()) {
            for (double v : row) {
                assertFalse(Double.isNaN(v) || Double.isInfinite(v));
            }
        }
    }

    @Test
    void removesMajorityPointsInvolvedInTomekLinksWhenClassesOverlap() {
        Random gen = new Random(3);
        int nMajority = 200;
        int nMinority = 20;
        double[][] x = new double[nMajority + nMinority][2];
        int[] y = new int[nMajority + nMinority];
        for (int i = 0; i < nMajority; i++) {
            x[i][0] = gen.nextGaussian();
            x[i][1] = gen.nextGaussian();
            y[i] = 0;
        }
        for (int i = 0; i < nMinority; i++) {
            x[nMajority + i][0] = gen.nextGaussian() * 0.5;
            x[nMajority + i][1] = gen.nextGaussian() * 0.5;
            y[nMajority + i] = 1;
        }

        SmoteTomek.Result r = new SmoteTomek(42).fitResample(x, y);

        int c0 = 0;
        int c1 = 0;
        for (int label : r.y()) {
            if (label == 0) c0++; else c1++;
        }
        assertTrue(c0 < nMajority, "overlapping majority points should have some Tomek removals");
        assertEquals(nMajority, c1, "minority should still be oversampled to the pre-cleaning majority count");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q test -Dtest=SmoteTomekTest`
Expected: FAIL — `SmoteTomek`/`KdTree` classes do not exist (compile error).

- [ ] **Step 3: Write `KdTree`**

```java
package com.acs.ml;

import java.util.Arrays;
import java.util.Comparator;
import java.util.PriorityQueue;

/** KD-tree over row-major points, for nearest-neighbor queries in low dimensions. */
public class KdTree {
    private final double[][] points;
    private final Node root;

    private static final class Node {
        final int pointIndex;
        Node left;
        Node right;

        Node(int pointIndex) {
            this.pointIndex = pointIndex;
        }
    }

    public KdTree(double[][] points) {
        this.points = points;
        Integer[] idx = new Integer[points.length];
        for (int i = 0; i < points.length; i++) {
            idx[i] = i;
        }
        this.root = build(idx, 0, idx.length, 0);
    }

    private int dims() {
        return points[0].length;
    }

    private Node build(Integer[] idx, int start, int end, int depth) {
        if (start >= end) {
            return null;
        }
        int axis = depth % dims();
        Arrays.sort(idx, start, end, Comparator.comparingDouble(i -> points[i][axis]));
        int mid = start + (end - start) / 2;
        Node node = new Node(idx[mid]);
        node.left = build(idx, start, mid, depth + 1);
        node.right = build(idx, mid + 1, end, depth + 1);
        return node;
    }

    private double distSq(double[] a, int b) {
        double sum = 0;
        double[] pb = points[b];
        for (int i = 0; i < a.length; i++) {
            double d = a[i] - pb[i];
            sum += d * d;
        }
        return sum;
    }

    /** k nearest neighbors to points[queryIndex], excluding itself. */
    public int[] kNearest(int queryIndex, int k) {
        return kNearest(points[queryIndex], k, queryIndex);
    }

    /** k nearest neighbors to an arbitrary query point, optionally excluding one point index (-1 for none). */
    public int[] kNearest(double[] query, int k, int excludeIndex) {
        PriorityQueue<Integer> heap = new PriorityQueue<>(
            (a, b) -> Double.compare(distSq(query, b), distSq(query, a))
        );
        search(root, query, k, excludeIndex, heap, 0);
        int[] result = new int[heap.size()];
        for (int i = result.length - 1; i >= 0; i--) {
            result[i] = heap.poll();
        }
        return result;
    }

    private void search(Node node, double[] query, int k, int excludeIndex, PriorityQueue<Integer> heap, int depth) {
        if (node == null) {
            return;
        }
        if (node.pointIndex != excludeIndex) {
            double d = distSq(query, node.pointIndex);
            if (heap.size() < k) {
                heap.offer(node.pointIndex);
            } else if (d < distSq(query, heap.peek())) {
                heap.poll();
                heap.offer(node.pointIndex);
            }
        }
        int axis = depth % dims();
        double diff = query[axis] - points[node.pointIndex][axis];
        Node near = diff <= 0 ? node.left : node.right;
        Node far = diff <= 0 ? node.right : node.left;
        search(near, query, k, excludeIndex, heap, depth + 1);
        if (heap.size() < k || diff * diff < distSq(query, heap.peek())) {
            search(far, query, k, excludeIndex, heap, depth + 1);
        }
    }
}
```

- [ ] **Step 4: Write `SmoteTomek`**

```java
package com.acs.ml;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

public class SmoteTomek {
    private final int kNeighbors;
    private final Random random;

    public record Result(double[][] x, int[] y) {
    }

    public SmoteTomek(long seed) {
        this(5, seed);
    }

    public SmoteTomek(int kNeighbors, long seed) {
        this.kNeighbors = kNeighbors;
        this.random = new Random(seed);
    }

    public Result fitResample(double[][] x, int[] y) {
        Result oversampled = smote(x, y);
        return tomekClean(oversampled.x(), oversampled.y());
    }

    private Result smote(double[][] x, int[] y) {
        Map<Integer, List<Integer>> byClass = groupByClass(y);
        int majorityCount = byClass.values().stream().mapToInt(List::size).max().orElse(0);
        int minorityLabel = byClass.entrySet().stream()
            .min(Comparator.comparingInt(e -> e.getValue().size()))
            .orElseThrow().getKey();
        List<Integer> minorityIdx = byClass.get(minorityLabel);
        int minorityCount = minorityIdx.size();
        int toGenerate = majorityCount - minorityCount;
        if (toGenerate <= 0) {
            return new Result(x, y);
        }

        double[][] minorityPoints = new double[minorityCount][];
        for (int i = 0; i < minorityCount; i++) {
            minorityPoints[i] = x[minorityIdx.get(i)];
        }
        int k = Math.min(kNeighbors, minorityCount - 1);
        KdTree minorityTree = k > 0 ? new KdTree(minorityPoints) : null;

        List<double[]> synthetic = new ArrayList<>(toGenerate);
        for (int g = 0; g < toGenerate; g++) {
            int baseIdx = random.nextInt(minorityCount);
            double[] base = minorityPoints[baseIdx];
            double[] neighborPoint = base;
            if (minorityTree != null) {
                int[] neighbors = minorityTree.kNearest(baseIdx, k);
                int chosen = neighbors[random.nextInt(neighbors.length)];
                neighborPoint = minorityPoints[chosen];
            }
            double gap = random.nextDouble();
            double[] newPoint = new double[base.length];
            for (int f = 0; f < base.length; f++) {
                newPoint[f] = base[f] + gap * (neighborPoint[f] - base[f]);
            }
            synthetic.add(newPoint);
        }

        double[][] xOut = new double[x.length + synthetic.size()][];
        int[] yOut = new int[x.length + synthetic.size()];
        System.arraycopy(x, 0, xOut, 0, x.length);
        System.arraycopy(y, 0, yOut, 0, y.length);
        for (int i = 0; i < synthetic.size(); i++) {
            xOut[x.length + i] = synthetic.get(i);
            yOut[x.length + i] = minorityLabel;
        }
        return new Result(xOut, yOut);
    }

    private Result tomekClean(double[][] x, int[] y) {
        KdTree tree = new KdTree(x);
        int n = x.length;
        int[] nearest = new int[n];
        for (int i = 0; i < n; i++) {
            nearest[i] = tree.kNearest(i, 1)[0];
        }

        Map<Integer, List<Integer>> byClass = groupByClass(y);
        int majorityLabel = byClass.entrySet().stream()
            .max(Comparator.comparingInt(e -> e.getValue().size()))
            .orElseThrow().getKey();

        boolean[] remove = new boolean[n];
        for (int i = 0; i < n; i++) {
            int j = nearest[i];
            if (y[i] != y[j] && nearest[j] == i) {
                if (y[i] == majorityLabel) {
                    remove[i] = true;
                }
                if (y[j] == majorityLabel) {
                    remove[j] = true;
                }
            }
        }

        List<double[]> xOut = new ArrayList<>();
        List<Integer> yOut = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            if (!remove[i]) {
                xOut.add(x[i]);
                yOut.add(y[i]);
            }
        }
        double[][] xArr = xOut.toArray(new double[0][]);
        int[] yArr = new int[yOut.size()];
        for (int i = 0; i < yArr.length; i++) {
            yArr[i] = yOut.get(i);
        }
        return new Result(xArr, yArr);
    }

    private Map<Integer, List<Integer>> groupByClass(int[] y) {
        Map<Integer, List<Integer>> byClass = new TreeMap<>();
        for (int i = 0; i < y.length; i++) {
            byClass.computeIfAbsent(y[i], k -> new ArrayList<>()).add(i);
        }
        return byClass;
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `mvn -q test -Dtest=SmoteTomekTest`
Expected: `Tests run: 2, Failures: 0, Errors: 0`

- [ ] **Step 6: Commit**

```bash
git add src/main/java/com/acs/ml/KdTree.java src/main/java/com/acs/ml/SmoteTomek.java \
        src/test/java/com/acs/ml/SmoteTomekTest.java
git commit -m "Hand-port imbalanced-learn-algorithm-faithful SmoteTomek with KD-tree neighbor search"
```

---

### Task 7: Simple agents (PolicyAgent, RiskAgent, HumanAgent, AuditLayer)

**Files:**
- Create: `src/main/java/com/acs/agents/PolicyAgent.java`
- Create: `src/main/java/com/acs/agents/RiskAgent.java`
- Create: `src/main/java/com/acs/agents/HumanAgent.java`
- Create: `src/main/java/com/acs/agents/AuditLayer.java`
- Test: `src/test/java/com/acs/agents/SimpleAgentsTest.java`

**Interfaces:**
- Produces: `PolicyAgent.evaluate(Table df)` → `int[]` (the `compliance_violation` column). `RiskAgent.compute(Table df)` → `double[]` (`0.4*velocity_score + 0.3*device_risk_score + 0.3*is_cross_border`). `HumanAgent.review(double amount)` → `int` (1 = reject, `amount > 20000`). `AuditLayer.log(int transactionId, String decision)` (appends `sha256(transactionId + decision)` to an internal log), `.logs()` → `List<String>`.
- Consumes: `FeatureEngineering` output columns (Task 3): `compliance_violation`, `velocity_score`, `device_risk_score`, `is_cross_border`.

- [ ] **Step 1: Write the failing test**

```java
package com.acs.agents;

import org.junit.jupiter.api.Test;
import tech.tablesaw.api.DoubleColumn;
import tech.tablesaw.api.IntColumn;
import tech.tablesaw.api.Table;

import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SimpleAgentsTest {

    @Test
    void policyAgentPassesThroughComplianceViolation() {
        Table df = Table.create("t", IntColumn.create("compliance_violation", 0, 1, 0));
        assertArrayEquals(new int[]{0, 1, 0}, new PolicyAgent().evaluate(df));
    }

    @Test
    void riskAgentComputesWeightedComposite() {
        Table df = Table.create("t",
            DoubleColumn.create("velocity_score", 1.0),
            DoubleColumn.create("device_risk_score", 1.0),
            DoubleColumn.create("is_cross_border", 1.0)
        );
        double[] result = new RiskAgent().compute(df);
        assertEquals(1.0, result[0], 0.0001); // 0.4 + 0.3 + 0.3
    }

    @Test
    void humanAgentRejectsAboveTwentyThousand() {
        HumanAgent human = new HumanAgent();
        assertEquals(1, human.review(20000.01));
        assertEquals(0, human.review(20000.0));
        assertEquals(0, human.review(19999.99));
    }

    @Test
    void auditLayerLogsSha256OfTransactionIdAndDecision() throws Exception {
        AuditLayer audit = new AuditLayer();
        audit.log(6, "FLAGGED");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest("6FLAGGED".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        StringBuilder expected = new StringBuilder();
        for (byte b : hash) {
            expected.append(String.format("%02x", b));
        }
        assertEquals(1, audit.logs().size());
        assertEquals(expected.toString(), audit.logs().get(0));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q test -Dtest=SimpleAgentsTest`
Expected: FAIL — agent classes do not exist (compile error).

- [ ] **Step 3: Write the implementations**

```java
package com.acs.agents;

import tech.tablesaw.api.Table;

public class PolicyAgent {
    public int[] evaluate(Table df) {
        return df.intColumn("compliance_violation").asIntArray();
    }
}
```

```java
package com.acs.agents;

import tech.tablesaw.api.Table;

public class RiskAgent {
    public double[] compute(Table df) {
        double[] velocity = df.doubleColumn("velocity_score").asDoubleArray();
        double[] deviceRisk = df.doubleColumn("device_risk_score").asDoubleArray();
        double[] crossBorder = df.doubleColumn("is_cross_border").asDoubleArray();
        double[] result = new double[velocity.length];
        for (int i = 0; i < result.length; i++) {
            result[i] = 0.4 * velocity[i] + 0.3 * deviceRisk[i] + 0.3 * crossBorder[i];
        }
        return result;
    }
}
```

```java
package com.acs.agents;

public class HumanAgent {
    /** 1 = reject, matching Python's HumanAgent.review. */
    public int review(double amount) {
        return amount > 20000 ? 1 : 0;
    }
}
```

```java
package com.acs.agents;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class AuditLayer {
    private final List<String> logs = new ArrayList<>();

    public void log(int transactionId, String decision) {
        String record = transactionId + decision;
        logs.add(sha256(record));
    }

    public List<String> logs() {
        return logs;
    }

    private static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mvn -q test -Dtest=SimpleAgentsTest`
Expected: `Tests run: 4, Failures: 0, Errors: 0`

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/acs/agents/PolicyAgent.java src/main/java/com/acs/agents/RiskAgent.java \
        src/main/java/com/acs/agents/HumanAgent.java src/main/java/com/acs/agents/AuditLayer.java \
        src/test/java/com/acs/agents/SimpleAgentsTest.java
git commit -m "Port PolicyAgent, RiskAgent, HumanAgent, AuditLayer"
```

---

### Task 8: agents.AnomalyAgent

**Files:**
- Create: `src/main/java/com/acs/agents/AnomalyAgent.java`
- Test: `src/test/java/com/acs/agents/AnomalyAgentTest.java`

**Interfaces:**
- Consumes: `com.acs.ml.IsolationForest` (Task 5).
- Produces: `new AnomalyAgent()` (defaults `contamination=0.02, randomState=42`, matching Python), `.train(double[][] x)`, `.predict(double[][] x)` → `int[]`.

- [ ] **Step 1: Write the failing test**

```java
package com.acs.agents;

import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertTrue;

class AnomalyAgentTest {
    @Test
    void flagsOutliersAfterTraining() {
        Random gen = new Random(2);
        int n = 300;
        double[][] data = new double[n][3];
        for (int i = 0; i < n - 6; i++) {
            data[i][0] = gen.nextGaussian();
            data[i][1] = gen.nextGaussian();
            data[i][2] = gen.nextGaussian();
        }
        for (int i = n - 6; i < n; i++) {
            data[i][0] = 15 + gen.nextGaussian();
            data[i][1] = 15 + gen.nextGaussian();
            data[i][2] = 15 + gen.nextGaussian();
        }

        AnomalyAgent agent = new AnomalyAgent();
        agent.train(data);
        int[] preds = agent.predict(data);

        int outlierFlags = 0;
        for (int i = n - 6; i < n; i++) {
            outlierFlags += preds[i];
        }
        assertTrue(outlierFlags >= 5, "most synthetic outliers should be flagged");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q test -Dtest=AnomalyAgentTest`
Expected: FAIL — `AnomalyAgent` class does not exist (compile error).

- [ ] **Step 3: Write the implementation**

```java
package com.acs.agents;

import com.acs.ml.IsolationForest;

public class AnomalyAgent {
    private final IsolationForest model;

    public AnomalyAgent() {
        this(0.02, 42);
    }

    public AnomalyAgent(double contamination, long randomState) {
        this.model = new IsolationForest(contamination, randomState);
    }

    public void train(double[][] x) {
        model.fit(x);
    }

    public int[] predict(double[][] x) {
        return model.predict(x);
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q test -Dtest=AnomalyAgentTest`
Expected: `Tests run: 1, Failures: 0, Errors: 0`

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/acs/agents/AnomalyAgent.java src/test/java/com/acs/agents/AnomalyAgentTest.java
git commit -m "Port AnomalyAgent wrapping hand-ported IsolationForest"
```

---

### Task 9: agents.MLAgent (XGBoost4J)

**Files:**
- Create: `src/main/java/com/acs/agents/MLAgent.java`
- Test: `src/test/java/com/acs/agents/MLAgentTest.java`

**Interfaces:**
- Produces: `new MLAgent()` (defaults matching Python's `MLAgent`: `n_estimators=300, max_depth=8, learning_rate=0.05, scale_pos_weight=10, random_state=42, eval_metric="logloss"`), `.train(double[][] x, int[] y)`, `.predictProba(double[][] x)` → `double[]` (probability of class 1).
- Consumes: `ml.dmlc:xgboost4j_2.12` (pom.xml, Task 1).

**Before running this task's tests:** confirm `brew install libomp` has been run on this machine (see Global Constraints) — without it, `DMatrix`/`XGBoost.train` throw `UnsatisfiedLinkError`, not a normal test failure. If you see that error, run `brew install libomp` and retry; it is not a bug in this code.

- [ ] **Step 1: Write the failing test**

```java
package com.acs.agents;

import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertTrue;

class MLAgentTest {
    @Test
    void trainsAndPredictsSeparableClasses() {
        Random gen = new Random(42);
        int n = 200;
        double[][] x = new double[n][2];
        int[] y = new int[n];
        for (int i = 0; i < n; i++) {
            boolean fraud = i % 5 == 0;
            x[i][0] = fraud ? 5 + gen.nextDouble() : gen.nextDouble();
            x[i][1] = fraud ? 5 + gen.nextDouble() : gen.nextDouble();
            y[i] = fraud ? 1 : 0;
        }

        MLAgent agent = new MLAgent();
        agent.train(x, y);
        double[] proba = agent.predictProba(x);

        assertTrue(proba[0] > 0.9, "clearly fraudulent point should get high probability, got " + proba[0]);
        assertTrue(proba[1] < 0.1, "clearly non-fraudulent point should get low probability, got " + proba[1]);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q test -Dtest=MLAgentTest`
Expected: FAIL — `MLAgent` class does not exist (compile error).

- [ ] **Step 3: Write the implementation**

```java
package com.acs.agents;

import ml.dmlc.xgboost4j.java.Booster;
import ml.dmlc.xgboost4j.java.DMatrix;
import ml.dmlc.xgboost4j.java.XGBoost;
import ml.dmlc.xgboost4j.java.XGBoostError;

import java.util.HashMap;
import java.util.Map;

public class MLAgent {
    private final int nEstimators;
    private final Map<String, Object> params;
    private Booster booster;

    public MLAgent() {
        this(300, 8, 0.05, 10, 42);
    }

    public MLAgent(int nEstimators, int maxDepth, double learningRate, int scalePosWeight, int randomState) {
        this.nEstimators = nEstimators;
        this.params = new HashMap<>();
        params.put("max_depth", maxDepth);
        params.put("eta", learningRate);
        params.put("scale_pos_weight", scalePosWeight);
        params.put("seed", randomState);
        params.put("eval_metric", "logloss");
        params.put("objective", "binary:logistic");
    }

    public void train(double[][] x, int[] y) {
        try {
            DMatrix train = new DMatrix(flatten(x), x.length, x[0].length, Float.NaN);
            train.setLabel(toFloatLabels(y));
            booster = XGBoost.train(train, params, nEstimators, new HashMap<>(), null, null);
        } catch (XGBoostError e) {
            throw new RuntimeException(e);
        }
    }

    public double[] predictProba(double[][] x) {
        try {
            DMatrix test = new DMatrix(flatten(x), x.length, x[0].length, Float.NaN);
            float[][] raw = booster.predict(test);
            double[] result = new double[raw.length];
            for (int i = 0; i < raw.length; i++) {
                result[i] = raw[i][0];
            }
            return result;
        } catch (XGBoostError e) {
            throw new RuntimeException(e);
        }
    }

    private static float[] flatten(double[][] x) {
        int rows = x.length;
        int cols = x[0].length;
        float[] flat = new float[rows * cols];
        for (int r = 0; r < rows; r++) {
            for (int c = 0; c < cols; c++) {
                flat[r * cols + c] = (float) x[r][c];
            }
        }
        return flat;
    }

    private static float[] toFloatLabels(int[] y) {
        float[] labels = new float[y.length];
        for (int i = 0; i < y.length; i++) {
            labels[i] = y[i];
        }
        return labels;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q test -Dtest=MLAgentTest`
Expected: `Tests run: 1, Failures: 0, Errors: 0`. If it fails with `UnsatisfiedLinkError`, run `brew install libomp` and retry.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/acs/agents/MLAgent.java src/test/java/com/acs/agents/MLAgentTest.java
git commit -m "Port MLAgent wrapping XGBoost4J with matching hyperparameters"
```

---

### Task 10: AcsOrchestrator

**Files:**
- Create: `src/main/java/com/acs/AcsOrchestrator.java`
- Test: `src/test/java/com/acs/AcsOrchestratorTest.java`

**Interfaces:**
- Consumes: `Features` (Task 4), all six agents (Tasks 7–9).
- Produces: `new AcsOrchestrator()` (default `flagThreshold=0.8`), `.run(Table df, double[][] xTrainResampled, int[] yTrainResampled, int[] testIdx)` → `Table` with columns `transaction_id` (int), `is_fraud` (int), `decision` (string, one of `APPROVED`/`FLAGGED`/`REJECTED`), one row per `testIdx` entry. `.audit()` → the internal `AuditLayer`, so `RunPipeline` (Task 12) can inspect logs if needed.

Mirrors Python's `ACS_Orchestrator.run` exactly, including the fact that `AnomalyAgent` trains and predicts on **every row of `df`** (not just the training split) while `MLAgent` trains only on the resampled training set and predicts only on `testIdx` — this is what the Python source does, not a bug to fix.

- [ ] **Step 1: Write the failing test**

```java
package com.acs;

import org.junit.jupiter.api.Test;
import tech.tablesaw.api.DoubleColumn;
import tech.tablesaw.api.IntColumn;
import tech.tablesaw.api.Table;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AcsOrchestratorTest {
    @Test
    void producesOneDecisionPerTestRowFromKnownVocabulary() {
        Random gen = new Random(5);
        int n = 200;
        int[] transactionId = new int[n];
        double[] amount = new double[n];
        double[] velocity = new double[n];
        double[] deviceRisk = new double[n];
        double[] crossBorder = new double[n];
        double[] timeDiff = new double[n];
        int[] complianceViolation = new int[n];
        int[] isFraud = new int[n];

        for (int i = 0; i < n; i++) {
            transactionId[i] = i + 1;
            boolean fraud = i % 5 == 0;
            amount[i] = fraud ? 25000 : 50 + gen.nextDouble() * 100;
            velocity[i] = fraud ? 0.9 : gen.nextDouble() * 0.1;
            deviceRisk[i] = fraud ? 0.9 : gen.nextDouble() * 0.1;
            crossBorder[i] = fraud ? 1.0 : 0.0;
            timeDiff[i] = gen.nextDouble() * 1000;
            complianceViolation[i] = 0;
            isFraud[i] = fraud ? 1 : 0;
        }

        Table df = Table.create("t",
            IntColumn.create("transaction_id", transactionId),
            DoubleColumn.create("amount", amount),
            DoubleColumn.create("velocity_score", velocity),
            DoubleColumn.create("device_risk_score", deviceRisk),
            DoubleColumn.create("is_cross_border", crossBorder),
            DoubleColumn.create("time_diff", timeDiff),
            IntColumn.create("compliance_violation", complianceViolation),
            IntColumn.create("is_fraud", isFraud)
        );

        double[][] xTrain = Features.extractAll(df, Features.COLUMNS);
        int[] testIdx = new int[n];
        for (int i = 0; i < n; i++) {
            testIdx[i] = i;
        }

        AcsOrchestrator orchestrator = new AcsOrchestrator();
        Table result = orchestrator.run(df, xTrain, isFraud, testIdx);

        assertEquals(n, result.rowCount());
        java.util.Set<String> allowed = java.util.Set.of("APPROVED", "FLAGGED", "REJECTED");
        for (String decision : result.stringColumn("decision").asObjectArray()) {
            assertTrue(allowed.contains(decision));
        }

        boolean anyFlaggedOrRejected = false;
        for (String decision : result.stringColumn("decision").asObjectArray()) {
            if (!decision.equals("APPROVED")) {
                anyFlaggedOrRejected = true;
            }
        }
        assertTrue(anyFlaggedOrRejected, "obviously fraud-like rows should trigger at least one non-APPROVED decision");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q test -Dtest=AcsOrchestratorTest`
Expected: FAIL — `AcsOrchestrator` class does not exist (compile error).

- [ ] **Step 3: Write the implementation**

```java
package com.acs;

import com.acs.agents.AnomalyAgent;
import com.acs.agents.AuditLayer;
import com.acs.agents.HumanAgent;
import com.acs.agents.MLAgent;
import com.acs.agents.PolicyAgent;
import com.acs.agents.RiskAgent;
import tech.tablesaw.api.DoubleColumn;
import tech.tablesaw.api.IntColumn;
import tech.tablesaw.api.StringColumn;
import tech.tablesaw.api.Table;

public class AcsOrchestrator {
    private static final String[] ANOMALY_FEATURES = {"amount", "velocity_score", "device_risk_score"};

    private final AnomalyAgent anomaly = new AnomalyAgent();
    private final PolicyAgent policy = new PolicyAgent();
    private final RiskAgent risk = new RiskAgent();
    private final HumanAgent human = new HumanAgent();
    private final AuditLayer audit = new AuditLayer();
    private final MLAgent ml = new MLAgent();
    private final double flagThreshold;

    public AcsOrchestrator() {
        this(0.8);
    }

    public AcsOrchestrator(double flagThreshold) {
        this.flagThreshold = flagThreshold;
    }

    public AuditLayer audit() {
        return audit;
    }

    public Table run(Table df, double[][] xTrainResampled, int[] yTrainResampled, int[] testIdx) {
        double[][] anomalyInput = Features.extractAll(df, ANOMALY_FEATURES);
        anomaly.train(anomalyInput);
        ml.train(xTrainResampled, yTrainResampled);

        int[] anomalyFlag = anomaly.predict(anomalyInput);
        int[] policyFlag = policy.evaluate(df);
        double[] riskScore = risk.compute(df); // computed for parity with Python's df["risk_score"]; not read below (matches Python, which never reads it either)

        double[][] xTest = Features.extract(df, Features.COLUMNS, testIdx);
        double[] mlScore = ml.predictProba(xTest);

        IntColumn transactionId = df.intColumn("transaction_id");
        IntColumn isFraud = df.intColumn("is_fraud");
        DoubleColumn amount = df.doubleColumn("amount");

        IntColumn resultTxId = IntColumn.create("transaction_id");
        IntColumn resultIsFraud = IntColumn.create("is_fraud");
        StringColumn resultDecision = StringColumn.create("decision");

        for (int i = 0; i < testIdx.length; i++) {
            int row = testIdx[i];
            String decision = "APPROVED";
            double score = 0.75 * mlScore[i] + 0.15 * anomalyFlag[row] + 0.1 * policyFlag[row];
            if (score > flagThreshold) {
                decision = "FLAGGED";
                if (human.review(amount.get(row)) == 1) {
                    decision = "REJECTED";
                }
            }
            audit.log(transactionId.get(row), decision);

            resultTxId.append(transactionId.get(row));
            resultIsFraud.append(isFraud.get(row));
            resultDecision.append(decision);
        }

        return Table.create("result", resultTxId, resultIsFraud, resultDecision);
    }
}
```

**Note on `RiskAgent`:** Python's orchestrator computes `df["risk_score"] = self.risk.compute(df)` but never reads that column afterward — it is dead code in the Python source (verified by grep, same as the dropped join columns from Task 2). The Java port keeps computing it (`riskScore` above) for behavioral parity with the Python source, and it goes unused for the same reason — this is a faithful port of a quirk in the original pipeline, not something to "clean up."

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q test -Dtest=AcsOrchestratorTest`
Expected: `Tests run: 1, Failures: 0, Errors: 0`

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/acs/AcsOrchestrator.java src/test/java/com/acs/AcsOrchestratorTest.java
git commit -m "Port AcsOrchestrator: agent wiring and decision fusion"
```

---

### Task 11: Evaluate

**Files:**
- Create: `src/main/java/com/acs/Evaluate.java`
- Test: `src/test/java/com/acs/EvaluateTest.java`

**Interfaces:**
- Produces: `Evaluate.Metrics` record with `int[][] confusionMatrix()` (`[ [TN, FP], [FN, TP] ]`, same layout as sklearn's `confusion_matrix`), `String report()` (precision/recall/f1-score/support per class + accuracy + macro/weighted avg, same fields as sklearn's `classification_report`), `Map<String, Integer> decisionCounts()`. `Evaluate.evaluateDecisions(int[] isFraud, String[] decisions)` → `Metrics` (a decision counts as predicted-fraud, i.e. `y_pred=1`, whenever it's not `"APPROVED"`).
- Consumes: `AcsOrchestrator.run(...)` output shape (Task 10): `is_fraud` int column, `decision` string column.

- [ ] **Step 1: Write the failing test**

```java
package com.acs;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EvaluateTest {
    @Test
    void computesConfusionMatrixAndDecisionCounts() {
        // 2 true negatives, 1 false positive, 1 false negative, 1 true positive
        int[] isFraud =        {0, 0, 0, 1, 1};
        String[] decisions = {"APPROVED", "APPROVED", "FLAGGED", "APPROVED", "REJECTED"};

        Evaluate.Metrics metrics = Evaluate.evaluateDecisions(isFraud, decisions);

        int[][] cm = metrics.confusionMatrix();
        assertEquals(2, cm[0][0]); // TN
        assertEquals(1, cm[0][1]); // FP
        assertEquals(1, cm[1][0]); // FN
        assertEquals(1, cm[1][1]); // TP

        assertEquals(3, metrics.decisionCounts().get("APPROVED"));
        assertEquals(1, metrics.decisionCounts().get("FLAGGED"));
        assertEquals(1, metrics.decisionCounts().get("REJECTED"));

        String report = metrics.report();
        assertTrue(report.contains("precision"));
        assertTrue(report.contains("recall"));
        assertTrue(report.contains("f1-score"));
        assertTrue(report.contains("accuracy"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q test -Dtest=EvaluateTest`
Expected: FAIL — `Evaluate` class does not exist (compile error).

- [ ] **Step 3: Write the implementation**

```java
package com.acs;

import java.util.LinkedHashMap;
import java.util.Map;

public class Evaluate {

    public record Metrics(int[][] confusionMatrix, String report, Map<String, Integer> decisionCounts) {
    }

    public static Metrics evaluateDecisions(int[] isFraud, String[] decisions) {
        int[] yPred = new int[decisions.length];
        for (int i = 0; i < decisions.length; i++) {
            yPred[i] = decisions[i].equals("APPROVED") ? 0 : 1;
        }

        int[][] cm = new int[2][2];
        for (int i = 0; i < isFraud.length; i++) {
            cm[isFraud[i]][yPred[i]]++;
        }

        String report = classificationReport(cm);

        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String d : decisions) {
            counts.merge(d, 1, Integer::sum);
        }

        return new Metrics(cm, report, counts);
    }

    private static String classificationReport(int[][] cm) {
        int tn = cm[0][0];
        int fp = cm[0][1];
        int fn = cm[1][0];
        int tp = cm[1][1];
        int support0 = tn + fp;
        int support1 = fn + tp;
        int total = support0 + support1;

        double precision0 = safeDiv(tn, tn + fn);
        double recall0 = safeDiv(tn, tn + fp);
        double f1_0 = safeDiv(2 * precision0 * recall0, precision0 + recall0);

        double precision1 = safeDiv(tp, tp + fp);
        double recall1 = safeDiv(tp, tp + fn);
        double f1_1 = safeDiv(2 * precision1 * recall1, precision1 + recall1);

        double accuracy = safeDiv(tn + tp, total);
        double macroPrecision = (precision0 + precision1) / 2;
        double macroRecall = (recall0 + recall1) / 2;
        double macroF1 = (f1_0 + f1_1) / 2;

        double weightedPrecision = total == 0 ? 0 : (precision0 * support0 + precision1 * support1) / total;
        double weightedRecall = total == 0 ? 0 : (recall0 * support0 + recall1 * support1) / total;
        double weightedF1 = total == 0 ? 0 : (f1_0 * support0 + f1_1 * support1) / total;

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%14s%12s%12s%12s%12s%n", "", "precision", "recall", "f1-score", "support"));
        sb.append(String.format("%n"));
        sb.append(String.format("%14s%12.4f%12.4f%12.4f%12d%n", "0", precision0, recall0, f1_0, support0));
        sb.append(String.format("%14s%12.4f%12.4f%12.4f%12d%n", "1", precision1, recall1, f1_1, support1));
        sb.append(String.format("%n"));
        sb.append(String.format("%14s%12s%12s%12.4f%12d%n", "accuracy", "", "", accuracy, total));
        sb.append(String.format("%14s%12.4f%12.4f%12.4f%12d%n", "macro avg", macroPrecision, macroRecall, macroF1, total));
        sb.append(String.format("%14s%12.4f%12.4f%12.4f%12d%n", "weighted avg", weightedPrecision, weightedRecall, weightedF1, total));
        return sb.toString();
    }

    private static double safeDiv(double a, double b) {
        return b == 0 ? 0.0 : a / b;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q test -Dtest=EvaluateTest`
Expected: `Tests run: 1, Failures: 0, Errors: 0`

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/acs/Evaluate.java src/test/java/com/acs/EvaluateTest.java
git commit -m "Port Evaluate: confusion matrix and classification-report formatting"
```

---

### Task 12: RunPipeline (full integration)

**Files:**
- Modify: `src/main/java/com/acs/RunPipeline.java` (replaces the Task 1 placeholder body entirely)
- Test: `src/test/java/com/acs/RunPipelineIntegrationTest.java`

**Interfaces:**
- Consumes: `DataLoader` (Task 2), `FeatureEngineering` (Task 3), `Features`/`TrainTestSplit` (Task 4), `SmoteTomek` (Task 6), `AcsOrchestrator` (Task 10), `Evaluate` (Task 11).
- Produces: running `com.acs.RunPipeline` writes `reports/confusion_matrix.png` and `reports/metrics_summary.txt`, matching the Python `scripts/run_pipeline.py`'s output files and general format (not exact numbers — see the design spec's Non-goals).

This is the task that proves the whole port actually works end-to-end against the real 120,000-row dataset, not just in isolated unit tests.

- [ ] **Step 1: Write the failing integration test**

```java
package com.acs;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

class RunPipelineIntegrationTest {
    @Test
    void runningMainProducesReportFiles() throws Exception {
        Path root = Path.of(System.getProperty("user.dir"));
        Path png = root.resolve("reports/confusion_matrix.png");
        Path txt = root.resolve("reports/metrics_summary.txt");
        Files.deleteIfExists(png);
        Files.deleteIfExists(txt);

        RunPipeline.main(new String[0]);

        assertTrue(Files.exists(png), "confusion_matrix.png should be written");
        assertTrue(Files.size(png) > 0);
        assertTrue(Files.exists(txt), "metrics_summary.txt should be written");
        String content = Files.readString(txt);
        assertTrue(content.contains("precision"));
        assertTrue(content.contains("recall"));
        assertTrue(content.contains("f1-score"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q test -Dtest=RunPipelineIntegrationTest`
Expected: FAIL — `RunPipeline.main` still just prints the Task 1 placeholder message, no files are written.

- [ ] **Step 3: Replace `RunPipeline.java`'s contents**

```java
package com.acs;

import com.acs.ml.SmoteTomek;
import com.acs.ml.TrainTestSplit;
import tech.tablesaw.api.Table;

import java.awt.Color;
import java.awt.FontMetrics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.imageio.ImageIO;

public class RunPipeline {
    private static final Path ROOT = Path.of(System.getProperty("user.dir"));
    private static final Path DATA_DIR = ROOT.resolve("data");
    private static final Path REPORTS_DIR = ROOT.resolve("reports");

    public static void main(String[] args) throws IOException {
        Files.createDirectories(REPORTS_DIR);

        System.out.println("Loading and merging source tables...");
        Table df = DataLoader.buildMergedTable(DATA_DIR);

        System.out.println("Engineering features (compliance + PROVISIONAL risk features)...");
        df = FeatureEngineering.engineerFeatures(df);

        int[] yAll = df.intColumn("is_fraud").asIntArray();
        TrainTestSplit.Split split = TrainTestSplit.stratifiedSplit(yAll, 0.2, 42);

        System.out.println("Balancing training set with SMOTETomek...");
        double[][] xTrain = Features.extract(df, Features.COLUMNS, split.trainIndices());
        int[] yTrain = extractLabels(yAll, split.trainIndices());
        SmoteTomek.Result resampled = new SmoteTomek(42).fitResample(xTrain, yTrain);

        System.out.println("Running ACS orchestrator (anomaly + ML + policy + human-on-the-loop)...");
        AcsOrchestrator acs = new AcsOrchestrator();
        Table result = acs.run(df, resampled.x(), resampled.y(), split.testIndices());

        int[] isFraud = result.intColumn("is_fraud").asIntArray();
        String[] decisions = result.stringColumn("decision").asObjectArray();
        Evaluate.Metrics metrics = Evaluate.evaluateDecisions(isFraud, decisions);

        System.out.println("\n=== Confusion Matrix ===");
        System.out.print(formatMatrix(metrics.confusionMatrix()));
        System.out.println("\n=== Classification Report ===");
        System.out.println(metrics.report());
        System.out.println("\n=== Decision Breakdown ===");
        metrics.decisionCounts().forEach((k, v) -> System.out.println(k + "    " + v));

        Path pngPath = REPORTS_DIR.resolve("confusion_matrix.png");
        writeConfusionMatrixPng(metrics.confusionMatrix(), pngPath);
        System.out.println("\nSaved figure to " + pngPath);

        Path txtPath = REPORTS_DIR.resolve("metrics_summary.txt");
        writeMetricsSummary(metrics, txtPath);
        System.out.println("Saved metrics summary to " + txtPath);
    }

    private static int[] extractLabels(int[] yAll, int[] indices) {
        int[] result = new int[indices.length];
        for (int i = 0; i < indices.length; i++) {
            result[i] = yAll[indices[i]];
        }
        return result;
    }

    private static String formatMatrix(int[][] cm) {
        StringBuilder sb = new StringBuilder();
        for (int[] row : cm) {
            sb.append("[");
            for (int i = 0; i < row.length; i++) {
                sb.append(row[i]);
                if (i < row.length - 1) {
                    sb.append(" ");
                }
            }
            sb.append("]\n");
        }
        return sb.toString();
    }

    private static void writeMetricsSummary(Evaluate.Metrics metrics, Path path) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("ACS pipeline run (provisional/reconstructed velocity_score, ")
          .append("device_risk_score, time_diff -- see FeatureEngineering.java)\n\n");
        sb.append(formatMatrix(metrics.confusionMatrix())).append("\n");
        sb.append(metrics.report()).append("\n\n");
        metrics.decisionCounts().forEach((k, v) -> sb.append(k).append("    ").append(v).append("\n"));
        Files.writeString(path, sb.toString());
    }

    private static void writeConfusionMatrixPng(int[][] cm, Path path) throws IOException {
        int cellSize = 140;
        int labelMargin = 90;
        int titleHeight = 40;
        int width = labelMargin + cellSize * 2;
        int height = titleHeight + cellSize * 2 + 30;

        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(Color.WHITE);
        g.fillRect(0, 0, width, height);
        g.setColor(Color.BLACK);
        g.drawString("Confusion Matrix - ACS Pipeline (reconstructed features)", 10, 20);

        int max = Math.max(Math.max(cm[0][0], cm[0][1]), Math.max(cm[1][0], cm[1][1]));
        for (int r = 0; r < 2; r++) {
            for (int c = 0; c < 2; c++) {
                int x = labelMargin + c * cellSize;
                int y = titleHeight + r * cellSize;
                float intensity = max == 0 ? 0f : (float) cm[r][c] / max;
                g.setColor(blend(Color.WHITE, new Color(0x1f77b4), intensity));
                g.fillRect(x, y, cellSize, cellSize);
                g.setColor(intensity > 0.5f ? Color.WHITE : Color.BLACK);
                String text = String.valueOf(cm[r][c]);
                FontMetrics fm = g.getFontMetrics();
                int tw = fm.stringWidth(text);
                g.drawString(text, x + (cellSize - tw) / 2, y + cellSize / 2);
            }
        }

        g.setColor(Color.BLACK);
        g.drawString("Pred: Approved", labelMargin + 10, titleHeight + cellSize * 2 + 15);
        g.drawString("Pred: Flagged/Rejected", labelMargin + cellSize + 10, titleHeight + cellSize * 2 + 15);
        g.dispose();

        ImageIO.write(image, "png", path.toFile());
    }

    private static Color blend(Color a, Color b, float t) {
        int r = (int) (a.getRed() + (b.getRed() - a.getRed()) * t);
        int g = (int) (a.getGreen() + (b.getGreen() - a.getGreen()) * t);
        int bl = (int) (a.getBlue() + (b.getBlue() - a.getBlue()) * t);
        return new Color(r, g, bl);
    }
}
```

- [ ] **Step 4: Run the integration test**

Run: `mvn -q test -Dtest=RunPipelineIntegrationTest` (this takes a minute or two — it runs the real 120,000-row pipeline including XGBoost training)
Expected: `Tests run: 1, Failures: 0, Errors: 0`. If `MLAgentTest`-style `UnsatisfiedLinkError` appears, confirm `brew install libomp` has run.

- [ ] **Step 5: Run the full test suite and inspect real output**

Run: `mvn -q test`
Expected: all tests across all tasks pass.

Run: `mvn -q exec:java`
Expected: prints the pipeline stages, confusion matrix, classification report, and decision breakdown to stdout; inspect `reports/metrics_summary.txt` and confirm the confusion matrix numbers are in a broadly similar range to the existing Python output (`[[19669,244],[4025,62]]`) — not identical (see the design spec's Non-goals), but a fraud-detection pipeline that behaves sensibly (most transactions approved, a minority flagged, non-degenerate precision/recall).

- [ ] **Step 6: Commit**

```bash
git add src/main/java/com/acs/RunPipeline.java src/test/java/com/acs/RunPipelineIntegrationTest.java
git commit -m "Wire up full RunPipeline: real end-to-end run against data/*.csv"
```

---

### Task 13: README, remove Python source, final verification

**Files:**
- Modify: `README.md`
- Delete: `requirements.txt`
- Delete: `src/acs/` (all `.py` files: `__init__.py`, `agents.py`, `data_loader.py`, `evaluate.py`, `feature_engineering.py`, `orchestrator.py`)
- Delete: `scripts/run_pipeline.py`
- Delete: `tests/test_pipeline.py`
- Keep unchanged: `notebooks/Code_RunFile.ipynb`, `data/`, `LICENSE`, `docs/superpowers/`

**Interfaces:** none — this is a documentation/cleanup task with a full-suite verification gate.

- [ ] **Step 1: Rewrite `README.md`**

```markdown
# ACS: Agentic Compliance System for Cross-Border Payments

Reference implementation supporting the manuscript *"A Decentralized Agentic
Architecture for Real-Time Compliance and Fraud Detection in Cross-Border
Payment Systems"* (Sankaranainar Parmsivan, submitted to IEEE IT
Professional).

The system simulates a decentralized multi-agent pipeline for real-time
fraud detection and compliance enforcement over ISO 20022-style cross-border
transactions: an anomaly detection agent, a policy enforcement agent, a
composite risk agent, a supervised ML agent (XGBoost), a human-on-the-loop
review step, and a hashed audit/trust layer — all coordinated by an
`AcsOrchestrator`. This is the Java port of the original Python reference
implementation.

## ⚠️ Known limitation — please read before citing results from this repo

The original project notebook (`notebooks/Code_RunFile.ipynb`) references
three features that are used to train the anomaly and ML agents —
`velocity_score`, `device_risk_score`, and `time_diff` — but the script that
computes them from the raw source data was not included in the delivered
project files. As provided, the notebook cannot run past the EDA section.

`src/main/java/com/acs/FeatureEngineering.java` includes a **provisional,
clearly-labeled reconstruction** of those three features (velocity from
per-user transaction gaps, device risk from the device fraud hint blended
with IP risk) so the full pipeline is runnable end to end. Running the
pipeline with these proxy features does **not** reproduce the
precision/recall/F1 numbers reported in the manuscript's Tables 2–3 — see
`reports/metrics_summary.txt` for the actual output of this repo's pipeline.

**This module is a placeholder.** It should be replaced with the original
feature-engineering logic (or a documented, agreed-upon substitute) before
this repository is treated as the authoritative validation artifact for the
published paper.

## About this Java port

This is a from-scratch Java port of the original Python implementation.
Two pieces of the original pipeline — scikit-learn's `IsolationForest` and
imbalanced-learn's `SMOTETomek` — have no equivalent Java library, so they
are hand-implemented to be algorithm-faithful (same tree-building /
neighbor-interpolation / Tomek-link logic), seeded with Java's own RNG. As
a result, running this pipeline reproduces the same *kind* of output as the
Python version (same stages, same fusion logic, same report format) but
**not bit-identical numbers** — `java.util.Random` and numpy's RNG produce
different sequences from the same seed, and the hand-ported algorithms are
faithful re-implementations, not a translation of scikit-learn's exact
internal random draws. `MLAgent` (XGBoost) is the one component using the
same core engine as the Python version (XGBoost4J), so it is the
closest-matching piece.

## Project structure

```
.
├── data/                          # Source CSVs (transactions, users, devices, ips, merchants, chargebacks)
├── notebooks/
│   └── Code_RunFile.ipynb         # Original exploratory notebook, unmodified
├── src/main/java/com/acs/
│   ├── DataLoader.java            # CSV load + minimal joins actually used downstream
│   ├── FeatureEngineering.java    # Compliance features + PROVISIONAL risk features (see warning above)
│   ├── Features.java              # Feature-matrix extraction helper
│   ├── ml/
│   │   ├── IsolationForest.java   # Hand-ported, sklearn-algorithm-faithful
│   │   ├── KdTree.java            # Nearest-neighbor helper used by SmoteTomek
│   │   ├── SmoteTomek.java        # Hand-ported, imbalanced-learn-algorithm-faithful
│   │   └── TrainTestSplit.java    # Stratified train/test split
│   ├── agents/
│   │   ├── AnomalyAgent.java
│   │   ├── PolicyAgent.java
│   │   ├── RiskAgent.java
│   │   ├── HumanAgent.java
│   │   ├── AuditLayer.java
│   │   └── MLAgent.java           # Wraps XGBoost4J
│   ├── AcsOrchestrator.java       # Coordinates all agents, fuses outputs into a decision
│   ├── Evaluate.java              # Confusion matrix / classification report
│   └── RunPipeline.java           # End-to-end runnable entrypoint
├── src/test/java/com/acs/         # JUnit 5 tests, mirroring the main tree
├── reports/                       # Generated: confusion_matrix.png, metrics_summary.txt
├── pom.xml
└── README.md
```

## Setup

Requires Java 21 and Maven.

On macOS, XGBoost4J's native library needs the OpenMP runtime:

```bash
brew install libomp
```

## Run

```bash
mvn exec:java
```

This loads the six CSVs from `data/` (joining only what's actually used —
see `DataLoader.java`), engineers features, trains the anomaly detector
and XGBoost classifier on a SMOTETomek-balanced split, runs the full agent
pipeline, and writes:

- `reports/confusion_matrix.png`
- `reports/metrics_summary.txt`

## Tests

```bash
mvn test
```

## Architecture reference

The four-layer architecture (Input → Agentic Orchestrator → Agent →
Decision/Implementation) and the human-on-the-loop escalation workflow are
described in full in the manuscript. This repository implements the
proof-of-concept version of that architecture over a synthetic 120,000-row
cross-border transaction dataset.

## License

MIT — see `LICENSE`.

## Citation

If you use this repository, please cite the manuscript once published
(details to be added upon acceptance). ORCID: 0009-0006-1738-3863.
```

- [ ] **Step 2: Delete the Python source, scripts, tests, and requirements file**

```bash
git rm -r src/acs requirements.txt scripts/run_pipeline.py tests/test_pipeline.py
```

If `scripts/` or `tests/` are now empty, remove the empty directories too:

```bash
rmdir scripts tests 2>/dev/null || true
```

- [ ] **Step 3: Run the full Java test suite one more time**

Run: `mvn -q test`
Expected: `BUILD SUCCESS`, all tests across every task pass, with the real `data/*.csv` on disk (nothing was deleted from `data/`).

- [ ] **Step 4: Run the pipeline one more time and inspect the reports**

Run: `mvn -q exec:java`

Then read `reports/metrics_summary.txt` and confirm it:
- Contains a confusion matrix, classification report, and decision breakdown
- Is a plausible fraud-detection result (not all-APPROVED or all-FLAGGED)
- Still carries the "provisional/reconstructed" caveat line

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "Rewrite README for the Java port; remove Python source now that the port is verified working"
```

(The `git rm` from Step 2 stages the deletions; include them in the same commit if not already staged, or as a separate commit — either is fine here since both land together before push.)

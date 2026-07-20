export interface DomainOption {
  value: string;
  label: string;
  description?: string;
}

export interface HealthStatus {
  status: string;
  llmAvailable: boolean;
  llmProvider: string;
}

export interface Scenario {
  id?: number;
  title: string;
  domain: string;
  flowDescription?: string;
  sourceCountry?: string;
  destinationCountry?: string;
  currency?: string;
  amount?: number;
  crossBorderFlag?: boolean;
  highRiskJurisdiction?: boolean;
  regulatedAsset?: boolean;
}

export interface TestCase {
  id: number;
  category: string;
  title: string;
  description: string;
  testInput?: string;
  expectedBehavior?: string;
  detectedByRules: boolean;
  detectedByLlm: boolean;
  confidenceScore?: number;
  llmReasoning?: string;
  engineType: string;
}

export interface CoverageReport {
  id?: number;
  ruleBasedTotalCases: number;
  ruleBasedUniqueCategories: number;
  ruleBasedCoverageScore: number;
  llmTotalCases: number;
  llmUniqueCategories: number;
  llmCoverageScore: number;
  llmExclusiveCases: number;
  coverageDeltaPercent: number;
  semanticOnlyCases: number;
  researchSummary: string;
  categoryBreakdownJson?: string;
}

export interface AnalysisResult {
  scenario: Scenario;
  ruleBasedCases: TestCase[];
  llmCases: TestCase[];
  coverageReport: CoverageReport;
}

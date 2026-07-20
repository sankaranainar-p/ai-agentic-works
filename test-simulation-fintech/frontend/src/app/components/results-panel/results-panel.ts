import { Component, Input } from '@angular/core';
import { AnalysisResult, TestCase } from '../../models/models';

@Component({
  selector: 'app-results-panel',
  standalone: false,
  templateUrl: './results-panel.html',
  styleUrl: './results-panel.scss',
})
export class ResultsPanel {
  @Input() result!: AnalysisResult;

  activeTab = 0;
  expandedCase: number | null = null;

  get llmExclusiveCases(): TestCase[] {
    return this.result?.llmCases?.filter(tc => !tc.detectedByRules) ?? [];
  }

  toggleCase(id: number): void {
    this.expandedCase = this.expandedCase === id ? null : id;
  }

  categoryColor(category: string): string {
    const colors: Record<string, string> = {
      TIMING_CONFLICT:    '#ff9800',
      JURISDICTION_OVERLAP: '#9c27b0',
      CURRENCY_ANOMALY:   '#00bcd4',
      VELOCITY_BREACH:    '#f44336',
      GEO_ANOMALY:        '#ff5722',
      SYNTHETIC_IDENTITY: '#e91e63',
      THRESHOLD_GAMING:   '#ff9800',
      AML_REPORTING:      '#f44336',
      MICA_VIOLATION:     '#673ab7',
      PCI_EXPOSURE:       '#e53935',
      SEMANTIC_AMBIGUITY: '#4caf50',
    };
    return colors[category] ?? '#607d8b';
  }

  categoryLabel(category: string): string {
    const labels: Record<string, string> = {
      TIMING_CONFLICT:    'Timing Conflict',
      JURISDICTION_OVERLAP: 'Jurisdiction Overlap',
      CURRENCY_ANOMALY:   'Currency Anomaly',
      VELOCITY_BREACH:    'Velocity Breach',
      GEO_ANOMALY:        'Geo Anomaly',
      SYNTHETIC_IDENTITY: 'Synthetic Identity',
      THRESHOLD_GAMING:   'Threshold Gaming',
      AML_REPORTING:      'AML Reporting',
      MICA_VIOLATION:     'MiCA Violation',
      PCI_EXPOSURE:       'PCI Exposure',
      SEMANTIC_AMBIGUITY: 'Semantic Ambiguity',
    };
    return labels[category] ?? category;
  }
}

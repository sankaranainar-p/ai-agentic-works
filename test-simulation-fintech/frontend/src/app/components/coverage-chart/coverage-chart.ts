import { Component, Input, OnChanges } from '@angular/core';
import { ChartData, ChartOptions } from 'chart.js';
import { CoverageReport } from '../../models/models';

@Component({
  selector: 'app-coverage-chart',
  standalone: false,
  templateUrl: './coverage-chart.html',
  styleUrl: './coverage-chart.scss',
})
export class CoverageChart implements OnChanges {
  @Input() report!: CoverageReport;

  barData: ChartData<'bar'> = { labels: [], datasets: [] };

  barOptions: ChartOptions<'bar'> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { position: 'top' },
    },
    scales: {
      y: { beginAtZero: true, ticks: { stepSize: 1 } },
    },
  };

  ngOnChanges(): void {
    if (!this.report) return;
    this.barData = {
      labels: ['Rule-based', 'LLM (Ollama)'],
      datasets: [
        {
          label: 'Total test cases',
          data: [this.report.ruleBasedTotalCases, this.report.llmTotalCases],
          backgroundColor: ['rgba(63,81,181,0.8)', 'rgba(0,188,212,0.8)'],
          borderColor: ['#3f51b5', '#00bcd4'],
          borderWidth: 1,
          borderRadius: 6,
        },
        {
          label: 'Unique categories',
          data: [this.report.ruleBasedUniqueCategories, this.report.llmUniqueCategories],
          backgroundColor: ['rgba(63,81,181,0.35)', 'rgba(0,188,212,0.35)'],
          borderColor: ['#3f51b5', '#00bcd4'],
          borderWidth: 1,
          borderRadius: 6,
        },
      ],
    };
  }
}

import { Component, OnInit } from '@angular/core';
import { AnalysisResult, HealthStatus } from '../../models/models';
import { ApiService } from '../../services/api.service';

@Component({
  selector: 'app-dashboard',
  standalone: false,
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.scss',
})
export class Dashboard implements OnInit {
  result: AnalysisResult | null = null;
  health: HealthStatus | null = null;

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.api.health().subscribe({
      next: (h) => (this.health = h),
      error: () => (this.health = null),
    });
  }

  onAnalysisComplete(result: AnalysisResult): void {
    this.result = result;
    setTimeout(() => {
      document.getElementById('results-anchor')?.scrollIntoView({ behavior: 'smooth' });
    }, 100);
  }
}

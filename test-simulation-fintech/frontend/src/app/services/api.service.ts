import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { AnalysisResult, DomainOption, HealthStatus } from '../models/models';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private base = '/api';

  constructor(private http: HttpClient) {}

  health(): Observable<HealthStatus> {
    return this.http.get<HealthStatus>(`${this.base}/health`);
  }

  getDomains(): Observable<DomainOption[]> {
    return this.http.get<DomainOption[]>(`${this.base}/domains`);
  }

  analyzeScenario(payload: unknown): Observable<AnalysisResult> {
    return this.http.post<AnalysisResult>(`${this.base}/scenarios`, payload);
  }
}

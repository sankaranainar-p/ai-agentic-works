import { NgModule, provideBrowserGlobalErrorListeners } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { ReactiveFormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { BaseChartDirective, provideCharts, withDefaultRegisterables } from 'ng2-charts';

// Angular Material
import { MatButtonModule } from '@angular/material/button';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatTabsModule } from '@angular/material/tabs';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatCardModule } from '@angular/material/card';

import { AppRoutingModule } from './app-routing-module';
import { AppComponent } from './app';
import { Dashboard } from './components/dashboard/dashboard';
import { ScenarioForm } from './components/scenario-form/scenario-form';
import { ResultsPanel } from './components/results-panel/results-panel';
import { CoverageChart } from './components/coverage-chart/coverage-chart';
import { DomainLabelPipe } from './pipes/domain-label-pipe';

@NgModule({
  declarations: [
    AppComponent,
    Dashboard,
    ScenarioForm,
    ResultsPanel,
    CoverageChart,
    DomainLabelPipe,
  ],
  imports: [
    BrowserModule,
    BrowserAnimationsModule,
    ReactiveFormsModule,
    HttpClientModule,
    BaseChartDirective,
    MatButtonModule,
    MatInputModule,
    MatFormFieldModule,
    MatSelectModule,
    MatCheckboxModule,
    MatTabsModule,
    MatIconModule,
    MatProgressBarModule,
    MatProgressSpinnerModule,
    MatCardModule,
    AppRoutingModule,
  ],
  providers: [provideBrowserGlobalErrorListeners(), provideCharts(withDefaultRegisterables())],
  bootstrap: [AppComponent],
})
export class AppModule {}

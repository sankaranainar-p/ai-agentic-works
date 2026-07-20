import { Component, EventEmitter, OnInit, Output } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { AnalysisResult, DomainOption } from '../../models/models';
import { ApiService } from '../../services/api.service';

const EXAMPLES: Record<string, Partial<Record<string, unknown>>> = {
  aml: {
    title: 'Layering via structuring — cash deposits below threshold',
    flowDescription:
      'Customer makes 9 daily cash deposits of $9,800 each across different branches over two weeks, followed by a single wire transfer to an offshore account in the Cayman Islands.',
    sourceCountry: 'US',
    destinationCountry: 'KY',
    currency: 'USD',
    amount: 88200,
    crossBorderFlag: true,
    highRiskJurisdiction: true,
    regulatedAsset: false,
  },
  swift: {
    title: 'SWIFT MT103 cross-border to high-risk corridor',
    flowDescription:
      'Corporate client initiates a €45,000 SWIFT MT103 transfer from Germany to UAE for goods procurement. Beneficiary bank is in Dubai free zone with correspondent relationship through a US bank.',
    sourceCountry: 'DE',
    destinationCountry: 'AE',
    currency: 'EUR',
    amount: 45000,
    crossBorderFlag: true,
    highRiskJurisdiction: false,
    regulatedAsset: false,
  },
  crypto: {
    title: 'Crypto-to-fiat conversion via unhosted wallet',
    flowDescription:
      'User sends 1.2 BTC from an unhosted wallet to a regulated exchange for conversion to GBP. Transaction originates from a mixer-associated address flagged in OFAC watchlist.',
    sourceCountry: 'GB',
    destinationCountry: 'GB',
    currency: 'BTC',
    amount: 1.2,
    crossBorderFlag: false,
    highRiskJurisdiction: false,
    regulatedAsset: true,
  },
  kyc: {
    title: 'High-value onboarding with PEP status',
    flowDescription:
      'New corporate account onboarding for a holding company with a politically exposed person (PEP) as beneficial owner. Company registered in Luxembourg, operations in Nigeria.',
    sourceCountry: 'LU',
    destinationCountry: 'NG',
    currency: 'EUR',
    amount: 500000,
    crossBorderFlag: true,
    highRiskJurisdiction: true,
    regulatedAsset: false,
  },
  sanctions: {
    title: 'OFAC SDN partial name match on wire transfer',
    flowDescription:
      'Outgoing USD wire for $120,000 where the beneficiary name produces a 78% fuzzy match against an OFAC SDN list entry. Transaction routed through a correspondent bank in Singapore.',
    sourceCountry: 'US',
    destinationCountry: 'SG',
    currency: 'USD',
    amount: 120000,
    crossBorderFlag: true,
    highRiskJurisdiction: false,
    regulatedAsset: false,
  },
};

@Component({
  selector: 'app-scenario-form',
  standalone: false,
  templateUrl: './scenario-form.html',
  styleUrl: './scenario-form.scss',
})
export class ScenarioForm implements OnInit {
  @Output() analysisComplete = new EventEmitter<AnalysisResult>();

  loading = false;
  error: string = '';

  domains: DomainOption[] = [];

  form!: FormGroup;

  constructor(
    private fb: FormBuilder,
    private api: ApiService,
  ) {}

  ngOnInit(): void {
    this.form = this.fb.group({
      title: ['', [Validators.required, Validators.minLength(5)]],
      domain: ['', Validators.required],
      flowDescription: ['', [Validators.required, Validators.minLength(20)]],
      sourceCountry: [''],
      destinationCountry: [''],
      currency: [''],
      amount: [null],
      crossBorderFlag: [false],
      highRiskJurisdiction: [false],
      regulatedAsset: [false],
    });

    this.api.getDomains().subscribe({
      next: (d) => { this.domains = d; },
      error: () => {
        this.domains = [
          { value: 'CROSS_BORDER_PAYMENT', label: 'Cross-Border Payment Delays', description: '' },
          { value: 'FRAUD_SPIKE', label: 'Fraud Spike Detection', description: '' },
          { value: 'COMPLIANCE_THRESHOLD', label: 'Compliance Threshold Violations', description: '' },
        ];
      },
    });
  }

  onDomainChange(): void {
    this.error = '';
  }

  loadExample(domain: string | null | undefined): void {
    if (!domain) return;

    const examples: Record<string, any> = {
      CROSS_BORDER_PAYMENT: {
        title: 'SWIFT cross-border to high-risk corridor',
        domain: 'CROSS_BORDER_PAYMENT',
        flowDescription: 'EUR payment from Germany to UAE via correspondent bank, submitted at 16:30 CET after SWIFT cutoff window. Payment routed through high-risk jurisdiction.',
        sourceCountry: 'DE',
        destinationCountry: 'AE',
        currency: 'EUR',
        amount: 45000,
        crossBorderFlag: true,
        highRiskJurisdiction: true,
        regulatedAsset: false,
      },
      FRAUD_SPIKE: {
        title: 'High-velocity card fraud across merchants',
        domain: 'FRAUD_SPIKE',
        flowDescription: 'Same card used across 6 different merchants in 10 minutes with amounts just below $10,000 reporting threshold. Transactions span retail, hotel, and travel categories.',
        sourceCountry: 'US',
        destinationCountry: 'US',
        currency: 'USD',
        amount: 9500,
        crossBorderFlag: false,
        highRiskJurisdiction: false,
        regulatedAsset: false,
      },
      COMPLIANCE_THRESHOLD: {
        title: 'Layering via structuring — cash deposits below threshold',
        domain: 'COMPLIANCE_THRESHOLD',
        flowDescription: 'Customer makes 9 daily cash deposits of $9,800 each across different branches over two weeks, followed by a single wire transfer to an offshore account in the Cayman Islands.',
        sourceCountry: 'US',
        destinationCountry: 'KY',
        currency: 'USD',
        amount: 88200,
        crossBorderFlag: true,
        highRiskJurisdiction: true,
        regulatedAsset: false,
      },
    };

    const example = examples[domain];
    if (example) {
      this.form.patchValue(example);
      this.form.markAllAsTouched();
    }
  }

  submit(): void {
    if (this.form.invalid) return;
    this.loading = true;
    this.error = '';

    const raw = this.form.value;
    const payload = {
      title: String(raw.title),
      domain: String(raw.domain),
      flowDescription: String(raw.flowDescription),
      sourceCountry: raw.sourceCountry ? String(raw.sourceCountry) : null,
      destinationCountry: raw.destinationCountry ? String(raw.destinationCountry) : null,
      currency: raw.currency ? String(raw.currency) : null,
      amount: raw.amount ? Number(raw.amount) : null,
      crossBorderFlag: Boolean(raw.crossBorderFlag),
      highRiskJurisdiction: Boolean(raw.highRiskJurisdiction),
      regulatedAsset: Boolean(raw.regulatedAsset),
    };

    this.api.analyzeScenario(payload).subscribe({
      next: (result: AnalysisResult) => {
        this.loading = false;
        this.analysisComplete.emit(result);
      },
      error: (err: any) => {
        this.loading = false;
        this.error = err?.error?.message || 'Analysis failed — check server logs.';
      },
    });
  }
}

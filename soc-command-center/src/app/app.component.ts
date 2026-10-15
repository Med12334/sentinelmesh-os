import { Component, ChangeDetectionStrategy, inject, signal, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SocCommandService } from './services/soc-command.service';
import { ForensicIncidentRecord, HoneypotTrapSession, ComplianceAuditEntry } from './models/sentinelmesh.models';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="soc-war-room">
      <header>
        <h1>SENTINELMESH OS // 10-Layer Zero-Trust SOAR, Deception Honeypot & Merkle Forensic War Room</h1>
      </header>

      <section class="grid">
        <div class="card">
          <h2>Execute Autonomous SOAR Playbook & Seal SHA-256 Merkle Proof</h2>
          <form (ngSubmit)="executeSoar()">
            <input [(ngModel)]="incidentForm.sourceIp" name="sourceIp" placeholder="185.220.101.44" required />
            <input [(ngModel)]="incidentForm.targetService" name="targetService" placeholder="payment-gateway" required />
            <input [(ngModel)]="incidentForm.mitreTacticId" name="mitreTacticId" placeholder="T1190_EXPLOIT_PUBLIC_APP" required />
            <input type="number" step="0.1" [(ngModel)]="incidentForm.threatScore" name="threatScore" required />
            <button type="submit">Trigger Lockdown & Seal Merkle Block</button>
          </form>
        </div>

        <div class="card">
          <h2>Active Deception Honeypot Traps (Layer 6)</h2>
          <ul>
            <li *ngFor="let trap of honeypotSessions()">
              <strong>{{ trap.attackerIp }}</strong> → <code>{{ trap.decoyEndpoint }}</code>
              [Payload: <code>{{ trap.capturedExploitPayload }}</code>]
            </li>
          </ul>
        </div>
      </section>

      <section class="card">
        <h2>Tamper-Proof PostgreSQL Forensic Merkle Ledger (Layer 8)</h2>
        <table>
          <thead>
            <tr>
              <th>Attacker IP</th>
              <th>Target Service</th>
              <th>MITRE ATT&CK ID</th>
              <th>Score</th>
              <th>SOAR Action</th>
              <th>SHA-256 Merkle Proof Hash</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let rec of forensicLedger()">
              <td>{{ rec.sourceIp }}</td>
              <td>{{ rec.targetService }}</td>
              <td>{{ rec.mitreTacticId }}</td>
              <td>{{ rec.threatScore }}</td>
              <td>{{ rec.remediationAction }}</td>
              <td><code>{{ rec.merkleHash }}</code></td>
            </tr>
          </tbody>
        </table>
      </section>
    </div>
  `
})
export class AppComponent implements OnInit {
  private readonly socService = inject(SocCommandService);

  readonly forensicLedger = signal<ForensicIncidentRecord[]>([]);
  readonly honeypotSessions = signal<HoneypotTrapSession[]>([]);
  readonly db2Audits = signal<ComplianceAuditEntry[]>([]);

  incidentForm = {
    sourceIp: '185.220.101.44',
    targetService: 'payment-gateway',
    mitreTacticId: 'T1190_EXPLOIT_PUBLIC_APP',
    threatScore: 9.6
  };

  ngOnInit(): void {
    this.refreshWarRoom();
  }

  executeSoar(): void {
    this.socService.triggerSoarPlaybook(this.incidentForm).subscribe(() => {
      this.refreshWarRoom();
    });
  }

  refreshWarRoom(): void {
    this.socService.getForensicMerkleLedger().subscribe(data => this.forensicLedger.set(data));
    this.socService.getHoneypotSessions().subscribe(data => this.honeypotSessions.set(data));
    this.socService.getDb2ComplianceVault().subscribe(data => this.db2Audits.set(data));
  }
}

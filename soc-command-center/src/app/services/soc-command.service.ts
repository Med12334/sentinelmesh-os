import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ForensicIncidentRecord, HoneypotTrapSession, ComplianceAuditEntry } from '../models/sentinelmesh.models';

@Injectable({ providedIn: 'root' })
export class SocCommandService {
  private readonly http = inject(HttpClient);
  private readonly gatewayUrl = 'http://localhost:8000/api/v1';

  triggerSoarPlaybook(payload: {
    sourceIp: string;
    targetService: string;
    mitreTacticId: string;
    threatScore: number;
  }): Observable<unknown> {
    return this.http.post(`${this.gatewayUrl}/soar/execute`, payload);
  }

  getForensicMerkleLedger(): Observable<ForensicIncidentRecord[]> {
    return this.http.get<ForensicIncidentRecord[]>(`${this.gatewayUrl}/soar/forensic-ledger`);
  }

  getHoneypotSessions(): Observable<HoneypotTrapSession[]> {
    return this.http.get<HoneypotTrapSession[]>(`${this.gatewayUrl}/honeypot/sessions`);
  }

  getDb2ComplianceVault(): Observable<ComplianceAuditEntry[]> {
    return this.http.get<ComplianceAuditEntry[]>(`${this.gatewayUrl}/compliance-vault`);
  }
}
